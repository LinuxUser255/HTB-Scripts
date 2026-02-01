# Using ripgrep for digging around SMB files


### Situation:
You just did a `smb: \> mget * ` and need a quick effiecent way to find the good stuff in the SMB files you just downloaded.

**Example:**
```bash
┌──(kali㉿kali)-[~/Boxes/Active/active.htb]
└─$ ll
total 12
drwxrwxr-x 5 kali kali 4096 Feb  1 14:20 DfsrPrivate
drwxrwxr-x 4 kali kali 4096 Feb  1 14:20 Policies
drwxrwxr-x 2 kali kali 4096 Feb  1 14:20 scripts
```

#### Here are some useful ripgrep commands for this situation.

- Hunt for GPP credentials:

```bash
rg -i "cpassword" .
```

- Find usernames:
```shell
rg -i "username\|user=" .
```

- Both at once:
```shell
rg -i "cpassword|username|password" .
```

- Find Groups.xml specifically:
```shell
find . -name "Groups.xml" -exec cat {} \;
```

- Search for common sensitive patterns:
```shell
rg -i "pass|pwd|cred|secret|key" .
```

- Show context around matches:
```shell
rg -i -C 3 "cpassword" .
```

- List all XML files (GPP lives in XML):
```bash
find . -name "*.xml" | xargs rg -i "cpassword|password"
```

- Quick one-liner for this box:
```bash
rg -i cpassword . && find . -name "Groups.xml"
```

- You're gonna be looking for something like this:

<Properties ... cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="active.htb\SVC_TGS" ...>

Once found, decrypt with:

```bash
gpp-decrypt "cpassword_string_here"
```

## And some other go-to commands for SMB exfil:
```bash
# 1. GPP passwords (your main target)
rg -i "cpassword" .

# 2. Any passwords/credentials
rg -i "password|passwd|pwd|credential|secret" .

# 3. Usernames (for user enumeration)
rg -i "username|samaccountname|user=" .

# 4. Find all XML files
find . -name "*.xml" -type f

# 5. Interesting file types
find . \( -name "*.xml" -o -name "*.config" -o -name "*.ini" -o -name "*.txt" -o -name "*.bat" -o -name "*.ps1" -o -name "*.vbs" \)

# 6. Combined hunting script
rg -i "cpassword|password|username|credential" . --glob "*.xml"
```

**What else to look for in SMB shares:**

|File/Location|Why|
|---|---|
|`Groups.xml`|GPP local user passwords|
|`ScheduledTasks.xml`|GPP scheduled task creds|
|`Services.xml`|GPP service account creds|
|`Drives.xml`|Mapped drive creds|
|`DataSources.xml`|Database connection strings|
|`*.ps1`, `*.bat`, `*.vbs`|Scripts with hardcoded creds|


**I also automated this entire process in a single shell script, it's in this Windows directory**



