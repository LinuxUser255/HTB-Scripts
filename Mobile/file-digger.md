# Regex for Android enumeration

```bash
# Initial broad search for secrets in system files - Looking for potential API keys or tokens in packages.xml; why: System configs might leak build-time secrets, though hits may be system perms (educational to check assumptions).
rg -i 'API_KEY|SECRET|TOKEN|BASE_URL' system/

# List installed packages to identify targets - What: Package names like com.example.app; why: Reveals installed apps, UIDs, and flags for focusing on potential target apps.
cat system/packages.list

# Filter packages for common patterns - What: Matches like 'app|com.'; why: Narrows to potential target apps in packages.list for cross-referencing perms/UIDs.
rg -i 'app|com\.' system/packages.list

# Check device policies for auth clues - What: Password/policy/admin terms; why: Reveals lock types/weaknesses (e.g., password quality) that gatekeep backups.
cat system/device_policies.xml

# Grep policies for restrictions - What: Case-insensitive password/policy/admin; why: Hints at enterprise rules or lock enforcement in device_policies.xml.
rg -i 'password|policy|admin' system/device_policies.xml

# Search all permissions in packages - What: Any 'permission' lines; why: Lists granted perms for over-privileging checks (e.g., risky like INTERNET/STORAGE).
rg 'permission' system/packages.xml

# Thematic package filter on filtered list - What: Common terms like app/system/user; why: Refines filtered packages.txt for potential target apps (e.g., privileged or custom apps).
rg -i 'app|system|user|secure|mobile' sys.com.packages.txt

# Correlate a package with perms - What: Example package name with context; why: Extracts full <package> block in packages.xml for app-specific perms (e.g., storage access). (Replace 'com.example.app' with dynamic/target package).
rg -i 'com.example.app' system/packages.xml -C 10

# Filter risky perms in existing output - What: storage/write/read/internet/admin; why: Flags potential data leaks/exfil in packages-permissions.txt.
rg -i 'storage|write|read|internet|admin' packages-permissions.txt

# Find/grep storage perms across files - What: permission with storage/file/external; why: Targets file-related vulns in packages.xml (e.g., for app access).
find system -name "packages.xml" -exec rg 'permission.*(storage|file|external)' {} +

# Dig deeper into policies for lock hints - What: quality/length/admin with context; why: Seeks password_quality (e.g., 65536=PIN) or app refs in device_policies.xml.
rg -i 'quality|length|admin' system/device_policies.xml -C 3

# Extract strings from policies - What: Printable strings grepped for password/policy; why: Pulls text from XML if structured grep misses (e.g., mangled formats).
strings system/device_policies.xml | rg 'password|policy'

# Broad policy search across XMLs - What: policy/admin/restriction in all *.xml; why: Policies might spill into other files (e.g., appops.xml) for complete lock/admin intel.
find system -type f -name "*.xml" -exec rg -i 'policy|admin|restriction' {} +

# Locate databases for lock data - What: All *.db files; why: Finds locksettings.db for querying salts/types (SQLite holds structured auth data).
find system -name "*.db"

# Query lock DB for password details - What: Rows like lockscreen.password%; why: Extracts type/salt/quality from locksettings.db (informs cracking strategy).
sqlite3 system/locksettings.db "SELECT * FROM locksettings WHERE name LIKE 'lockscreen.password%';"

# Strings from lock DB - What: Grepped for password/salt/hash/quality; why: Alternative to SQL if query fails—extracts text from binary DB.
strings system/locksettings.db | rg -i 'password|salt|hash|quality'

# Hex dump password key - What: Grouped hex of password.key; why: Dumps binary hash (SHA-1 + MD5) for extraction/cracking.
xxd -g1 system/password.key

# Grep gesture key for hash - What: 40-char hex (SHA1); why: Checks for pattern lock hash (20B SHA1, negated if empty).
strings system/gesture.key | rg '[a-f0-9]{40}'

# List files with lock terms - What: Files containing password/key/salt/etc.; why: Inventories all files with auth clues for further strings/xxd.
rg -i 'password|key|salt|hash|pin|pattern' system/ -l

# Plain hex dump of password key - What: Continuous hex without offsets; why: Preps for cutting SHA-1/MD5 parts (easier slicing).
xxd -p system/password.key

# Extract SHA-1 hex - What: First 40 chars; why: Isolates SHA-1 hash for Hashcat input.
cat plain_hex.txt | cut -c 1-40

# Extract MD5 hex - What: Next 32 chars; why: Isolates MD5 for verification after cracking.
cat plain_hex.txt | cut -c 41-72

# Verify hex length - What: Char count of plain_hex.txt; why: Ensures 72 chars (36B file) before slicing.
wc -c plain_hex.txt

# Check key file size - What: Byte size of password.key; why: Confirms 72B (SHA-1 20B + MD5 16B + padding?).
ls -l system/password.key

# Clean and lowercase hex - What: Remove newlines/uppercase; why: Standardizes for Hashcat (lowercase hex expected).
cat plain_hex.txt | tr -d '\n' | tr 'A-F' 'a-f'

# Prepare Hashcat input - What: sha1:salt format; why: Formats for mode 130 cracking.
echo "$(cat sha1_lower.txt):$(echo 5ca5e19b48fb3b04)"
```
