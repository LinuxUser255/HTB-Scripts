# Android App Security File Analysis Cheat Sheet

Android app security has a similar "grep through everything" phase.

---

## 📱 Android App File Structure

```
MyApp.apk (it's just a ZIP file)
├── AndroidManifest.xml          # App permissions, components, configs
├── classes.dex                  # Compiled Java/Kotlin code
├── resources.arsc               # Compiled resources
├── res/                         # Resources (images, layouts, strings)
│   ├── layout/                  # UI layouts
│   ├── values/
│   │   ├── strings.xml          # Hardcoded strings (GOLD MINE!)
│   │   └── colors.xml
│   ├── drawable/                # Images
│   └── xml/                     # Config files
├── assets/                      # Additional files (databases, configs)
├── lib/                         # Native libraries (.so files)
│   ├── arm64-v8a/
│   ├── armeabi-v7a/
│   └── x86/
├── META-INF/                    # Signatures and manifests
│   ├── CERT.RSA
│   ├── CERT.SF
│   └── MANIFEST.MF
└── original/                    # (After apktool decode)
```

---

## 🔧 Quick Setup

```bash
# Install tools
pipx install apkleaks
pipx install mobsfscan
sudo apt install ripgrep fd-find apktool jadx

# Extract APK
apktool d app.apk -o app_decoded

# Decompile to Java
jadx app.apk -d app_source

# Now you have two directories to search:
# app_decoded/  - Resources, XML, smali code
# app_source/   - Java source code
```

---

## 🎯 Critical Files to Check (Priority Order)

### **1. AndroidManifest.xml** (ALWAYS CHECK FIRST)
```bash
# Location after apktool
app_decoded/AndroidManifest.xml

# What to look for:
cat AndroidManifest.xml | grep -E 'android:exported="true"'  # Exposed components
cat AndroidManifest.xml | grep -E 'android:debuggable'       # Debug mode
cat AndroidManifest.xml | grep -E 'usesCleartextTraffic'     # HTTP allowed
cat AndroidManifest.xml | grep -E 'android:allowBackup'      # Backup allowed
cat AndroidManifest.xml | grep -E 'permission'                # Permissions
```

### **2. strings.xml** (SECRETS GALORE)
```bash
# Location
app_decoded/res/values/strings.xml

# Search for secrets
rg -i 'api[_-]?key|password|secret|token|auth' app_decoded/res/values/strings.xml
rg 'AKIA[0-9A-Z]{16}' app_decoded/res/values/strings.xml  # AWS keys
```

### **3. BuildConfig and Gradle files**
```bash
# After jadx decompilation
app_source/sources/com/example/app/BuildConfig.java

# Look for:
rg -i 'API_KEY|SECRET|TOKEN|BASE_URL' app_source/
```

### **4. assets/ folder** (Config files, databases)
```bash
# Common findings:
app_decoded/assets/config.json
app_decoded/assets/database.db
app_decoded/assets/*.plist
app_decoded/assets/*.xml

# Search everything in assets
rg -i 'password|secret|key|token' app_decoded/assets/
```

### **5. Shared Preferences XML**
```bash
# Usually in decompiled source or device
app_decoded/res/xml/
/data/data/com.example.app/shared_prefs/*.xml  # On device

# Search for sensitive data
rg -i 'password|session|token|user' app_decoded/res/xml/
```

### **6. Network Security Config**
```bash
app_decoded/res/xml/network_security_config.xml

# Check for:
<certificates src="user"/> # User certs allowed (bad for pinning bypass)
<domain-config cleartextTrafficPermitted="true"> # HTTP allowed
```

---

## 🔍 Ripgrep Patterns for Android Security

### **Secret Hunting (The Big One)**

```bash
#!/bin/bash
# android-secrets.sh

APP_DIR="app_decoded"
SOURCE_DIR="app_source"

echo "[*] Searching for secrets..."

# AWS Keys
echo "\n[*] AWS Access Keys:"
rg -i 'AKIA[0-9A-Z]{16}' $APP_DIR $SOURCE_DIR

# Generic API Keys
echo "\n[*] API Keys:"
rg -i '(api[_-]?key|apikey|api[_-]?secret)["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}' $APP_DIR $SOURCE_DIR

# Passwords (hardcoded)
echo "\n[*] Passwords:"
rg -i '(password|passwd|pwd)["\s]*[:=]["\s]*["\'][^"\']{3,}' $APP_DIR $SOURCE_DIR

# JWT Tokens
echo "\n[*] JWT Tokens:"
rg 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' $APP_DIR $SOURCE_DIR

# Private Keys
echo "\n[*] Private Keys:"
rg -i 'BEGIN.*PRIVATE KEY' $APP_DIR $SOURCE_DIR

# Database credentials
echo "\n[*] Database Strings:"
rg -i 'mongodb://|mysql://|postgres://|jdbc:' $APP_DIR $SOURCE_DIR

# Google API Keys
echo "\n[*] Google API Keys:"
rg 'AIza[0-9A-Za-z\\-_]{35}' $APP_DIR $SOURCE_DIR

# Firebase
echo "\n[*] Firebase URLs:"
rg '\.firebaseio\.com' $APP_DIR $SOURCE_DIR

# Slack tokens
echo "\n[*] Slack Tokens:"
rg 'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}' $APP_DIR $SOURCE_DIR

# Generic secrets
echo "\n[*] Generic Secrets:"
rg -i '(secret|token|auth)[_-]?(key|token)["\s]*[:=]' $APP_DIR $SOURCE_DIR
```

### **URL/Endpoint Discovery**

```bash
#!/bin/bash
# find-urls.sh

echo "[*] Finding URLs and endpoints..."

# HTTP/HTTPS URLs
rg -o 'https?://[a-zA-Z0-9./?=_-]*' app_decoded/ app_source/ | sort -u > urls.txt

# API endpoints
rg -o '/api/[a-zA-Z0-9/._-]*' app_decoded/ app_source/ | sort -u > endpoints.txt

# IP addresses
rg -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' app_decoded/ app_source/ | sort -u > ips.txt

# Domains
rg -o '[a-zA-Z0-9.-]+\.(com|net|org|io|dev|app|xyz)' app_decoded/ app_source/ | sort -u > domains.txt

echo "[+] Results saved to urls.txt, endpoints.txt, ips.txt, domains.txt"
```

### **Security Misconfigurations**

```bash
#!/bin/bash
# find-misconfigs.sh

echo "[*] Checking for security misconfigurations..."

# Exported components
echo "\n[+] Exported Activities:"
rg 'exported="true".*activity' app_decoded/AndroidManifest.xml

# Debuggable
echo "\n[+] Debug Mode:"
rg 'android:debuggable="true"' app_decoded/AndroidManifest.xml

# Cleartext traffic
echo "\n[+] Cleartext HTTP Allowed:"
rg 'usesCleartextTraffic="true"' app_decoded/AndroidManifest.xml

# Backup allowed
echo "\n[+] Backup Allowed:"
rg 'allowBackup="true"' app_decoded/AndroidManifest.xml

# Weak crypto
echo "\n[+] Weak Crypto:"
rg -i 'DES|MD5|SHA1|ECB' app_source/

# Hardcoded IVs
echo "\n[+] Hardcoded IVs:"
rg 'IvParameterSpec' app_source/

# SQL Injection potential
echo "\n[+] Potential SQLi:"
rg 'rawQuery|execSQL' app_source/ | rg -v 'PreparedStatement'
```

### **Authentication & Session Issues**

```bash
#!/bin/bash
# find-auth-issues.sh

# Insecure random
echo "[*] Insecure Random:"
rg 'new Random\(\)' app_source/

# Hardcoded credentials
echo "\n[*] Hardcoded Credentials:"
rg -i '(username|user|login)["\s]*[:=]["\s]*["\'][a-zA-Z0-9]+["\']' app_source/

# Session tokens in logs
echo "\n[*] Logging Sensitive Data:"
rg 'Log\.[dviwe]\(.*token|password|session' app_source/

# SharedPreferences without encryption
echo "\n[*] SharedPreferences Usage:"
rg 'getSharedPreferences|getPreferences' app_source/

# WebView issues
echo "\n[*] WebView JavaScript Enabled:"
rg 'setJavaScriptEnabled\(true\)' app_source/
```

---

## 🛠️ Complete Analysis Script

```bash
#!/bin/bash
# android-app-analysis.sh

APK="$1"
OUTPUT_DIR="analysis_output"

if [ -z "$APK" ]; then
    echo "Usage: $0 <app.apk>"
    exit 1
fi

echo "[*] Starting analysis of $APK"

# Create output directory
mkdir -p $OUTPUT_DIR

# Extract APK
echo "[*] Extracting APK with apktool..."
apktool d "$APK" -o "$OUTPUT_DIR/decoded" -f

# Decompile to Java
echo "[*] Decompiling to Java with jadx..."
jadx "$APK" -d "$OUTPUT_DIR/source" --no-res

# Quick wins
echo "[*] Running quick checks..."

echo "\n=== MANIFEST ANALYSIS ===" | tee $OUTPUT_DIR/manifest_findings.txt
grep -E 'exported="true"|debuggable="true"|usesCleartextTraffic' \
    $OUTPUT_DIR/decoded/AndroidManifest.xml | tee -a $OUTPUT_DIR/manifest_findings.txt

echo "\n=== URL DISCOVERY ===" | tee $OUTPUT_DIR/urls.txt
rg -o 'https?://[a-zA-Z0-9./?=_-]*' $OUTPUT_DIR/ --no-filename | \
    sort -u | tee -a $OUTPUT_DIR/urls.txt

echo "\n=== API KEYS ===" | tee $OUTPUT_DIR/secrets.txt
rg -i 'api[_-]?key.*[:=].*[a-zA-Z0-9]{20,}' $OUTPUT_DIR/ --no-filename | \
    tee -a $OUTPUT_DIR/secrets.txt

echo "\n=== AWS KEYS ===" | tee -a $OUTPUT_DIR/secrets.txt
rg 'AKIA[0-9A-Z]{16}' $OUTPUT_DIR/ --no-filename | \
    tee -a $OUTPUT_DIR/secrets.txt

echo "\n=== PASSWORDS ===" | tee -a $OUTPUT_DIR/secrets.txt
rg -i 'password.*[:=]' $OUTPUT_DIR/decoded/res/values/ --no-filename | \
    tee -a $OUTPUT_DIR/secrets.txt

echo "\n=== WEAK CRYPTO ===" | tee $OUTPUT_DIR/crypto.txt
rg -i 'DES|MD5|SHA1|ECB' $OUTPUT_DIR/source/ --no-filename | \
    head -20 | tee -a $OUTPUT_DIR/crypto.txt

echo "\n=== SQL INJECTION ===" | tee $OUTPUT_DIR/sqli.txt
rg 'rawQuery|execSQL' $OUTPUT_DIR/source/ --no-filename | \
    head -20 | tee -a $OUTPUT_DIR/sqli.txt

# Run automated tools
echo "\n[*] Running apkleaks..."
apkleaks -f "$APK" -o $OUTPUT_DIR/apkleaks.txt

echo "\n[*] Running mobsfscan..."
mobsfscan $OUTPUT_DIR/source/ --json -o $OUTPUT_DIR/mobsfscan.json

echo "\n[+] Analysis complete! Results in $OUTPUT_DIR/"
ls -lh $OUTPUT_DIR/
```

**Usage:**
```bash
chmod +x android-app-analysis.sh
./android-app-analysis.sh app.apk
```

---

## 🔥 High-Value Targets (What to Grep For)

### **Secrets & Credentials**
```bash
# The essentials
rg -i 'api[_-]?key|apikey|api[_-]?secret'
rg -i 'password|passwd|pwd'
rg -i 'secret[_-]?key|client[_-]?secret'
rg -i 'auth[_-]?token|bearer'
rg -i 'private[_-]?key'
rg -i 'access[_-]?token|refresh[_-]?token'

# Cloud providers
rg 'AKIA[0-9A-Z]{16}'                    # AWS
rg 'AIza[0-9A-Za-z\\-_]{35}'            # Google
rg 'sk_live_[0-9a-zA-Z]{24}'            # Stripe
rg '[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'  # OAuth
```

### **Network & Infrastructure**
```bash
# URLs
rg -o 'https?://[a-zA-Z0-9./?=_-]*'

# Internal IPs
rg '(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}'

# Domains
rg -o '[a-zA-Z0-9.-]+\.(com|net|org|io|dev|app)'

# Ports
rg ':[0-9]{2,5}[/"\s]'
```

### **Vulnerability Patterns**
```bash
# SQL Injection
rg 'rawQuery|execSQL' | rg -v '?'

# Path Traversal
rg 'getExternalStorageDirectory|openFileOutput'

# XSS in WebView
rg 'loadUrl.*javascript:|evaluateJavascript'

# Insecure crypto
rg -i 'DES|ECB|MD5|SHA1'

# Broadcast receivers
rg 'sendBroadcast|registerReceiver'

# Content providers
rg 'ContentProvider|query\(.*uri'
```

---

## 📁 Important Locations Cheat Sheet

```bash
# After apktool decode
app_decoded/
├── AndroidManifest.xml          # rg 'exported|debuggable|backup'
├── res/values/strings.xml       # rg -i 'api|key|password|secret'
├── res/xml/*.xml                # Check all XMLs for configs
├── assets/                      # rg -r '.' for all files
├── lib/                         # Check .so files with strings
└── smali/                       # Smali code (if you read it)

# After jadx decompile
app_source/
├── sources/com/example/app/
│   ├── BuildConfig.java        # API keys, URLs, build configs
│   ├── MainActivity.java
│   └── utils/Crypto.java       # Crypto implementations
└── resources/
    └── res/values/strings.xml   # Same as apktool
```

---

## 🎯 One-Liner Goldmines

```bash
# Find all strings.xml files and grep for secrets
find app_decoded/ -name strings.xml -exec rg -i 'api|key|secret|password|token' {} +

# Find hardcoded URLs in Java source
rg -o 'https?://[^"]*' app_source/sources/ | sort -u

# Extract all strings from DEX
strings classes.dex | rg -i 'api|key|secret|http' | sort -u

# Find all SQLite databases
find . -name "*.db" -o -name "*.sqlite"

# Check for exported components with intent filters
rg -A5 'exported="true"' app_decoded/AndroidManifest.xml | rg 'intent-filter'

# Find potential command injection
rg 'Runtime\.getRuntime\(\)\.exec'

# Find WebView SSL errors ignored
rg 'onReceivedSslError.*\.proceed\(\)'

# Find Firebase URLs
rg -o '[a-zA-Z0-9-]+\.firebaseio\.com' | sort -u
```

---

## 🔍 Native Library Analysis

```bash
# Extract strings from .so files
for so in $(find app_decoded/lib -name "*.so"); do
    echo "\n[*] Analyzing $so"
    strings "$so" | rg -i 'http|key|secret|password'
done

# Check for hardcoded crypto keys in native libs
strings app_decoded/lib/arm64-v8a/*.so | rg '[A-Za-z0-9+/]{32,}='

# Find function names in native libs
nm -D app_decoded/lib/arm64-v8a/*.so | rg ' T '
```

---

## 📊 Automated Tools Integration

```bash
# Combine tools for complete coverage

# 1. Quick secrets scan
apkleaks -f app.apk -o secrets.txt

# 2. Code vulnerability scan
mobsfscan app_source/ --json -o vulns.json

# 3. Custom pattern search
rg -f patterns.txt app_decoded/ app_source/ > custom_findings.txt

# 4. Combine results
cat secrets.txt vulns.json custom_findings.txt > full_report.txt
```

---

## 🎓 Pro Tips

1. **Always decompile twice**: Use both `apktool` (for resources) and `jadx` (for code)

2. **Check the obvious first**:
   ```bash
   cat app_decoded/res/values/strings.xml | less
   ```

3. **Use ripgrep's context flags**:
   ```bash
   rg -C3 'api_key' app_decoded/  # Show 3 lines before/after
   ```

4. **Combine with other tools**:
   ```bash
   # Extract, search, pipe to mobsfscan
   apktool d app.apk && mobsfscan app/
   ```

5. **Build a patterns file** (`patterns.txt`):
   ```
   api[_-]?key
   password
   secret
   AKIA[0-9A-Z]{16}
   eyJ[A-Za-z0-9_-]*\.eyJ
   ```
   Then: `rg -f patterns.txt app_decoded/`

6. **Script everything**: Like your SMB script, build reusable scripts

7. **Check backups**:
   ```bash
   adb backup -f backup.ab com.example.app
   dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
   tar xf backup.tar
   rg -i 'password|token' apps/
   ```

---

## 🚀 Complete Workflow Example

```bash
# 1. Get the APK
adb pull /data/app/com.example.app-*/base.apk app.apk

# 2. Extract everything
apktool d app.apk -o decoded
jadx app.apk -d source

# 3. Quick manifest check
cat decoded/AndroidManifest.xml | grep exported

# 4. Find secrets
rg -i 'api.*key|password|secret' decoded/ source/

# 5. Extract URLs
rg -o 'https?://[^"]*' source/ | sort -u > urls.txt

# 6. Check for SQLi
rg 'rawQuery\(' source/ --color=always | less

# 7. Run automated scans
apkleaks -f app.apk -o leaks.txt
mobsfscan source/ --json -o scan.json

# 8. Review and report
less leaks.txt scan.json
```

---

This is the Android equivalent of the SMB ripgrep cheat sheet! Same concept, different targets. 🎯

**Key difference from Windows/SMB hunting**: With Android apps, you're looking for secrets and vulns in *compiled/decompiled code* rather than live file shares, so you combine static analysis tools (apktool, jadx) with pattern matching (ripgrep).

