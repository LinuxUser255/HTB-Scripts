#!/usr/bin/env bash

# apk_search.sh - Search graudit output for security-relevant patterns
# Usage: ./apk_search.sh <directory_containing_scan_files>

DIR="${1:-.}"

echo "========================================="
echo "  ANDROID SCAN"
echo "========================================="

echo "--- Data Leaks & Storage ---"
rg -in "SharedPreferences|MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|openFileOutput|getExternalStorage|SQLiteDatabase|ContentProvider|getSharedPreferences" "$DIR/android_scan.txt"

echo ""
echo "--- WebView Attacks ---"
rg -in "setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|loadUrl|loadData|evaluateJavascript|onReceivedSslError" "$DIR/android_scan.txt"

echo ""
echo "--- Intent / IPC ---"
rg -in 'startActivity|sendBroadcast|startService|getIntent|getStringExtra|getSerializableExtra|PendingIntent|exported' "$DIR/android_scan.txt"

echo ""
echo "--- Logging & Debug ---"
rg -in "Log\.d|Log\.v|Log\.i|System\.out\.println|printStackTrace|debuggable" "$DIR/android_scan.txt"


echo ""
echo "========================================="
echo "  JAVA SCAN"
echo "========================================="

echo "--- Command Injection ---"
rg -in "Runtime\.getRuntime|ProcessBuilder|\.exec\(" "$DIR/java_scan.txt"

echo ""
echo "--- SQL Injection ---"
rg -in "rawQuery|execSQL|\.execute\(|Statement|prepareStatement|SELECT|INSERT|UPDATE|DELETE" "$DIR/java_scan.txt"

echo ""
echo "--- Deserialization ---"
rg -in "ObjectInputStream|readObject|Serializable|Parcelable|fromJson" "$DIR/java_scan.txt"

echo ""
echo "--- Path Traversal / File Access ---"
rg -in "FileOutputStream|FileInputStream|FileWriter|new File\(|getAbsolutePath|\.\.\/" "$DIR/java_scan.txt"

echo ""
echo "--- Crypto (weak or misused) ---"
rg -in "SecretKeySpec|Cipher|getInstance|DES|AES|ECB|MD5|SHA1|Base64|java\.util\.Random|getBytes" "$DIR/java_scan.txt"

echo ""
echo "--- Network ---"
rg -in "HttpURLConnection|HttpsURLConnection|URL\(|SSLContext|TrustManager|X509TrustManager|HostnameVerifier|ALLOW_ALL|SSLSocketFactory" "$DIR/java_scan.txt"

echo ""
echo "--- Reflection / Dynamic Loading ---"
rg -in "Class\.forName|Method\.invoke|DexClassLoader|PathClassLoader" "$DIR/java_scan.txt"


echo ""
echo "========================================="
echo "  SECRETS SCAN"
echo "========================================="

echo "--- Credentials ---"
rg -in "password|passwd|secret|token|api_key|apikey|API_KEY|auth|Bearer|Authorization" "$DIR/secrets_scan.txt"

echo ""
echo "--- Keys & Certs ---"
rg -in "BEGIN|PRIVATE KEY|RSA|SecretKeySpec|\.pem|\.p12|\.keystore|certificate" "$DIR/secrets_scan.txt"

echo ""
echo "--- Connection Strings ---"
rg -in "jdbc:|mysql://|postgres://|mongodb://|redis://|amqp://|sqlite:" "$DIR/secrets_scan.txt"

echo ""
echo "--- Cloud & Service Keys ---"
rg -in "AKIA|AWS_SECRET|GOOGLE_API|firebase|sk_live|ghp_|xox" "$DIR/secrets_scan.txt"

echo ""
echo "--- Hardcoded Values ---"
rg -n 'return "|final String|static String|= "http|const ' "$DIR/secrets_scan.txt"


echo ""
echo "========================================="
echo "  CMD EXEC SCAN"
echo "========================================="

rg -in "Runtime|ProcessBuilder|exec\(|system\(|getRuntime|\.exec|shell|cmd" "$DIR/cmd_exec_scan.txt"


echo ""
echo "========================================="
echo "  SQLI SCAN"
echo "========================================="

rg -in "rawQuery|execSQL|execute|Statement|prepareStatement|SELECT|INSERT|UPDATE|DELETE|cursor|query\(|sqlite" "$DIR/sqli_scan.txt"

