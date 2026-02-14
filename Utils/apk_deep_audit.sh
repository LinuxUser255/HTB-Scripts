#!/usr/bin/env bash

# apk_deep_audit.sh - Comprehensive APK security audit

set -euo pipefail

APK="$1"
OUTPUT="deep_audit_$(basename "$APK" .apk)"

if [ -z "$APK" ]; then
    echo "Usage: $0 <apk_file>"
    exit 1
fi

mkdir -p "$OUTPUT"

echo "[1/6] Decompiling with APKTool..."
apktool d "$APK" -o "$OUTPUT/apktool" -f 2>/dev/null

echo "[2/6] Decompiling with JADX..."
jadx -d "$OUTPUT/jadx" "$APK" --no-res 2>/dev/null

echo "[3/6] Extracting DEX files..."
mkdir -p "$OUTPUT/dex"
unzip -jo "$APK" "*.dex" -d "$OUTPUT/dex" 2>/dev/null || true

echo "[4/6] Running security scans..."

# Scan Java sources
graudit -B -z -d android "$OUTPUT/jadx/sources" > "$OUTPUT/report_android.txt" 2>/dev/null || true
graudit -B -z -d java "$OUTPUT/jadx/sources" > "$OUTPUT/report_java.txt" 2>/dev/null || true
graudit -B -z -d secrets "$OUTPUT/jadx/sources" > "$OUTPUT/report_secrets.txt" 2>/dev/null || true
graudit -B -z -d sql "$OUTPUT/jadx/sources" > "$OUTPUT/report_sql.txt" 2>/dev/null || true

# Scan Smali
graudit -B -z -d android "$OUTPUT/apktool/smali" > "$OUTPUT/report_smali.txt" 2>/dev/null || true

echo "[5/6] Analyzing manifest..."
{
    echo "=== EXPORTED COMPONENTS ==="
    grep -A 3 "exported=\"true\"" "$OUTPUT/apktool/AndroidManifest.xml" || echo "None found"
    echo ""
    echo "=== PERMISSIONS ==="
    grep "permission" "$OUTPUT/apktool/AndroidManifest.xml" || echo "None found"
    echo ""
    echo "=== DEBUGGABLE ==="
    grep "debuggable" "$OUTPUT/apktool/AndroidManifest.xml" || echo "Not debuggable"
    echo ""
    echo "=== NETWORK SECURITY CONFIG ==="
    grep "networkSecurityConfig" "$OUTPUT/apktool/AndroidManifest.xml" || echo "Not configured"
} > "$OUTPUT/manifest_analysis.txt"

echo "[6/6] Searching for interesting strings..."
{
    echo "=== URLs ==="
    grep -roh "http[s]\?://[a-zA-Z0-9./?=_-]*" "$OUTPUT/apktool/res/" | sort -u || true
    echo ""
    echo "=== POTENTIAL API KEYS ==="
    grep -rioh "['\"][a-zA-Z0-9_-]\{20,\}['\"]" "$OUTPUT/apktool/res/" | sort -u | head -20 || true
} > "$OUTPUT/interesting_strings.txt"

echo ""
echo "=== AUDIT SUMMARY ==="
echo "Android issues: $(wc -l < "$OUTPUT/report_android.txt")"
echo "Java issues: $(wc -l < "$OUTPUT/report_java.txt")"
echo "Secrets: $(wc -l < "$OUTPUT/report_secrets.txt")"
echo "SQL injection: $(wc -l < "$OUTPUT/report_sql.txt")"
echo "Smali issues: $(wc -l < "$OUTPUT/report_smali.txt")"
echo ""
echo "Full results in: $OUTPUT/"
echo ""
echo "Key files:"
echo "  - $OUTPUT/report_*.txt (vulnerability reports)"
echo "  - $OUTPUT/manifest_analysis.txt (manifest security)"
echo "  - $OUTPUT/interesting_strings.txt (URLs, keys)"
