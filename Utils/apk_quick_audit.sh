#!/usr/bin/env bash

# apk_quick_audit.sh - Fast APK security assessment
# ./apk_quick_audit.sh app.apk


set -euo pipefail

APK="$1"
OUTPUT_DIR="apk_audit_$(basename "$APK" .apk)"

if [ -z "$APK" ]; then
    echo "Usage: $0 <apk_file>"
    exit 1
fi

echo "[*] Creating output directory..."
mkdir -p "$OUTPUT_DIR"

echo "[*] Decompiling APK with JADX..."
jadx -d "$OUTPUT_DIR/decompiled" "$APK" --no-res 2>/dev/null

echo "[*] Running graudit scans..."
cd "$OUTPUT_DIR/decompiled/sources"

graudit -B -z -d android . > "$OUTPUT_DIR/android_vulns.txt" 2>/dev/null || true
graudit -B -z -d java . > "$OUTPUT_DIR/java_vulns.txt" 2>/dev/null || true
graudit -B -z -d secrets . > "$OUTPUT_DIR/secrets.txt" 2>/dev/null || true
graudit -B -z -d sql . > "$OUTPUT_DIR/sql_injection.txt" 2>/dev/null || true

cd - > /dev/null

echo "[*] Analyzing AndroidManifest.xml..."
grep -A 5 "exported=\"true\"" "$OUTPUT_DIR/decompiled/resources/AndroidManifest.xml" \
  > "$OUTPUT_DIR/exported_components.txt" 2>/dev/null || true

grep "permission" "$OUTPUT_DIR/decompiled/resources/AndroidManifest.xml" \
  > "$OUTPUT_DIR/permissions.txt" 2>/dev/null || true

echo ""
echo "=== Summary ==="
echo "Android vulnerabilities: $(wc -l < "$OUTPUT_DIR/android_vulns.txt")"
echo "Java vulnerabilities: $(wc -l < "$OUTPUT_DIR/java_vulns.txt")"
echo "Secrets found: $(wc -l < "$OUTPUT_DIR/secrets.txt")"
echo "SQL injection candidates: $(wc -l < "$OUTPUT_DIR/sql_injection.txt")"
echo ""
echo "Results saved to: $OUTPUT_DIR/"
