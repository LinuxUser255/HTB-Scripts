#!/usr/bin/env bash
#===============================================================================
# Android Enumeration & Sensitive Data Discovery Script
# Automates information discovery for mobile pentesting scenarios
# Works on: System dumps (/data/system), Decompiled APKs (apktool), or any dir
# Usage: ./android_enum.sh [OPTIONS] [TARGET_DIR]
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

#-------------------------------------------------------------------------------
# Configuration & Globals
#-------------------------------------------------------------------------------
readonly VERSION="2.0.0"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET_DIR="."
OUTPUT_DIR="./analysis_output"
VERBOSE=0
LOGGING=0
TARGET_PKG=""
SKIP_TO_HASH=0
LOG_FILE=""
MODE="auto"  # auto, apk, system, general

#-------------------------------------------------------------------------------
# Color Codes
#-------------------------------------------------------------------------------
readonly C_RST='\e[0m'
readonly C_RED='\e[1;31m'
readonly C_GRN='\e[1;32m'
readonly C_YLW='\e[1;33m'
readonly C_BLU='\e[1;34m'
readonly C_MAG='\e[1;35m'
readonly C_CYN='\e[1;36m'

#-------------------------------------------------------------------------------
# Logging Functions
#-------------------------------------------------------------------------------
log_info(){
        printf "${C_GRN}[+]${C_RST} %s\n" "$1"
        ((LOGGING)) && printf "[INFO] %s - %s\n" "$(date +%T)" "$1" >> "$LOG_FILE"
}

log_warn(){
        printf "${C_YLW}[!]${C_RST} %s\n" "$1"
        ((LOGGING)) && printf "[WARN] %s - %s\n" "$(date +%T)" "$1" >> "$LOG_FILE"
}

log_err(){
        printf "${C_RED}[-]${C_RST} %s\n" "$1" >&2
        ((LOGGING)) && printf "[ERR] %s - %s\n" "$(date +%T)" "$1" >> "$LOG_FILE"
}

log_dbg(){
        ((VERBOSE)) && printf "${C_CYN}[*]${C_RST} %s\n" "$1"
        ((LOGGING && VERBOSE)) && printf "[DBG] %s - %s\n" "$(date +%T)" "$1" >> "$LOG_FILE"
}

log_section(){
        printf "\n${C_MAG}[=== %s ===${C_RST}]\n" "$1"
}

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------
die(){
        log_err "$1"
        exit "${2:-1}"
}

file_exists(){
        [[ -f "$1" ]] && return 0 || { log_warn "File not found: $1"; return 1; }
}

dir_exists(){
        [[ -d "$1" ]] && return 0 || { log_warn "Directory not found: $1"; return 1; }
}

save_output(){
        local name="$1" content="$2"
        local outfile="${OUTPUT_DIR}/${name}_${TIMESTAMP}.txt"
        printf '%s\n' "$content" > "$outfile"
        log_dbg "Saved: $outfile"
        printf '%s' "$outfile"
}

run_cmd(){
        # Execute command, capture output, handle errors
        local desc="$1"; shift
        local output
        log_dbg "Running: $*"
        output=$("$@" 2>&1) && {
                [[ -n "$output" ]] && printf '%s' "$output"
                return 0
        } || {
                log_warn "$desc failed or returned empty"
                [[ -n "$output" ]] && printf '%s' "$output"
                return 1
        }
}

#-------------------------------------------------------------------------------
# Prerequisite Check
#-------------------------------------------------------------------------------
check_requirements(){
        log_section "Checking Prerequisites"
        local missing=() pkg_mgr=""

        # Detect package manager
        command -v apt-get &>/dev/null && pkg_mgr="apt"
        command -v pacman &>/dev/null && pkg_mgr="pacman"
        command -v dnf &>/dev/null && pkg_mgr="dnf"

        # Check required tools
        for cmd in rg sqlite3 xxd; do
                command -v "$cmd" &>/dev/null || missing+=("$cmd")
        done

        ((${#missing[@]} == 0)) && { log_info "All prerequisites met"; return 0; }

        log_warn "Missing tools: ${missing[*]}"

        # Map tool names to packages
        local -A pkg_map=([rg]="ripgrep" [sqlite3]="sqlite3" [xxd]="xxd")

        [[ -z "$pkg_mgr" ]] && die "No supported package manager found. Install manually: ${missing[*]}"

        printf "${C_YLW}Install missing packages? [y/N]:${C_RST} "
        read -r response
        [[ "$response" =~ ^[Yy]$ ]] || die "Prerequisites not met"

        for tool in "${missing[@]}"; do
                local pkg="${pkg_map[$tool]:-$tool}"
                log_info "Installing $pkg..."
                case "$pkg_mgr" in
                        apt)    sudo apt-get install -y "$pkg" ;;
                        pacman) sudo pacman -S --noconfirm "$pkg" ;;
                        dnf)    sudo dnf install -y "$pkg" ;;
                esac
        done

        log_info "Prerequisites installed"
}

#-------------------------------------------------------------------------------
# Argument Parsing
#-------------------------------------------------------------------------------
usage(){
        cat <<-EOF
	${C_BLU}Android Enumeration & Sensitive Data Discovery v${VERSION}${C_RST}

	Usage: ${0##*/} [OPTIONS] [TARGET_DIR]

	${C_CYN}Description:${C_RST}
	  Point this script at any Android-related directory to hunt for sensitive
	  data: API keys, secrets, credentials, endpoints, lock hashes, and more.
	  Auto-detects directory type (APK output, system dump, or general).

	${C_CYN}Options:${C_RST}
	  -d DIR    Target directory to analyze (or pass as positional arg)
	  -o DIR    Output directory for results (default: ./analysis_output)
	  -m MODE   Force mode: apk, system, general, or auto (default: auto)
	  -p PKG    Target package name for focused analysis
	  -v        Verbose output (show all commands)
	  -l        Enable logging to file
	  -x        Skip to hash extraction (system dumps only)
	  -h        Show this help with examples

	${C_CYN}Modes:${C_RST}
	  auto      Auto-detect based on directory contents
	  apk       Decompiled APK analysis (apktool output)
	  system    Android system dump (/data/system)
	  general   Generic sensitive data scan (any directory)

	${C_MAG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RST}
	${C_YLW}EXAMPLES:${C_RST}
	${C_MAG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RST}

	${C_GRN}# Decompiled APK Analysis (most common workflow):${C_RST}
	  apktool d target.apk -o ./decompiled
	  ${0##*/} ./decompiled -v

	${C_GRN}# APK with custom output directory:${C_RST}
	  ${0##*/} -d ./decompiled -o ./target_results -l

	${C_GRN}# Force APK mode on ambiguous directory:${C_RST}
	  ${0##*/} -m apk ./some_dir

	${C_GRN}# System dump from device extraction:${C_RST}
	  adb pull /data/system ./system_dump
	  ${0##*/} -m system ./system_dump -x

	${C_GRN}# Just extract lock hashes (skip enumeration):${C_RST}
	  ${0##*/} ./system_dump -x

	${C_GRN}# Analyze specific package in system dump:${C_RST}
	  ${0##*/} ./system -p com.target.app -v

	${C_GRN}# Scan any directory for secrets (CTF, backup, etc.):${C_RST}
	  ${0##*/} -m general ./extracted_backup

	${C_GRN}# Recursive scan of multiple APK outputs:${C_RST}
	  for d in ./apks/*/; do ${0##*/} "\$d" -o "./results/\$(basename \$d)"; done

	${C_GRN}# Pipe-friendly: just get secrets (combine with jq, etc.):${C_RST}
	  ${0##*/} ./app -v 2>/dev/null | rg -o 'Found:.*'

	${C_MAG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RST}
	${C_YLW}WHAT IT FINDS:${C_RST}
	${C_MAG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RST}

	${C_CYN}APK Mode:${C_RST}
	  • AndroidManifest.xml: permissions, exported components, debuggable
	  • strings.xml/resources: hardcoded secrets, API endpoints
	  • smali: API keys, crypto, reflection, native libs, URLs
	  • assets/raw: config files, certs, embedded DBs

	${C_CYN}System Mode:${C_RST}
	  • packages.xml: installed apps, permissions, UIDs
	  • device_policies.xml: lock types, admin policies
	  • locksettings.db: password hashes, salts
	  • *.key files: SHA-1/MD5 hashes for cracking

	${C_CYN}General Mode:${C_RST}
	  • API keys, tokens, secrets in any file
	  • Hardcoded credentials, passwords
	  • URLs, endpoints, IP addresses
	  • Private keys, certificates

	EOF
        exit 0
}

parse_args(){
        while getopts ":d:o:m:p:vlxh" opt; do
                case "$opt" in
                        d) TARGET_DIR="$OPTARG" ;;
                        o) OUTPUT_DIR="$OPTARG" ;;
                        m) MODE="$OPTARG" ;;
                        p) TARGET_PKG="$OPTARG" ;;
                        v) VERBOSE=1 ;;
                        l) LOGGING=1 ;;
                        x) SKIP_TO_HASH=1 ;;
                        h) usage ;;
                        :) die "Option -$OPTARG requires an argument" ;;
                        *) die "Invalid option: -$OPTARG" ;;
                esac
        done
        shift $((OPTIND - 1))

        # Positional argument takes precedence for target dir
        [[ $# -gt 0 ]] && TARGET_DIR="$1"

        # Validate target directory
        dir_exists "$TARGET_DIR" || die "Target directory not found: $TARGET_DIR"
        TARGET_DIR=$(realpath "$TARGET_DIR")

        # Create output directory
        mkdir -p "$OUTPUT_DIR" || die "Cannot create output directory"
        OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
        log_info "Target: $TARGET_DIR"
        log_info "Output: $OUTPUT_DIR"

        # Setup logging
        ((LOGGING)) && {
                LOG_FILE="${OUTPUT_DIR}/enum_${TIMESTAMP}.log"
                : > "$LOG_FILE"
                log_info "Logging to: $LOG_FILE"
        }

        # Auto-detect mode if needed
        [[ "$MODE" == "auto" ]] && detect_mode
        log_info "Mode: $MODE"
}

#-------------------------------------------------------------------------------
# Mode Detection
#-------------------------------------------------------------------------------
detect_mode(){
        log_dbg "Auto-detecting directory type..."

        # Check for APK decompiled markers
        [[ -f "${TARGET_DIR}/AndroidManifest.xml" ]] && { MODE="apk"; return; }
        [[ -d "${TARGET_DIR}/smali" ]] && { MODE="apk"; return; }
        [[ -d "${TARGET_DIR}/res" && -d "${TARGET_DIR}/original" ]] && { MODE="apk"; return; }

        # Check for system dump markers
        [[ -f "${TARGET_DIR}/packages.xml" ]] && { MODE="system"; return; }
        [[ -f "${TARGET_DIR}/packages.list" ]] && { MODE="system"; return; }
        [[ -f "${TARGET_DIR}/locksettings.db" ]] && { MODE="system"; return; }

        # Default to general
        MODE="general"
}

#-------------------------------------------------------------------------------
# APK Analysis Module
#-------------------------------------------------------------------------------
analyze_apk(){
        log_section "APK Analysis: $TARGET_DIR"
        local manifest="${TARGET_DIR}/AndroidManifest.xml"

        # Analyze AndroidManifest.xml
        file_exists "$manifest" && {
                log_info "Parsing AndroidManifest.xml..."

                # Extract package name
                local pkg_name
                pkg_name=$(rg -o 'package="[^"]+"' "$manifest" | head -1 | cut -d'"' -f2 || true)
                [[ -n "$pkg_name" ]] && {
                        log_info "Package: $pkg_name"
                        printf '%s' "$pkg_name" > "${OUTPUT_DIR}/package_name.txt"
                }

                # Check for dangerous flags
                log_info "Checking for dangerous manifest flags..."
                local dangerous_flags
                dangerous_flags=$(
                        rg -i 'android:debuggable="true"|android:allowBackup="true"|android:usesCleartextTraffic="true"|android:exported="true"' "$manifest" || true
                )
                [[ -n "$dangerous_flags" ]] && {
                        save_output "manifest_dangerous_flags" "$dangerous_flags"
                        log_warn "Found dangerous manifest flags!"
                }

                # Extract permissions
                log_info "Extracting permissions..."
                local perms
                perms=$(rg -o 'android:name="android\.permission\.[^"]+"' "$manifest" | sort -u || true)
                [[ -n "$perms" ]] && save_output "manifest_permissions" "$perms"

                # Dangerous permissions check
                local dangerous_perms
                dangerous_perms=$(rg -i 'INTERNET|READ_EXTERNAL|WRITE_EXTERNAL|READ_CONTACTS|ACCESS_FINE_LOCATION|CAMERA|RECORD_AUDIO|READ_SMS|RECEIVE_SMS|READ_CALL_LOG' "$manifest" || true)
                [[ -n "$dangerous_perms" ]] && save_output "dangerous_permissions" "$dangerous_perms"

                # Exported components (potential attack surface)
                log_info "Finding exported components..."
                local exported
                exported=$(rg -B2 -A5 'android:exported="true"' "$manifest" || true)
                [[ -n "$exported" ]] && save_output "exported_components" "$exported"

                # Intent filters (deeplinks, schemes)
                log_info "Extracting intent filters/deeplinks..."
                local intents
                intents=$(rg -A10 '<intent-filter' "$manifest" | rg -i 'scheme|host|path|action|category' || true)
                [[ -n "$intents" ]] && save_output "intent_filters" "$intents"
        }

        # Scan resources
        scan_apk_resources

        # Scan smali code
        scan_apk_smali

        # Scan assets
        scan_apk_assets

        # General secrets scan
        scan_secrets
}

scan_apk_resources(){
        log_info "Scanning resources for secrets..."
        local res_dir="${TARGET_DIR}/res"

        dir_exists "$res_dir" || return 0

        # strings.xml analysis
        local strings_files
        strings_files=$(find "$res_dir" -name "strings.xml" 2>/dev/null || true)
        [[ -n "$strings_files" ]] && {
                log_info "Analyzing strings.xml files..."
                local api_strings
                api_strings=$(rg -i 'api|key|secret|token|url|endpoint|server|host|password|auth' $strings_files || true)
                [[ -n "$api_strings" ]] && save_output "resource_strings_sensitive" "$api_strings"
        }

        # Find hardcoded URLs in resources
        log_info "Finding URLs in resources..."
        local urls
        urls=$(rg -o 'https?://[^"<>\s]+' "$res_dir" 2>/dev/null | sort -u || true)
        [[ -n "$urls" ]] && save_output "resource_urls" "$urls"
}

scan_apk_smali(){
        log_info "Scanning smali for sensitive patterns..."

        # Check for smali or smali_classes* dirs
        local smali_dirs
        smali_dirs=$(find "$TARGET_DIR" -maxdepth 1 -type d -name "smali*" 2>/dev/null || true)
        [[ -z "$smali_dirs" ]] && { log_warn "No smali directories found"; return 0; }

        # API key patterns in smali
        log_info "Hunting API keys in smali..."
        local smali_secrets
        smali_secrets=$(rg -i 'const-string.*\b(api[_-]?key|secret|token|password|bearer|auth)' $smali_dirs 2>/dev/null || true)
        [[ -n "$smali_secrets" ]] && save_output "smali_secrets" "$smali_secrets"

        # Hardcoded strings that look like keys
        log_info "Finding potential hardcoded keys..."
        local hardcoded
        hardcoded=$(rg 'const-string [vp][0-9]+, "[A-Za-z0-9+/=_-]{20,}"' $smali_dirs 2>/dev/null | rg -v '(android\.|com\.google\.|java\.|kotlin\.)' || true)
        [[ -n "$hardcoded" ]] && save_output "smali_hardcoded_strings" "$hardcoded"

        # URLs in smali
        log_info "Extracting URLs from smali..."
        local smali_urls
        smali_urls=$(rg -o 'https?://[^"]+' $smali_dirs 2>/dev/null | sort -u || true)
        [[ -n "$smali_urls" ]] && save_output "smali_urls" "$smali_urls"

        # Crypto usage (potential weak crypto)
        log_info "Checking crypto usage..."
        local crypto
        crypto=$(rg -i 'Ljavax/crypto|Ljava/security|AES|DES|RSA|MD5|SHA1|SecretKeySpec|Cipher' $smali_dirs 2>/dev/null | head -100 || true)
        [[ -n "$crypto" ]] && save_output "smali_crypto_usage" "$crypto"

        # Native library loading
        log_info "Finding native library usage..."
        local native
        native=$(rg 'System;->loadLibrary|System;->load\(' $smali_dirs 2>/dev/null || true)
        [[ -n "$native" ]] && save_output "smali_native_libs" "$native"

        # Reflection usage (potential obfuscation)
        log_info "Checking reflection usage..."
        local reflection
        reflection=$(rg 'Ljava/lang/reflect|Class;->forName|Method;->invoke' $smali_dirs 2>/dev/null | head -50 || true)
        [[ -n "$reflection" ]] && save_output "smali_reflection" "$reflection"

        # WebView JavaScript interfaces (potential XSS)
        log_info "Finding WebView JS interfaces..."
        local webview
        webview=$(rg -i 'addJavascriptInterface|setJavaScriptEnabled|loadUrl|evaluateJavascript' $smali_dirs 2>/dev/null || true)
        [[ -n "$webview" ]] && save_output "smali_webview_usage" "$webview"

        # SQL queries (potential injection)
        log_info "Finding SQL patterns..."
        local sql
        sql=$(rg -i 'rawQuery|execSQL|SELECT.*FROM|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM' $smali_dirs 2>/dev/null | head -50 || true)
        [[ -n "$sql" ]] && save_output "smali_sql_queries" "$sql"
}

scan_apk_assets(){
        log_info "Scanning assets directory..."
        local assets_dir="${TARGET_DIR}/assets"

        dir_exists "$assets_dir" || return 0

        # List all assets
        local asset_list
        asset_list=$(find "$assets_dir" -type f 2>/dev/null || true)
        [[ -n "$asset_list" ]] && save_output "assets_list" "$asset_list"

        # Find interesting file types
        log_info "Finding interesting asset files..."
        local interesting
        interesting=$(find "$assets_dir" -type f \( -name "*.json" -o -name "*.xml" -o -name "*.db" -o -name "*.sqlite" -o -name "*.pem" -o -name "*.key" -o -name "*.crt" -o -name "*.p12" -o -name "*.properties" -o -name "*.conf" -o -name "*.cfg" \) 2>/dev/null || true)
        [[ -n "$interesting" ]] && {
                save_output "assets_interesting_files" "$interesting"
                # Scan content of these files
                for f in $interesting; do
                        [[ -f "$f" ]] && {
                                local content
                                content=$(rg -i 'api|key|secret|token|password|url|endpoint' "$f" 2>/dev/null || true)
                                [[ -n "$content" ]] && save_output "assets_$(basename "$f")_secrets" "$content"
                        }
                done
        }

        # Scan for Firebase configs
        log_info "Looking for Firebase/Google configs..."
        local firebase
        firebase=$(find "$assets_dir" -name "google-services.json" -o -name "firebase*.json" 2>/dev/null || true)
        [[ -n "$firebase" ]] && {
                save_output "firebase_configs" "$firebase"
                for f in $firebase; do
                        [[ -f "$f" ]] && cat "$f" >> "${OUTPUT_DIR}/firebase_config_contents_${TIMESTAMP}.txt"
                done
        }
}

#-------------------------------------------------------------------------------
# General Secrets Scanner
#-------------------------------------------------------------------------------
scan_secrets(){
        log_section "Secrets & Sensitive Data Scan"

        # Broad secrets search
        log_info "Searching for API keys and tokens..."
        local secrets
        secrets=$(rg -i 'api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|bearer|secret[_-]?key' "$TARGET_DIR" --type-not binary 2>/dev/null | head -200 || true)
        [[ -n "$secrets" ]] && save_output "secrets_api_keys" "$secrets"

        # Password patterns
        log_info "Searching for password patterns..."
        local passwords
        passwords=$(rg -i 'password\s*[=:]|passwd\s*[=:]|pwd\s*[=:]' "$TARGET_DIR" --type-not binary 2>/dev/null | head -100 || true)
        [[ -n "$passwords" ]] && save_output "secrets_passwords" "$passwords"

        # AWS keys
        log_info "Searching for AWS credentials..."
        local aws
        aws=$(rg 'AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key' "$TARGET_DIR" --type-not binary 2>/dev/null || true)
        [[ -n "$aws" ]] && {
                save_output "secrets_aws" "$aws"
                log_warn "Potential AWS credentials found!"
        }

        # Google API keys
        log_info "Searching for Google API keys..."
        local gcp
        gcp=$(rg 'AIza[0-9A-Za-z_-]{35}' "$TARGET_DIR" --type-not binary 2>/dev/null || true)
        [[ -n "$gcp" ]] && {
                save_output "secrets_google_api" "$gcp"
                log_warn "Potential Google API key found!"
        }

        # Private keys
        log_info "Searching for private keys..."
        local privkeys
        privkeys=$(rg -l 'BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY' "$TARGET_DIR" 2>/dev/null || true)
        [[ -n "$privkeys" ]] && {
                save_output "secrets_private_keys" "$privkeys"
                log_warn "Private key files found!"
        }

        # JWT tokens
        log_info "Searching for JWT tokens..."
        local jwt
        jwt=$(rg 'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*' "$TARGET_DIR" --type-not binary 2>/dev/null || true)
        [[ -n "$jwt" ]] && save_output "secrets_jwt" "$jwt"

        # URLs extraction
        log_info "Extracting all URLs..."
        local all_urls
        all_urls=$(rg -o 'https?://[^"'\''<>\s]+' "$TARGET_DIR" --type-not binary 2>/dev/null | sort -u || true)
        [[ -n "$all_urls" ]] && save_output "all_urls" "$all_urls"

        # IP addresses
        log_info "Extracting IP addresses..."
        local ips
        ips=$(rg -o '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$TARGET_DIR" --type-not binary 2>/dev/null | sort -u | rg -v '^(127\.|0\.|255\.)' || true)
        [[ -n "$ips" ]] && save_output "ip_addresses" "$ips"

        # Database files
        log_info "Finding database files..."
        local dbs
        dbs=$(find "$TARGET_DIR" -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null || true)
        [[ -n "$dbs" ]] && {
                save_output "database_files" "$dbs"
                # Extract strings from small DBs
                for db in $dbs; do
                        [[ -f "$db" && $(stat -c%s "$db" 2>/dev/null || stat -f%z "$db" 2>/dev/null) -lt 5000000 ]] && {
                                local db_strings
                                db_strings=$(strings "$db" | rg -i 'password|secret|key|token|api' || true)
                                [[ -n "$db_strings" ]] && save_output "db_$(basename "$db")_strings" "$db_strings"
                        }
                done
        }

        # Config files
        log_info "Finding config files..."
        local configs
        configs=$(find "$TARGET_DIR" -type f \( -name "*.json" -o -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.cfg" -o -name "*.yml" -o -name "*.yaml" -o -name "*.env" -o -name ".env*" \) 2>/dev/null || true)
        [[ -n "$configs" ]] && save_output "config_files" "$configs"
}

#-------------------------------------------------------------------------------
# Package Enumeration Module (System Dumps)
#-------------------------------------------------------------------------------
enum_packages(){
        log_section "Package Enumeration"
        local packages_list="${TARGET_DIR}/packages.list"
        local packages_xml="${TARGET_DIR}/packages.xml"

        # Initial broad search for secrets in system files
        # Looking for potential API keys or tokens; system configs might leak build-time secrets
        log_info "Searching for secrets/tokens in system files..."
        local secrets
        secrets=$(run_cmd "secrets search" rg -i 'API_KEY|SECRET|TOKEN|BASE_URL' "$TARGET_DIR" || true)
        [[ -n "$secrets" ]] && {
                save_output "secrets_search" "$secrets"
                log_info "Found potential secrets (may be system perms - verify manually)"
        }

        # List installed packages to identify targets
        # Reveals installed apps, UIDs, and flags for focusing analysis
        if file_exists "$packages_list"; then
                log_info "Extracting installed packages..."
                local pkg_list
                pkg_list=$(cat "$packages_list")
                save_output "packages_list" "$pkg_list"

                # Filter packages for common patterns
                # Narrows to potential target apps for cross-referencing perms/UIDs
                log_info "Filtering packages for app patterns..."
                local filtered
                filtered=$(rg -i 'app|com\.' "$packages_list" || true)
                [[ -n "$filtered" ]] && save_output "packages_filtered" "$filtered"
        fi

        # Search all permissions in packages.xml
        # Lists granted perms for over-privileging checks (e.g., INTERNET/STORAGE)
        if file_exists "$packages_xml"; then
                log_info "Extracting permissions from packages.xml..."
                local perms
                perms=$(rg 'permission' "$packages_xml" || true)
                [[ -n "$perms" ]] && {
                        local perm_file
                        perm_file=$(save_output "packages_permissions" "$perms")

                        # Filter risky permissions
                        # Flags potential data leaks/exfiltration risks
                        log_info "Filtering risky permissions..."
                        local risky
                        risky=$(rg -i 'storage|write|read|internet|admin' "$perm_file" || true)
                        [[ -n "$risky" ]] && save_output "risky_permissions" "$risky"
                }

                # Find storage-related permissions across files
                # Targets file-related vulnerabilities for app access
                log_info "Searching storage/file permissions..."
                local storage_perms
                storage_perms=$(find "$TARGET_DIR" -name "packages.xml" -exec rg 'permission.*(storage|file|external)' {} + 2>/dev/null || true)
                [[ -n "$storage_perms" ]] && save_output "storage_permissions" "$storage_perms"
        fi
}

#-------------------------------------------------------------------------------
# Target Package Analysis
#-------------------------------------------------------------------------------
analyze_target_package(){
        local pkg="${1:-$TARGET_PKG}"
        [[ -z "$pkg" ]] && {
                printf "${C_YLW}Enter target package name (e.g., com.example.app):${C_RST} "
                read -r pkg
                [[ -z "$pkg" ]] && { log_warn "No package specified, skipping"; return 1; }
        }

        log_section "Analyzing Package: $pkg"
        local packages_xml="${TARGET_DIR}/packages.xml"

        file_exists "$packages_xml" || return 1

        # Correlate package with permissions
        # Extracts full <package> block for app-specific perms (e.g., storage access)
        log_info "Extracting package details with context..."
        local pkg_details
        pkg_details=$(rg -i "$pkg" "$packages_xml" -C 10 || true)
        [[ -n "$pkg_details" ]] && {
                save_output "pkg_${pkg//\./_}_details" "$pkg_details"
                log_info "Package details saved"
        } || log_warn "Package not found in packages.xml"
}

#-------------------------------------------------------------------------------
# Policy Check Module
#-------------------------------------------------------------------------------
check_policies(){
        log_section "Device Policy Analysis"
        local policies_xml="${TARGET_DIR}/device_policies.xml"

        # Check device policies for auth clues
        # Reveals lock types/weaknesses that gatekeep backups
        if file_exists "$policies_xml"; then
                log_info "Extracting device policies..."
                local policies
                policies=$(cat "$policies_xml")
                save_output "device_policies" "$policies"

                # Grep policies for restrictions
                # Hints at enterprise rules or lock enforcement
                log_info "Searching for password/policy/admin references..."
                local policy_refs
                policy_refs=$(rg -i 'password|policy|admin' "$policies_xml" || true)
                [[ -n "$policy_refs" ]] && save_output "policy_references" "$policy_refs"

                # Dig deeper for lock hints
                # Seeks password_quality (e.g., 65536=PIN) or app refs
                log_info "Extracting quality/length/admin with context..."
                local lock_hints
                lock_hints=$(rg -i 'quality|length|admin' "$policies_xml" -C 3 || true)
                [[ -n "$lock_hints" ]] && save_output "lock_hints" "$lock_hints"

                # Extract strings from policies
                # Pulls text from XML if structured grep misses
                log_info "Extracting strings from policy file..."
                local policy_strings
                policy_strings=$(strings "$policies_xml" | rg 'password|policy' || true)
                [[ -n "$policy_strings" ]] && save_output "policy_strings" "$policy_strings"
        fi

        # Broad policy search across all XMLs
        # Policies might spill into other files (e.g., appops.xml)
        log_info "Searching all XMLs for policy/admin/restriction..."
        local all_policies
        all_policies=$(find "$TARGET_DIR" -type f -name "*.xml" -exec rg -i 'policy|admin|restriction' {} + 2>/dev/null || true)
        [[ -n "$all_policies" ]] && save_output "all_policy_refs" "$all_policies"
}

#-------------------------------------------------------------------------------
# Lock Database Hunting Module
#-------------------------------------------------------------------------------
hunt_lock_data(){
        log_section "Lock Data Discovery"

        # Locate databases for lock data
        # Finds locksettings.db for querying salts/types
        log_info "Locating database files..."
        local db_files
        db_files=$(find "$TARGET_DIR" -name "*.db" 2>/dev/null || true)
        [[ -n "$db_files" ]] && {
                save_output "database_files" "$db_files"
                log_info "Found databases:\n$db_files"
        }

        local lock_db="${TARGET_DIR}/locksettings.db"

        # Query lock DB for password details
        # Extracts type/salt/quality from locksettings.db (informs cracking strategy)
        if file_exists "$lock_db"; then
                log_info "Querying locksettings.db..."
                local lock_data
                lock_data=$(sqlite3 "$lock_db" "SELECT * FROM locksettings WHERE name LIKE 'lockscreen.password%';" 2>/dev/null || true)
                [[ -n "$lock_data" ]] && {
                        save_output "lock_db_query" "$lock_data"
                        log_info "Lock settings extracted"
                        printf "${C_GRN}Lock data found:${C_RST}\n%s\n" "$lock_data"
                }

                # Strings from lock DB as fallback
                # Alternative to SQL if query fails
                log_info "Extracting strings from lock DB..."
                local lock_strings
                lock_strings=$(strings "$lock_db" | rg -i 'password|salt|hash|quality' || true)
                [[ -n "$lock_strings" ]] && save_output "lock_db_strings" "$lock_strings"

                return 0
        fi

        log_warn "locksettings.db not found"
        return 1
}

#-------------------------------------------------------------------------------
# Hash Extraction Module
#-------------------------------------------------------------------------------
extract_hashes(){
        log_section "Hash Extraction"
        local pwd_key="${TARGET_DIR}/password.key"
        local gesture_key="${TARGET_DIR}/gesture.key"

        # List files with lock terms
        # Inventories all files with auth clues
        log_info "Finding files with lock-related terms..."
        local lock_files
        lock_files=$(rg -i 'password|key|salt|hash|pin|pattern' "$TARGET_DIR" -l 2>/dev/null || true)
        [[ -n "$lock_files" ]] && save_output "lock_related_files" "$lock_files"

        # Process password.key
        if file_exists "$pwd_key"; then
                log_info "Processing password.key..."

                # Check key file size
                # Confirms expected size (SHA-1 20B + MD5 16B = 36B, or 72 hex chars)
                local key_size
                key_size=$(stat -c%s "$pwd_key" 2>/dev/null || stat -f%z "$pwd_key" 2>/dev/null)
                log_info "password.key size: ${key_size} bytes"

                # Hex dump password key (grouped)
                # Dumps binary hash (SHA-1 + MD5) for extraction
                log_info "Creating hex dump..."
                local hex_grouped
                hex_grouped=$(xxd -g1 "$pwd_key")
                save_output "password_key_hex_grouped" "$hex_grouped"

                # Plain hex dump (continuous)
                # Preps for cutting SHA-1/MD5 parts
                local hex_plain
                hex_plain=$(xxd -p "$pwd_key" | tr -d '\n')
                local hex_file
                hex_file=$(save_output "password_key_hex_plain" "$hex_plain")

                # Verify hex length
                # Ensures expected char count before slicing
                local hex_len=${#hex_plain}
                log_info "Hex length: $hex_len characters"

                ((hex_len >= 72)) && {
                        # Extract SHA-1 hex (first 40 chars)
                        # Isolates SHA-1 hash for Hashcat input
                        local sha1_hash
                        sha1_hash=$(printf '%s' "$hex_plain" | cut -c 1-40 | tr 'A-F' 'a-f')
                        save_output "sha1_hash" "$sha1_hash"
                        log_info "SHA-1 hash: $sha1_hash"

                        # Extract MD5 hex (next 32 chars)
                        # Isolates MD5 for verification after cracking
                        local md5_hash
                        md5_hash=$(printf '%s' "$hex_plain" | cut -c 41-72 | tr 'A-F' 'a-f')
                        save_output "md5_hash" "$md5_hash"
                        log_info "MD5 hash: $md5_hash"

                        printf "\n${C_GRN}[+] Hash Extraction Complete${C_RST}\n"
                        printf "    SHA-1: %s\n" "$sha1_hash"
                        printf "    MD5:   %s\n" "$md5_hash"
                }
        fi

        # Process gesture.key
        # Checks for pattern lock hash (20B SHA1)
        if file_exists "$gesture_key"; then
                log_info "Processing gesture.key..."
                local gesture_hash
                gesture_hash=$(strings "$gesture_key" | rg '[a-f0-9]{40}' || xxd -p "$gesture_key" | tr -d '\n' | cut -c 1-40)
                [[ -n "$gesture_hash" ]] && {
                        save_output "gesture_hash" "$gesture_hash"
                        log_info "Gesture hash: $gesture_hash"
                }
        fi
}

#-------------------------------------------------------------------------------
# Hashcat Preparation
#-------------------------------------------------------------------------------
prepare_hashcat(){
        log_section "Hashcat Preparation"
        local sha1_file="${OUTPUT_DIR}/sha1_hash_${TIMESTAMP}.txt"

        [[ -f "$sha1_file" ]] || {
                # Try to find most recent sha1 hash file
                sha1_file=$(find "$OUTPUT_DIR" -name "sha1_hash_*.txt" -type f | sort -r | head -1)
                [[ -z "$sha1_file" ]] && { log_warn "No SHA-1 hash file found"; return 1; }
        }

        local sha1_hash
        sha1_hash=$(cat "$sha1_file" | tr -d '\n')

        # Prompt for salt if needed
        printf "${C_YLW}Enter salt value (hex, or leave empty):${C_RST} "
        read -r salt

        if [[ -n "$salt" ]]; then
                # Prepare Hashcat input with salt
                # Formats for mode 130 (sha1:salt) cracking
                local hashcat_input="${sha1_hash}:${salt}"
                save_output "hashcat_input" "$hashcat_input"
                printf "\n${C_GRN}Hashcat command (mode 130 - SHA1 + salt):${C_RST}\n"
                printf "hashcat -m 130 -a 0 '%s' wordlist.txt\n" "$hashcat_input"
        else
                save_output "hashcat_input" "$sha1_hash"
                printf "\n${C_GRN}Hashcat command (mode 100 - raw SHA1):${C_RST}\n"
                printf "hashcat -m 100 -a 0 '%s' wordlist.txt\n" "$sha1_hash"
        fi

        printf "\n${C_CYN}For PIN cracking (4-6 digits):${C_RST}\n"
        printf "hashcat -m 130 -a 3 '%s' ?d?d?d?d?d?d\n" "${sha1_hash}:${salt:-SALT}"
}

#-------------------------------------------------------------------------------
# Summary Generation
#-------------------------------------------------------------------------------
generate_summary(){
        log_section "Analysis Summary"

        local summary="Android Enumeration Summary\n"
        summary+="=====================================\n"
        summary+="Timestamp: $TIMESTAMP\n"
        summary+="Target Dir: $TARGET_DIR\n"
        summary+="Output Dir: $OUTPUT_DIR\n"
        summary+="Mode: $MODE\n\n"

        summary+="Files Generated:\n"
        local count=0
        for f in "$OUTPUT_DIR"/*_"$TIMESTAMP".txt; do
                [[ -f "$f" ]] && {
                        summary+="  - ${f##*/}\n"
                        ((count++))
                }
        done
        summary+="\nTotal files: $count\n"

        # Key findings
        summary+="\n--- Key Findings ---\n"

        local sha1_file="${OUTPUT_DIR}/sha1_hash_${TIMESTAMP}.txt"
        [[ -f "$sha1_file" ]] && summary+="SHA-1 Hash: $(cat "$sha1_file")\n"

        local md5_file="${OUTPUT_DIR}/md5_hash_${TIMESTAMP}.txt"
        [[ -f "$md5_file" ]] && summary+="MD5 Hash: $(cat "$md5_file")\n"

        local lock_file="${OUTPUT_DIR}/lock_db_query_${TIMESTAMP}.txt"
        [[ -f "$lock_file" ]] && summary+="\nLock Settings:\n$(cat "$lock_file")\n"

        printf '%b' "$summary"
        save_output "summary" "$(printf '%b' "$summary")"
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------
main(){
        printf "${C_BLU}Android Enumeration & Sensitive Data Discovery v${VERSION}${C_RST}\n"
        printf "${C_CYN}Starting at: %s${C_RST}\n" "$(date)"

        parse_args "$@"
        check_requirements

        # Skip to hash extraction if flag set (system mode only)
        ((SKIP_TO_HASH)) && {
                log_info "Skipping to hash extraction..."
                hunt_lock_data && extract_hashes && prepare_hashcat
                generate_summary
                exit 0
        }

        # Execute based on detected/forced mode
        case "$MODE" in
                apk)
                        analyze_apk
                        ;;
                system)
                        enum_packages
                        [[ -n "$TARGET_PKG" ]] && analyze_target_package "$TARGET_PKG"
                        check_policies
                        hunt_lock_data
                        extract_hashes
                        # Offer hashcat prep
                        printf "\n${C_YLW}Prepare Hashcat input? [y/N]:${C_RST} "
                        read -r response
                        [[ "$response" =~ ^[Yy]$ ]] && prepare_hashcat
                        ;;
                general)
                        scan_secrets
                        ;;
                *)
                        die "Unknown mode: $MODE"
                        ;;
        esac

        generate_summary

        printf "\n${C_GRN}[+] Enumeration complete!${C_RST}\n"
        printf "Results saved to: %s\n" "$OUTPUT_DIR"
}

main "$@"
