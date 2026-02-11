#!/usr/bin/env bash
#===============================================================================
# Android System Dump Enumeration Script
# Automates information discovery for mobile pentesting scenarios
# Usage: ./android_enum.sh [-s SYSTEM_DIR] [-o OUTPUT_DIR] [-v] [-l] [-p PKG] [-x]
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

#-------------------------------------------------------------------------------
# Configuration & Globals
#-------------------------------------------------------------------------------
readonly VERSION="1.0.0"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SYSTEM_DIR="./system"
OUTPUT_DIR="./analysis_output"
VERBOSE=0
LOGGING=0
TARGET_PKG=""
SKIP_TO_HASH=0
LOG_FILE=""

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
	${C_BLU}Android System Dump Enumeration v${VERSION}${C_RST}

	Usage: ${0##*/} [OPTIONS]

	Options:
	  -s DIR    System directory path (default: ./system)
	  -o DIR    Output directory (default: ./analysis_output)
	  -p PKG    Target package name for detailed analysis
	  -v        Verbose output
	  -l        Enable logging to file
	  -x        Skip to hash extraction (if lock DB found)
	  -h        Show this help

	Examples:
	  ${0##*/} -s /path/to/system -o ./results -v
	  ${0##*/} -p com.example.app -x
	EOF
        exit 0
}

parse_args(){
        while getopts ":s:o:p:vlxh" opt; do
                case "$opt" in
                        s) SYSTEM_DIR="$OPTARG" ;;
                        o) OUTPUT_DIR="$OPTARG" ;;
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

        # Validate system directory
        dir_exists "$SYSTEM_DIR" || die "System directory not found: $SYSTEM_DIR"

        # Create output directory
        mkdir -p "$OUTPUT_DIR" || die "Cannot create output directory"
        log_info "Output directory: $OUTPUT_DIR"

        # Setup logging
        ((LOGGING)) && {
                LOG_FILE="${OUTPUT_DIR}/enum_${TIMESTAMP}.log"
                : > "$LOG_FILE"
                log_info "Logging to: $LOG_FILE"
        }
}

#-------------------------------------------------------------------------------
# Package Enumeration Module
#-------------------------------------------------------------------------------
enum_packages(){
        log_section "Package Enumeration"
        local packages_list="${SYSTEM_DIR}/packages.list"
        local packages_xml="${SYSTEM_DIR}/packages.xml"

        # Initial broad search for secrets in system files
        # Looking for potential API keys or tokens; system configs might leak build-time secrets
        log_info "Searching for secrets/tokens in system files..."
        local secrets
        secrets=$(run_cmd "secrets search" rg -i 'API_KEY|SECRET|TOKEN|BASE_URL' "$SYSTEM_DIR" || true)
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
                storage_perms=$(find "$SYSTEM_DIR" -name "packages.xml" -exec rg 'permission.*(storage|file|external)' {} + 2>/dev/null || true)
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
        local packages_xml="${SYSTEM_DIR}/packages.xml"

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
        local policies_xml="${SYSTEM_DIR}/device_policies.xml"

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
        all_policies=$(find "$SYSTEM_DIR" -type f -name "*.xml" -exec rg -i 'policy|admin|restriction' {} + 2>/dev/null || true)
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
        db_files=$(find "$SYSTEM_DIR" -name "*.db" 2>/dev/null || true)
        [[ -n "$db_files" ]] && {
                save_output "database_files" "$db_files"
                log_info "Found databases:\n$db_files"
        }

        local lock_db="${SYSTEM_DIR}/locksettings.db"

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
        local pwd_key="${SYSTEM_DIR}/password.key"
        local gesture_key="${SYSTEM_DIR}/gesture.key"

        # List files with lock terms
        # Inventories all files with auth clues
        log_info "Finding files with lock-related terms..."
        local lock_files
        lock_files=$(rg -i 'password|key|salt|hash|pin|pattern' "$SYSTEM_DIR" -l 2>/dev/null || true)
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

        local summary="Android System Dump Analysis Summary\n"
        summary+="=====================================\n"
        summary+="Timestamp: $TIMESTAMP\n"
        summary+="System Dir: $SYSTEM_DIR\n"
        summary+="Output Dir: $OUTPUT_DIR\n\n"

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
        printf "${C_BLU}Android System Dump Enumeration v${VERSION}${C_RST}\n"
        printf "${C_CYN}Starting at: %s${C_RST}\n" "$(date)"

        parse_args "$@"
        check_requirements

        # Skip to hash extraction if flag set and lock DB exists
        ((SKIP_TO_HASH)) && {
                log_info "Skipping to hash extraction..."
                hunt_lock_data && extract_hashes && prepare_hashcat
                generate_summary
                exit 0
        }

        # Full enumeration sequence
        enum_packages

        # Analyze specific package if provided
        [[ -n "$TARGET_PKG" ]] && analyze_target_package "$TARGET_PKG"

        check_policies
        hunt_lock_data
        extract_hashes

        # Offer hashcat prep
        printf "\n${C_YLW}Prepare Hashcat input? [y/N]:${C_RST} "
        read -r response
        [[ "$response" =~ ^[Yy]$ ]] && prepare_hashcat

        generate_summary

        printf "\n${C_GRN}[+] Enumeration complete!${C_RST}\n"
        printf "Results saved to: %s\n" "$OUTPUT_DIR"
}

main "$@"
