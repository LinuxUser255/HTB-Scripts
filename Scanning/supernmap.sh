#!/usr/bin/env bash
# =============================================================================
# SCRIPT:       supernmap.sh
# DESCRIPTION:  Comprehensive Nmap scanning tool with multiple scan profiles
#               for HackTheBox and penetration testing engagements.
# USAGE:        ./supernmap.sh <target_ip> [OPTIONS]
# DEPENDENCIES: nmap, tee
# =============================================================================
set -euo pipefail  # §1 strict-mode
IFS=$'\n\t'        # §1 strict-mode

if [[ -t 1 ]]; then                               # §11 suppress colors for non-TTY
        readonly RED='\033[0;31m'
        readonly GREEN='\033[0;32m'
        readonly YELLOW='\033[1;33m'
        readonly BLUE='\033[0;34m'
        readonly CYAN='\033[0;36m'
        readonly MAGENTA='\033[0;35m'
        readonly NC='\033[0m'
else
        readonly RED=''
        readonly GREEN=''
        readonly YELLOW=''
        readonly BLUE=''
        readonly CYAN=''
        readonly MAGENTA=''
        readonly NC=''
fi

DEBUG="${DEBUG:-0}"                               # §8 safe defaults
VERBOSE="${VERBOSE:-0}"
TARGET="${TARGET:-}"
OUTPUT_DIR="${OUTPUT_DIR:-./nmap-results}"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
readonly TIMESTAMP                                # §8 constant after assignment

# ============================================
# Utility Helpers
# ============================================

err() {
        printf '%b\n' "${RED}[-]${NC} $*" >&2   # §7 printf not echo
        return 0                                  # §2 &&-trap
}

debug() {
        [[ "${DEBUG:-0}" == 1 ]] && printf '[DEBUG] %s\n' "$*"
        return 0  # §2 &&-trap: must always exit 0 under set -e
}

log() {
        printf '%b\n' "${CYAN}[INFO]${NC} $*"   # §7 printf not echo
        return 0                                  # §2 &&-trap
}

info() {
        printf '%b\n' "${BLUE}[*]${NC} $*"      # §7 printf not echo
        return 0                                  # §2 &&-trap
}

success() {
        printf '%b\n' "${GREEN}[+]${NC} $*"     # §7 printf not echo
        return 0                                  # §2 &&-trap
}

warning() {
        printf '%b\n' "${YELLOW}[!]${NC} $*"    # §7 printf not echo
        return 0                                  # §2 &&-trap
}

show_help() {
        printf '%s\n' "Usage: ${0##*/} <target_ip> [OPTIONS]"  # §5 no-fork: no basename
        printf '%s\n' ''
        printf '%s\n' 'Comprehensive nmap scanning tool with multiple scan profiles.'
        printf '%s\n' ''
        printf '%s\n' 'OPTIONS:'
        printf '%s\n' '    -h, --help          Show this help menu'
        printf '%s\n' '    -o, --output DIR    Output directory (default: ./nmap-results)'
        printf '%s\n' ''
        printf '%s\n' 'EXAMPLES:'
        printf '%s\n' "    ${0##*/} 10.129.6.135"
        printf '%s\n' "    ${0##*/} 10.129.6.135 -o ~/scans"
        printf '%s\n' ''
        return 0
}

# ============================================
# Requirements, Parsing & Cleanup
# ============================================

check_requirements() {
        debug "check_requirements called"
        local cmd=''
        local -a missing=()
        for cmd in nmap tee; do                   # §4 command -v only
                command -v "${cmd}" &>/dev/null || missing+=("${cmd}")
        done
        (( ${#missing[@]} > 0 )) && {
                err "Missing dependencies: ${missing[*]}"
                exit 1
        }
        return 0
}

parse_args() {
        debug "parse_args called with: $*"
        [[ "${*}" == *"--help"* ]] && { show_help; exit 0; }   # §3 --help before loop
        while [[ $# -gt 0 ]]; do
                case "${1}" in
                        -h|--help)
                                show_help
                                exit 0
                                ;;
                        -o|--output)
                                if [[ $# -lt 2 ]] || [[ -z "${2:-}" ]]; then
                                        err "--output requires a directory argument"
                                        exit 2
                                fi
                                OUTPUT_DIR="${2}"
                                shift 2
                                ;;
                        -*)
                                err "Unknown argument: ${1}"    # §3 unknown options
                                exit 2
                                ;;
                        *)
                                if [[ -z "${TARGET}" ]]; then
                                        TARGET="${1}"
                                fi
                                shift
                                ;;
                esac
        done
        return 0
}

cleanup() {
        debug "cleanup called"
        return 0
}

trap 'cleanup' EXIT INT TERM  # §9 trap before side effects

# ============================================
# Scan Infrastructure
# ============================================

banner() {
        printf '%b\n' "${CYAN}"                  # §7 printf not echo
        cat << 'EOF'
  __  __            _   _
 |  \/  | __ ___  _| \ | |_ __ ___   __ _ _ __
 | |\/| |/ _` \ \/  \/  | '_ ` _ \ / _` | '_ \
 | |  | | (_| |>  <| |\  | | | | | | (_| | |_) |
 |_|  |_|\__,_/_/\_\_| \_|_| |_| |_|\__,_| .__/
                                          |_|
EOF
        printf '%b\n' "${NC}"
        printf '%s\n' '         Comprehensive Nmap Scanner'
        printf '%s\n' '=========================================='
        printf '\n'
        return 0
}

check_root() {
        debug "check_root called"
        if (( EUID != 0 )); then                  # §7 (( )) for arithmetic
                warning "Some scans require root. Run with sudo for full functionality."
        fi
        return 0
}

setup_output() {
        debug "setup_output called"
        mkdir -p "${OUTPUT_DIR}"
        info "Output directory: ${OUTPUT_DIR}"
        return 0
}

validate_ip() {
        local ip="${1}"
        debug "validate_ip called with: ${ip}"
        local ip_re='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
        local host_re
        host_re='^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        host_re+='(\.[a-zA-Z]{2,})+$'
        if [[ ! "${ip}" =~ ${ip_re} ]]; then
                if [[ ! "${ip}" =~ ${host_re} ]]; then
                        debug "Not a standard IP/hostname; nmap will validate."
                fi
        fi
        return 0
}

run_scan() {
        # §9 no eval: command dispatched via "$@" array expansion
        local name="${1}"
        local outfile="${OUTPUT_DIR}/${TARGET//./_}_${name}_${TIMESTAMP}"
        shift 1
        printf '\n'
        info "Running: ${name}"
        info "Command: $*"
        printf '\n'
        if "$@" \
                -oN "${outfile}.txt" \
                -oX "${outfile}.xml" \
                | tee "${outfile}_console.txt"; then
                success "Saved to: ${outfile}.txt"
        else
                err "Scan failed or interrupted"
        fi
        return 0
}

# ============================================
# Scan Functions
# ============================================

scan_quick() {
        info "Quick Scan - Top 100 ports, fast"
        run_scan "quick" nmap -T4 --top-ports 100 -v "${TARGET}"
        return 0
}

scan_ippsec() {
        info "IppSec Scan - Default scripts and version detection"
        run_scan "ippsec" nmap -sC -sV -v "${TARGET}"
        return 0
}

scan_standard() {
        info "Standard Scan - All ports, scripts, versions"
        run_scan "standard" \
                nmap -p- --min-rate 1000 -T4 -sC -sV -v "${TARGET}"
        return 0
}

scan_full() {
        info "Full Scan - All ports, all scripts, aggressive"
        run_scan "full" nmap -p- -A -T4 -v "${TARGET}"
        return 0
}

scan_stealth() {
        info "Stealth Scan - SYN scan, slow timing, fragmented"
        run_scan "stealth" sudo nmap -sS -T2 -f -v "${TARGET}"
        return 0
}

scan_udp() {
        info "UDP Scan - Top 100 UDP ports"
        run_scan "udp" sudo nmap -sU --top-ports 100 -T4 -v "${TARGET}"
        return 0
}

scan_udp_full() {
        info "Full UDP Scan - Top 1000 UDP ports (slow)"
        run_scan "udp_full" \
                sudo nmap -sU --top-ports 1000 -T4 -v "${TARGET}"
        return 0
}

scan_vuln() {
        info "Vulnerability Scan - Common vuln scripts"
        run_scan "vuln" \
                nmap -p- --min-rate 1000 "--script=vuln" -v "${TARGET}"
        return 0
}

scan_safe_scripts() {
        info "Safe Scripts Scan - All safe category scripts"
        run_scan "safe_scripts" \
                nmap -p- --min-rate 1000 "--script=safe" -v "${TARGET}"
        return 0
}

scan_discovery() {
        info "Discovery Scan - Host discovery, no port scan"
        run_scan "discovery" \
                nmap -sn -PE -PP -PM \
                -PS21,22,23,25,80,443,3389 -v "${TARGET}"
        return 0
}

scan_os_detect() {
        info "OS Detection Scan"
        run_scan "os_detect" \
                sudo nmap -O --osscan-guess -v "${TARGET}"
        return 0
}

scan_service_version() {
        info "Service Version Scan - Intensive version detection"
        run_scan "service_version" \
                nmap -p- --min-rate 1000 -sV \
                --version-intensity 5 -v "${TARGET}"
        return 0
}

scan_firewall_evasion() {
        info "Firewall Evasion Scan - Fragmented, decoy, MTU"
        run_scan "fw_evasion" \
                sudo nmap -p- -f --mtu 24 -T2 -Pn -v "${TARGET}"
        return 0
}

scan_smb() {
        info "SMB Enumeration Scan"
        local scripts='smb-enum-shares,smb-enum-users'
        scripts+=',smb-os-discovery,smb-security-mode,smb-vuln*'
        run_scan "smb" nmap -p 139,445 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_web() {
        info "Web Enumeration Scan"
        local scripts
        scripts='http-title,http-headers,http-methods,http-enum,http-vuln*'
        run_scan "web" nmap -p 80,443,8080,8443 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_dns() {
        info "DNS Enumeration Scan"
        local scripts='dns-brute,dns-zone-transfer,dns-cache-snoop'
        run_scan "dns" nmap -p 53 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_ldap() {
        info "LDAP Enumeration Scan"
        local scripts='ldap-search,ldap-rootdse'
        run_scan "ldap" \
                nmap -p 389,636,3268,3269 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_kerberos() {
        info "Kerberos Enumeration Scan"
        run_scan "kerberos" \
                nmap -p 88 "--script=krb5-enum-users" -v "${TARGET}"
        return 0
}

scan_ftp() {
        info "FTP Enumeration Scan"
        local scripts='ftp-anon,ftp-bounce,ftp-syst,ftp-vuln*'
        run_scan "ftp" nmap -p 21 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_ssh() {
        info "SSH Enumeration Scan"
        local scripts='ssh-auth-methods,ssh-hostkey,ssh2-enum-algos'
        run_scan "ssh" nmap -p 22 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_smtp() {
        info "SMTP Enumeration Scan"
        local scripts='smtp-commands,smtp-enum-users,smtp-vuln*'
        run_scan "smtp" nmap -p 25,465,587 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_mysql() {
        info "MySQL Enumeration Scan"
        local scripts='mysql-info,mysql-enum,mysql-vuln*'
        run_scan "mysql" nmap -p 3306 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_mssql() {
        info "MSSQL Enumeration Scan"
        local scripts='ms-sql-info,ms-sql-config,ms-sql-empty-password'
        run_scan "mssql" nmap -p 1433,1434 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_mongodb() {
        info "MongoDB Enumeration Scan"
        local scripts='mongodb-info,mongodb-databases'
        run_scan "mongodb" nmap -p 27017,27018,27019 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_rdp() {
        info "RDP Enumeration Scan"
        local scripts='rdp-enum-encryption,rdp-vuln*'
        run_scan "rdp" nmap -p 3389 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_snmp() {
        info "SNMP Enumeration Scan"
        local scripts
        scripts='snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr'
        run_scan "snmp" \
                sudo nmap -sU -p 161,162 \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_all_tcp() {
        info "All TCP Ports - No scripts (fast discovery)"
        run_scan "all_tcp" \
                nmap -p- --min-rate 5000 -T4 -Pn -v "${TARGET}"
        return 0
}

scan_top_1000() {
        info "Top 1000 Ports with Scripts"
        run_scan "top1000" \
                nmap --top-ports 1000 -sC -sV -T4 -v "${TARGET}"
        return 0
}

scan_custom_ports() {
        local ports=''
        printf '\n'
        read -rp "Enter ports (comma-separated, e.g., 21,22,80,443): " ports
        if [[ -n "${ports}" ]]; then
                run_scan "custom" \
                        nmap -p "${ports}" -sC -sV -T4 -v "${TARGET}"
        else
                warning "No ports specified"
        fi
        return 0
}

scan_custom_command() {
        local cmd=''
        local -a cmd_arr=()
        printf '\n'
        read -rp "Enter custom nmap flags (target added automatically): " cmd
        if [[ -n "${cmd}" ]]; then
                read -ra cmd_arr <<< "${cmd}"    # §5 no-fork: split without subshell
                run_scan "custom_cmd" nmap "${cmd_arr[@]}" "${TARGET}"
        else
                warning "No command specified"
        fi
        return 0
}

# ============================================
# Combo Scans
# ============================================

scan_htb_combo() {
        info "HTB Combo - Quick → Full TCP → Service Detection"
        scan_all_tcp
        scan_standard
        return 0
}

scan_ad_combo() {
        info "Active Directory Combo - SMB, LDAP, Kerberos, DNS"
        scan_smb
        scan_ldap
        scan_kerberos
        scan_dns
        return 0
}

scan_web_combo() {
        info "Web Combo - All web ports and scripts"
        local scripts
        scripts='http-title,http-headers,http-methods,'
        scripts+='http-enum,http-robots.txt,http-sitemap-generator'
        run_scan "web_combo" \
                nmap -p 80,443,8000,8080,8443,8888 -sC -sV \
                "--script=${scripts}" -v "${TARGET}"
        return 0
}

scan_full_recon() {
        info "Full Recon - Everything (takes a long time)"
        scan_all_tcp
        scan_standard
        scan_udp
        scan_vuln
        return 0
}

# ============================================
# Menu System
# ============================================

show_menu() {
        printf '%b\n' "${MAGENTA}"               # §7 printf not echo
        printf '%s\n' '=========================================='
        printf '%s\n' '          SELECT SCAN TYPE'
        printf '%s\n' '=========================================='
        printf '%b\n' "${NC}"
        printf '%b\n' "${CYAN}--- Quick Scans ---${NC}"
        printf '%s\n' '  1) Quick Scan          (Top 100 ports, fast)'
        printf '%s\n' '  2) Standard Scan       (All ports, scripts, versions)'
        printf '%s\n' '  3) Full Scan           (All ports, aggressive)'
        printf '%s\n' '  4) All TCP Ports       (Fast port discovery only)'
        printf '%s\n' '  5) Top 1000 Ports      (With scripts)'
        printf '%s\n' '  6) IppSec Scan         (-sC -sV)'
        printf '\n'
        printf '%b\n' "${CYAN}--- Stealth & Evasion ---${NC}"
        printf '%s\n' ' 10) Stealth Scan        (SYN, slow, fragmented)'
        printf '%s\n' ' 11) Firewall Evasion    (Fragmented, MTU, decoy)'
        printf '\n'
        printf '%b\n' "${CYAN}--- UDP Scans ---${NC}"
        printf '%s\n' ' 15) UDP Quick           (Top 100 UDP ports)'
        printf '%s\n' ' 16) UDP Full            (Top 1000 UDP ports)'
        printf '\n'
        printf '%b\n' "${CYAN}--- Enumeration Scans ---${NC}"
        printf '%s\n' ' 20) OS Detection'
        printf '%s\n' ' 21) Service Versions    (Intensive)'
        printf '%s\n' ' 22) Vulnerability Scan  (--script=vuln)'
        printf '%s\n' ' 23) Safe Scripts        (--script=safe)'
        printf '%s\n' ' 24) Discovery Only      (No port scan)'
        printf '\n'
        printf '%b\n' "${CYAN}--- Service-Specific ---${NC}"
        printf '%s\n' ' 30) SMB Enumeration     (139,445)'
        printf '%s\n' ' 31) Web Enumeration     (80,443,8080,8443)'
        printf '%s\n' ' 32) DNS Enumeration     (53)'
        printf '%s\n' ' 33) LDAP Enumeration    (389,636,3268)'
        printf '%s\n' ' 34) Kerberos Enum       (88)'
        printf '%s\n' ' 35) FTP Enumeration     (21)'
        printf '%s\n' ' 36) SSH Enumeration     (22)'
        printf '%s\n' ' 37) SMTP Enumeration    (25,465,587)'
        printf '%s\n' ' 38) MySQL Enumeration   (3306)'
        printf '%s\n' ' 39) MSSQL Enumeration   (1433,1434)'
        printf '%s\n' ' 40) MongoDB Enumeration (27017)'
        printf '%s\n' ' 41) RDP Enumeration     (3389)'
        printf '%s\n' ' 42) SNMP Enumeration    (161,162 UDP)'
        printf '\n'
        printf '%b\n' "${CYAN}--- Combo Scans ---${NC}"
        printf '%s\n' ' 50) HTB Combo           (Quick + Full + Services)'
        printf '%s\n' ' 51) AD Combo            (SMB + LDAP + Kerberos + DNS)'
        printf '%s\n' ' 52) Web Combo           (All web ports + scripts)'
        printf '%s\n' ' 53) Full Recon          (Everything - SLOW)'
        printf '\n'
        printf '%b\n' "${CYAN}--- Custom ---${NC}"
        printf '%s\n' ' 60) Custom Ports        (Specify your own ports)'
        printf '%s\n' ' 61) Custom Command      (Specify your own flags)'
        printf '\n'
        printf '%b\n' "  ${YELLOW}0) Exit${NC}"
        printf '\n'
        return 0
}

process_choice() {
        local choice="${1}"
        case "${choice}" in
                1)  scan_quick ;;
                2)  scan_standard ;;
                3)  scan_full ;;
                4)  scan_all_tcp ;;
                5)  scan_top_1000 ;;
                6)  scan_ippsec ;;
                10) scan_stealth ;;
                11) scan_firewall_evasion ;;
                15) scan_udp ;;
                16) scan_udp_full ;;
                20) scan_os_detect ;;
                21) scan_service_version ;;
                22) scan_vuln ;;
                23) scan_safe_scripts ;;
                24) scan_discovery ;;
                30) scan_smb ;;
                31) scan_web ;;
                32) scan_dns ;;
                33) scan_ldap ;;
                34) scan_kerberos ;;
                35) scan_ftp ;;
                36) scan_ssh ;;
                37) scan_smtp ;;
                38) scan_mysql ;;
                39) scan_mssql ;;
                40) scan_mongodb ;;
                41) scan_rdp ;;
                42) scan_snmp ;;
                50) scan_htb_combo ;;
                51) scan_ad_combo ;;
                52) scan_web_combo ;;
                53) scan_full_recon ;;
                60) scan_custom_ports ;;
                61) scan_custom_command ;;
                0)
                        success "Exiting. Results saved in ${OUTPUT_DIR}"
                        exit 0
                        ;;
                *)
                        err "Invalid option: ${choice}"
                        ;;
        esac
        return 0
}

# ============================================
# Main
# ============================================

main() {
        debug "main called"
        check_requirements                        # §4 first call in main
        parse_args "$@"

        if [[ -z "${TARGET}" ]]; then
                err "No target specified"
                show_help
                exit 1
        fi

        validate_ip "${TARGET}"
        banner
        info "Target: ${TARGET}"
        check_root
        setup_output

        local choice=''
        while true; do
                show_menu
                read -rp "Select scan [0-61]: " choice || exit 0
                process_choice "${choice}"
                printf '\n'
                read -rp "Press Enter to continue..." || true
        done
        return 0
}

main "$@"
