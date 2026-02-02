#!/usr/bin/env bash

# maxnmap.sh - Comprehensive Nmap Scanning Tool
# Usage: ./maxnmap.sh <target_ip>

set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Defaults
TARGET=""
OUTPUT_DIR="./nmap-results"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# ============================================
# Helper Functions
# ============================================

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }

banner() {
    echo -e "${CYAN}"
    cat << "EOF"
  __  __            _   _
 |  \/  | __ ___  _| \ | |_ __ ___   __ _ _ __
 | |\/| |/ _` \ \/ /  \| | '_ ` _ \ / _` | '_ \
 | |  | | (_| |>  <| |\  | | | | | | (_| | |_) |
 |_|  |_|\__,_/_/\_\_| \_|_| |_| |_|\__,_| .__/
                                         |_|
EOF
    echo -e "${NC}"
    echo "         Comprehensive Nmap Scanner"
    echo "=========================================="
    echo ""
}

usage() {
    cat << EOF
Usage: $SCRIPT_NAME <target_ip> [OPTIONS]

Comprehensive nmap scanning tool with multiple scan profiles.

OPTIONS:
    -h, --help          Show this help menu
    -o, --output DIR    Output directory (default: ./nmap-results)

EXAMPLES:
    $SCRIPT_NAME 10.129.6.135
    $SCRIPT_NAME 10.129.6.135 -o ~/scans

EOF
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        warning "Some scans require root. Run with sudo for full functionality."
    fi
}

setup_output() {
    mkdir -p "$OUTPUT_DIR"
    info "Output directory: $OUTPUT_DIR"
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Allow hostnames too
        if [[ ! "$ip" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
            # Just allow it and let nmap handle validation
            return 0
        fi
    fi
    return 0
}

run_scan() {
    local name="$1"
    local cmd="$2"
    local outfile="$OUTPUT_DIR/${TARGET//\./_}_${name}_${TIMESTAMP}"

    echo ""
    info "Running: $name"
    info "Command: $cmd"
    echo ""

    if eval "$cmd -oN ${outfile}.txt -oX ${outfile}.xml" | tee "${outfile}_console.txt"; then
        success "Saved to: ${outfile}.txt"
    else
        error "Scan failed or interrupted"
    fi
}

# ============================================
# Scan Functions
# ============================================

scan_quick() {
    info "Quick Scan - Top 100 ports, fast"
    run_scan "quick" "nmap -T4 --top-ports 100 -v $TARGET"
}

scan_standard() {
    info "Standard Scan - All ports, scripts, versions"
    run_scan "standard" "nmap -p- --min-rate 1000 -T4 -sC -sV -v $TARGET"
}

scan_full() {
    info "Full Scan - All ports, all scripts, aggressive"
    run_scan "full" "nmap -p- -A -T4 -v $TARGET"
}

scan_stealth() {
    info "Stealth Scan - SYN scan, slow timing, fragmented"
    run_scan "stealth" "sudo nmap -sS -T2 -f -v $TARGET"
}

scan_udp() {
    info "UDP Scan - Top 100 UDP ports"
    run_scan "udp" "sudo nmap -sU --top-ports 100 -T4 -v $TARGET"
}

scan_udp_full() {
    info "Full UDP Scan - Top 1000 UDP ports (slow)"
    run_scan "udp_full" "sudo nmap -sU --top-ports 1000 -T4 -v $TARGET"
}

scan_vuln() {
    info "Vulnerability Scan - Common vuln scripts"
    run_scan "vuln" "nmap -p- --min-rate 1000 --script=vuln -v $TARGET"
}

scan_safe_scripts() {
    info "Safe Scripts Scan - All safe category scripts"
    run_scan "safe_scripts" "nmap -p- --min-rate 1000 --script=safe -v $TARGET"
}

scan_discovery() {
    info "Discovery Scan - Host discovery, no port scan"
    run_scan "discovery" "nmap -sn -PE -PP -PM -PS21,22,23,25,80,443,3389 -v $TARGET"
}

scan_os_detect() {
    info "OS Detection Scan"
    run_scan "os_detect" "sudo nmap -O --osscan-guess -v $TARGET"
}

scan_service_version() {
    info "Service Version Scan - Intensive version detection"
    run_scan "service_version" "nmap -p- --min-rate 1000 -sV --version-intensity 5 -v $TARGET"
}

scan_firewall_evasion() {
    info "Firewall Evasion Scan - Fragmented, decoy, MTU"
    run_scan "fw_evasion" "sudo nmap -p- -f --mtu 24 -T2 -Pn -v $TARGET"
}

scan_smb() {
    info "SMB Enumeration Scan"
    run_scan "smb" "nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln* -v $TARGET"
}

scan_web() {
    info "Web Enumeration Scan"
    run_scan "web" "nmap -p 80,443,8080,8443 --script=http-title,http-headers,http-methods,http-enum,http-vuln* -v $TARGET"
}

scan_dns() {
    info "DNS Enumeration Scan"
    run_scan "dns" "nmap -p 53 --script=dns-brute,dns-zone-transfer,dns-cache-snoop -v $TARGET"
}

scan_ldap() {
    info "LDAP Enumeration Scan"
    run_scan "ldap" "nmap -p 389,636,3268,3269 --script=ldap-search,ldap-rootdse -v $TARGET"
}

scan_kerberos() {
    info "Kerberos Enumeration Scan"
    run_scan "kerberos" "nmap -p 88 --script=krb5-enum-users -v $TARGET"
}

scan_ftp() {
    info "FTP Enumeration Scan"
    run_scan "ftp" "nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vuln* -v $TARGET"
}

scan_ssh() {
    info "SSH Enumeration Scan"
    run_scan "ssh" "nmap -p 22 --script=ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -v $TARGET"
}

scan_smtp() {
    info "SMTP Enumeration Scan"
    run_scan "smtp" "nmap -p 25,465,587 --script=smtp-commands,smtp-enum-users,smtp-vuln* -v $TARGET"
}

scan_mysql() {
    info "MySQL Enumeration Scan"
    run_scan "mysql" "nmap -p 3306 --script=mysql-info,mysql-enum,mysql-vuln* -v $TARGET"
}

scan_mssql() {
    info "MSSQL Enumeration Scan"
    run_scan "mssql" "nmap -p 1433,1434 --script=ms-sql-info,ms-sql-config,ms-sql-empty-password -v $TARGET"
}

scan_mongodb() {
    info "MongoDB Enumeration Scan"
    run_scan "mongodb" "nmap -p 27017,27018,27019 --script=mongodb-info,mongodb-databases -v $TARGET"
}

scan_rdp() {
    info "RDP Enumeration Scan"
    run_scan "rdp" "nmap -p 3389 --script=rdp-enum-encryption,rdp-vuln* -v $TARGET"
}

scan_snmp() {
    info "SNMP Enumeration Scan"
    run_scan "snmp" "sudo nmap -sU -p 161,162 --script=snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr -v $TARGET"
}

scan_all_tcp() {
    info "All TCP Ports - No scripts (fast discovery)"
    run_scan "all_tcp" "nmap -p- --min-rate 5000 -T4 -Pn -v $TARGET"
}

scan_top_1000() {
    info "Top 1000 Ports with Scripts"
    run_scan "top1000" "nmap --top-ports 1000 -sC -sV -T4 -v $TARGET"
}

scan_custom_ports() {
    local ports
    echo ""
    read -rp "Enter ports (comma-separated, e.g., 21,22,80,443): " ports
    if [[ -n "$ports" ]]; then
        run_scan "custom" "nmap -p $ports -sC -sV -T4 -v $TARGET"
    else
        warning "No ports specified"
    fi
}

scan_custom_command() {
    local cmd
    echo ""
    read -rp "Enter custom nmap flags (target added automatically): " cmd
    if [[ -n "$cmd" ]]; then
        run_scan "custom_cmd" "nmap $cmd $TARGET"
    else
        warning "No command specified"
    fi
}

# ============================================
# Combo Scans
# ============================================

scan_htb_combo() {
    info "HTB Combo - Quick → Full TCP → Service Detection"
    scan_all_tcp
    scan_standard
}

scan_ad_combo() {
    info "Active Directory Combo - SMB, LDAP, Kerberos, DNS"
    scan_smb
    scan_ldap
    scan_kerberos
    scan_dns
}

scan_web_combo() {
    info "Web Combo - All web ports and scripts"
    run_scan "web_combo" "nmap -p 80,443,8000,8080,8443,8888 -sC -sV --script=http-title,http-headers,http-methods,http-enum,http-robots.txt,http-sitemap-generator -v $TARGET"
}

scan_full_recon() {
    info "Full Recon - Everything (takes a long time)"
    scan_all_tcp
    scan_standard
    scan_udp
    scan_vuln
}

# ============================================
# Menu System
# ============================================

show_menu() {
    echo -e "${MAGENTA}"
    echo "=========================================="
    echo "          SELECT SCAN TYPE"
    echo "=========================================="
    echo -e "${NC}"

    echo -e "${CYAN}--- Quick Scans ---${NC}"
    echo "  1) Quick Scan          (Top 100 ports, fast)"
    echo "  2) Standard Scan       (All ports, scripts, versions)"
    echo "  3) Full Scan           (All ports, aggressive)"
    echo "  4) All TCP Ports       (Fast port discovery only)"
    echo "  5) Top 1000 Ports      (With scripts)"
    echo ""

    echo -e "${CYAN}--- Stealth & Evasion ---${NC}"
    echo " 10) Stealth Scan        (SYN, slow, fragmented)"
    echo " 11) Firewall Evasion    (Fragmented, MTU, decoy)"
    echo ""

    echo -e "${CYAN}--- UDP Scans ---${NC}"
    echo " 15) UDP Quick           (Top 100 UDP ports)"
    echo " 16) UDP Full            (Top 1000 UDP ports)"
    echo ""

    echo -e "${CYAN}--- Enumeration Scans ---${NC}"
    echo " 20) OS Detection"
    echo " 21) Service Versions    (Intensive)"
    echo " 22) Vulnerability Scan  (--script=vuln)"
    echo " 23) Safe Scripts        (--script=safe)"
    echo " 24) Discovery Only      (No port scan)"
    echo ""

    echo -e "${CYAN}--- Service-Specific ---${NC}"
    echo " 30) SMB Enumeration     (139,445)"
    echo " 31) Web Enumeration     (80,443,8080,8443)"
    echo " 32) DNS Enumeration     (53)"
    echo " 33) LDAP Enumeration    (389,636,3268)"
    echo " 34) Kerberos Enum       (88)"
    echo " 35) FTP Enumeration     (21)"
    echo " 36) SSH Enumeration     (22)"
    echo " 37) SMTP Enumeration    (25,465,587)"
    echo " 38) MySQL Enumeration   (3306)"
    echo " 39) MSSQL Enumeration   (1433,1434)"
    echo " 40) MongoDB Enumeration (27017)"
    echo " 41) RDP Enumeration     (3389)"
    echo " 42) SNMP Enumeration    (161,162 UDP)"
    echo ""

    echo -e "${CYAN}--- Combo Scans ---${NC}"
    echo " 50) HTB Combo           (Quick + Full + Services)"
    echo " 51) AD Combo            (SMB + LDAP + Kerberos + DNS)"
    echo " 52) Web Combo           (All web ports + scripts)"
    echo " 53) Full Recon          (Everything - SLOW)"
    echo ""

    echo -e "${CYAN}--- Custom ---${NC}"
    echo " 60) Custom Ports        (Specify your own ports)"
    echo " 61) Custom Command      (Specify your own flags)"
    echo ""

    echo -e "${YELLOW}  0) Exit${NC}"
    echo ""
}

process_choice() {
    local choice="$1"

    case "$choice" in
        1)  scan_quick ;;
        2)  scan_standard ;;
        3)  scan_full ;;
        4)  scan_all_tcp ;;
        5)  scan_top_1000 ;;

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
            success "Exiting. Results saved in $OUTPUT_DIR"
            exit 0
            ;;
        *)
            error "Invalid option: $choice"
            ;;
    esac
}

# ============================================
# Main
# ============================================

main() {
    banner

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            *)
                if [[ -z "$TARGET" ]]; then
                    TARGET="$1"
                fi
                shift
                ;;
        esac
    done

    # Validate target
    if [[ -z "$TARGET" ]]; then
        error "No target specified"
        usage
    fi

    validate_ip "$TARGET"

    info "Target: $TARGET"
    check_root
    setup_output

    # Main menu loop
    while true; do
        show_menu
        read -rp "Select scan [0-61]: " choice
        process_choice "$choice"
        echo ""
        read -rp "Press Enter to continue..."
    done
}

main "$@"
