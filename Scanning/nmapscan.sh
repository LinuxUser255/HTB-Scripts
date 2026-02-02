#!/usr/bin/env bash

# This is the nmap scan to automate:
# nmap -p- --min-rate 1000 -T4 -sC -sV -v <IP> | tee scan.txt

# Enable strict mode
# Set IFS (safer word splitting)
set -euo pipefail
IFS=$'\n\t'

# Maximum number of parallel jobs (e.g., number of CPU cores)"
MAX_JOBS="$(nproc)"


# Define functions here

usage() {
    echo "Usage: $0 <IP>"
    echo "Example: $0 10.129.6.135"
    exit 1
}

run_scan() {
    local ip="$1"
    local output="scan.txt"

    echo "[*] Starting nmap scan on $ip"
    echo "[*] Output file: $output"

    nmap -p- --min-rate 1000 -T4 -sC -sV -v "$ip" | tee "$output"

    echo "[*] Scan complete. Results saved to $output"
}


# Main function
main() {
    # Check if IP argument provided
    if [[ $# -lt 1 ]]; then
        usage
    fi

    local target_ip="$1"

    # Basic IP format validation
    if [[ ! "$target_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Invalid IP format"
        usage
    fi

    run_scan "$target_ip"
}


# Calling the main function
main "$@"
