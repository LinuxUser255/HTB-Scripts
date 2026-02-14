#!/usr/bin/env bash

# Batch Git Clone from file
# Reads repository URLs from a text file and clones them

# Show help
# ./git-clone.sh --help

# Clone from file
#./git-clone.sh repos.txt

# Clone into specific directory
# ./git-clone.sh -d ~/tools repos.txt

set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"

usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] <repos_file>

Batch clone multiple git repositories from a file.

OPTIONS:
    -h, --help      Show this help menu
    -d, --dir DIR   Clone into specified directory (default: current)

ARGUMENTS:
    repos_file      Text file containing repository URLs (one per line)

EXAMPLES:
    $SCRIPT_NAME repos.txt
    $SCRIPT_NAME -d ~/projects repos.txt
    $SCRIPT_NAME --dir /opt/tools repos.txt

FILE FORMAT (repos.txt):
    git@gitlab.com:user/repo1.git
    git@gitlab.com:user/repo2.git
    # Lines starting with # are ignored
    https://github.com/user/repo3.git

EOF
    exit 0
}

main() {
    local clone_dir="."
    local file=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -d|--dir)
                clone_dir="$2"
                shift 2
                ;;
            *)
                file="$1"
                shift
                ;;
        esac
    done

    # Check if file provided
    if [[ -z "$file" ]]; then
        echo "Error: No repos file specified."
        echo "Run '$SCRIPT_NAME --help' for usage."
        exit 1
    fi

    # Check if file exists
    if [[ ! -f "$file" ]]; then
        echo "Error: File not found: $file"
        exit 1
    fi

    # Create and enter clone directory
    mkdir -p "$clone_dir"
    cd "$clone_dir"
    echo "[*] Cloning into: $(pwd)"
    echo ""

    # Clone repos
    while read -r repo; do
        [[ -z "$repo" || "$repo" =~ ^# ]] && continue
        echo "[*] Cloning: $repo"
        git clone "$repo" || echo "[-] Failed: $repo"
        echo ""
    done < "$file"
    
    echo "[+] Done."
}

main "$@"
