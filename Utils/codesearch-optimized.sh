#!/usr/bin/env bash
# codesearch.sh - Interactive code search across any codebase
# Usage: ./codesearch.sh <directory> <search_term>
#    or: ./codesearch.sh <directory>   (prompts for term)

# Any non-zero exit code, anywhere, for any reason, terminates the script immediately and silently.
set -eou pipefail

# and disable unicode
LC_ALL=C
LANG=C

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Script-wide state variables (all globals initialized to satisfy set -u)
DIR="${1:-.}"
TERM="${2:-}"
DEBUG="${DEBUG:-0}"                # §4 default value to satisfy set -u

# One-liner dbug helper function -- emits only when DEBUG is set to 1
#NOTE: Always leave spaces around the operators inside th [[ ]] else, it will cause a syntax error
# Exe:    [[ condition ]] -- evenly spaced
debug() { [[ "$DEBUG" == 1 ]] && echo "[DEBUG] $*"; return 0; }  # §5 debug function; return 0 prevents set -e triggering when DEBUG=0

print_banner(){
    debug "print_banner" # debug at function start
    printf '%b\n' "${CYAN}╔════════════════════════════════════════════════════╗${NC}"  # §3 printf for formatted output
    printf '%b\n' "${CYAN}║        Searching: "${DIR}"                         ║${NC}"
    printf '%b\n' "${CYAN}║        Term:      "${TERM}"                        ║${NC}"
    printf '%b\n' "${CYAN}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
#    echo "========================================="
#    echo "  Searching: $DIR"
#    echo "  Term: "${TERM}"
#    echo "========================================="
#    echo ""
}

does_dir_exist(){
    if [[ ! -d "$DIR" ]]; then
        #echo "Error: Directory '$DIR' does not exist." >&2
        printf '%b\n' "${RED}[Error]:${NC} Directory '${DIR}' does not exist." >&2
        exit 1
    fi
}

check_ripgrep(){
    debug "check_ripgrep" # debug at function start
    if ! command -v rg &> /dev/null; then
        printf '%b\n' "${RED}[Error]:${NC} ripgrep (rg) is not installed." >&2
        printf '%b\n' "${YELLOW}[Warning]:${NC} Install ripgrep by installing rust." >&2
        printf '%b\n' "${YELLOW}[Warning]:${NC} curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh." >&2
        printf '%b\n' "${YELLOW}[Warning]:${NC} And see the repo: https://github.com/BurntSushi/ripgrep." >&2
        echo ""
        exit 1
    fi
}
# -z var	If the length of string is zero.
# If no argument is provided, the script will prompt the user to enter a search term.
get_search_term(){
    debug "get_search_term" # debug at function start
    if [[ -z "$TERM" ]]; then
        read -p "Search for: " TERM
    fi

    # Validate search term (alphanumeric, underscores, hyphens, dot)
    case "$TERM" in
        '') # empty string Invalid
            printf '%b\n' "${RED}[Error]:${NC} Search term cannot be an empty space." >&2
            exit 1
            ;;
        *[!a-zA-Z0-9_.-]*) # contains invalid characters
            printf '%b\n' "${RED}[Error]:${NC} Search term contains invalid characters. Alphanumeric characters, underscores, hyphens and dots only." >&2
            exit 1
            ;;
        *) # Valid input, continue
            ;;
    esac
}


count_matches(){
    MATCHES=$(rg -c "$TERM" "$DIR" 2>/dev/null | wc -l)
    echo "Files with matches: $MATCHES"
    echo ""
}

# Show matches with 2 lines of context
show_matches_two_context_lines(){
    echo "Matching files:"
    rg -l "$TERM" "$DIR"  2>/dev/null | sed "s|^\./||"

    echo " "
    echo "Matches with context:"
    rg -n -C 2 "$TERM" "$DIR" --type-add 'code:*.{java,kt,xml,json,js,py,c,cpp,h,go,rs,rb,php,swift,smali}' -t code
}

main(){
    does_dir_exist
    check_ripgrep
    get_search_term

    print_banner
    count_matches
    show_matches_two_context_lines
}

main "$@"
