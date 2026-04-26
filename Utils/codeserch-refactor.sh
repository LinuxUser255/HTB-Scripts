#!/usr/bin/env bash
# codesearch.sh - Interactive code search across any codebase
# Usage: ./codesearch.sh <directory> <search_term>
#    or: ./codesearch.sh <directory>   (prompts for term)

set -eou pipefail

DIR="${1:-.}"
TERM="${2:-}"

does_dir_exist(){
    if [ ! -d "$DIR" ]; then
        echo "Error: Directory '$DIR' does not exist." >&2
        exit 1
    fi
}

is_rg_installed(){
    if ! command -v rg &> /dev/null; then
        echo "Error: ripgrep (rg) is not installed." >&2
        exit 1
    fi
}

get_search_term(){
    if [ -z "$TERM" ]; then
        read -p "Search for: " TERM
    fi
}

print_header(){
    echo "========================================="
    echo "  Searching: $DIR"
    echo "  Term: $TERM"
    echo "========================================="
    echo ""
}

# Count matches
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
    is_rg_installed
    get_search_term

    print_header
    count_matches
    show_matches_two_context_lines
}

main "$@"
