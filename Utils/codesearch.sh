#!/usr/bin/env bash

# codesearch.sh - Interactive code search across any codebase
# Usage: ./codesearch.sh <directory> <search_term>
#    or: ./codesearch.sh <directory>   (prompts for term)

DIR="${1:-.}"
TERM="${2}"

if [ -z "$TERM" ]; then
    read -p "Search for: " TERM
fi

echo "========================================="
echo "  Searching: $DIR"
echo "  Term: $TERM"
echo "========================================="
echo ""

# Count matches
MATCHES=$(rg -c "$TERM" "$DIR" -r 2>/dev/null | wc -l)
echo "Files with matches: $MATCHES"
echo ""

# Show matches with 2 lines of context
rg -n -C 2 "$TERM" "$DIR" --type-add 'code:*.{java,kt,xml,json,js,py,c,cpp,h,go,rs,rb,php,swift,smali}' -t code
