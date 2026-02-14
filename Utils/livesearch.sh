#!/usr/bin/env bash

# livesearch.sh - Live fuzzy search with preview
# Usage: ./livesearch.sh <directory>

DIR="${1:-.}"

rg --files "$DIR" | fzf \
    --preview 'batcat --color=always --style=numbers {}' \
    --header 'Type to filter files, CTRL-R to search contents' \
    --bind "ctrl-r:reload(rg -l {q} $DIR)+change-prompt(ripgrep> )" \
    --bind "ctrl-f:reload(rg --files $DIR)+change-prompt(files> )" \
    --bind "enter:execute(nvim {})"
