#!/bin/sh

[[ $# -lt 1 ]] && echo "Usage: $0 PROJECT_PATH" && exit
PROJECT_PATH="$1"
CWD="$(pwd)"
cd "$PROJECT_PATH/src"
latexmk -pdf -outdir=out main.tex > /dev/null
rm -rf "$CWD/out"
mv out "$CWD/"
