#!/bin/sh

[[ $# -lt 1 ]] && echo "Usage: $0 FILE_NAME [LINE_LENGTH]" && exit
FILE_NAME=$1
TMP_FILE_NAME=$FILE_NAME.tmp
LINE_LENGTH=$([[ $# -eq 2 ]] && echo $2 || echo 80)
cat "$FILE_NAME" | fold -w $LINE_LENGTH -s > "$TMP_FILE_NAME"
mv "$TMP_FILE_NAME" "$FILE_NAME"
