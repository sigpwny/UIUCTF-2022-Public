#!/bin/bash

set -euo pipefail

if (($# != 0 )); then
    echo "Running commands noninteractively is disabled."
    exit 1
fi

if ((EUID != 0)); then
    exec sudo /nsjail-shell3.sh
fi

TEMP_OUTPUT=$(mktemp)

echo "Type your input. You won't get any output (not even echo) back until the shell exits."

script -c "kctf_drop_privs kctf_pow nsjail --config /home/user/nsjail3.cfg" -q $TEMP_OUTPUT >/dev/null 2>/dev/null

echo "Output:"
echo "---"

# cut out the script started... lines and script ended line
cat $TEMP_OUTPUT | tail -n +2 | head -n -1
echo "---"
rm $TEMP_OUTPUT
