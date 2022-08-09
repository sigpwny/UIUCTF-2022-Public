#!/bin/bash

set -euo pipefail

if (($# != 0 )); then
    echo "Running commands noninteractively is disabled."
    exit 1
fi

if ((EUID != 0)); then
    exec sudo /nsjail-shell2.sh
fi

TEMP_OUTPUT=$(mktemp)

kctf_drop_privs kctf_pow nsjail --config /home/user/nsjail2.cfg > $TEMP_OUTPUT 2>&1 || :

echo "Output:"
echo "---"
cat $TEMP_OUTPUT
echo "---"
rm $TEMP_OUTPUT
