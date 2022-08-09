#!/bin/bash

set -euo pipefail

if (($# != 0 )); then
    echo "Running commands noninteractively is disabled."
    exit 1
fi

if ((EUID != 0)); then
    exec sudo /nsjail-shell.sh
fi

exec kctf_drop_privs kctf_pow nsjail --config /home/user/nsjail.cfg
