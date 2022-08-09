#!/bin/sh

nsjail --config /home/user/nsjail.cfg -- \
    /bin/ash -c "dropbear -E -s -p :1337 && exec socat - TCP:127.0.0.1:1337"
