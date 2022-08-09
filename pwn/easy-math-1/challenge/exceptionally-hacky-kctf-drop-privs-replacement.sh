#!/bin/bash

# There are two copies of this file in the nsjail and healthcheck base images.

all_caps="-cap_0"
for i in $(seq 1 $(cat /proc/sys/kernel/cap_last_cap)); do
 if [[ $i == 6 || $i == 7 ]]; then
  all_caps+=",+cap_${i}"
 else
  all_caps+=",-cap_${i}"
 fi
done

exec setpriv --init-groups --reset-env --reuid user --regid user --inh-caps=${all_caps} --ambient-caps=+cap_6,+cap_7 -- "$@"
