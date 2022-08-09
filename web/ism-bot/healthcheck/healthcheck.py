#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))


r = remote('127.0.0.1', 1337)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

l = listen()
r.readuntil(b'URL to open.', timeout=10)
r.send(bytes('http://localhost:{}/ok'.format(l.lport), 'ascii'))

l.wait_for_connection()
l.readuntil(b'GET /ok HTTP/1.1')

exit(0)
