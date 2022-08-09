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


client = pwnlib.tubes.remote.remote('127.0.0.1', 1338)
server = pwnlib.tubes.remote.remote('127.0.0.1', 1337)

print(client.recvuntil(b'== proof-of-work: '))
if client.recvline().startswith(b'enabled'):
    handle_pow(client)

print(server.recvuntil(b'== proof-of-work: '))
if server.recvline().startswith(b'enabled'):
    handle_pow(server)

########## Downgrade Handshake ##########

# get client encryption suite
client.recvline()
# get client random
client_random = client.recvline().decode('utf-8').strip()

# send client cipher suite and client random
server.sendline(b"AES.MODE_ECB")
server.sendline(client_random.encode())

# get server signed certificate
cert = server.recvline().decode('utf-8').strip()
# send server signed cert to client
client.sendline(cert.encode())

# get selected cipher suite from server
server.recvline()

# send selected cipher suite to client
client.sendline(b"AES.MODE_ECB")

# get server random
server_random = server.recvline().decode('utf-8').strip()
# send client server random
client.sendline(server_random.encode())
# get encrypted premaster secret
encrypted_premaster_secret = client.recvline().decode('utf-8').strip()
server.sendline(encrypted_premaster_secret.encode())

# get chosen cipher
chosen_cipher = client.recvline().decode('utf-8').strip()
# send server chosen cipher: should be ECB
server.sendline(chosen_cipher.encode())

# send server finish message
finish = client.recvline().decode('utf-8').strip()
server.sendline(finish.encode())
# send client server's confirm finish
client.sendline(b"finish")

########## Breaking ECB Mode ##########

# get correct ciphertext
client.sendline(b'')
ciphertext_hex = client.recvline().decode('utf-8').strip()

expected_ciphertext_hex_len = len(ciphertext_hex)
filler_byte = b'20'
padded_bytes = b''
while len(ciphertext_hex) == expected_ciphertext_hex_len:
    padded_bytes  = padded_bytes + filler_byte
    client.sendline(padded_bytes)
    ciphertext_hex = client.recvline().decode('utf-8').strip()

block_size = int((len(ciphertext_hex) - expected_ciphertext_hex_len) / 2)
flag_length = int((expected_ciphertext_hex_len / 2) - (len(padded_bytes) / 2))

def match_blocks(known_bytes, block_size, target, received_output):
    need_match = ((known_bytes // block_size) + 1) * (block_size * 2)
    for chars in range(need_match):
        if target[chars] != received_output[chars]:
            return False
    return True

plaintext = ""
plaintext_hex = ""
random_byte = b'20'

for i in range(flag_length):
    client.sendline(b'20' * (block_size - (i + 1)))
    target = client.recvline().decode('utf-8').strip()

    for byte in range(32, 128):

        # convert byte to hex with appropriate length
        brute_byte = hex(byte)[2:]
        if len(brute_byte) != 2:
            while (len(brute_byte) != 2):
                brute_byte = "0" + brute_byte
        # TODO: add math to take care of cases that have more than one block
        client.sendline((b'20' * (block_size - (i + 1))) + plaintext_hex.encode() + brute_byte.encode())
        received_output = client.recvline().decode('utf-8').strip()

        # check result
        if match_blocks(len(plaintext), block_size, target, received_output):
            plaintext_hex += brute_byte
            plaintext += chr(byte)
            break

print(plaintext)
