#!/usr/bin/env python3

import pwnlib.tubes
import base64, io
import numpy as np
from PIL import Image

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('pierated-art.chal.uiuc.tf', 1337)

# comment out the code below if no proof of work is needed
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

for _ in range(10):
    # debug
    # r.recvline()
    # header
    r.recvline()
    # img
    line = r.recvline().decode('utf-8')
    # input
    # print(r.recvline())
    b64 = base64.b64decode(line)
    img = Image.open(io.BytesIO(b64))
    # print('done loading')
    # img.save('out.png')
    arr = np.array(img)
    # filter yellow pixels
    s = [56, 4]

    y_dir = 0
    x_dir = 1

    pixel = np.array((0, 0, 0))
    filtered_pic = np.where(np.all(arr == pixel, axis=2), 1, 0)
    answer = ""
    while True:
        if np.array_equal(arr[s[1]][s[0]], np.array((255,192,192))):
            end = True
        else:
            end = False
        if np.array_equal(arr[s[1]][s[0]], np.array((255,255,0))) and np.array_equal(arr[s[1] - y_dir][s[0] - x_dir], np.array((255,255,0))):
            count = 0
            # print('-------')
            for i in range(6):
                for j in range(6):
                    if y_dir == 1:
                        new_y = s[1] - i # down needs to be neg
                    else:
                        new_y = s[1] + i

                    if x_dir == 1:
                        new_x = s[0] - j
                    else:
                        new_x = s[0] + j
                    # print(new_y, new_x)
                    if np.array_equal(arr[new_y][new_x], np.array((255,255,0))):
                        count += 1
            # print(count)
            # print(s)
            l = 78 + 26 + 26 - count
            if l > 122:
                l -= 26
            answer += chr(l)
            # print('hit yellow', count)
            # print(x_dir, y_dir)
        elif filtered_pic[s[1] + y_dir][s[0] + x_dir] == 1:
            # print(s[::-1])
            # print('change direction')
            if end:
                break
            if x_dir == 1:
                x_dir = 0
                y_dir = 1
            elif y_dir == 1:
                x_dir = -1
                y_dir = 0
            elif x_dir == -1:
                x_dir = 0
                y_dir = -1
            elif y_dir == -1:
                x_dir = 1
                y_dir = 0

        s[0] += x_dir
        s[1] += y_dir
    answer = answer[::-1]
    print(answer)
    r.sendline(answer.encode('utf-8'))
    success = r.recvline()
    print(success)
r.recvline()
flag = r.recvline()
print(flag)
