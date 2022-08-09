#!/usr/bin/env python3

from pwn import *

# base39 string to an integer value
def base39_to_int(s):
    n = 0
    for c in s:
        if c == '\n':
            continue
        cur = 0
        if c == ' ':
            cur = 0
        elif c == '.':
            cur = 1
        elif c == ',':
            cur = 2
        elif ord(c) >= ord('0') and ord(c) <= ord('9'):
            cur = ord(c) - ord('0') + 3
        else:
            cur = ord(c) - ord('a') + 10 + 3
        n = n * 39 + cur
    return n

# source: https://www.nayuki.io/page/fast-skipping-in-a-linear-congruential-generator
# this (negative n) is the inverse of lcg forward skipping
def skip(a, c, m, x, n):
    if n < 0:
        ainv = pow(a, -1, m)
        a = ainv
        c = -ainv * c
        n = -n
    a1 = a - 1
    ma = a1 * m
    y = (pow(a, n, ma) - 1) // a1 * c
    z = pow(a, n, m) * x
    new_x = (y + z) % m
    return new_x

def lcg(a, c, m, x):
    return (a * x + c) % m

num_chars = 3200
possible_chars = 39

# same parameters as lcg in the chal
a = possible_chars * (1 * 1) + 1
c = 32 * 1 + 1
m = possible_chars**3200
n = 2**512

# if the user "finds" this page in the library of babel, they win
answer = 'this page cannot be found.'
# pad to num_chars
answer = answer.ljust(num_chars, ' ')

# what we're looking for
x1 = base39_to_int(answer)
x2 = skip(a, c, m, x1, -n)

# split the answer into "coordinates"
z = x2 % (39**(num_chars//4))
x2 = x2 // (39**(num_chars//4))
y = x2 % (39**(num_chars//4))
x2 = x2 // (39**(num_chars//4))
x = x2 % (39**(num_chars//4))
x2 = x2 // (39**(num_chars//4))
w = x2 % (39**(num_chars//4))

# uncomment for more debug info
# print('w =', w)
# print('x =', x)
# print('y =', y)
# print('z =', z)

def main():
    r = remote('library-of-babel.chal.uiuc.tf', 1337)

    r.sendlineafter(b'w: ', str(w).encode('utf-8'))
    r.sendlineafter(b'x: ', str(x).encode('utf-8'))
    r.sendlineafter(b'y: ', str(y).encode('utf-8'))
    r.sendlineafter(b'z: ', str(z).encode('utf-8'))
    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', b'1')
    r.recvuntil(b'Flag: ')
    print(r.recvuntil(b'uiuctf{') + r.recvuntil(b'}'))
    exit(0)

main()
