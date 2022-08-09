#!/usr/bin/env python3

# source: https://stackoverflow.com/a/31515396
def reverse_xor_lshift(y, shift, w=8):
    x = y & ((1<<shift) - 1)
    for i in range(w - shift):
        x |= (1 if bool(x & (1<<i)) ^ bool(y & (1<<(shift+i))) else 0)<<(shift+i)
    return x

def reverse_bin(x, w=8):
    return int(bin(x)[2:].rjust(w, '0')[::-1], 2)

def reverse_xor_rshift(y, shift, w=8):
    # for simplicity, we just reuse reverse_xor_lshift here
    return reverse_bin(reverse_xor_lshift(reverse_bin(y), shift))

def unxorshift(b):
    b = reverse_xor_lshift(b, 1)
    b = reverse_xor_rshift(b, 7)
    b = reverse_xor_lshift(b, 6)
    return b


def unxorpass(s, seed):
    accum = seed & 0xFF
    for i in range(len(s)):
        c = unxorshift(s[i])
        c ^= accum
        accum = s[i]
        s[i] = c
    return s

def unxor(s, seed):
    s = s[::-1]
    s = unxorpass(s, 51 * seed)
    s = s[::-1]
    s = unxorpass(s, 47 * seed)
    return s

def unmerge(s, n):
    s = unxor(s, n)

    # undo reverse
    s = s[::-1]

    # undo zipper merge
    left = bytearray()
    right = bytearray()
    for i in range(len(s)):
        if i % 2 == 0:
            right.append(s[i])
        else:
            left.append(s[i])
    return left, right

def unmix(s, n):
    if len(s) == 1:
        return s
    left, right = unmerge(s, n)
    return unmix(left, (n << 1) | 0) + unmix(right, (n << 1) | 1)

answer = 'e338e9cc0199e8c24b43760f2277cf56f9b7ddff343aaf116fe26cafca4538cfb9c26477e377d19a301e13'
flag = unmix(bytearray.fromhex(answer), 1)
assert(flag == b'uiuctf{n41tv3_func7iona1_pr0gr4mm1ng_1n_C!}')
print(flag.decode())
