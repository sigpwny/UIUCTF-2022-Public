from secret import flag
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from sage.all import *
from math import prod

small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
def gen_prime(bits, lim = 7, sz = 64):
    while True:
        p = prod([getPrime(sz) for _ in range(bits//sz)])
        for i in range(lim):
            if isPrime(p+1):
                return p+1
            p *= small_primes[i]

def gen_prime2(bits):
    return prod([getPrime(bits) for _ in range(1)])

p = gen_prime(512)
q = gen_prime(512)
n = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = pow(e, -1, phi)

msg = bytes_to_long(flag)
ct = pow(msg, e, n)

print("p = ", p)
print("q = ", q)
print("n = p*q")
print("chall info:")
print()
print("'''")
print("e = ", e)
print("d = ", d)
print("ct = ", ct)
print("'''")
print()
print("FACTORING TO MAKE SURE ITS POSSIBLE")
print(e*d-1)
print(factor(e*d-1))

