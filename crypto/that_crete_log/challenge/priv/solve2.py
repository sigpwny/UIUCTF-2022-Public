from Crypto.Util.number import long_to_bytes, getPrime, isPrime
from sage.all import *
from pwn import *

N = [0 for _ in range(5)]
factors = [[] for _ in range(5)]

def make_prime(p):
    for j in range(23):
        if isPrime(2**j * p + 1):
            return (2, j)


for i in range(5):
    print("Generating for ", i)
    while factors[i] == []:
        p = getPrime(513) 
        facts = []
        facts.append((p, 1))
        while p < 2**9999:
            q = getPrime(32)
            facts.append((q, 1))
            p*=q
            if p < 2**1024 and p > 2**900:
                out = make_prime(p)
                if out != None:
                    facts.append(out)
                    factors[i] = facts
                    N[i] = out[0] ** out[1] * p + 1
                    break


conn = remote("log.chal.uiuc.tf", 1337)
print(conn.recvuntil("session: "))
token = int(conn.recvuntil("\n").strip())

dl = []
mods = []

try:
    for i in range(5):
        NN = N[i]
        facts = factors[i]
        primes = []
        print("solving ", NN, len(bin(NN))-2)
        for p, mult in facts:
            if p > 256:
                conn.send(str(p)+' ')
                primes.append(p)
            else:
                for _ in range(mult):
                    conn.send(str(p)+' ')
        conn.sendline()

        F = Zmod(NN)
        conn.recvuntil("x = ")
        x = F(int(conn.recvuntil("\n").strip()))
        conn.recvuntil("out = ")
        out = F(int(conn.recvuntil("\n").strip()))
        for p, mult in facts:
            if p < 256: continue
            if p > 2**64: continue
            xp = pow(x, NN//p, NN)
            outp = pow(out, NN//p, NN)
            F = Zmod(NN)
            dlog = sage.groups.generic.bsgs(F(xp), F(outp), [0, Integers()(p)])
            print(dlog, p)
            dl.append(dlog)
            mods.append(p)

    ans = crt(dl, mods)
    print(ans^token)
    print(long_to_bytes(ans^token))
except Exception as e:
    print(e)
    conn.interactive()

