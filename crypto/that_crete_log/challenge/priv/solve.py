from Crypto.Util.number import long_to_bytes
from sage.all import *
from pwn import *

N = [8000822673837171080457965238714593305783001567435596595416857079066119217638050462745330518945039882493159717745176779616041407842201262497169906487856690023, 6833376710107961919010116197998345657871899500234514402563475665617210084707792554944112390215306903130930980928441510070838497794533807513744725595820952840762197261593523645795053, 1811487833498770000757111931952159797168965897188504235091426342505188968019923644115308257599646111112157421694725681051572865283050507143782791082569411203083565028550491084300017, 99946180853647900190507548715272903174357488699712311838997229400136184717522738422690503782179557338589725941930728176136290921097105623417778178497728256867523, 481612240792825001364273172183786732295300693400152565390465466521812886672554996902853684505168325958711029567115707265890791199990234401175461599696942292915237534225029]

conn = remote("log.chal.uiuc.tf", 1337)
print(conn.recvuntil("session: "))
token = int(conn.recvuntil("\n").strip())

dl = []
mods = []

for i in range(5):
    NN = N[i]
    facts = factor(NN-1)
    pseudoprime = 1
    primes = []
    for p, mult in facts:
        if p > 256:
            pseudoprime *= p
            primes.append(p)
        else:
            for _ in range(mult):
                conn.send(str(p)+' ')
    conn.sendline(str(pseudoprime))

    F = Zmod(NN)
    conn.recvuntil("x = ")
    x = F(int(conn.recvuntil("\n").strip()))
    conn.recvuntil("out = ")
    out = F(int(conn.recvuntil("\n").strip()))
    dlog = out.log(x)
    assert(pow(x,dlog,NN)==out)
    for p, mult in factor(N[i]-1):
        if p < 256: continue
        print(dlog%p, p)
        dl.append(dlog%p)
        mods.append(p)

ans = crt(dl, mods)
print(ans^token)
print(long_to_bytes(ans^token))
