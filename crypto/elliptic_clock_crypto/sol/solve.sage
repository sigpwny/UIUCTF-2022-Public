"""
By experimenting with small p, it can be seen that the given operation forms a group operation on the set

C(p) = {(x,y): x*x + y*y = 1 (mod p)}, with |C(p)| = p-1

with identity (0, 1). We can therefore find inverses as defined below.

Note that since p-1 is sufficiently smooth, we can use Pohlig-Hellman to efficiently solve discrete logarithm over this group.
"""

from tqdm import tqdm
from hashlib import md5
from Crypto.Cipher import AES

# Parameters from challenge

p = 62471552838526783778491264313097878073079117790686615043492079411583156507853
Fp = Integers(p)
base_point = (Fp(34510208759284660042264570994647050969649037508662054358547659196695638877343),Fp(4603880836195915415499609181813839155074976164846557299963454168096659979337))
alice_point = (Fp(929134947869102207395031929764558470992898835457519444223855594752208888786),Fp(6062966687214232450679564356947266828438789510002221469043877962705671155351))

point_add = lambda p1, p2: (p1[0]*p2[1]+p1[1]*p2[0],p1[1]*p2[1]-p1[0]*p2[0])

def scalar_mult(x, n):
    y = (Fp(0), Fp(1))
    if n == 0: return y
    if n == 1: return x
    while n > 1:
        if n % 2 == 0:
            x = point_add(x,x)
            n = n//2
        else:
            y = point_add(x,y)
            x = point_add(x,x)
            n = (n-1) // 2
    return point_add(x,y)

def inverse(pt):
    x,y = pt
    if x == 0:
        return (0, 1 / y)
    else:
        return (-x, y)


def bsgs(a, b, N):
    if N < 100:
        for i in range(N):
            if scalar_mult(a, i) == b:
                return i
        return -1
    else:
        m = ceil(sqrt(N))
        table = {scalar_mult(a,j): j for j in tqdm(range(m))}
        tmp = b
        for i in tqdm(range(m)):
            if tmp in table:
                return i*m + table[tmp]
            else:
                tmp = point_add(tmp, scalar_mult(a, (p-1)-m))
        return -1

residues = []
moduli = []
for p_,e_ in factor(p-1):
    exponent = (p-1) // (p_^e_)
    g_i = scalar_mult(base_point, exponent)
    h_i = scalar_mult(alice_point, exponent)
    x_i = bsgs(g_i, h_i, p_^e_)
    print(h_i, scalar_mult(g_i, int(x_i)))
    moduli.append(int(p_^e_))
    residues.append(int(x_i))
    print(p_, e_, x_i)

x = crt(residues, moduli)

assert alice_point == scalar_mult(base_point, x)

bob_point = (Fp(49232075403052702050387790782794967611571247026847692455242150234019745608330),Fp(46585435492967888378295263037933777203199027198295712697342810710712585850566))

shared_secret = scalar_mult(bob_point, x)

flag_enc = b' \xe9\x1aY.+E\xac\x1b\xc41\x1c\xf7\xba}\x80\x11\xa8;%]\x93\x88\x1fu\x87\x91\x88\x87\x88\x9b\x19'

key = md5(f"({shared_secret[0]},{shared_secret[1]})".encode()).digest()

print(AES.new(key, AES.MODE_ECB).decrypt(flag_enc))

