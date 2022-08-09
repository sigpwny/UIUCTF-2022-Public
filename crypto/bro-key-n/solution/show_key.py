import base64, re
from colorama import Fore, Style
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from itertools import cycle
from string import printable

def num_to_b64(n):
    out = base64.b64encode(long_to_bytes(n)).replace(b"=", b"").decode()
    return out[1:-1] if len(out) > 10 else f"{n}"

key = open("key.pem", "r").read()
key_str = "".join(key.splitlines()[1:-1])

k = RSA.import_key(key)
n = k.n
e = k.e
d = k.d
p = k.p
q = k.q

ITEMS = [n,e,d, p, q, d%(p-1), d%(q-1), pow(q,-1,p)]

for num, color, name in zip(ITEMS, cycle([Fore.RED, Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.CYAN, Fore.MAGENTA, Fore.WHITE]), "n,e,d,p,q,dp,dq,qp".split(",")):
    for i in range(16):
        key_str = key_str.replace(num_to_b64(2**i*num), color + num_to_b64(2**i*num) + Style.RESET_ALL)

print()
WIDTH = 64
curr_line = ""
for char in key_str:
    curr_line += char
    if len(re.sub('\x1b[^m]*m',"", curr_line)) == WIDTH:
        print(curr_line); curr_line = '';
if curr_line: print(curr_line)
