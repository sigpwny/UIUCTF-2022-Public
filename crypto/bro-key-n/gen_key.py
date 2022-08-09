import base64, random, re
from itertools import count
from tqdm import tqdm
from string import ascii_lowercase, ascii_uppercase, digits, hexdigits
from Crypto.Util.number import *
from Crypto.Util.asn1 import DerSequence

BITS = 2048
B64_ALPHABET = ascii_uppercase + ascii_lowercase + digits + "+/"

FLAG = "/uiuctf/hidden/in/plain/sight/"
LENGTH = BITS // 8

while True:
    try:
        _ = base64.b64decode(FLAG)
        break
    except:
        FLAG += "/"

get_bytes = lambda N: bytes(random.choices(range(256), k=N))

random.seed(42)

def gen_prime():
    s = get_bytes(3*random.randint(2, 4))
    PREFIX = s + base64.b64decode(FLAG)
    for _ in tqdm(count(1)):
        SUFFIX = get_bytes( LENGTH - len(PREFIX) )
        out = PREFIX + SUFFIX
        if isPrime(bytes_to_long(out)):
            return bytes_to_long(out)

"""
    RSAPrivateKey ::= SEQUENCE {
      version           Version,
      modulus           INTEGER,  -- n
      publicExponent    INTEGER,  -- e
      privateExponent   INTEGER,  -- d
      prime1            INTEGER,  -- p
      prime2            INTEGER,  -- q
      exponent1         INTEGER,  -- d mod (p-1)
      exponent2         INTEGER,  -- d mod (q-1)
      coefficient       INTEGER,  -- (inverse of q) mod p
      otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }
"""



while True:
    p = gen_prime()
    q = getPrime(BITS)
    n = p*q
    e = 65537
    d = pow(e, -1, (p-1)*(q-1))

    ITEMS = [
     0, # Not multiprime RSA, see https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2
     n,
     e,
     d,
     p,
     q,
     d % (p-1),
     d % (q-1),
     pow(q, -1, p)
    ]

    priv_key = base64.b64encode(DerSequence(ITEMS).encode())
    if FLAG.encode() in priv_key:
        break
    print(priv_key)

key = priv_key.decode()
lines = [priv_key[i:i+64].decode() for i in range(0, len(priv_key), 64)]
key_lines = ["-----BEGIN RSA PRIVATE KEY-----"] + lines + ["-----END RSA PRIVATE KEY-----"]

f = open("key.pem", "w")
f.write("\n".join(key_lines))
f.close()


def key_summary():
    key_hex = base64.b64decode("".join(lines)).hex()
    for item, name in zip([n,e,d,p,q,d%(p-1),d%(q-1),pow(q,-1,p)], ["n","e","d","p","q","dp","dq","qp"]):
        item_hex = hex(item)[2:]
        key_hex = key_hex.replace(item_hex, f"[[{name}: {len(item_hex)*2}]]")
    print(key_hex)

key_summary()

"""
For key, we will do the following:
 - n (all)
 - e (all)
 - d (top 1/8 bits)
 - p (none)
 - q (lower 1/4 bits)
 - dp (top 3/4 bits)
 - dq (none)
 - qp (none)
"""

def gen_redacted_key_hex():
    key_hex = base64.b64decode(key).hex()
    # Replace d
    d_ = hex(d)[2:]
    new_d = d_[:len(d_)//8] + "_"*(len(d_) - len(d_)//8)
    print(f"new_d: {new_d}")
    key_hex = key_hex.replace(d_, new_d)
    # Replace p
    key_hex = key_hex.replace(hex(p)[2:], "_"*len(hex(p)[2:]))
    # Replace q
    q_ = hex(q)[2:]
    new_q = "_" * (3*len(q_)//4) + q_[3*len(q_)//4:]
    print(f"new_q: {new_q}")
    key_hex = key_hex.replace(q_, new_q)
    # Replace dp
    dp_ = hex(d % (p-1))[2:]
    new_dp = dp_[:len(dp_)*3//4] + "_"*(len(dp_) - len(dp_)*3//4)
    print(f"new_dp: {new_dp}")
    key_hex = key_hex.replace(dp_, new_dp)
    # Replace dq, qp
    dq = hex(d%(q-1))[2:]
    qp = hex(pow(q, -1, p))[2:]
    key_hex = key_hex.replace(dq, "_"*len(dq))
    key_hex = key_hex.replace(qp, "_"*len(qp))
    blocks = re.findall(".*?_+", key_hex)
    return "".join([b if len(b) - b.count("_") > 10 else "_"*len(b) for b in blocks])

# Redact part of the key and convert back to base64
key_hex = gen_redacted_key_hex()
key_bin = "".join(["????" if i<0 else bin(i)[2:].zfill(4) for i in map(lambda c: hexdigits.find(c), key_hex)])
key_redacted = ""
for i in range(0, len(key_bin), 6):
    curr_char = key_bin[i:i+6]
    if "?" in curr_char:
        key_redacted += "_"
    else:
        key_redacted += B64_ALPHABET[int(curr_char,2)]

lines = [key_redacted[i:i+64] for i in range(0, len(key_redacted), 64)]
key_redacted_lines = ["-----BEGIN RSA PRIVATE KEY-----"] + lines + ["-----END RSA PRIVATE KEY-----"]


f = open("key_redacted.pem", "w")
f.write("\n".join(key_redacted_lines))
f.close()

key1 = "\n".join(key_lines)
key2 = "\n".join(key_redacted_lines)


print(key1, key2)
