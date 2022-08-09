from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad
from hashlib import md5
from base64 import b64encode, b64decode
from itertools import cycle
from tqdm import tqdm

MD5 = lambda s: md5(s).digest()
KEY_PAD = lambda key: b"\x00" * (16 - len(key)) + key

# Mostly same code except for decrypt

def decrypt(ciphertext, password, keysize):
    def _gen_key(password):
        key = password
        for i in range(1000):
            key = MD5(key)
        return key
    key = bytes_to_long(_gen_key(password))
    ciphers = [AES.new(KEY_PAD(long_to_bytes((key*(i+1)) % 2**128)) ,AES.MODE_ECB) for i in range(0, keysize, 16)]
    ct = b64decode(ciphertext)
    ct_blocks = [
        ct[i:i+16] for i in range(0, len(ct), 16)
    ]
    return b"".join([cipher.decrypt(ct_block) for ct_block, cipher in zip(ct_blocks, cycle(ciphers))])

ciphertext = open("../challenge/flag.enc").read()
for i in tqdm(range(0, 999999)):
    pt = decrypt(ciphertext, str(i).encode().zfill(6), 2048)
    if pt.startswith(b"uiuctf"):
        print(pt)
        break
