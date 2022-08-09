from string import ascii_uppercase, ascii_lowercase, digits, hexdigits
import re

# Convert the key from base64 -> bin -> hex to make it easier to read

B64_ALPHABET = ascii_uppercase + ascii_lowercase + digits + "+/"

key_b64 = "".join(open("key_redacted.pem", "r").readlines()[1:-1]).replace("\n", "")
key_bin = "".join(["??????" if i < 0 else bin(i)[2:].zfill(6) for i in map(lambda c: B64_ALPHABET.find(c), key_b64)])
key_hex_blocks = [key_bin[i:i+4] for i in range(0, len(key_bin), 4)]
key_hex = "".join(["?" if "?" in b else hexdigits[int(b, 2)] for b in key_hex_blocks ])

for s in re.findall("\?{2,}", key_hex):
    key_hex = key_hex.replace(s, f"\n[[{len(s)} ?]]\n")

print(key_hex)
