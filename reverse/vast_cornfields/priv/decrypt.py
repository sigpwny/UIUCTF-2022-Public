#      1            2
#  a b c d e    V A S T B
#  f g h i j    C D E F G
#  k l m n o    H I J K L
#  p r s t u    M N O P R
#  v w x y z    U W X Y Z
#
#      4            3
#  C O R N F    a b c d e
#  I E L D S    f g h i j
#  A B G H J    k l m n o
#  K M P T U    p r s t u
#  V W X Y Z    v w x y z
#
# I could write this out but TBH I'd just regurgitate the wikipedia explanation
# https://en.wikipedia.org/wiki/Four-square_cipher

def main():
    alive = True
    while alive:
        cipher_text = input("[$] Enter a string to decrypt or [E]xit : ").strip()
        if cipher_text.lower() == 'e':
            alive  = False
        if alive:
            decrypting = True
            if decrypting:
                count = 0
                for c in cipher_text:
                    if c != '_':
                        count += 1
                if (len(cipher_text) % 2 != 0
                    or cipher_text[-1] == "_"
                    or not all(c == '_' or (96 < ord(c) < 113) or (113 < ord(c) < 123) for c in cipher_text)
                    or count % 2 != 0
                    ):
                    for c in cipher_text:
                        if (not all(c == '_' or (96 < ord(c) < 113) or (113 < ord(c) < 123) for c in cipher_text)):
                            print(c)
                            break
                    decrypting = False
                if decrypting:
                    plain_text = ["_" for _ in range(len(cipher_text))]
                    indices = [i for i, c in enumerate(cipher_text) if c != '_']
                    alpha = "abcdefghijklmnoprstuvwxyz"
                    two = "vastbcdefghijklmnopruwxyz"
                    four = "cornfieldsabghjkmptuvwxyz"
                    for i in range(0, len(indices), 2):
                        first, second = indices[i], indices[i + 1]
                        idx_1 = two.index(cipher_text[first])
                        idx_2 = four.index(cipher_text[second])
                        x1, y2 = divmod(idx_1, 5)
                        x2, y1 = divmod(idx_2, 5)
                        plain_text[first] = alpha[5*x1 + y1]
                        plain_text[second] = alpha[5*x2 + y2]
                    res = "".join(plain_text)
                    print(f"[$] Decrypted cipher text: {res}")

                if not decrypting:
                    print("[$] Something went wrong...")
if __name__ == "__main__":
    main()
