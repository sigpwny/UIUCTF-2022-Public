from Crypto.Cipher import AES
from hashlib import md5

ss = (50083804414231461401595056330790023555867368168553915276510083181608584750347, 14189124507533212350071541113815612879050540876532350188482736055458349409981)

flag_enc = b' \xe9\x1aY.+E\xac\x1b\xc41\x1c\xf7\xba}\x80\x11\xa8;%]\x93\x88\x1fu\x87\x91\x88\x87\x88\x9b\x19'

key = md5(f"({ss[0]},{ss[1]})".encode()).digest()

print(AES.new(key, AES.MODE_ECB).decrypt(flag_enc))
