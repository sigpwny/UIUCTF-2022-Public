cat <<EOF> /tmp/solve.py
import os
import sys
import subprocess

(r, w) = os.pipe()

os.close(0)
os.close(1)
os.dup(r)
os.dup(r)

def pr(x):
    os.write(2, x)

proc = subprocess.Popen("/home/ctf/easy-math", stdin=r, stdout=subprocess.PIPE)

for _ in range(5):
    pr(proc.stdout.readline())

for _ in range(10000):
    q = b''
    while True:
        q += proc.stdout.read(1)
        if q[-3:] == b' = ':
            break
    pr(q)
    line = q.split(b" ")
    res = int(line[2]) * int(line[4])
    res = str(res).encode() + b"\n"
    pr(res)
    os.write(w, res)
pr(proc.communicate()[0])

EOF
exec python3 /tmp/solve.py
