import requests
import subprocess
import time
SECRET = "6LeqscMgAAAAAHLguaL3CkD37ksJjzPTPwcUOTAv"

r = requests.post("http://spoink.chal.uiuc.tf", data={"bypass":SECRET}, allow_redirects=False)
url = r.headers["Location"]

HOST = url[2:]
PORT = 80
print(HOST,PORT)

time.sleep(10)
print("starting...")

subprocess.Popen(["python3","test1.py",f"{HOST}:{PORT}"])
time.sleep(2)
subprocess.Popen(["python3","test2.py",f"{HOST}:{PORT}"])
print("spawned processes...")

time.sleep(10)
print("done")
