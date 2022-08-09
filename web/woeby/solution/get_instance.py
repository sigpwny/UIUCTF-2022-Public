import requests
import subprocess
import time
SECRET = "6LeqscMgAAAAAHLguaL3CkD37ksJjzPTPwcUOTAv"

r = requests.post(f"http://woeby.chal.uiuc.tf", data={"bypass":SECRET}, allow_redirects=False)
url = r.headers["Location"]

HOST = url[2:]
print(f"http://{HOST}/")
