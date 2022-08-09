# Solution
1. it is pretty clear that the challenge involves SSTI, due to there being a template engine being used, and RCE is needed
2. Pebble tries to prevent SSTI, but the spring boot extension introduces objects in global scope that make RCE possible, as the sandbox is not very good
3. the SSTI payload is documented in payload.pebble
4. the second problem is actually getting the payload onto the system
5. we can do this by sending a large multipart POST and hanging after sending file contents (test1.py)
  1. this causes TomCat to create a temporary file and the fd stays open until it receives the end of that multipart file block
6. we then get a ref to the file via /proc/self/fd/X
7. our payload executes ./getflag and exfiltrates it :)
