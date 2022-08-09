#! /usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2021-2022 Google LLC.

import os

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
authorizer.add_anonymous('/home/user/ftproot')

handler = FTPHandler
handler.authorizer = authorizer

address = ('', 2121)
server = FTPServer(address, handler)

# Daemonize
if os.fork():
    os._exit(0)

os.setsid()

fd = os.open('/tmp/ftpd.log', os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
os.dup2(fd, 1)
os.dup2(fd, 2)
os.close(fd)

fd = os.open('/dev/null', os.O_RDONLY)
os.dup2(fd, 0)
os.close(fd)

server.serve_forever()
