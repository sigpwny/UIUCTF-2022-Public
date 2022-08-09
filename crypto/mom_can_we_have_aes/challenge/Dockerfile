# Copyright 2022 Google LLC
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

FROM alpine as chroot

RUN apk add python3 python3-dev libc-dev gcc
RUN python3 -m ensurepip
RUN pip3 install -U pip pycryptodome

COPY secret.py fields.py /home/user/

FROM chroot as chroot-server
COPY server.py my_credit_card_number.pem /home/user/

FROM chroot as chroot-client
COPY client.py receiver.pem /home/user/

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

COPY --from=chroot-server / /server
COPY --from=chroot-client / /client

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    bash -c '\
      socat \
        TCP-LISTEN:1337,reuseaddr,fork \
        EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg --bindmount_ro /server\:/ -- /usr/bin/python3 /home/user/server.py" & \
      socat \
        TCP-LISTEN:1338,reuseaddr,fork \
        EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg --bindmount_ro /client\:/ -- /usr/bin/python3 /home/user/client.py" '
