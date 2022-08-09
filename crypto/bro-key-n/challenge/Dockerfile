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

FROM alpine as alpine-build

RUN apk add openssh

COPY key.pem key.pem
RUN echo -n 'no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="cat /msg" ' > key.pub
RUN ssh-keygen -f key.pem -y >> key.pub

FROM alpine as chroot

RUN adduser user -D
RUN apk add dropbear socat

RUN mkdir /etc/dropbear/
RUN dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
RUN chown 1000:1000 /etc/dropbear/dropbear_rsa_host_key

RUN mkdir /home/user/.ssh
COPY --from=alpine-build key.pub /home/user/.ssh/authorized_keys
RUN chown -R 1000:1000 /home/user/.ssh
RUN chmod 755 /home/user/.ssh
RUN chmod 644 /home/user/.ssh/authorized_keys

COPY msg /msg

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

COPY --from=chroot / /chroot

RUN mknod -m 666 /chroot/dev/null c 1 3 && \
    mknod -m 666 /chroot/dev/zero c 1 5 && \
    mknod -m 666 /chroot/dev/tty c 5 0 && \
    mknod -m 622 /chroot/dev/console c 5 1 && \
    mknod -m 666 /chroot/dev/ptmx c 5 2 && \
    mknod -m 444 /chroot/dev/random c 1 8 && \
    mknod -m 444 /chroot/dev/urandom c 1 9 && \
    ln -s /proc/self/fd /chroot/dev/fd && \
    ln -s /proc/self/fd/0 /chroot/dev/stdin && \
    ln -s /proc/self/fd/1 /chroot/dev/stdout && \
    ln -s /proc/self/fd/2 /chroot/dev/stderr && \
    mkdir /chroot/dev/pts

COPY nsjail.cfg spawn.sh /home/user/

CMD kctf_setup && \
    mount -o remount,rw,bind /sys/fs/cgroup/pids && \
    mkdir /sys/fs/cgroup/pids/NSJAIL && \
    chown -R 1000:1000 /sys/fs/cgroup/pids/NSJAIL && \
    kctf_drop_privs \
    socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/user/spawn.sh
