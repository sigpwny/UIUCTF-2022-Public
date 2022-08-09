# Copyright 2021-2022 Google LLC
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


FROM gentoo/stage3:amd64-musl as gentoo-build

RUN emerge-webrsync

# We don't have CAP_PTRACE for this to function properly
RUN rm /usr/bin/sandbox

RUN mkdir -p /etc/portage/patches/app-emulation/qemu
COPY 0001-Implement-UIUCTFPORTIO-device.patch /etc/portage/patches/app-emulation/qemu

RUN USE='-* binary caps fdt qemu seavgabios seccomp slirp static static-libs static-user virtfs xattr qemu_softmmu_targets_x86_64 '"$(python --version | sed -r 's/Python ([0-9]+)\.([0-9]+)(\.([0-9]+))/python_targets_python\1_\2/')" emerge -v app-emulation/qemu

FROM ubuntu:20.04 as tar-extract

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y zstd

RUN mkdir /home/user/
COPY chal.tar.zst /home/user/
RUN tar -C /home/user/ -xf /home/user/chal.tar.zst

FROM alpine as chroot

RUN apk add expect python3

RUN python3 -m ensurepip
RUN pip3 install -U pip setuptools wheel

RUN pip3 install pyftpdlib

RUN mkdir /home/user/

COPY bootscript.exp ftpd.py /home/user/
COPY --from=tar-extract /home/user/chal/run.sh /home/user/
COPY --from=tar-extract /home/user/chal/bzImage /home/user/
COPY --from=tar-extract /home/user/chal/disk.img /home/user/
COPY --from=tar-extract /home/user/chal/ftproot /home/user/ftproot

COPY --from=gentoo-build /usr/bin/qemu-system-x86_64 /usr/bin/
COPY --from=gentoo-build /usr/share/qemu /usr/share/qemu
COPY --from=gentoo-build /usr/share/seavgabios /usr/share/seavgabios
COPY --from=gentoo-build /usr/share/seabios /usr/share/seabios

RUN rm /usr/share/qemu/edk2-*

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

COPY --from=chroot / /chroot
RUN mkdir -p /chroot/proc /chroot/var/tmp /chroot/dev/pts

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/bootscript.exp'
