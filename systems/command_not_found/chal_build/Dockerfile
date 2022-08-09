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

# DOCKER_BUILDKIT=1 docker build . --target release --output type=local,dest=../challenge

FROM gentoo/stage3:amd64-musl as gentoo-build

RUN emerge-webrsync

# We don't have CAP_PTRACE for this to function properly
RUN rm /usr/bin/sandbox

RUN USE='bindist static static-libs' emerge -v sys-fs/btrfs-progs

# Required for installing to /disk
RUN USE='bindist static-libs' emerge -v sys-libs/ncurses virtual/libcrypt

RUN mkdir /disk /disk/proc
RUN mkdir -p /disk/bin /disk/sbin
RUN mkdir -p /disk/usr/bin /disk/usr/sbin
RUN mkdir -p /disk/usr/local/bin /disk/usr/local/sbin

ENV USE='-* bindist ftp ncurses net readline static static-libs unicode'
RUN emerge --root disk -v sys-apps/baselayout sys-libs/musl
RUN emerge --root disk -v sys-apps/busybox
RUN emerge --root disk -v app-shells/bash sys-apps/coreutils sys-apps/util-linux
RUN emerge --root disk -v sys-process/procps
RUN emerge --root disk -v sys-apps/iproute2 net-misc/curl
RUN emerge --root disk -v sys-fs/btrfs-progs

RUN bash -c 'for FILE in disk/sbin/*.static; do mv "$FILE" "${FILE/%.static/}"; done'

RUN find disk/usr/share/terminfo/ -mindepth 2 -maxdepth 2 ! -name 'linux' -delete || true
RUN find disk/usr/share/terminfo/ -empty -type d -delete || true

RUN rm -r disk/usr/share/doc/ || true
RUN rm -r disk/usr/share/man/ || true
RUN rm -r disk/usr/share/info/ || true
RUN rm -r disk/usr/include/ || true

RUN find disk/usr/lib{,64}/ -name '*.a' -delete || true
RUN find disk/usr/lib{,64}/ -name '*.o' -delete || true
RUN find disk/usr/lib{,64}/ -name '*.la' -delete || true
RUN find disk/usr/lib{,64}/ -name '*.pc' -delete || true

RUN rm -r disk/var/db/pkg/ || true
RUN rm -r disk/var/cache/edb/ || true
RUN rm -r disk/etc/portage/ || true

RUN rm -r disk/lib/gentoo/ || true
RUN rm -r disk/var/lib/gentoo/ || true
RUN rm -r disk/var/lib/portage/ || true

RUN rm -r disk/usr/share/gdb/ || true
RUN rm -r disk/usr/share/bash-completion/ || true
RUN rm -r disk/usr/share/baselayout/ || true

COPY init /disk/sbin/init
RUN chmod 755 /disk/sbin/init

RUN cp -a /disk /disk_handout

COPY get_flag.c get_flag_handout.c /tmp/
RUN gcc -static -Os /tmp/get_flag.c -o /tmp/get_flag
RUN gcc -static -Os /tmp/get_flag_handout.c -o /tmp/get_flag_handout

COPY get_flag.c /disk/usr/local/bin/get_flag.c
RUN cp /tmp/get_flag /disk/usr/local/bin/get_flag

COPY get_flag_handout.c /disk_handout/usr/local/bin/get_flag_handout.c
RUN cp /tmp/get_flag_handout /disk_handout/usr/local/bin/get_flag_handout

RUN touch /disk.img /disk_handout.img
RUN mkfs.btrfs -r /disk /disk.img
RUN mkfs.btrfs -r /disk_handout /disk_handout.img

FROM ubuntu:22.04 as ubuntu-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y wget build-essential && \
    apt-get install -y gawk flex bison bc zstd && \
    apt-get install -y libncurses-dev libssl-dev libssl-dev libelf-dev libudev-dev libpci-dev libiberty-dev

RUN apt-get install -y gcc-$(gcc --version | grep -oP '([0-9]+)\.([0-9]+).([0-9]+)' | uniq | cut -d. -f1)-plugin-dev

RUN mkdir /kernel
RUN wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.18.14.tar.xz -O /kernel/linux.tar.xz
RUN tar -C /kernel -xf /kernel/linux.tar.xz

COPY kconfig /kernel/linux-5.18.14/.config
COPY 0001-ptp_kvm-Silence-initialization-warning.patch /tmp/
RUN patch -p1 -d /kernel/linux-5.18.14 < /tmp/0001-ptp_kvm-Silence-initialization-warning.patch

RUN make -j$(nproc) -C /kernel/linux-5.18.14

FROM alpine as alpine-build

RUN apk add tar zstd

RUN mkdir /handout
COPY handout-readme /handout/README
COPY run_handout.sh /handout/run.sh
COPY --from=ubuntu-build /kernel/linux-5.18.14/arch/x86/boot/bzImage /handout/
COPY --from=gentoo-build /disk_handout.img /handout/disk.img

RUN mkdir /handout/ftproot
COPY --from=gentoo-build /disk/bin/busybox /handout/ftproot
COPY --from=gentoo-build /sbin/btrfs.static /handout/ftproot/btrfs
COPY --from=gentoo-build /sbin/btrfs-find-root.static /handout/ftproot/btrfs-find-root

RUN mkdir /chal
COPY run.sh /chal/run.sh
COPY --from=ubuntu-build /kernel/linux-5.18.14/arch/x86/boot/bzImage /chal/
COPY --from=gentoo-build /disk.img /chal/disk.img

RUN mkdir /chal/ftproot
COPY --from=gentoo-build /disk/bin/busybox /chal/ftproot
COPY --from=gentoo-build /sbin/btrfs.static /chal/ftproot/btrfs
COPY --from=gentoo-build /sbin/btrfs-find-root.static /chal/ftproot/btrfs-find-root

RUN tar --mtime="@0" --sort=name -cf - handout | zstd -19 -T0 > /handout.tar.zst
RUN tar --mtime="@0" --sort=name -cf - chal | zstd -19 -T0 > /chal.tar.zst

FROM scratch as release
COPY --from=alpine-build /handout.tar.zst /chal.tar.zst /
