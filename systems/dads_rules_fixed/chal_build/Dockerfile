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

FROM alpine as alpine-build

RUN apk add git build-base linux-headers bash pkgconfig flex bison ncurses coreutils
RUN apk add libpcap-dev ncurses-dev libsodium-dev libnetfilter_conntrack-dev libnl3-dev userspace-rcu-dev libnet-dev zlib-dev

RUN git clone https://github.com/netsniff-ng/netsniff-ng /tmp/netsniff-ng -b v0.6.8 \
    --recursive --depth=1 --shallow-submodules

RUN cd /tmp/netsniff-ng && \
    ./configure && \
    make -j $(nproc) && \
    mkdir -p /dest/usr/local/sbin && \
    make install DESTDIR=/dest && \
    rm -rf /dest/usr/local/share/man

COPY jail.c /tmp/
RUN gcc /tmp/jail.c -Os -o /tmp/jail

FROM alpine as initrd

RUN apk add bash coreutils util-linux iproute2 netcat-openbsd nftables tcpdump procps strace
RUN apk add libpcap ncurses-libs libsodium libnetfilter_conntrack libnl3 userspace-rcu libnet zlib

RUN rm -rf /usr/share/apk

RUN mkdir /home/user/

COPY setup.sh /home/user/
COPY jail.c /home/user/
COPY --from=alpine-build /tmp/jail /home/user/
COPY --from=alpine-build /dest/usr/local /usr/local

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

FROM alpine as handout-build

RUN apk add tar zstd

COPY --from=initrd / /initrd

RUN mkdir -p /handout/run
COPY --from=ubuntu-build /kernel/linux-5.18.14/arch/x86/boot/bzImage /handout/run/

COPY run_nojail.sh /handout/run/run_nojail.sh
COPY init_nojail /initrd/init
RUN cd /initrd && find . -print0 | cpio -0ov -H newc | zstd -19 -T0 > /handout/run/initrd_nojail

COPY run_jail.sh /handout/run/run_jail.sh
COPY init_jail /initrd/init
RUN cd /initrd && find . -print0 | cpio -0ov -H newc | zstd -19 -T0 > /handout/run/initrd_jail

COPY . /handout/chal_build
COPY handout-readme /handout/README

RUN tar --mtime="@0" --sort=name -cf - handout | zstd -19 -T0 > /handout.tar.zst

FROM scratch as release
COPY --from=handout-build /handout.tar.zst /
