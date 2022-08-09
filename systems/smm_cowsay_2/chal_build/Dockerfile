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

RUN apk update && apk add git

RUN mkdir /build
RUN git clone https://github.com/qemu/qemu.git /build/qemu -b v7.0.0 \
    --recursive --depth=1 --shallow-submodules
RUN git clone https://github.com/tianocore/edk2.git /build/edk2 -b edk2-stable202205 \
    --recursive --depth=1 --shallow-submodules

COPY patches /patches

RUN git config --global user.email "${USER}@${HOSTNAME}"
RUN git -C /build/qemu am /patches/qemu/*
RUN git -C /build/edk2 am /patches/edk2/* --keep-cr

RUN apk add tar zstd
# RUN tar -C /build --mtime="@0" --sort=name -cf - . | zstd -19 -T0 > /all_sources.tar.zst

RUN apk add build-base linux-headers python3 ninja pkgconfig \
        glib-dev glib-static pixman-dev pixman-static bash perl zlib-static

RUN mkdir /build/qemu/build
RUN cd /build/qemu/build && \
    ../configure --target-list=x86_64-softmmu --disable-tools \
      --disable-kvm --disable-debug-info --disable-slirp --disable-blobs --enable-lto --static && \
    make -j $(nproc)

RUN apk add curl nasm iasl
RUN dos2unix /build/edk2/BaseTools/Source/C/VfrCompile/VfrUtilityLib.cpp
RUN curl https://git.alpinelinux.org/aports/plain/community/edk2/build-hack.patch | patch -p1 -l -d /build/edk2
RUN cd /build/edk2 && \
    bash -c 'source edksetup.sh && \
        make -C BaseTools/Source/C -j $(nproc) && \
        build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5'

RUN mkdir -p /handout/edk2_artifacts
RUN cp /build/edk2/Build/OvmfX64/DEBUG_GCC5/X64/*.debug /handout/edk2_artifacts
RUN cp /build/edk2/Build/OvmfX64/DEBUG_GCC5/X64/*.efi /handout/edk2_artifacts

RUN mkdir -p /initchal/rootfs
RUN cp /build/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd /initchal/OVMF_CODE.fd
RUN cp /build/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd /initchal/OVMF_VARS.fd
RUN cp /build/edk2/Build/OvmfX64/DEBUG_GCC5/X64/MdeModulePkg/Application/Binexec/Binexec/OUTPUT/Binexec.efi /initchal/rootfs/binexec.efi
RUN echo 'binexec' > /initchal/rootfs/startup.nsh

RUN timeout 10 /build/qemu/build/qemu-system-x86_64 \
  -no-reboot \
  -machine q35,smm=on \
  -cpu max \
  -net none \
  -serial stdio \
  -display none \
  -vga none \
  -debugcon file:/handout/edk2debug.log \
  -global isa-debugcon.iobase=0x402 \
  -global ICH9-LPC.disable_s3=1 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -drive if=pflash,format=raw,unit=0,file=/initchal/OVMF_CODE.fd,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=/initchal/OVMF_VARS.fd \
  -drive format=raw,file=fat:rw:/initchal/rootfs

RUN mkdir -p /handout/run/rootfs
RUN cp /build/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd /handout/run/OVMF_CODE.fd
RUN cp /build/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd /handout/run/OVMF_VARS.fd
RUN cp /build/edk2/Build/OvmfX64/DEBUG_GCC5/X64/MdeModulePkg/Application/Binexec/Binexec/OUTPUT/Binexec.efi /handout/run/rootfs/binexec.efi
RUN echo 'binexec' > /handout/run/rootfs/startup.nsh
RUN cp /build/qemu/build/qemu-system-x86_64 /handout/run/qemu-system-x86_64
RUN strip -g /handout/run/qemu-system-x86_64
RUN cp /build/qemu/build/pc-bios/kvmvapic.bin /handout/run/kvmvapic.bin
RUN echo 'uiuctf{TestFlag}' > /handout/run/region4
COPY handout_run.sh /handout/run/run.sh

COPY . /handout/chal_build

COPY handout-readme /handout/README

RUN tar --mtime="@0" --sort=name -cf - handout | zstd -19 -T0 > /handout.tar.zst

FROM scratch as release
COPY --from=alpine-build /handout.tar.zst /
