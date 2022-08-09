#! /bin/sh

cp OVMF_VARS.fd OVMF_VARS_copy.fd

./qemu-system-x86_64 \
  -d cpu_reset \
  -no-reboot \
  -machine q35,smm=on \
  -cpu max \
  -net none \
  -serial stdio \
  -display none \
  -vga none \
  -global ICH9-LPC.disable_s3=1 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=OVMF_VARS_copy.fd \
  -drive format=raw,file=fat:rw:rootfs
