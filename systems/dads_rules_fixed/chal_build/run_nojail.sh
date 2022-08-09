#! /bin/sh

qemu-system-x86_64 \
  -no-reboot \
  -cpu max \
  -net none \
  -serial stdio \
  -display none \
  -monitor none \
  -vga none \
  -initrd initrd_nojail \
  -kernel bzImage
