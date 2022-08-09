#! /bin/sh

qemu-system-x86_64 \
  -no-reboot \
  -cpu max \
  -net none \
  -serial stdio \
  -display none \
  -monitor none \
  -vga none \
  -virtfs local,multidevs=remap,path=/secret,security_model=none,mount_tag=flag,readonly=on \
  -initrd /home/user/initrd \
  -kernel /home/user/bzImage
