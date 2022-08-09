#! /bin/sh

/home/user/ftpd.py

qemu-system-x86_64 \
  -no-reboot \
  -cpu max \
  -net none \
  -serial stdio \
  -display none \
  -monitor none \
  -vga none \
  -nic user,model=virtio-net-pci \
  -drive file=/home/user/disk.img,format=raw,if=virtio,snapshot=on \
  -snapshot \
  -kernel /home/user/bzImage
