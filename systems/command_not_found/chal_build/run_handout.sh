#! /bin/sh

qemu-system-x86_64 \
  -no-reboot \
  -cpu max \
  -net none \
  -serial stdio \
  -display none \
  -monitor none \
  -vga none \
  -nic user,model=virtio-net-pci \
  -drive file=disk.img,format=raw,if=virtio,snapshot=on \
  -snapshot \
  -kernel bzImage
