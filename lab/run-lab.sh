#!/bin/sh
# Boot the lab kernel + attack initramfs in QEMU vexpress-a9.
REPO=$(cd "$(dirname "$0")/.." && pwd)
S=$REPO/work/kernel-src
K=${1:-$S/arch/arm/boot/zImage}
exec qemu-system-arm -M vexpress-a9 -m 512 -nographic -no-reboot \
  -kernel "$K" \
  -initrd "$REPO/lab/tmp/initrd.gz" \
  -append "console=ttyAMA0"
