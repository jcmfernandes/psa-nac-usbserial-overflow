#!/bin/sh
# Boot the lab kernel + attack initramfs in QEMU vexpress-a9.
# NET_ARGS: QEMU user networking with host port forward 2023 -> guest
# 23, for the lab-telnet preset (e.g.
#   NET_ARGS="-netdev user,id=n0,hostfwd=tcp::2023-:23 -device lan9118,netdev=n0"
# ). Empty default: no NIC, like every previous run.
REPO=$(cd "$(dirname "$0")/.." && pwd)
S=$REPO/work/kernel-src
K=${1:-$S/arch/arm/boot/zImage}
exec qemu-system-arm -M vexpress-a9 -m 512 -nographic -no-reboot \
  ${NET_ARGS:-} \
  -kernel "$K" \
  -initrd "$REPO/lab/tmp/initrd.gz" \
  -append "console=ttyAMA0"
