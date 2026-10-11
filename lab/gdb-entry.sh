#!/bin/sh
# Ground truth: freeze QEMU at start, set HW bp at call_usermodehelper
# (0x803cd2f8) BEFORE the kernel runs, print r0-r3 at every hit.
# Lab21's zero hits = attached too late (attack ran before the 12s sleep).
REPO=$(cd "$(dirname "$0")/.." && pwd)
S=$REPO/work/kernel-src
QLOG=$REPO/lab/tmp/boot-gdb.log
GLOG=$REPO/lab/tmp/gdb-gdb.log

timeout 120 qemu-system-arm -M vexpress-a9 -m 512 -nographic -no-reboot \
  -kernel "$S/arch/arm/boot/zImage" \
  -initrd "$REPO/lab/tmp/initrd.gz" \
  -append "console=ttyAMA0" -s -S >"$QLOG" 2>&1 &
QPID=$!

nix shell nixpkgs#gdb --command gdb -q -batch -x "$REPO/lab/gdb.cmd" >"$GLOG" 2>&1 &
GPID=$!
wait $GPID
kill $QPID 2>/dev/null
echo done
