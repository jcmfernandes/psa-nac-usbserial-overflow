#!/bin/sh
# Lab kernel: NXP 3.10.53 source, vexpress-a9, gadgetfs+dummy_hcd+ftdi builtin.
REPO=$(cd "$(dirname "$0")/.." && pwd)
S=$REPO/work/kernel-src
L=$REPO/lab/tmp/build.log
cd "$S" || exit 1
: >"$L"
export ARCH=arm CROSS_COMPILE=armv7l-unknown-linux-gnueabihf-
# 3.10 only knows gcc3/gcc4 headers; gcc 15 needs the gcc4 one aliased.
[ -f include/linux/compiler-gcc15.h ] || ln -s compiler-gcc4.h include/linux/compiler-gcc15.h
# gcc15 renumbers asm operands -> __asmeq ".err" fires spuriously (gcc PR15089
# check, ancient). Lab-only: neutralize the check.
sed -i 's|^#define __asmeq(x, y).*|#define __asmeq(x, y)  ""|' arch/arm/include/asm/compiler.h
# binutils >= 2.36 dropped '#alloc' section-flag syntax; use ELF letters.
grep -rl '#alloc' arch/arm --include='*.S' | xargs -r sed -i \
  's/#alloc, #execinstr/"a", "x"/g; s/#alloc, #write/"a", "w"/g; s/, *#alloc/, "a"/g; s/#alloc/"a"/g'
# NXP backport of tso.c misses the tcp header include.
grep -q 'net/tcp.h' net/core/tso.c || sed -i 's|#include <net/ip.h>|#include <net/ip.h>\n#include <net/tcp.h>|' net/core/tso.c
# NXP of.c/of.h backport bug: of.o builds on CONFIG_OF but the header only
# declares the prototype under CONFIG_OF&&USB_PHY (USB_PHY is def_bool n).
# vexpress needs no OF usb helpers -> gate of.o on USB_PHY like mainline.
sed -i 's|obj-\$(CONFIG_OF).*+= of.o|obj-$(CONFIG_USB_PHY) += of.o|' drivers/usb/phy/Makefile
# UMHDBG printks: find where do_execve EFAULTs with kernel-pointer argv.
python3 -I "$REPO/lab/patch-umh-debug.py" "$S" || echo PATCH-FAIL
make mrproper >>"$L" 2>&1
ln -sf compiler-gcc4.h include/linux/compiler-gcc15.h 2>/dev/null
make vexpress_defconfig >>"$L" 2>&1 || { echo DEFCONFIG-FAIL; exit 1; }
for l in CONFIG_USB_SUPPORT CONFIG_USB CONFIG_USB_GADGET CONFIG_USB_DUMMY_HCD \
         CONFIG_USB_GADGETFS CONFIG_USB_SERIAL CONFIG_USB_SERIAL_FTDI_SIO \
         CONFIG_DEBUG_INFO CONFIG_KALLSYMS CONFIG_BLK_DEV_INITRD \
         CONFIG_RD_GZIP CONFIG_DEVTMPFS CONFIG_USB_DEBUG CONFIG_USB_GADGET_DEBUG \
         CONFIG_USB_SERIAL_PL2303; do
  bash ./scripts/config --file .config --enable "$l" || echo "cfg fail $l"
done
yes '' | make oldnoconfig >>"$L" 2>&1
# gcc15: gnu23 default + -fno-common + C23-era errors. Downgrade to gnu11 lab build.
W="-Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-return-mismatch -Wno-enum-int-mismatch"
K="-fcommon -std=gnu11 -fgnu89-inline $W"
make -j"$(nproc)" HOSTCFLAGS="-O2 -std=gnu11 -fcommon $W" KCFLAGS="$K" zImage >>"$L" 2>&1
rc=$?
echo "build rc=$rc log=$L" | tee -a "$L"
grep -m8 'error:' "$L"
ls -la arch/arm/boot/zImage 2>/dev/null
