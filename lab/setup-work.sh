#!/bin/sh
# Populate work/emmc from scratch: download the wave4 firmware from
# PSA's public server, decrypt the split eMMC image with ludwig-v's
# SMIME key, dump the ext4 tree with debugfs.
# All userspace - no sudo, no kernel modules. Run inside `devenv shell`
# (it provides curl, git, openssl, e2fsprogs' debugfs).
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
W=$REPO/work
URL=https://majestic-web.mpsa.com/nas/eu/mjb00/PSA/mjbsu/PSA_ovip-int-firmware-version_44-07-33-32_NAC-r0_NAC_EUR_WAVE4.tar
SIZE=6312212480          # server Content-Length; full file = download done
KEYREPO=https://github.com/ludwig-v/psa-nac-firmware-reverse-engineering
KEY=Firmware_Keys/WAVE4/44.07.33-32-r0.key
T=$W/third/psa-nac-firmware-reverse-engineering

for c in curl git tar openssl debugfs find; do
  command -v "$c" >/dev/null || { echo "missing: $c (run inside devenv shell)"; exit 1; }
done

if [ -e "$W/emmc" ]; then
  echo "work/emmc already exists - remove it first to redo extraction"
  exit 0
fi
mkdir -p "$W/third" "$W/firmware"

# 1. firmware tar (6.3 GB, resumable)
cur=0
if [ -f "$W/firmware.tar" ]; then cur=$(wc -c < "$W/firmware.tar"); fi
if [ "$cur" -ne "$SIZE" ]; then curl -C - -o "$W/firmware.tar" "$URL"; fi

# 2. ludwig-v's per-version key
if [ ! -d "$T" ]; then git clone --depth 1 "$KEYREPO" "$T"; fi

# 3. extract only the eMMC image parts (each part is its own SMIME blob)
tar xf "$W/firmware.tar" -C "$W/firmware" \
    --wildcards 'SWL/*/Firmware/AUTO/*/NAC_EU/EMMC/rootfs-emmc.fsn*'
EMMC=$(find "$W/firmware" -type d -name EMMC | head -n 1)
if [ -z "$EMMC" ]; then echo "no EMMC dir in the tar"; exit 1; fi

# 4. decrypt the parts in order, concatenate -> ext4 image (~768 MB)
: > "$W/emmc-ext4.img"
for f in "$EMMC"/rootfs-emmc.fsn "$EMMC"/rootfs-emmc.fsn0*; do
  openssl smime -decrypt -in "$f" -inkey "$T/$KEY" >> "$W/emmc-ext4.img"
done
echo "ext4 image: $(wc -c < "$W/emmc-ext4.img") bytes"

# 5. dump the whole tree (debugfs flattens symlinks and drops some exec
#    bits - same quirks as the existing extraction; fix per file if
#    something must run)
mkdir -p "$W/emmc"
debugfs -R "rdump / $W/emmc" "$W/emmc-ext4.img" 2>&1 \
  | grep -v 'changing ownership' || true
[ -f "$W/emmc/bin/busybox" ] || { echo "rdump failed"; exit 1; }
echo "done: $(find "$W/emmc" -type f | wc -l) files in work/emmc"
