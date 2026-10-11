#!/bin/sh
# Populate work/ from scratch: the NXP kernel source (GitHub mirror of
# NXP's tree, ~1.3 GB) and the car's eMMC tree — the latter from PSA's
# public firmware server, decrypted with ludwig-v's SMIME key, dumped
# with debugfs.
# All userspace - no sudo, no kernel modules. Run inside `devenv shell`
# (it provides curl, tar, openssl, e2fsprogs' debugfs).
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
W=$REPO/work
KSRC_URL=https://codeload.github.com/nxp-imx/linux-imx/tar.gz/refs/heads/imx_3.10.53_1.1.0_ga_caf
URL=https://majestic-web.mpsa.com/nas/eu/mjb00/PSA/mjbsu/PSA_ovip-int-firmware-version_44-07-33-32_NAC-r0_NAC_EUR_WAVE4.tar
SIZE=6312212480          # server Content-Length; full file = download done
# Per-version SMIME firmware key from ludwig-v's research, which
# extracted and published PSA's firmware keys:
# https://github.com/ludwig-v/psa-nac-firmware-reverse-engineering
KEY_URL=https://raw.githubusercontent.com/ludwig-v/psa-nac-firmware-reverse-engineering/master/Firmware_Keys/WAVE4/44.07.33-32-r0.key
KEY=$W/third/44.07.33-32-r0.key

for c in curl tar openssl debugfs find; do
  command -v "$c" >/dev/null || { echo "missing: $c (run inside devenv shell)"; exit 1; }
done

mkdir -p "$W"

# 0. NXP kernel source for build-kernel.sh (~1.3 GB; codeload streams,
#    no resume)
if [ ! -e "$W/kernel-src" ]; then
  curl -fL -o "$W/kernel-src.tar.gz" "$KSRC_URL"
  dir=$(tar tzf "$W/kernel-src.tar.gz" | head -n 1 | cut -d/ -f1)
  tar xf "$W/kernel-src.tar.gz" -C "$W"
  rm "$W/kernel-src.tar.gz"
  ln -s "$dir" "$W/kernel-src"
  echo "kernel source: $W/$dir"
fi

if [ -e "$W/emmc" ]; then
  echo "work/emmc already exists - remove it first to redo extraction"
  exit 0
fi
mkdir -p "$W/third" "$W/firmware"

# 1. firmware tar (6.3 GB, resumable)
cur=0
if [ -f "$W/firmware.tar" ]; then cur=$(wc -c < "$W/firmware.tar"); fi
if [ "$cur" -ne "$SIZE" ]; then curl -C - -o "$W/firmware.tar" "$URL"; fi

# 2. per-version key (see attribution at the top)
if [ ! -f "$KEY" ]; then curl -fsSL -o "$KEY" "$KEY_URL"; fi

# 3. extract only the eMMC image parts (each part is its own SMIME blob)
tar xf "$W/firmware.tar" -C "$W/firmware" \
    --wildcards 'SWL/*/Firmware/AUTO/*/NAC_EU/EMMC/rootfs-emmc.fsn*'
EMMC=$(find "$W/firmware" -type d -name EMMC | head -n 1)
if [ -z "$EMMC" ]; then echo "no EMMC dir in the tar"; exit 1; fi

# 4. decrypt the parts in order, concatenate -> ext4 image (~768 MB)
: > "$W/emmc-ext4.img"
for f in "$EMMC"/rootfs-emmc.fsn "$EMMC"/rootfs-emmc.fsn0*; do
  openssl smime -decrypt -in "$f" -inkey "$KEY" >> "$W/emmc-ext4.img"
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
