{ pkgs, ... }:

{
  # Lab toolchain: cross gcc/binutils for build-kernel.sh (the
  # CROSS_COMPILE prefix armv7l-unknown-linux-gnueabihf- matches the
  # wrapper), kernel build deps, cpio/gzip for mkinitramfs.sh,
  # qemu + gdb for run-lab.sh / gdb-entry.sh, python3 for gen_blob.py,
  # patch-umh-debug.py, check_desc.py; openssl + e2fsprogs' debugfs +
  # curl/git for setup-work.sh (firmware download + decryption + rdump).
  packages = with pkgs; [
    pkgsCross.armv7l-hf-multiplatform.buildPackages.gcc
    pkgsCross.armv7l-hf-multiplatform.buildPackages.binutils
    bash
    bc
    bison
    cpio
    curl
    e2fsprogs
    flex
    gdb
    git
    gzip
    openssl
    perl
    python3
    qemu
  ];
}
