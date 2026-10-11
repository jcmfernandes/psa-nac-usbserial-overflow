{ pkgs, ... }:

{
  # Lab toolchain: cross gcc/binutils for build-kernel.sh (the
  # CROSS_COMPILE prefix armv7l-unknown-linux-gnueabihf- matches the
  # wrapper), kernel build deps, cpio/gzip for mkinitramfs.sh,
  # qemu + gdb for run-lab.sh / gdb-entry.sh, python3 for gen_blob.py,
  # patch-umh-debug.py, check_desc.py.
  packages = with pkgs; [
    pkgsCross.armv7l-hf-multiplatform.buildPackages.gcc
    pkgsCross.armv7l-hf-multiplatform.buildPackages.binutils
    bash
    bc
    bison
    cpio
    flex
    gdb
    gzip
    perl
    python3
    qemu
  ];
}
