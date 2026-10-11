{
  description = "NAC usb-serial stack overflow lab — tools to build and boot it";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" ];
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          cross = import nixpkgs {
            localSystem = system;
            crossSystem = nixpkgs.lib.systems.examples.armv7l-hf-multiplatform;
          };
        in
        {
          # Everything "Reproduce the lab" needs:
          #   build-kernel.sh  — cross gcc/binutils (CROSS_COMPILE prefix
          #     armv7l-unknown-linux-gnueabihf- matches the wrapper),
          #     kernel build deps (bc, flex, bison, perl, bash for
          #     scripts/config)
          #   mkinitramfs.sh   — cpio, gzip
          #   run-lab.sh / gdb-entry.sh — qemu-system-arm, gdb
          #   gen_blob.py / patch-umh-debug.py / check_desc.py — python3
          default = pkgs.mkShell {
            packages = with pkgs; [
              cross.buildPackages.gcc
              cross.buildPackages.binutils
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
          };
        });
    };
}
