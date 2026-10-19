# NAC usb-serial stack overflow — research repo

Security research on my own PSA NAC head unit
(NAC_EUR_WAVE4, Continental OVIP i.MX6 ARM32, firmware
44.07.33.33_NAC-r0, kernel 3.10.53 NXP imx_3.10.53_1.1.0_ga).
Goal: passwordless root on the diagnostic UART console of my own unit.

## The bug

NXP's vendor tree lacks upstream fix d979e9f9ecab ("USB: serial: fix
potential stack buffer overflow", in stable 3.10.y). `usb_serial_probe()`
stores one kernel pointer per bulk-IN endpoint into unbounded stack
arrays (`bulk_in_endpoint[MAX_NUM_PORTS=8]`, arrays at sp+104, saved
{r4..r11,lr} frame at sp+172..204 — verified on the car's own
`usbserial.ko`). A fake PL2303 (067b:2303) interface declaring many
bulk-IN endpoints overflows the frame:

- bulk_in[17] lands on saved r4
- bulk_in[26] lands on saved LR (car; 25 in the QEMU lab build)

Probe returns through the hijacked LR = the 26th endpoint's
`usb_host_endpoint` (44-byte stride). Its descriptor word@0 is a
harmless `add` (bLength=9 header bytes), word@4 is
`ldr pc,[r4,#off]` with off = (26−17)\*44+32 = 0x1AC — pointing into
the same chunk's `extra` field, i.e. the trailing 252-byte blob in the
config descriptor. The blob builds argv/envp PC-relative and calls
`call_usermodehelper("/bin/sh", ["sh","-c",CMD], {NULL}, UMH_WAIT_PROC)`
at 0x8003e7c0 (car vmlinux).

Payload CMD: remount / rw, sed the root line in /etc/passwd
(`root::0:0:root:/home/root:/bin/sh`), sync, reboot -f.

The PL2303 choice matters: pl2303's `.attach` rewrites the private
pointer, and the "HORRIBLE HACK" path (`num_bulk_out==0`) returns
-ENODEV right after the endpoint loop — clean return through the
hijacked LR, no further stack use.

## What boots as /

fstab is empty — the root mount comes from the bootloader's kernel
cmdline attachment: `root=ubi0_50/51` ubifs-on-NAND (HW2016/HW2019
bootloaders) or `root=/dev/mmcblk1p5/p6 rootfstype=ext4` (HW2020+).
The SWL ships both rootfs images for the whole hardware fleet; the
two are byte-identical where it matters (zImage, passwd family,
DiagSvcTsw — cmp-verified), and `/etc` is not overlaid (only /var,
/opt get bind-mounted from a separate ubi volume). So the payload's
`mount -o remount,rw /` works either way — the vendor's own
early-init does the same remount dance on the live root. Which medium
a given unit boots shows in its `cat /proc/cmdline` (`root=ubi0_51`
vs `root=/dev/mmcblk1p6`).

## Layout

- `devenv.nix` / `devenv.yaml` — devenv shell (`devenv shell`) with the
  lab toolchain: armv7l cross gcc/binutils, kernel build deps, cpio,
  qemu, gdb, python3
- `exploit/` — deployment on a Raspberry Pi against the car (Pi 5
  primary — its USB-C power port is the gadget port; Zero 2 W works
  too)
  - `nac_pwn.py` — raw-gadget attacker, takes a payload name
  - `payloads/` — car payload blobs (`sed`: root UART; `cfg`: AA
    autoconnect flag; `both`), built by `lab/gen_blob.py` presets
    `car-sed` / `car-cfg` / `car-both`
  - `setup-pi.sh` — dwc2 overlay check, out-of-tree raw_gadget module
    build+load (Pi OS ships none)
  - `raw_gadget_src/` — kernel module source v6.6 + Makefile
    (`raw_gadget-7.2.c` kept for the v6.7+ DELAYED_STATUS difference)
  - `INSTRUCTIONS.md` — step-by-step deployment + troubleshooting
- `lab/` — QEMU vexpress-a9 lab reproducing the car kernel
  - `build-kernel.sh` — NXP 3.10.53 + gcc16 cross (15 also builds —
    the script aliases the compiler-gccN.h headers), gadgetfs/
    dummy_hcd/ftdi_sio/pl2303/usbserial builtin (six gcc15 build fixes)
  - `mkinitramfs.sh` — initramfs from the car's own busybox+eglibc,
    packs the blob; `gen_blob.py` builds the gadgetfs blob file
  - `run-lab.sh` — boots the lab with the blob attack
  - `patch-umh-debug.py` — UMHDBG/EPDBG printk instrumentation
  - `gdb.cmd` / `gdb-entry.sh` — gdbstub ground-truth scripts
  - `check_desc.py` — sysfs byte-compare of served descriptors
  - `car.config` — the car's own kernel config, extracted from the
    `IKCFG_ST` blob of its vmlinux (target evidence, not a lab input —
    the lab builds its own vexpress-a9 config)
  - evidence captures (full-chain boot logs, the verified passwd
    patch, the raw-gadget host test) live outside the repo

Inputs live under `work/` (gitignored — provide them yourself):
- `work/kernel-src/` — NXP imx_3.10.53_1.1.0_ga kernel source tree
  (linux-imx-imx_3.10.53_1.1.0_ga_caf; ~1.3 GB, fetched by
  `lab/setup-work.sh` from NXP's GitHub mirror)
- `work/emmc/out/` — extracted car eMMC image (busybox, eglibc, /etc —
  what the lab initramfs and payload pre-checks are built on);
  `lab/setup-work.sh` builds it from PSA's public firmware server +
  the SMIME key published by ludwig-v's
  [psa-nac-firmware-reverse-engineering](https://github.com/ludwig-v/psa-nac-firmware-reverse-engineering)
  (download, per-part decrypt, debugfs rdump — all userspace, no sudo,
  runs inside the devenv shell)

Transient lab outputs (initramfs, blob, logs) land in `lab/tmp/`
(gitignored). Untrusted-data rule: run Python over the
extraction with `-I`, scripts outside it.

## Reproduce the lab

0. `devenv shell` — pulls every tool via devenv.nix (cross gcc,
   kernel build deps, cpio, qemu, gdb, python3).
1. `sh setup-work.sh` — fetches the NXP source into `work/kernel-src/`
   (skips what's already there; also builds `work/emmc/` if missing).
2. `build-kernel.sh` (~8 min; gcc 15 and 16 both build — the script
   aliases their compiler-gccN.h headers).
3. `python3 -I gen_blob.py lab-sed` then `sh mkinitramfs.sh`
   (re-run after every blob change — the initrd packs a copy; after a
   kernel rebuild, re-pin the lab preset helper addrs in gen_blob.py
   from the new System.map first).
4. `timeout 90 sh run-lab.sh > tmp/boot.log` — expect
   `UMHDBG: umh entry path=/bin/sh` and the patched /etc/passwd
   dumped to console.

## Changing the payload

The payload is the CMD string in `lab/gen_blob.py`'s presets
(ordered as `(n_eps, hijack, helper, CMD, wait)`).

- lab: edit the `lab-sed` preset, `python3 -I gen_blob.py lab-sed`,
  then `sh mkinitramfs.sh` — the initrd packs its own blob copy —
  and `timeout 90 sh run-lab.sh > tmp/boot.log`.
- car: edit the matching `car-*` preset, regenerate the payload
  (`python3 -I gen_blob.py car-sed ../exploit/payloads/sed`), copy
  to the Pi, re-run the deploy.
- CMD constraints (~145 bytes hard cap — blob is 252, shared with
  shellcode, argv, helper addr; the build asserts on overflow).
  The car CMD is 109 bytes — ~36 bytes of headroom.
  No NUL, no 04/05 control bytes — normal shell text qualifies.
  `pad_cmd()` pads trailing spaces for the alignment (a sh -c
  no-op).
- No address re-pin needed: CMD is data. Only kernel rebuilds move
  the helper addresses.

## Deploy

See `exploit/INSTRUCTIONS.md`. Summary: `dtoverlay=dwc2,dr_mode=peripheral`
on the Pi, GPIO-header 5V power (the Pi 5's USB-C is the gadget port),
`setup-pi.sh` builds+loads raw_gadget (module source matched to the
kernel: pre-6.6 vs 6.7+ DELAYED_STATUS), plug into the car, run
`sudo python3 nac_pwn.py sed` (or `cfg` / `both`); head unit reboots
(the `sed`/`both` payloads); UART root console is passwordless.

## Gotchas learned the hard way

- ARM `add imm` encodings: Rn is bits 19-16, Rd is 15-12 — a swap
  clobbers the wrong register silently (bit twice; decode generated
  words with an assembler, don't trust comments).
- Blob byte 0 IS the `ldr pc` target: an odd address flips the CPU to
  Thumb state → garbage → oops. `gen_blob.py pad_cmd()` pads the
  command string with spaces until the blob offset is 4-aligned
  (real silicon wants word-aligned ARM code; QEMU tolerates more).
- raw-gadget: EP0_WRITE answers IN setups, EP0_READ answers OUT ones;
  v6.7+ returns USB_GADGET_DELAYED_STATUS for 0-length control OUT —
  the status stage then waits for an EP0_READ(0) ack, older kernels
  auto-complete and an ack can wedge ep0. `nac_pwn.py` gates on uname.
- gadgetfs ep0 fd must stay open (closing = dev_release = unbind);
  every /dev/raw-gadget open is one gadget instance — overlapping
  runs wedge the UDC.
- kernel rebuilds move symbol addresses (call_usermodehelper, printk,
  usb_serial_probe) — re-read System.map after every rebuild and
  re-pin the lab preset addrs in gen_blob.py; the car preset pins the
  car vmlinux address.
- The car's /etc/passwd is a symlink (flattened on extraction) to
  `passwd-user-access-rights-inactive-closed`; the sed pattern targets
  its active root line.
## License

GPL-3.0-or-later — see LICENSE. Exception: `exploit/raw_gadget_src/`
is vendored Linux kernel source and stays GPL-2.0
(see `exploit/raw_gadget_src/COPYING`).
