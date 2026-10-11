#!/usr/bin/env python3
# Host smoke-test helper: find the fake 067b:2303 device, read its descriptors
# via usbfs, byte-compare with the blob the attack script is serving.
import sys, os, glob, struct, fcntl, ctypes

blob_path = sys.argv[1]
blob = open(blob_path, 'rb').read()
dev, cfg = blob[-18:], blob[4:-18]
VID, PID = struct.unpack('<HH', dev[8:12])

class Ctrl(ctypes.Structure):
    _fields_ = [('bmRequestType', ctypes.c_ubyte), ('bRequest', ctypes.c_ubyte),
                ('wValue', ctypes.c_ushort), ('wIndex', ctypes.c_ushort),
                ('wLength', ctypes.c_ushort), ('timeout', ctypes.c_uint),
                ('data', ctypes.c_void_p)]

USBDEVFS_CONTROL = (3 << 30) | (24 << 16) | (0x55 << 8) | 0

def ctrl(fd, rt, rq, wv, wi, wl):
    buf = ctypes.create_string_buffer(wl)
    cr = Ctrl(rt, rq, wv, wi, wl, 1000, ctypes.cast(buf, ctypes.c_void_p))
    ret = fcntl.ioctl(fd, USBDEVFS_CONTROL, cr)
    assert ret >= 0, f'ioctl failed: {ret}'
    return buf.raw[:ret]

path = None
for p in sorted(x for x in glob.glob('/sys/bus/usb/devices/*')
                if ':' not in x):
    try:
        v = open(p + '/idVendor').read().strip()
        i = open(p + '/idProduct').read().strip()
    except OSError:
        continue
    if (v, i) == (f'{VID:04x}', f'{PID:04x}'):
        path = p
        break
if path is None:
    sys.exit('fake device not found in /sys/bus/usb/devices')

raw = open(path + '/descriptors', 'rb').read()   # device + config descriptors
d  = raw[:18]                                    # device descriptor first
cf = raw[18:18 + len(cfg)]                      # then config descriptor

print(f'sysfs path:  {path}')
print(f'device desc: {"OK" if d == dev else "MISMATCH"} ({len(d)} bytes)')
print(f'config full: {"OK" if cf == cfg else "MISMATCH"} ({len(cf)} bytes)')
print(f'read {len(raw)} bytes total, expected {18 + len(cfg)}')
eps = [i for i in range(len(cf)) if cf[i:i+2] == b'\x07\x05']
print(f'7-byte endpoint descriptors found: {len(eps)}')
hijack = [i for i in range(len(cf)) if cf[i:i+2] == b'\x09\x05']
print(f'9-byte hijack descriptor found: {"YES" if hijack else "NO"}')
