#!/usr/bin/env python3
"""x15_utfdump.py -- raw dump of the two @UTF blocks so the sub-header fields can
be read by eye instead of guessed."""
import struct
PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()
for base, end in ((0x820, 0x9E0), (0xA60, 0xE20)):
    print('=== @UTF @0x%X .. 0x%X ===' % (base, end))
    for a in range(base, end, 16):
        row = D[a:a+16]
        print('  +0x%03X 0x%08X  %s  %s' % (a-base, a, row.hex(' '),
              ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)))
    print()
# explicit field values as u32 BE at each 4-byte slot of the header region
for base in (0x820, 0xA60):
    print('u32 BE values in the 0x20..0x40 header window of @0x%X:' % base)
    for off in range(0x20, 0x44, 4):
        print('  +0x%02X = 0x%08X  (%d)' % (off, struct.unpack_from('>I', D, base+off)[0],
                                            struct.unpack_from('>I', D, base+off)[0]))
    print()
