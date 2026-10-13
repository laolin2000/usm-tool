#!/usr/bin/env python3
"""x6_dump_region.py -- full hexdump of 0x7F0..0x1120 plus a marker/gap census."""
import struct, re, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()
N = len(D)

print('=== HEXDUMP 0x7F0 .. 0x1120 ===')
for a in range(0x7F0, 0x1120, 16):
    print('  0x%08X  %s  %s' % (a, D[a:a+16].hex(' '),
          ''.join(chr(c) if 32 <= c < 127 else '.' for c in D[a:a+16])))

print('\n=== ALL @SFV/@UTF/@SFA/... markers in first 0x3000 ===')
for m in re.finditer(rb'@[A-Z]{3}', D[:0x3000]):
    print('  0x%08X %r' % (m.start(), m.group()))

print('\n=== marker alignment census over WHOLE file ===')
mk = [m.start() for m in re.finditer(rb'@(?:SFV|UTF|SFA|SBT|SCC|SES|SVP|SVR|SHM|SLI|SPR|SST|SML|SOV|SCM|SMC)', D)]
print('total markers:', len(mk))
al = collections.Counter(x % 0x40 for x in mk)
print('offset % 0x40 :', sorted(al.items()))
al2 = collections.Counter(x % 0x10 for x in mk)
print('offset % 0x10 :', sorted(al2.items()))
# validate: at each marker, size BE, next marker == off+size (+pad)?
ok = 0; bad = 0; badlist = []
for x in mk:
    if x + 8 > N: continue
    size = struct.unpack_from('>I', D, x+4)[0]
    nxt = x + size
    if nxt > N:
        bad += 1; badlist.append((x, size, 'overflow')); continue
    # allow pad up to 0x10 zero bytes
    k = 0
    while k < 0x10 and D[nxt+k] == 0: k += 1
    if x + size + k in set(mk):
        ok += 1
    else:
        bad += 1
        if len(badlist) < 12: badlist.append((hex(x), hex(size), D[x+size:x+size+8].hex(' ')))
print('validated marker->size->next-marker chains: ok=%d bad=%d' % (ok, bad))
print('bad examples:', badlist)
