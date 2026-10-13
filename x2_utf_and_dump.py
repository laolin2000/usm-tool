#!/usr/bin/env python3
"""x2_utf_and_dump.py -- parse the CRI @UTF table at 0x20, and hexdump the
region around the first @SFV markers so the real chunk/record framing is visible."""
import struct, re

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()

# ------------------------------------------------------------------ @UTF
o = 0x20
print('=== @UTF TABLE AT 0x%X ===' % o)
assert D[o:o+4] == b'@UTF'
size      = struct.unpack_from('>I', D, o+4)[0]
print('table size (BE)      :', size, hex(size), '-> table ends 0x%X' % (o+size))
print('unknown1 @0x28       :', D[o+8:o+0xC].hex(' '))
print('payload offset @0x2C :', D[o+0xC:o+0x10].hex(' '))
print('unknown2 @0x30       :', D[o+0x10:o+0x14].hex(' '))
rows     = struct.unpack_from('>H', D, o+0x14)[0]
columns  = struct.unpack_from('>H', D, o+0x16)[0]
row_w    = struct.unpack_from('>H', D, o+0x18)[0]
str_off  = struct.unpack_from('>I', D, o+0x1A)[0]
data_off = struct.unpack_from('>I', D, o+0x1E)[0]
print('rows=%d columns=%d row_width=%d string_off=0x%X data_off=0x%X' % (rows, columns, row_w, str_off, data_off))

so, do = o+str_off, o+data_off
raw = D[so:so+0x300]
end = raw.index(b'\x00')
strs = raw[:end].split(b'\x00')
print('strings:', strs)

def read_val(t, ro):
    if t == 0: return D[ro]
    if t == 1: return struct.unpack_from('>b', D, ro)[0]
    if t == 2: return struct.unpack_from('>H', D, ro)[0]
    if t == 3: return struct.unpack_from('>h', D, ro)[0]
    if t == 4: return struct.unpack_from('>I', D, ro)[0]
    if t == 5: return struct.unpack_from('>i', D, ro)[0]
    if t == 6: return struct.unpack_from('>f', D, ro)[0]
    if t == 7: return struct.unpack_from('>Q', D, ro)[0]
    if t == 8: return struct.unpack_from('>d', D, ro)[0]
    if t == 0xA:
        s = struct.unpack_from('>I', D, ro)[0]
        return strs[s] if s < len(strs) else b'?'
    return b'?'

# column descriptors
co = 0x20 + 0x20
cols = []
for i in range(columns):
    flags = D[co]; nm = struct.unpack_from('>I', D, co+1)[0]; t = D[co+5]
    cols.append((flags, strs[nm] if nm < len(strs) else '?', t))
    co += 8
    print('  col %d flags=0x%02X name=%-10s type=%d' % (i, flags, cols[-1][1], t))

print('\nrows:')
ro = o + 8 + struct.unpack_from('>I', D, o+0xC)[0] + rows*0  # unused
ro = o + data_off
print('row area starts 0x%X' % ro)
for r in range(rows):
    base = ro + r*row_w
    rec = {}
    for i, (f, nm, t) in enumerate(cols):
        rec[nm] = read_val(t, base + i*4)
    print('  row %d: %s' % (r, {k.decode() if isinstance(k, bytes) else k:
                               (v.decode('latin1') if isinstance(v, bytes) else v)
                               for k, v in rec.items()}))

# ------------------------------------------------- hexdump the first @SFV
print('\n=== RAW HEXDUMP around first @SFV markers ===')
mk = [m.start() for m in re.finditer(b'@SFV', D)]
for target in (mk[0], mk[1], mk[2], mk[3], mk[4], mk[5]):
    lo = (target - 0x40) & ~0xF
    print('\n--- @SFV at 0x%X (context 0x%X..0x%X) ---' % (target, lo, target+0x60))
    for a in range(lo, target+0x60, 16):
        tag = ''
        if a <= target < a+16: tag = '  <-- @SFV here'
        print('  0x%08X  %s %s%s' % (a, D[a:a+16].hex(' '),
              ''.join(chr(c) if 32 <= c < 127 else '.' for c in D[a:a+16]), tag))

# ------------------------------------------- look at very first bytes again
print('\n=== 0x00..0x120 raw ===')
for a in range(0, 0x120, 16):
    print('  0x%08X  %s %s' % (a, D[a:a+16].hex(' '),
          ''.join(chr(c) if 32 <= c < 127 else '.' for c in D[a:a+16])))
