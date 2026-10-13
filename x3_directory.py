#!/usr/bin/env python3
"""
x3_directory.py -- parse the CRI @UTF directory at 0x20 CORRECTLY (big-endian
sub-header), then walk the whole USM with the 32-byte chunk header and confirm
that chunk sizes exactly tile the file.

Key hypothesis under test:
  chunk header = 32 bytes:
    0x00 sig4 | 0x04 u32 size | 0x08 u16 0x18 | 0x0A u16 0x18 | 0x0C u32 1
    0x10 u32 0 | 0x14 u32 0x1E | 0x18 u32 0 | 0x1C u32 0
"""
import struct, re, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()
N = len(D)
u16 = lambda o: struct.unpack_from('<H', D, o)[0]
u32 = lambda o: struct.unpack_from('<I', D, o)[0]
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

def parse_utf(base):
    """base = offset of '@UTF'. Returns (size, cols, rows) with big-endian sub-header."""
    assert D[base:base+4] == b'@UTF', D[base:base+4]
    size = b32(base+4)
    rows = b16(base+0x14); columns = b16(base+0x16); row_w = b16(base+0x18)
    str_off = b32(base+0x1A); data_off = b32(base+0x1E)
    so = base + str_off; do = base + data_off
    raw = D[so:so+0x600]
    end = raw.index(b'\x00')
    strs = raw[:end].split(b'\x00')
    co = base + 0x20
    cols = []
    for i in range(columns):
        flags = D[co]; nm = b32(co+1); t = D[co+5]
        cols.append((flags, strs[nm].decode('latin1') if nm < len(strs) else '?', t))
        co += 8
    def rd(t, ro):
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
            s = b32(ro); return strs[s].decode('latin1') if s < len(strs) else '?'
        return '?t%d' % t
    rows_out = []
    for r in range(rows):
        base_r = do + r*row_w
        rows_out.append({cols[i][1]: rd(cols[i][2], base_r + i*4) for i in range(columns)})
    return dict(size=size, rows=rows, ncols=columns, row_w=row_w,
                str_off=str_off, data_off=data_off, cols=cols, data=rows_out,
                raw_strings=strs)

print('=== DIRECTORY @UTF at 0x20 ===')
t = parse_utf(0x20)
print('size=%d (0x%X) -> ends at 0x%X' % (t['size'], t['size'], 0x20+t['size']))
print('rows=%d columns=%d row_w=%d str_off=0x%X data_off=0x%X' % (t['rows'], t['ncols'], t['row_w'], t['str_off'], t['data_off']))
print('columns:', t['cols'])
for i, r in enumerate(t['data']):
    print('row %d:' % i, r)

# ------------------------------------------------------------------- walk
print('\n=== FULL CHUNK WALK (32-byte header) FROM 0x00 ===')
chunks = []
o = 0x00
bad = None
while o + 0x20 <= N:
    s = D[o:o+4]
    size = u32(o+4)
    if size < 0x20 or o + size > N:
        bad = ('bad size', o, size); break
    chunks.append(dict(off=o, sig=s.decode('latin1'), size=size, payload=o+0x20, plen=size-0x20,
                       u16a=u16(o+8), u16b=u16(o+0xa), u32c=u32(o+0xc), u32d=u32(o+0x10),
                       u32e=u32(o+0x14), u32f=u32(o+0x18), u32g=u32(o+0x1c)))
    o += size
print('chunks:', len(chunks), 'stop:', bad if bad else ('eof', o, N))
cons = sum(c['size'] for c in chunks)
print('consumed =', cons, ' file =', N, ' leftover =', N - cons)
print('sig histogram:', collections.Counter(c['sig'] for c in chunks))
print('u16a(0x08) hist:', collections.Counter(c['u16a'] for c in chunks))
print('u16b(0x0A) hist:', collections.Counter(c['u16b'] for c in chunks))
print('u32c(0x0C) hist:', collections.Counter(c['u32c'] for c in chunks).most_common(6))
print('u32d(0x10) hist:', collections.Counter(c['u32d'] for c in chunks).most_common(6))
print('u32e(0x14) hist:', collections.Counter(c['u32e'] for c in chunks).most_common(6))

print('\nfirst 24 chunks:')
for c in chunks[:24]:
    print('  0x%08X %-5s size=%-8d payload=0x%08X plen=%-8d u16a=0x%04X u16b=0x%04X u32c=%d u32e=0x%X'
          % (c['off'], c['sig'], c['size'], c['payload'], c['plen'], c['u16a'], c['u16b'], c['u32c'], c['u32e']))

# relation between the two u16s
rel = collections.Counter((c['u16a'], c['u16b']) for c in chunks)
print('\n(u16a,u16b) pairs:', rel.most_common(10))

# --------------------------------------------------- @SFV chunks deep dive
sfv = [c for c in chunks if c['sig'] == '@SFV']
print('\n=== @SFV CHUNKS: %d ===' % len(sfv))
print('size stats: min=%d max=%d' % (min(c['size'] for c in sfv), max(c['size'] for c in sfv)))
print('first 10 @SFV chunk headers, raw 32 bytes each:')
for c in sfv[:10]:
    print('  0x%08X size=%-8d : %s' % (c['off'], c['size'], D[c['off']:c['off']+0x20].hex(' ')))
# payload structure: what follows the 32-byte header?
print('\npayload first 48 bytes of a few @SFV chunks:')
for c in sfv[:6]:
    print('  0x%08X plen=%-8d %s' % (c['off'], c['plen'], D[c['payload']:c['payload']+48].hex(' ')))

# ------------------------------------------- the chunks around 0xEC0/0xEE0
print('\n=== CHUNKS near the known plaintext IVF header ===')
for c in chunks:
    if 0xE00 <= c['off'] <= 0x1100:
        print('  0x%08X %-5s size=%-8d payload=0x%08X plen=%d' % (c['off'], c['sig'], c['size'], c['payload'], c['plen']))
        print('      payload+0x00: %s' % D[c['payload']:c['payload']+32].hex(' '))
        print('      payload data : %s' % ''.join(chr(x) if 32 <= x < 127 else '.' for x in D[c['payload']:c['payload']+32]))

# locate IVF header inside chunk list
for c in chunks:
    if c['off'] <= 0xEE0 < c['off']+c['size']:
        print('\nIVF header 0xEE0 is +0x%X into chunk @0x%X (%s, size %d)' % (0xEE0-c['off'], c['off'], c['sig'], c['size']))
    if c['off'] <= 0xF00 < c['off']+c['size']:
        print('IVF frame  0xF00 is +0x%X into chunk @0x%X (%s, size %d)' % (0xF00-c['off'], c['off'], c['sig'], c['size']))
