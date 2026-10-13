#!/usr/bin/env python3
"""
x1_parse_chunks.py -- Determine the TRUE CRI USM chunk layout of 001960.dat.

Competing hypotheses:
  H32: chunk header = 32 bytes, payload = size-32 bytes
  H24: chunk header = 24 bytes, payload = size-24 bytes

Tests: (a) does a chunk walk stay in-bounds and consume the file exactly,
(b) do payload sizes match known inner structures (e.g. the @SFV header,
    the IVF header at 0xEE0, the 262-byte VP9 frame at 0xF0C),
(c) what lies at the reported "offset" field values (0x18 / 0x20).
"""
import struct, sys, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()
print('file size', len(D), hex(len(D)))

def u8 (o): return D[o]
def u16(o): return struct.unpack_from('<H', D, o)[0]
def u32(o): return struct.unpack_from('<I', D, o)[0]
def u64(o): return struct.unpack_from('<Q', D, o)[0]
def sig(o): return D[o:o+4]

# ---------------------------------------------------------------- top header
print('\n=== TOP HEADER (0x00..0x20) ===')
print('0x00 sig      :', sig(0))
print('0x04 u32      :', hex(u32(4)),  '   (size of @UTF block+? )')
print('0x08 u32      :', hex(u32(8)))
print('0x0C u32      :', hex(u32(0xc)), 'payload offset?')
print('0x10 u32      :', hex(u32(0x10)))
print('0x14 u32      :', hex(u32(0x14)))
print('0x18 u32      :', hex(u32(0x18)))
print('0x1C u32      :', hex(u32(0x1C)))
print('raw 0x00..0x20:', D[0:0x20].hex(' '))

# ------------------------------------------------------------- walk chunks
def walk(hdrlen, limit=None):
    """Walk chunks assuming header length hdrlen. Returns list of dicts."""
    chunks = []
    o = 0
    n = len(D)
    while o + hdrlen <= n:
        s = sig(o)
        if not (s[:1] == b'@' and s[1:4].isalnum()):
            return chunks, ('bad signature', o, s)
        size = u32(o+4)
        if size < hdrlen or o + size > n:
            return chunks, ('bad size', o, size)
        chunks.append(dict(off=o, sig=s.decode('latin1'), size=size,
                           off_f=u8(o+1), b2=u16(o+2), b3=u8(o+4+0)if False else None,
                           chno=u8(o+9), ptype=u8(o+0xA),
                           fts=struct.unpack_from('<f', D, o+0xB)[0] if False else None,
                           ftime=u32(o+0xB), frate=u32(o+0xF),
                           u1=u8(o+1), u2=u16(o+2), u3=u8(o+4), u4=u8(o+5),
                           u5=u8(o+6), u6=u8(o+7), u7=u32(o+8),
                           u8_=u32(o+0x13), u9=u32(o+0x17),
                           u10=u32(o+0x1B), u11=u8(o+0x1F),
                           payload_off=o+hdrlen, payload_len=size-hdrlen))
        o += size
        if limit and len(chunks) >= limit:
            return chunks, ('limit', o)
    return chunks, ('eof', o, n)

for hl in (24, 32):
    ch, stop = walk(hl)
    consumed = sum(c['size'] for c in ch)
    print('\n=== WALK with header length %d ===' % hl)
    print('chunks parsed   :', len(ch))
    print('first stop      :', stop)
    print('bytes consumed  :', consumed, 'file', len(D), 'leftover', len(D)-consumed)
    print('first 6 chunks  :')
    for c in ch[:6]:
        print('  off=0x%08X %-5s size=%-8d payload_off=0x%08X payload_len=%-8d chno=%-3d ptype=%d '
              'ftime=%-6d frate=%-6d u1=%d u2=%d u3=%d u4=%d u5=%d u6=%d u7=0x%X u8_=0x%X u9=0x%X u10=0x%X u11=%d'
              % (c['off'], c['sig'], c['size'], c['payload_off'], c['payload_len'], c['chno'], c['ptype'],
                 c['ftime'], c['frate'], c['u1'], c['u2'], c['u3'], c['u4'], c['u5'], c['u6'],
                 c['u7'], c['u8_'], c['u9'], c['u10'], c['u11']))

# ------------------------------------------------- @SFV marker histogram
print('\n=== "@SFV" MARKER OFFSETS (raw scan) ===')
import re
mk = [m.start() for m in re.finditer(b'@SFV', D)]
print('count:', len(mk))
print('first 8 offsets:', [hex(x) for x in mk[:8]])
print('last  4 offsets:', [hex(x) for x in mk[-4:]])
# deltas
dl = collections.Counter(mk[i+1]-mk[i] for i in range(len(mk)-1))
print('delta histogram (top 8):', dl.most_common(8))

# how many markers align to the H32 walk boundaries?
h32, _ = walk(32)
offs32 = set(c['off'] for c in h32)
print('markers that ARE h32 chunk starts :', sum(1 for x in mk if x in offs32), '/', len(mk))
print('markers that are h32_start+0x20   :', sum(1 for x in mk if (x-0x20) in offs32))
print('markers that are h32_start+0x18   :', sum(1 for x in mk if (x-0x18) in offs32))
print('markers that are h32_start+0x40   :', sum(1 for x in mk if (x-0x40) in offs32))
print('markers that are h32_start+0x30   :', sum(1 for x in mk if (x-0x30) in offs32))

# ------------------------------------------------------- specific offsets
print('\n=== KEY OFFSETS CHECK ===')
for o, label in ((0xEE0, 'IVF header'), (0xF00, 'IVF frame hdr'), (0xF0C, 'VP9 frame0')):
    print('0x%04X %-14s sig=%r  in_h32_chunks=%s' % (
        o, label, D[o:o+4],
        [hex(c['off']) for c in h32 if c['off'] <= o < c['off']+c['size']][:3]))

print('\nIVF header @0xEE0:', D[0xEE0:0xEE0+32].hex(' '))
print('IVF header fields: magic=%r ver=%d hdrlen=%d fourcc=%r w=%d h=%d rate=%d/%d frames=%d unused=%d'
      % (D[0xEE0:0xEE4], u16(0xEE4), u16(0xEE6), D[0xEE8:0xEEC], u16(0xEEC), u16(0xEEE),
         u32(0xEF0), u32(0xEF4), u32(0xEF8), u32(0xEFC)))
print('IVF frame0 hdr @0xF00: size=%d ts=%d' % (u32(0xF00), u64(0xF04)))
print('VP9 frame0 first 16B: ', D[0xF0C:0xF0C+16].hex(' '))

# The @SFV chunk containing 0xEE0:
for c in h32:
    if c['off'] <= 0xEE0 < c['off']+c['size']:
        print('\nthe chunk containing 0xEE0: off=0x%X sig=%s size=%d payload_off=0x%X payload_len=%d'
              % (c['off'], c['sig'], c['size'], c['payload_off'], c['payload_len']))
        print('  payload head (64B):')
        p = c['payload_off']
        for r in range(4):
            print('   +0x%02X  %s' % (r*16, D[p+r*16:p+r*16+16].hex(' ')))
        print('  u32 fields after sig:', ['0x%X' % u32(p+4+i*4) for i in range(8)])
