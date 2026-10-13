#!/usr/bin/env python3
"""
x4_usm_layout.py -- FINAL chunk-layout proof for 001960.dat.

Chunk header (verified below) = 32 bytes:
  0x00 char[4] signature ('@SFV' ... or 'CRID' for the first block)
  0x04 u32 BE  total chunk size (header + payload)
  0x08 u16 BE  0x18   (payload header offset / always 0x18)
  0x0A u16 BE  payload offset within chunk (0x18 = no padding, 0x20 = padded)
  0x0C u32 BE  1
  0x10 u32 BE  0x18 | (channels<<8)   [chunk id / channel info]
  0x14 u32 BE  0                    (frame time)
  0x18 u32 BE  0x1E                 (frame rate = 30)
  0x1A u16 BE  chno                 (channel number)
  0x1C u32 BE  zeros
Proves: u16@0x0A + 8 == 0x20 -> payload begins at chunk+0x20.
"""
import struct, collections, re

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()
N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

print('file size = %d (0x%X)' % (N, N))

# ---------------------------------------------------------------------------------
# 1. The first block: its own 32-byte header at 0x00, payload = @UTF at 0x20
print('\n=== BLOCK 0 HEADER (0x00..0x20) ===')
print(D[0:0x20].hex(' '))
print('sig      =', D[0:4])
print('size(BE) = 0x%X (%d)  -> block 0 = 0x00..0x%X' % (b32(4), b32(4), b32(4)-1))
print('u16@0x08 = 0x%04X' % b16(8))
print('u16@0x0A = 0x%04X   (0x%X + 8 = 0x%X => payload at +0x20)' % (b16(0x0A), b16(0x0A), b16(0x0A)+8))
print('u32@0x0C = %d' % b32(0x0C))
print('u32@0x10 = 0x%X' % b32(0x10))
print('u32@0x14 = %d' % b32(0x14))
print('u32@0x18 = %d  (frame rate)' % b32(0x18))
print('u16@0x1C = %d' % b16(0x1C))
print('payload    =', D[0x20:0x24], '(size of @UTF table at 0x24 = 0x%X)' % b32(0x24))
print('block 0 ends at 0x%X ; next bytes: %s %r' % (b32(4), D[b32(4):b32(4)+4].hex(' '), D[b32(4):b32(4)+4]))

# ------------------------------------------------------------------- walk
print('\n=== FULL WALK with 32-byte header, BIG-ENDIAN size ===')
chunks = []
o = 0
bad = None
while o + 0x20 <= N:
    s = D[o:o+4]
    size = b32(o+4)
    if size < 0x20 or o + size > N:
        bad = ('bad size', o, size); break
    pad = b16(o+0x0A)
    chunks.append(dict(off=o, sig=s.decode('latin1'), size=size,
                       pad=pad, payload=o+pad+8, plen=size-(pad+8),
                       u8=b16(o+8), cid=b32(o+0x0C), chinfo=b32(o+0x10),
                       ftime=b32(o+0x14), frate=b32(o+0x18), chno=b16(o+0x1A)))
    o += size
cons = sum(c['size'] for c in chunks)
print('chunks parsed  :', len(chunks))
print('stop reason    :', bad if bad else ('clean EOF at 0x%X' % o))
print('bytes consumed :', cons, '/', N, ' leftover =', N - cons)
print('signatures     :', collections.Counter(c['sig'] for c in chunks).most_common(12))
print('pad u16@0x0A   :', collections.Counter(c['pad'] for c in chunks).most_common(6))
print('u16@0x08       :', collections.Counter(c['u8'] for c in chunks).most_common(6))
print('chinfo u32@0x10:', collections.Counter(c['chinfo'] for c in chunks).most_common(8))
print('frate u32@0x18 :', collections.Counter(c['frate'] for c in chunks).most_common(6))
print('chno u16@0x1A  :', collections.Counter(c['chno'] for c in chunks).most_common(8))

print('\nfirst 20 chunks:')
for c in chunks[:20]:
    print('  0x%08X %-5s size=%-9d pad=0x%04X payload=0x%08X plen=%-9d chinfo=0x%08X chno=%-3d ftime=%d frate=%d'
          % (c['off'], c['sig'], c['size'], c['pad'], c['payload'], c['plen'],
             c['chinfo'], c['chno'], c['ftime'], c['frate']))

# mark which chunks carry a decodable VP9 frame header
def vp9_kind(b):
    if len(b) < 2: return '?'
    f = (b[0] << 8) | b[1]
    if (f >> 14) & 1: return 'invalid'
    ft = (f >> 13) & 1
    if ft == 0:
        if len(b) < 3: return '?'
        return 'KEY' if b[2] == 0x49 else 'key?b2=0x%02X' % b[2]
    return 'inter'

sfv = [c for c in chunks if c['sig'] == '@SFV']
print('\n=== @SFV CHUNKS: %d ===' % len(sfv))
print('sizes: min=%d max=%d sum=%d' % (min(c['size'] for c in sfv), max(c['size'] for c in sfv), sum(c['size'] for c in sfv)))
print('\nfirst 12 @SFV: header | payload first 12 bytes | vp9 kind')
for c in sfv[:12]:
    p = D[c['payload']:c['payload']+12]
    print('  0x%08X size=%-8d plen=%-8d %s  %s  %s' % (c['off'], c['size'], c['plen'], D[c['off']:c['off']+0x20].hex(' ')[:64], p.hex(' '), vp9_kind(p)))

# ---------------------------------------------------------------- IVF region
print('\n=== IVF REGION MAP ===')
for c in chunks:
    if c['off'] <= 0xEE0 < c['off']+c['size']:
        print('IVF header 0xEE0 is at +0x%X inside chunk @0x%X (%s size=%d plen=%d)'
              % (0xEE0-c['off'], c['off'], c['sig'], c['size'], c['plen']))
        print('  chunk bytes: %s' % D[c['off']:c['off']+0x20].hex(' '))
        print('  payload starts 0x%X : %s' % (c['payload'], D[c['payload']:c['payload']+0x30].hex(' ')))
    if c['off'] <= 0xF00 < c['off']+c['size']:
        print('IVF frame0 0xF00 is at +0x%X inside chunk @0x%X (%s size=%d)'
              % (0xF00-c['off'], c['off'], c['sig'], c['size']))

# The chunk right before the IVF header should be the video header chunk
print('\nchunks from 0xE00 to 0x1200:')
for c in chunks:
    if 0xE00 <= c['off'] < 0x1200:
        print('  0x%08X %-5s size=%-8d plen=%-8d chinfo=0x%08X chno=%d | payload: %s'
              % (c['off'], c['sig'], c['size'], c['plen'], c['chinfo'], c['chno'], D[c['payload']:c['payload']+24].hex(' ')))
