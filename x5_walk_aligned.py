#!/usr/bin/env python3
"""
x5_walk_aligned.py -- USM chunk walk tolerant of inter-chunk padding.

Chunk header = 32 bytes, all multi-byte fields BIG-ENDIAN.
After each chunk we skip up to 16 zero bytes before the next signature.
"""
import struct, collections, re

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()
N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

chunks = []
o = 0
gaps = collections.Counter()
while o + 0x20 <= N:
    sig = D[o:o+4]
    size = b32(o+4)
    ok = ((sig[:1] == b'@' and sig[1:4].isalnum()) or sig == b'CRID') and 0x20 <= size <= N - o
    if not ok:
        print('!! stop at 0x%X: sig=%r size=%d' % (o, sig, size))
        break
    pad = b16(o+0x0A)
    chunks.append(dict(off=o, sig=sig.decode('latin1'), size=size, pad=pad,
                       payload=o+0x20, plen=size-0x20,
                       u8=b16(o+8), cid=b32(o+0x0C), chinfo=b32(o+0x10),
                       ftime=b32(o+0x14), frate=b32(o+0x18), chno=b16(o+0x1A),
                       trailer=D[o+size:o+size+16]))
    nxt = o + size
    # skip zero padding
    k = 0
    while k < 16 and nxt + k + 4 <= N and D[nxt+k] == 0:
        k += 1
    gaps[k] += 1
    if k == 16:
        print('!! 16+ zeros after chunk @0x%X' % o); break
    o = nxt + k

cons_end = o
print('chunks parsed :', len(chunks))
print('walk ended at : 0x%X  (file 0x%X)' % (o, N))
print('trailing bytes:', N - o)
print('gap histogram :', gaps.most_common(8))
print('signatures    :', collections.Counter(c['sig'] for c in chunks).most_common(12))
print('sum of sizes  :', sum(c['size'] for c in chunks))
print('pad u16@0x0A  :', collections.Counter(c['pad'] for c in chunks).most_common(6))
print('u16@0x08      :', collections.Counter(c['u8'] for c in chunks).most_common(6))
print('chinfo@0x10   :', collections.Counter(c['chinfo'] for c in chunks).most_common(8))
print('frate@0x18    :', collections.Counter(c['frate'] for c in chunks).most_common(6))
print('chno@0x1A     :', collections.Counter(c['chno'] for c in chunks).most_common(8))

print('\nfirst 20 chunks (header hex | size | payload off/len | chinfo chno):')
for c in chunks[:20]:
    print('  0x%08X %s size=%-8d plen=%-8d chinfo=0x%08X chno=%-3d | %s'
          % (c['off'], D[c['off']:c['off']+0x20].hex(' '), c['size'], c['plen'], c['chinfo'], c['chno'],
             ''.join(chr(x) if 32 <= x < 127 else '.' for x in c['trailer'][:8])))

# ---------------------------------------------------------- @SFV chunk census
sfv = [c for c in chunks if c['sig'] == '@SFV']
sfv_v = [c for c in sfv if c['chinfo'] & 0x100]   # video channel?
print('\n=== @SFV: %d chunks ===' % len(sfv))
print('sizes min/max/sum:', min(c['size'] for c in sfv), max(c['size'] for c in sfv), sum(c['size'] for c in sfv))
print('pad values:', collections.Counter(c['pad'] for c in sfv).most_common(6))
print('chinfo values:', collections.Counter(c['chinfo'] for c in sfv).most_common(8))
print('chno values:', collections.Counter(c['chno'] for c in sfv).most_common(8))
print('frate values:', collections.Counter(c['frate'] for c in sfv).most_common(8))
print('ftime first 20:', [c['ftime'] for c in sfv[:20]])

# which @SFV chunks look like VP9?
def vp9_kind(b):
    if len(b) < 3: return '?'
    f = (b[0] << 8) | b[1]
    if (f >> 14) & 1: return 'invalid'
    if ((f >> 13) & 1) == 0:
        return 'KEY' if b[2] == 0x49 else 'key-ish(0x%02X)' % b[2]
    return 'inter'

kinds = collections.Counter()
for c in sfv:
    kinds[vp9_kind(D[c['payload']:c['payload']+3])] += 1
print('\nVP9-header-shape census over @SFV payload starts:', kinds.most_common(10))
