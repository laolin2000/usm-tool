#!/usr/bin/env python3
"""x19_frametable2.py -- locate the VP9 bitstream start inside each @SFV chunk by
scanning for the keyframe sync / interframe marker, then build the frame table."""
import struct, re, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read(); N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

mk = sorted(set(m.start() for m in re.finditer(b'@SFV', D)))
print('@SFV chunks: %d' % len(mk))

# for each chunk, search the first 0x60 bytes for '82 49 83 42' (VP9 keyframe)
kf_off = collections.Counter()
tbl = []
for x in mk:
    size = b32(x+4)
    if not (0x20 <= size <= N-x):
        tbl.append((x, size, None)); continue
    win = D[x+0x20:x+0x80]
    p = win.find(b'\x82\x49\x83\x42')
    tbl.append((x, size, p if p >= 0 else None))
    if p >= 0: kf_off[p] += 1
print('\nkeyframe-sync position within chunk (from chunk+0x20):', kf_off.most_common(8))

keys = [(x, s) for (x, s, p) in tbl if p is not None]
print('chunks containing a VP9 keyframe: %d' % len(keys))

# Now: the bitstream of OTHER chunks. Look at the bytes right after the 0x20-byte
# header for a plausible VP9 profile-0 interframe: b0 in [0x80..0xBF], b1 bit0=0
def inter_shape(x, size):
    for start in (0x2D, 0x2E, 0x30, 0x31, 0x2C, 0x2B, 0x2A, 0x29, 0x28):
        if x + start + 4 > N: continue
        b0 = D[x+start]
        if 0x80 <= b0 <= 0xBF and (D[x+start+1] & 1) == 0:
            return start
    return None

shapes = collections.Counter()
for x, s, p in tbl:
    if p is not None: continue
    shapes[inter_shape(x, s)] += 1
print('interframe start-offset histogram:', shapes.most_common(10))

print('\n--- chosen layout: bitstream starts at chunk+0x2D ---')
# verify: for chunks where keyframe found, p should be 0xD
print('keyframe p values:', collections.Counter(p for x, s, p in tbl if p is not None).most_common(6))

# Are ALL chunks video?  count how many start with a VP9 keyframe pattern at +0x2D
n_key = 0; n_inter = 0; n_none = 0
siz = []
for x, s, p in tbl:
    b0 = D[x+0x2D] if x+0x2D < N else None
    body = D[x+0x2D:x+0x2D+2]
    if body[:2] == b'\x82\x49': n_key += 1
    elif b0 is not None and 0x80 <= b0 <= 0xBF: n_inter += 1
    else: n_none += 1
print('at +0x2D: key=%d inter-ish=%d other=%d' % (n_key, n_inter, n_none))

# sample a few "other" chunks
others = [x for x, s, p in tbl if not (0x80 <= D[x+0x2D] <= 0xBF)][:6]
print('\nsample chunks whose +0x2D is not VP9-shaped:')
for x in others:
    s = b32(x+4)
    print('  @0x%08X size=%-8d chinfo=0x%08X | +0x20..+0x50: %s'
          % (x, s, b32(x+0x10), D[x+0x20:x+0x50].hex(' ')))

# the big video chunks
big = sorted([(s, x) for x, s, p in tbl if s > 20000], reverse=True)[:10]
print('\n10 largest @SFV chunks:')
for s, x in big:
    print('  @0x%08X size=%-8d chinfo=0x%08X cid=%-5d | +0x20..+0x50: %s'
          % (x, s, b32(x+0x10), b32(x+0x0C), D[x+0x20:x+0x50].hex(' ')))
