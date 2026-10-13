#!/usr/bin/env python3
"""x12_vp9_hunt.py -- find where real VP9 keyframe sync codes (0x49 0x83 0x42) live,
and check whether that region is contiguous."""
import struct, re, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read(); N = len(D)
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

# VP9 keyframe sync: frame_marker=2, profile 0, show_existing=0, frame_type=0,
# then byte1 error_resilient, byte2 = 0x49, byte3 = 0x83, byte4 = 0x42
pat = re.compile(rb'\x49\x83\x42')
hits = [m.start() for m in pat.finditer(D)]
print('occurrences of 49 83 42 :', len(hits))
print('first 40:', [hex(x) for x in hits[:40]])
print('last 10 :', [hex(x) for x in hits[-10:]])

# tighter: require 0x82 in front (frame marker 10xxxxxx, profile0, show_existing=0, keyframe)
pat2 = re.compile(rb'[\x82-\x83][\x00-\xff]\x49\x83\x42')
h2 = [m.start() for m in pat2.finditer(D)]
print('\nkeyframe-ish (b0 0x82/0x83 + b2..b4 = 49 83 42):', len(h2))
print('first 40:', [hex(x) for x in h2[:40]])

# where do they cluster?
if h2:
    buckets = collections.Counter(x >> 16 for x in h2)
    print('clusters by 64KB block:', sorted(buckets.items())[:20])

# context around the very first hit
if hits:
    x = hits[0]
    print('\ncontext around first 49 83 42 at 0x%X:' % x)
    lo = (x-0x20) & ~0xF
    for a in range(lo, x+0x30, 16):
        print('  0x%08X  %s  %s' % (a, D[a:a+16].hex(' '),
              ''.join(chr(c) if 32 <= c < 127 else '.' for c in D[a:a+16])))

# Also check: are the 0x1020.. region chunks really video? Look for '00 00 00 01' start codes
sc = [m.start() for m in re.finditer(rb'\x00\x00\x00\x01', D)]
print('\n00 00 00 01 start codes:', len(sc), 'first:', [hex(x) for x in sc[:10]])
sc3 = [m.start() for m in re.finditer(rb'\x00\x00\x01', D)]
print('00 00 01 start codes:', len(sc3))

# ------------------------------------------------- chain partition with exact tiling
mk = sorted(set(m.start() for m in re.finditer(b'@SFV', D)))
mset = set(mk)
print('\n@SFV count:', len(mk))
# count how many chunks have size that lands close to another marker
exact = 0; pad0_64 = 0; other = 0
for x in mk:
    s = b32(x+4)
    if x+s in mset: exact += 1
    elif any(x+s+k in mset for k in range(1, 0x40)): pad0_64 += 1
    else: other += 1
print('markers whose end is exactly another marker :', exact)
print('markers whose end + (1..0x3F) is a marker     :', pad0_64)
print('markers with no marker within 0x40 after end  :', other)

# coverage: greedy chain from 0 picking the FIRST valid successor
o = 0; path = []; fails = 0
while o < N:
    if o not in mset: print('  dead end at 0x%X' % o); break
    s = b32(o+4); path.append(o)
    nxt = None
    for k in range(0, 0x41):
        if o+s+k in mset: nxt = o+s+k; break
    if nxt is None: print('  no successor at 0x%X (size %d)' % (o, s)); break
    o = nxt
print('greedy chain length:', len(path), 'ended 0x%X' % o)
print('coverage: %d / %d = %.4f%%' % (o, N, 100.0*o/N))
