#!/usr/bin/env python3
"""
x18_frametable.py -- decode the per-frame header inside every @SFV chunk and
identify which chunks are VP9 video frames.

Per-frame chunk layout (VERIFIED against sync codes at 0xF0D / 0x43F0D / 0xD9E4D):
  chunk+0x00  32-byte USM chunk header
  chunk+0x20  u16 BE 0x0018 | u16 BE frame_stride | u32 BE 0x00000001 | u32 BE 0
  chunk+0x2C  u32 BE frame_duration (ms)      <- 0x3C = 60 ms, 0x78 = 120 ms
  chunk+0x30  u8 0x00 (1 byte pad)
  chunk+0x31  bitstream ... (VP9 keyframe starts 0x82 49 83 42 at chunk+0x2D)
"""
import struct, re, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read(); N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

mk = sorted(set(m.start() for m in re.finditer(b'@SFV', D)))
print('@SFV chunks: %d' % len(mk))

rows = []
for x in mk:
    size = b32(x+4)
    if not (0x20 <= size <= N-x):
        rows.append(dict(off=x, size=size, bad=True)); continue
    rows.append(dict(off=x, size=size, bad=False,
                     u8=b16(x+8), ua=b16(x+0x0A), cid=b32(x+0x0C),
                     chinfo=b32(x+0x10), f1=b32(x+0x14), f2=b32(x+0x18),
                     chno=b16(x+0x1A),
                     stride=b16(x+0x22), one=b32(x+0x24), zero=b32(x+0x28),
                     dur=b32(x+0x2C), padbyte=D[x+0x30]))

print('\nframe_stride (u16@chunk+0x22) histogram:',
      collections.Counter(r.get('stride') for r in rows if not r['bad']).most_common(10))
print('u32@chunk+0x24 histogram:',
      collections.Counter(r.get('one') for r in rows if not r['bad']).most_common(6))
print('u32@chunk+0x28 histogram:',
      collections.Counter(r.get('zero') for r in rows if not r['bad']).most_common(6))
print('frame_duration (u32@chunk+0x2C) histogram:',
      collections.Counter(r.get('dur') for r in rows if not r['bad']).most_common(10))
print('pad byte @+0x30 histogram:',
      collections.Counter(r.get('padbyte') for r in rows if not r['bad']).most_common(6))

# VP9 video chunks: keyframe sync at chunk+0x2D, or interframe begins at +0x2D too
def vp9_check(r):
    if r['bad']: return None
    x = r['off']; body = D[x+0x2D:x+0x2D+4]
    if len(body) < 4: return None
    first = (body[0] << 8) | body[1]
    if body[0] == 0x82 and body[1] == 0x49: return 'KEY'
    if (body[0] & 0xC0) == 0x80: return 'inter?'
    return None

kinds = collections.Counter()
vids = []
for r in rows:
    k = vp9_check(r)
    kinds[k] += 1
    if k: vids.append((r, k))
print('\nVP9 shape at chunk+0x2D:', kinds.most_common())
print('video frames found: %d' % len(vids))

print('\nfirst 8 video frames:')
for r, k in vids[:8]:
    print('  @0x%08X size=%-8d cid=%-4d chinfo=0x%08X stride=%-4d dur=%-4d %s  body=%s'
          % (r['off'], r['size'], r['cid'], r['chinfo'], r['stride'], r['dur'], k,
             D[r['off']+0x2D:r['off']+0x2D+8].hex(' ')))
print('last 4 video frames:')
for r, k in vids[-4:]:
    print('  @0x%08X size=%-8d cid=%-4d chinfo=0x%08X stride=%-4d dur=%-4d %s  body=%s'
          % (r['off'], r['size'], r['cid'], r['chinfo'], r['stride'], r['dur'], k,
             D[r['off']+0x2D:r['off']+0x2D+8].hex(' ')))

# durations add up?
tot = sum(r['dur'] for r, k in vids)
print('\nsum of durations over %d video frames = %d ms = %.3f s' % (len(vids), tot, tot/1000.0))
print('cid sequence of video frames (first 12):', [r['cid'] for r, k in vids[:12]])
print('cid deltas (first 12):', [vids[i+1][0]['cid']-vids[i][0]['cid'] for i in range(11)])
print('cid range: %d .. %d' % (vids[0][0]['cid'], vids[-1][0]['cid']))
print('keyframe count:', sum(1 for r, k in vids if k == 'KEY'))

# total video payload bytes
tb = sum(r['size'] for r, k in vids)
print('total video chunk bytes: %d (%.1f MB)' % (tb, tb/1048576))
import json
json.dump([(r['off'], r['size'], r['cid'], r['dur'], k) for r, k in vids],
          open(r'C:\Users\<you>\Desktop\DSHStool\usm-tool\probe\videoframes.json', 'w'))
print('saved probe\\videoframes.json')
