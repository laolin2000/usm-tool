#!/usr/bin/env python3
"""
x21_layout_fix.py -- candidate layouts re-tested with the corrected field map:
  L1: size@+0x20, data@+0x2C
  L2: size@+0x24, data@+0x2C  (size is the 'unknown' field, frame = rest)
  L3: size@+0x20, data@+0x2C but drop 6 trailing bytes
"""
import struct, re, subprocess, os, os.path as p, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
OUT = r'C:\Users\<you>\Desktop\DSHStool\usm-tool\probe'
os.makedirs(OUT, exist_ok=True)
D = open(PATH, 'rb').read(); N = len(D)
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

mk = sorted(set(m.start() for m in re.finditer(b'@SFV', D)))
big = [(x, b32(x+4)) for x in mk if b32(x+4) > 20000]
print('large @SFV chunks: %d' % len(big))

print('\n=== consistency of u32@+0x20 as frame size (big chunks) ===')
sl = collections.Counter()
for x, s in big:
    v = b32(x+0x20)
    slack = (s - 0x2C) - v
    sl[slack] += 1
print('slack distribution ((size-0x2C) - u32@+0x20):', sl.most_common(8))
print('u32@+0x24 distribution:', collections.Counter(b32(x+0x24) for x, s in big).most_common(6))

# also on the small chunks
small = [(x, b32(x+4)) for x in mk if 0x40 < b32(x+4) <= 20000]
print('\nsmall chunks: %d' % len(small))
sl2 = collections.Counter()
for x, s in small:
    v = b32(x+0x20)
    sl2[(s - 0x2C) - v] += 1
print('slack distribution (small):', sl2.most_common(8))

def ivf(frames, path, w=1080, h=608):
    b = bytearray(b'DKIF'+struct.pack('<HH', 0, 32)+b'VP90'+struct.pack('<HHIIII', w, h, 30000, 1000, len(frames), 0))
    for i, f in enumerate(frames):
        b += struct.pack('<IQ', len(f), i)+f
    open(path, 'wb').write(b)

def judge(tag, frames):
    path = p.join(OUT, 'L_%s.ivf' % tag)
    ivf(frames, path)
    r = subprocess.run([FFMPEG, '-hide_banner', '-v', 'error', '-i', path, '-map', '0:v:0', '-f', 'null', '-'],
                       capture_output=True, timeout=600)
    err = r.stderr.decode('utf-8', 'replace').strip()
    lines = [l for l in err.splitlines() if l.strip()]
    print('  %-26s n=%-5d bytes=%-10d errlines=%-5d %s' % (tag, len(frames), p.getsize(path), len(lines),
          'CLEAN DECODE' if not lines else lines[0][:95]))
    if lines:
        print('      ', collections.Counter(l.split('] ')[-1][:60] for l in lines).most_common(3))
    return len(lines)

print('\n=== ffmpeg tests on first 200 large chunks ===')
judge('L1_sz20_d2C', [D[x+0x2C:x+0x2C+b32(x+0x20)] for x, s in big[:200]])
judge('L2_d2C_rest', [D[x+0x2C:x+s] for x, s in big[:200]])
judge('L3_sz20_d2C_minus8', [D[x+0x2C:x+0x2C+b32(x+0x20)-8] for x, s in big[:200]])
judge('L4_sz20_d30', [D[x+0x30:x+0x30+b32(x+0x20)] for x, s in big[:200]])

print('\n=== mixed: all chunks with u32@+0x20 plausible, first 300 ===')
allfr = []
for x, s in mk:
    if s < 0x40: continue
    v = b32(x+0x20)
    if 0 < v <= s-0x30 and (s-0x2C)-v < 64:
        allfr.append(D[x+0x2C:x+0x2C+v])
print('frames collected: %d' % len(allfr))
judge('MIX_sz20_d2C', allfr[:300])
judge('MIX_sz20d2C_all', allfr)
