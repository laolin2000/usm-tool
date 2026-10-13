#!/usr/bin/env python3
"""
x20_frame_extract.py -- extract VP9 frames from 001960.dat and let ffmpeg judge.

Observed per-frame chunk layout for big video chunks (@0x0179AE0 etc.):
  chunk+0x20  ca bd 02 00 | e8 0d 00 00 | 00 00 00 00 | 84 00 | <bitstream>
  i.e. u16@+0x22 = 0x02CA/0x02BD (=stride?), u32@+0x26..+0x28 = 0x0DE8,
       u32@+0x29 = frame_size, then 2-3 flag bytes, then the bitstream.
This script searches for the (size_field_offset, data_offset) pair that makes
size_field == (chunk_size - data_offset) - pad  and then feeds ffmpeg.
"""
import struct, re, collections, subprocess, os, os.path as p

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
OUT = r'C:\Users\<you>\Desktop\DSHStool\usm-tool\probe'
os.makedirs(OUT, exist_ok=True)
D = open(PATH, 'rb').read(); N = len(D)
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

mk = sorted(set(m.start() for m in re.finditer(b'@SFV', D)))
big = [(x, b32(x+4)) for x in mk if b32(x+4) > 20000]
print('large @SFV chunks (>20000 B): %d' % len(big))

print('\n=== searching for a (size_field_off, data_off) pair consistent across chunks ===')
best = []
for sf in range(0x20, 0x40):
    for do in range(sf+4, 0x40):
        good = 0; slack = []
        for x, s in big[:40]:
            v = b32(x+sf)
            if 0 < v <= s - do and (s - do) - v < 64:
                good += 1; slack.append((s-do)-v)
        if good >= 35:
            best.append((good, sf, do, collections.Counter(slack).most_common(3)))
for good, sf, do, sl in sorted(best, reverse=True)[:12]:
    print('  size_field@+0x%02X data@+0x%02X  good=%d/40  slack=%s' % (sf, do, good, sl))

# inspect one chunk byte by byte
x, s = big[0]
print('\n=== byte map of chunk @0x%X (size=%d) ===' % (x, s))
for a in range(x, x+0x40, 1):
    pass
for a in range(x+0x20, x+0x40, 4):
    print('  +0x%02X  %s  u32BE=%d' % (a-x, D[a:a+4].hex(' '), b32(a)))

def ivf(frames, path, w=1080, h=608):
    b = bytearray(b'DKIF'+struct.pack('<HH', 0, 32)+b'VP90'+struct.pack('<HHIIII', w, h, 30000, 1000, len(frames), 0))
    for i, f in enumerate(frames):
        b += struct.pack('<IQ', len(f), i)+f
    open(path, 'wb').write(b)

def ffcount(path, timeout=600):
    r = subprocess.run([FFMPEG, '-hide_banner', '-v', 'error', '-i', path, '-map', '0:v:0', '-f', 'null', '-'],
                       capture_output=True, timeout=timeout)
    return r.stderr.decode('utf-8', 'replace').strip()

# try the promising candidates on a subset then all
cands = [(sf, do) for good, sf, do, sl in sorted(best, reverse=True)[:6]]
for sf, do in cands:
    frames = [D[x+do:x+s] for x, s in big[:200]]
    path = p.join(OUT, 'cand_%02X_%02X.ivf' % (sf, do))
    ivf(frames, path)
    err = ffcount(path)
    lines = [l for l in err.splitlines() if l.strip()]
    print('  sf=+0x%02X do=+0x%02X n=200 : errlines=%d  %s' % (sf, do, len(lines), lines[0][:90] if lines else 'CLEAN'))
