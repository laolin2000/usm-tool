"""
Brute-force scan: wrap each candidate offset as a single IVF frame and let ffmpeg decide.
Uses one ffmpeg invocation per batch by building a multi-frame IVF and checking which frames
produce errors -- far faster than one process per offset.
"""
import sys, struct, os, subprocess, re

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = buf[0xEE0:0xEE0+32]

# Build one IVF where each "frame" is a 4096-byte window from a grid of offsets.
GRID = 64
offsets = list(range(0x1000, 0x40000, GRID))
WIN = 4096
h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, len(offsets))
blob = bytearray(h)
for i, o in enumerate(offsets):
    data = buf[o:o+WIN]
    blob += struct.pack('<IQ', len(data), i) + data
p = os.path.join(workdir, 'grid.ivf')
open(p, 'wb').write(blob)

r = subprocess.run([FFMPEG, '-v', 'info', '-y', '-i', p, '-f', 'null', '-'],
                   capture_output=True, text=True, errors='replace')
out = r.stderr or ''
print('=== ffmpeg stderr (first 60 lines) ===')
for line in out.splitlines()[:60]:
    print(' ', line)

frames = re.findall(r'frame=\s*(\d+)', out)
print('\nframes decoded:', frames[-1] if frames else 'unknown')

# Also: single-window tests at a coarse grid, reporting which offsets decode OK
print('\n=== per-offset single-frame test (coarse grid, 0x400 step) ===')
ok_offsets = []
for o in range(0xF00, 0x40000, 0x400):
    hh = bytearray(IVF_HDR); struct.pack_into('<I', hh, 24, 1)
    bb = bytes(hh) + struct.pack('<IQ', WIN, 0) + buf[o:o+WIN]
    pp = os.path.join(workdir, 'g%d.ivf' % o)
    open(pp, 'wb').write(bb)
    rr = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', pp, '-f', 'null', '-'],
                        capture_output=True, text=True, errors='replace')
    if not (rr.stderr or '').strip():
        ok_offsets.append(o)
print('offsets decoding cleanly:', [hex(x) for x in ok_offsets] or 'none')
