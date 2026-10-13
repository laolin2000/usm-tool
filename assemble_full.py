"""
Assemble the complete video: frame 0 (plaintext at 0xF0C) + frames 1..4411 recovered from
the '@SFV' chunks, in index order, and decode.

The only remaining error was "Not all references are available" = missing keyframe.
"""
import sys, struct, os, subprocess

src = sys.argv[1]; outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

def al(n, a=0x20): return (n + a - 1) // a * a

# ---- collect frames ----
chunks = []
o = 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20; continue
    flen = struct.unpack_from('<I', buf, o+0x20)[0]
    fidx = struct.unpack_from('<I', buf, o+0x24)[0]
    if 0 < flen <= 1_500_000 and o + 0x2C + flen <= len(buf):
        chunks.append((fidx, o+0x2C, flen))
    o = al(o + size)
chunks.sort()
print(f'frames 1..N collected: {len(chunks)}')

# ---- frame 0 ----
f0 = buf[0xF0C:0xF0C+262]
ivf = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]

items = [(0xF0C, 262)] + [(off, fl) for _, off, fl in chunks]
print(f'total frames: {len(items)}  (IVF header declares {struct.unpack_from("<I", ivf, 24)[0]})')
print(f'frame0 first bytes: {f0[:8].hex(" ")}')

h = bytearray(ivf)
struct.pack_into('<I', h, 24, len(items))
out = bytearray(h)
for i, (off, fl) in enumerate(items):
    out += struct.pack('<IQ', fl, i) + buf[off:off+fl]
out += struct.pack('<I', len(items))
p = os.path.join(outdir, 'complete.ivf')
open(p, 'wb').write(out)
print(f'wrote {p} ({len(out)} bytes)')

r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                   capture_output=True, text=True, errors='replace')
err = (r.stderr or '').strip().replace('\n', ' | ')
print('decode ->', 'DECODE OK' if not err else err[:400])

# count frames actually decoded
r2 = subprocess.run([FFMPEG, '-v', 'info', '-i', p, '-f', 'null', '-'],
                    capture_output=True, text=True, errors='replace')
import re
m = re.findall(r'frame=\s*(\d+)', r2.stderr or '')
print('decoder progress:', m[-1] if m else 'n/a')
