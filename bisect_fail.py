"""
Locate where the assembled stream breaks: decode progressive prefixes of the assembled
frame list and report the first frame count that fails.
"""
import sys, struct, os, subprocess, re

src = sys.argv[1]; outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

def al(n, a=0x20): return (n + a - 1) // a * a

chunks = []
o = 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf): o += 0x20; continue
    flen = struct.unpack_from('<I', buf, o+0x20)[0]
    fidx = struct.unpack_from('<I', buf, o+0x24)[0]
    if 0 < flen <= 1_500_000 and o + 0x2C + flen <= len(buf):
        chunks.append((fidx, o+0x2C, flen))
    o = al(o + size)
chunks.sort()
items = [(0xF0C, 262)] + [(off, fl) for _, off, fl in chunks]
ivf = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]

def build(n, name):
    sel = items[:n]
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(sel))
    out = bytearray(h)
    for i, (off, fl) in enumerate(sel):
        out += struct.pack('<IQ', fl, i) + buf[off:off+fl]
    out += struct.pack('<I', len(sel))
    p = os.path.join(outdir, name); open(p, 'wb').write(out)
    return p

def decode(p):
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    return (r.stderr or '').strip().replace('\n', ' | ')

print('=== progressive prefix decode ===')
for n in (1, 2, 3, 5, 10, 20, 50, 100, 200, 400, 800):
    p = build(n, f'pre{n}.ivf')
    e = decode(p)
    print(f'  first {n:4d} frames -> {"OK" if not e else e[:90]}', flush=True)

# find the first bad frame index within the first 800 by bisection on failure presence
print('\n=== bisect the first failing frame (within first 800) ===')
lo, hi = 1, 800
while lo < hi:
    mid = (lo + hi) // 2
    e = decode(build(mid, 'bis.ivf'))
    if e: hi = mid
    else: lo = mid + 1
print(f'  first failing prefix length: {lo}')
if lo >= 2:
    print(f'  frame at position {lo-1}: fidx={chunks[lo-2][0] if lo-2 < len(chunks) else "?"} len={items[lo-1][1]}')
    off = items[lo-1][0]
    print(f'  its data head: {buf[off:off+32].hex(" ")}')
    print(f'  previous data head: {buf[items[lo-2][0]:items[lo-2][0]+32].hex(" ")}')
