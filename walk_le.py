"""
Frame header at chunk+0x20 is LITTLE-endian:
    +0x20 frameLen (bytes)      e.g. anchor1: 00 01 3d 5e -> 257
    +0x24 frameIndex            e.g. 3c 00 00 00    -> 60
    +0x28 duration/count        e.g. 00 00 00 00
    +0x2C VP9 frame data
Walking anchor1 + 257 lands exactly on the next anchor, which confirms the layout.
"""
import sys, struct, os, re, subprocess

src = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0+32])
SIG = b'\x82\x49\x83\x42'

anchors = []
i = buf.find(SIG)
while i != -1:
    anchors.append(i); i = buf.find(SIG, i+1)

print('=== LE frame header at anchors ===')
for k, a in enumerate(anchors[:6]):
    c = a - 0x2C
    flen = struct.unpack_from('<I', buf, c+0x20)[0]
    fidx = struct.unpack_from('<I', buf, c+0x24)[0]
    dur  = struct.unpack_from('<I', buf, c+0x28)[0]
    nxt = anchors[k+1] if k+1 < len(anchors) else None
    ok = (nxt == a + flen) if nxt else None
    print(f'  anchor 0x{a:x}: flen={flen:<8} fidx={fidx:<7} dur={dur:<8} '
          f'next-match={ok}  (dist={nxt-a if nxt else None})')

# ---------- walk frames using the LE layout, starting from chunk 0x1000 ----------
def al(n, a=0x20): return (n + a - 1) // a * a

frames = []
fpos = 0x1000
guard = 0
while fpos + 0x2C <= len(buf) and guard < 100000:
    guard += 1
    if buf[fpos:fpos+4] != b'@SFV':
        fpos += 0x20
        continue
    flen = struct.unpack_from('<I', buf, fpos+0x20)[0]
    fidx = struct.unpack_from('<I', buf, fpos+0x24)[0]
    dur  = struct.unpack_from('<I', buf, fpos+0x28)[0]
    if flen == 0 or flen > 2_000_000 or fpos + 0x2C + flen > len(buf):
        # resync: jump to next @SFV
        nxt = buf.find(b'@SFV', fpos+0x20)
        if nxt < 0: break
        fpos = nxt
        continue
    frames.append((fpos, flen, fidx, dur))
    fpos = al(fpos + 0x2C + flen)

print(f'\nframes walked: {len(frames)}')
if frames:
    print(f'  index range: {frames[0][2]} .. {frames[-1][2]}')
    mono = sum(1 for k in range(1, len(frames)) if frames[k][2] > frames[k-1][2])
    print(f'  increasing index steps: {mono}/{len(frames)-1}')
    print(f'  total frame bytes: {sum(f[1] for f in frames)}')
    print(f'  first 10 (off, len, idx, dur):')
    for f in frames[:10]:
        print(f'    0x{f[0]:x} len={f[1]} idx={f[2]} dur={f[3]}')

# ---------- build IVF from the walked frames and test ----------
def build_ivf(path, sel):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, len(sel))
    out = bytearray(h)
    for i2, (o, flen, fidx, dur) in enumerate(sel):
        out += struct.pack('<IQ', flen, i2) + buf[o+0x2C:o+0x2C+flen]
    out += struct.pack('<I', len(sel))
    open(path, 'wb').write(out)
    return path

if frames:
    sel = frames[:2000]
    p = build_ivf(os.path.join(outdir, 'walk.ivf'), sel)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip().replace('\n', ' | ')
    print(f'\nwalk IVF ({len(sel)} frames) -> {"DECODE OK" if not err else err[:200]}')
