"""
Per-chunk inner frame walk.

Layout:
  chunk header  : '@SFV' + size(BE) + ... ; payload starts at chunk+0x20
  chunk payload : repeated { u32 LE frameLen, u32 LE frameIndex, u32 LE reserved,
                             VP9 frame data[frameLen] }
  The walk is 0x20-aligned, so padding may appear between frames.

Anchor proof: chunk 0x43ee0 + 0x20 -> flen=81246, fidx=60; the next keyframe anchor is at
chunk+0x2C and fidx increments by 60 across keyframes (60-frame GOP).
"""
import sys, struct, os, re, subprocess

src = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0+32])
SIG = b'\x82\x49\x83\x42'

def al(n, a=0x20): return (n + a - 1) // a * a

# ---- collect video chunks ----
chunks, o = [], 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)
print(f'video chunks: {len(chunks)}')

# ---- walk frames inside each chunk ----
frames = []
for c, size in chunks:
    end = c + size
    p = c + 0x20
    while p + 0x0C <= end:
        flen = struct.unpack_from('<I', buf, p)[0]
        fidx = struct.unpack_from('<I', buf, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(buf):
            break
        frames.append((p + 0x0C, flen, fidx))
        p = al(p + 0x0C + flen)
        if p + 0x0C > end:
            break

print(f'frames walked: {len(frames)}')
if frames:
    idxs = [f[2] for f in frames]
    print(f'  index range {idxs[0]}..{idxs[-1]}')
    mono = sum(1 for k in range(1, len(idxs)) if idxs[k] > idxs[k-1])
    print(f'  increasing steps {mono}/{len(idxs)-1}')
    print(f'  total bytes {sum(f[1] for f in frames)}')
    keyf = sum(1 for off, fl, _ in frames if buf[off:off+4] == SIG)
    print(f'  frames opening with VP9 keyframe sync: {keyf}')
    print('  largest frames:', sorted((f[1] for f in frames), reverse=True)[:8])
    print('  first 8:', [(hex(f[0]), f[1], f[2]) for f in frames[:8]])

def build_ivf(path, sel):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, len(sel))
    out = bytearray(h)
    for i, (off, fl, idx) in enumerate(sel):
        out += struct.pack('<IQ', fl, i) + buf[off:off+fl]
    out += struct.pack('<I', len(sel))
    open(path, 'wb').write(out)
    return path

if frames:
    for label, sel in [('first2000', frames[:2000]), ('all', frames)]:
        p = build_ivf(os.path.join(outdir, f'chunkwalk_{label}.ivf'), sel)
        r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                           capture_output=True, text=True, errors='replace')
        err = (r.stderr or '').strip().replace('\n', ' | ')
        print(f'\n{label} ({len(sel)} frames) -> {"DECODE OK" if not err else err[:200]}')
