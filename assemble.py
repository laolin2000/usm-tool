"""
Final assembly: prepend frame 0 (the plaintext keyframe at 0xF0C) and decode the whole
4412-frame set. Also dump the first frames to inspect their bitstream headers.
"""
import sys, struct, os, subprocess, re

src = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0+32])
SIG = b'\x82\x49\x83\x42'

def al(n, a=0x20): return (n + a - 1) // a * a

chunks, o = [], 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)

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
        if p + 0x0C > end: break

print(f'frames: {len(frames)}')
print('\n=== raw header of the first 3 frames ===')
for off, fl, idx in frames[:3]:
    print(f'  frame idx={idx} len={fl}')
    print(f'    hdr-16: {buf[off-16:off].hex(" ")}')
    print(f'    data  : {buf[off:off+48].hex(" ")}')

print('\n=== frame size profile (every 250th frame) ===')
for k in range(0, len(frames), 250):
    off, fl, idx = frames[k]
    print(f'  idx={idx:<5} len={fl:<8} first4={buf[off:off+4].hex(" ")}')

def build(path, items):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, (off, ln) in enumerate(items):
        out += struct.pack('<IQ', ln, i) + buf[off:off+ln]
    out += struct.pack('<I', len(items))
    open(path, 'wb').write(out)
    return path

def dec(path):
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', path, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    return (r.stderr or '').strip().replace('\n', ' | ')

# variant A: frames 1..N with frame 0 prepended
itemsA = [(0xF0C, 262)] + [(off, fl) for off, fl, _ in frames]
pA = build(os.path.join(outdir, 'with_frame0.ivf'), itemsA)
print(f'\nA) with frame 0 prepended ({len(itemsA)} frames): {dec(pA)[:200] or "DECODE OK"}')

# variant B: frames only
itemsB = [(off, fl) for off, fl, _ in frames]
pB = build(os.path.join(outdir, 'frames_only.ivf'), itemsB)
print(f'B) frames only ({len(itemsB)} frames): {dec(pB)[:200] or "DECODE OK"}')

# variant C: just the first 400 frames after frame 0 (to read errors clearly)
itemsC = [(0xF0C, 262)] + [(off, fl) for off, fl, _ in frames[:400]]
pC = build(os.path.join(outdir, 'first400.ivf'), itemsC)
print(f'C) frame0 + first 400: {dec(pC)[:300] or "DECODE OK"}')

# count decodable frames
r = subprocess.run([FFMPEG, '-v', 'error', '-i', pA, '-f', 'null', '-'],
                   capture_output=True, text=True, errors='replace')
m = re.findall(r'frame=\s*(\d+)', r.stderr or '')
print('\nfull-run decoder progress:', m[-1] if m else 'n/a')
