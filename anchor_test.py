"""
73 of the 74 '82 49 83 42' (VP9 keyframe sync) occurrences sit at chunk+0x2C.
So chunk+0x2C IS the frame start. Use the sync-code positions as keyframe anchors and
verify by feeding each candidate keyframe to ffmpeg.
"""
import sys, struct, os, subprocess, re

src = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0 + 32])
SIG = b'\x82\x49\x83\x42'

def al(n, a=0x20): return (n + a - 1) // a * a

# chunk list
chunks, o = [], 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)

# keyframe anchors
anchors = []
i = buf.find(SIG)
while i != -1:
    anchors.append(i); i = buf.find(SIG, i+1)
print(f'keyframe anchors: {len(anchors)}')
for a in anchors[:6]:
    owner = next((c for c, s in chunks if c <= a < c+s), None)
    print(f'  0x{a:x} owner=0x{owner:x} rel=0x{a-owner:x}' if owner else f'  0x{a:x} no owner')

# Probe: each anchor as a standalone frame, sized generously (up to next anchor).
def probe_frame(off, length, label):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, 1)
    blob = bytes(h) + struct.pack('<IQ', length, 0) + buf[off:off+length]
    p = os.path.join(outdir, label + '.ivf')
    open(p, 'wb').write(blob)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    return (r.stderr or '').strip().replace('\n', ' | ')

print('\n=== probe the first 8 anchors as standalone keyframes ===')
for k, a in enumerate(anchors[:8]):
    nxt = anchors[k+1] if k+1 < len(anchors) else a + 0x4000
    ln = min(nxt - a, 0x40000)
    err = probe_frame(a, ln, f'anchor{k}')
    print(f'  anchor 0x{a:x} len={ln} -> {"OK" if not err else err[:110]}')

# Also probe a few frames just after each chunk payload start (chunk+0x20) in case the
# frame header is smaller than assumed.
print('\n=== probe chunk+0x20 / +0x24 / +0x28 / +0x2C as frame starts (first 5 chunks) ===')
for c, s in chunks[6:11]:
    for rel in (0x20, 0x24, 0x28, 0x2C):
        ln = min(s - rel, 0x4000)
        if ln <= 0: continue
        err = probe_frame(c + rel, ln, f'c{c:x}_{rel:x}')
        if not err:
            print(f'  *** chunk 0x{c:x} +0x{rel:x} DECODES ({ln} bytes)')
