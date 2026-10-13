"""
Corrected grid search + frame-length sweep, using the VP9 keyframe anchors.

Also dumps the raw header bytes at each anchor's owning chunk so the field layout can be
read directly instead of assumed.
"""
import sys, struct, os, subprocess

src = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0+32])
SIG = b'\x82\x49\x83\x42'

def test(data):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, 1)
    p = os.path.join(outdir, 'g.ivf')
    open(p, 'wb').write(bytes(h) + struct.pack('<IQ', len(data), 0) + data)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    return not (r.stderr or '').strip()

anchors = []
i = buf.find(SIG)
while i != -1:
    anchors.append(i); i = buf.find(SIG, i+1)
print(f'anchors: {len(anchors)}')
for a in anchors[:10]:
    print(f'  0x{a:x}')

# --- read the chunk header of the first few anchors ---
print('\n=== header bytes at chunks owning anchors 1..5 (chunk+0x2C == anchor) ===')
for a in anchors[1:6]:
    c = a - 0x2C
    print(f'\n chunk 0x{c:x} (anchor 0x{a:x}):')
    for r in range(0, 0x40, 16):
        print(f'   +0x{r:02x}: {buf[c+r:c+r+16].hex(" ")}')

# --- frame-length sweep on an anchor: find a length that decodes ---
print('\n=== length sweep: does ANY length make the anchor decodable? ===')
A = anchors[1]
best = []
for ln in [0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000,
           0x20000, 0x40000, 0x80000, 0x100000, 0x200000]:
    if A + ln > len(buf): break
    ok = test(buf[A:A+ln])
    best.append((ln, ok))
    print(f'  len=0x{ln:<7x} -> {"DECODE OK" if ok else "fail"}')

# --- also sweep whether including preceding bytes helps (frame may start earlier) ---
print('\n=== start-offset sweep around an anchor ===')
for delta in [-0x2C, -0x28, -0x24, -0x20, -0x10, 0, 0x2C, 0x40]:
    s = A + delta
    if s < 0 or s + 0x8000 > len(buf): continue
    ok = test(buf[s:s+0x8000])
    print(f'  start=anchor{delta:+#x} -> {"DECODE OK" if ok else "fail"}')
