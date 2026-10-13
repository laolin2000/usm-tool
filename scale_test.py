"""
The frame-length field (chunk+0x20) may be in a scaled unit. Derive the true unit by
requiring the slice to land on the next keyframe anchor AND decode with ffmpeg.

Anchors (VP9 sync 82 49 83 42) are known-good frame starts:
   0x43f0c, 0xd9e4c, 0x1e89cc, ...
So: from anchor A, next anchor B; frameLen must satisfy A + hdr + scale*field = B for the
correct scale/semantics.
"""
import sys, struct, os, subprocess

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

print('=== frame field at each anchor chunk, with distance to next anchor ===')
for k, a in enumerate(anchors[:8]):
    c = a - 0x2C
    f20 = struct.unpack_from('>I', buf, c + 0x20)[0]
    f24 = struct.unpack_from('>I', buf, c + 0x24)[0]
    nxt = anchors[k+1] if k + 1 < len(anchors) else None
    dist = (nxt - a) if nxt else None
    print(f'  anchor 0x{a:x}: field@+20=0x{f20:x} ({f20})  field@+24=0x{f24:x} ({f24})  '
          f'next=0x{nxt:x} dist=0x{dist:x} ({dist})' if nxt else
          f'  anchor 0x{a:x}: field@+20=0x{f20:x} field@+24=0x{f24:x} (last)')

def test(data):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, 1)
    open(os.path.join(outdir, 'g.ivf'), 'wb').write(bytes(h) + struct.pack('<IQ', len(data), 0) + data)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', os.path.join(outdir, 'g.ivf'),
                        '-f', 'null', '-'], capture_output=True, text=True, errors='replace')
    return not (r.stderr or '').strip()

# --- try scales: treat field@+0x20 as a length in units of `scale` bytes, plus header ---
print('\n=== scale sweep: slice from anchor 1 and try to decode ===')
A = anchors[1]
C = A - 0x2C
f20 = struct.unpack_from('>I', buf, C + 0x20)[0]
print(f'anchor 0x{A:x} field=0x{f20:x}={f20}')
for scale in [1, 2, 4, 8, 16, 0x20, 0x40, 0x100, 0x200, 1/8, 1/4, 1/2]:
    ln = int(f20 * scale) if isinstance(scale, float) else f20 * scale
    if ln <= 0 or A + ln > len(buf): 
        print(f'  scale={scale}: len={ln} out of range')
        continue
    ok = test(buf[A:A+ln])
    print(f'  scale={scale!r:>8}: len={ln:<9} -> {"DECODE OK" if ok else "fail"}')

# --- maybe the field is the frame size of the frame ENDING at this anchor ---
print('\n=== alternative: chunk size field (+0x04) semantics ===')
for k, a in enumerate(anchors[:4]):
    c = a - 0x2C
    csize = struct.unpack_from('>I', buf, c + 4)[0]
    print(f'  anchor 0x{a:x} chunk=0x{c:x} chunkSize=0x{csize:x} ({csize})')

# --- Try: take the whole span between two anchors as one frame ---
print('\n=== try span between anchor1 and anchor2 as a single frame ===')
sp = anchors[2] - anchors[1]
print(f'  span = 0x{sp:x} ({sp})')
print('  decode ->', 'OK' if test(buf[anchors[1]:anchors[2]]) else 'fail')
