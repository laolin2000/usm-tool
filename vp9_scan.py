"""
VP9 profile-0 keyframe signature (82 49 83 42) scan + ffmpeg validation of each hit.
0xF0C (frame 0) matched this signature, so hits are real frame starts.
"""
import sys, struct, os, subprocess

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = buf[0xEE0:0xEE0+32]

hits = []
i = buf.find(b'\x82\x49\x83\x42')
while i != -1:
    hits.append(i)
    i = buf.find(b'\x82\x49\x83\x42', i + 1)
print(f'keyframe-signature hits: {len(hits)}')
print('  first 20:', [hex(x) for x in hits[:20]])
if len(hits) > 1:
    strides = [hits[k+1]-hits[k] for k in range(min(len(hits)-1, 30))]
    print('  strides:', strides)

def test_frame(offset, length, label):
    h = bytearray(IVF_HDR)
    struct.pack_into('<I', h, 24, 1)
    blob = bytes(h) + struct.pack('<IQ', length, 0) + buf[offset:offset+length]
    p = os.path.join(workdir, label + '.ivf')
    open(p, 'wb').write(blob)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True)
    err = (r.stderr or '').strip().replace('\n', ' | ')
    return 'OK' if not err else err[:110]

print('\n=== validate first hits as standalone keyframes ===')
for k, p in enumerate(hits[:10]):
    nxt = hits[k+1] if k+1 < len(hits) else None
    length = (nxt - p) if nxt else 0x10000
    print(f'  0x{p:x} len={length} -> {test_frame(p, min(length, 0x20000), f"kf{k}")}')

# If the hits are dense (every frame), their spacing tells us the frame sizes.
if len(hits) > 200:
    import collections
    c = collections.Counter(hits[k+1]-hits[k] for k in range(len(hits)-1))
    print('\n=== stride histogram (top 15) ===')
    for s, n in c.most_common(15):
        print(f'  {s:8d} x{n}')
