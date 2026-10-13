"""
Extract plaintext VP9 frames from the USM by following the per-frame header.

Layout (verified against the 4417 '@SFV' video chunks):
    chunk+0x00  '@SFV' magic                      (4B)
    chunk+0x04  chunk/payload size, big-endian    (4B)
    chunk+0x08..0x20  chunk meta                  (24B, payload starts at chunk+0x20)
    chunk+0x20  frame byte count                  (4B BE)
    chunk+0x24  frame index                       (4B BE)
    chunk+0x28  duration ms                       (4B BE)
    chunk+0x2C  VP9 bitstream -------------------> (frameLen bytes)
Then the next frame header follows immediately.

Sanity anchor: the VP9 keyframe sync code 82 49 83 42 appears at chunk+0x2C for keyframes
(the subagent reported all 78 occurrences landing exactly there).
"""
import sys, struct, os, re, subprocess

src = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0 + 32])

def al(n, a=0x20): return (n + a - 1) // a * a

# ---------- locate the video chunks ----------
chunks = []
o = 0x800
while o + 0x20 <= len(buf):
    if buf[o:o + 4] != b'@SFV':
        o += 0x20
        continue
    size = struct.unpack_from('>I', buf, o + 4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20
        continue
    chunks.append((o, size))
    o = al(o + size)
print(f'video chunks: {len(chunks)}')

# ---------- check the keyframe-sync invariant ----------
sig = b'\x82\x49\x83\x42'
at_2c = at_0c = other = 0
offsets = []
i = buf.find(sig)
while i != -1:
    offsets.append(i)
    i = buf.find(sig, i + 1)
for p in offsets:
    # find owning chunk
    owner = None
    for c, s in chunks:
        if c <= p < c + s:
            owner = (c, s)
            break
    if owner:
        rel = p - owner[0]
        if rel == 0x2C: at_2c += 1
        elif rel == 0x0C: at_0c += 1
        else: other += 1
    else:
        other += 1
print(f'82 49 83 42 occurrences: total={len(offsets)} at chunk+0x2C={at_2c} at chunk+0x0C={at_0c} elsewhere={other}')

# ---------- slice frames by walking frame headers ----------
frames = []
fpos = 0x800
guard = 0
while fpos + 0x2C <= len(buf) and guard < 200000:
    guard += 1
    if buf[fpos:fpos + 4] != b'@SFV':
        # resync to the next chunk
        nxt = None
        for c, s in chunks:
            if c > fpos: nxt = c; break
        if nxt is None: break
        fpos = nxt
        continue
    flen = struct.unpack_from('>I', buf, fpos + 0x20)[0]
    fidx = struct.unpack_from('>I', buf, fpos + 0x24)[0]
    dur  = struct.unpack_from('>I', buf, fpos + 0x28)[0]
    if flen == 0 or flen > 4_000_000 or fpos + 0x2C + flen > len(buf):
        nxt = None
        for c, s in chunks:
            if c > fpos: nxt = c; break
        if nxt is None: break
        fpos = nxt
        continue
    frames.append((fpos, flen, fidx, dur, buf[fpos + 0x2C:fpos + 0x2C + flen]))
    fpos = fpos + 0x2C + flen

print(f'frames sliced: {len(frames)}')
print(f'  total bytes : {sum(f[1] for f in frames)}')
print(f'  frame indices: first={[f[2] for f in frames[:8]]} last={[f[2] for f in frames[-4:]]}')
print(f'  first frame lens: {[f[1] for f in frames[:10]]}')
keyf = sum(1 for f in frames if f[4][:4] == sig)
print(f'  frames starting with VP9 keyframe sync: {keyf}')

# ---------- build IVF ----------
def build_ivf(frs, path):
    h = bytearray(IVF_HDR)
    struct.pack_into('<I', h, 24, len(frs))
    out = bytearray(h)
    for i, (_, flen, fidx, dur, data) in enumerate(frs):
        out += struct.pack('<IQ', len(data), i) + data
    out += struct.pack('<I', len(frs))
    open(path, 'wb').write(out)
    return path

sel = frames[:400]
p = build_ivf(sel, os.path.join(outdir, 'test_start.ivf'))
r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                   capture_output=True, text=True, errors='replace')
err = (r.stderr or '').strip().replace('\n', ' | ')
print(f'\ntest IVF ({len(sel)} frames): {"DECODE OK" if not err else err[:300]}')

# count how many frames actually decode
r2 = subprocess.run([FFMPEG, '-v', 'error', '-i', p, '-f', 'null', '-'],
                    capture_output=True, text=True, errors='replace')
m = re.findall(r'frame=\s*(\d+)', r2.stderr or '')
print('  decoded frames reported:', m[-1] if m else 'n/a')
