"""
Records are 0x20-aligned: stride 128 with size 120 => 8 bytes of padding.
This script walks records with alignment, builds the video stream, and tests decoding.
"""
import sys, struct, re, os, subprocess

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0+32])

recs = []
for m in re.finditer(b'@SFV', buf):
    o = m.start()
    if o + 0x40 > len(buf): continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if 0 < size < 4_000_000 and o + size <= len(buf):
        recs.append((o, size))
print(f'records={len(recs)}')

def al(n, a=0x20): return (n + a - 1) // a * a

contig = sum(1 for i in range(len(recs)-1) if al(recs[i][0] + recs[i][1]) == recs[i+1][0])
print(f'aligned-contiguous pairs: {contig}/{len(recs)-1}')

def build(frames, label):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, len(frames))
    out = bytearray(h)
    for i, f in enumerate(frames):
        out += struct.pack('<IQ', len(f), i) + f
    out += struct.pack('<I', len(frames))
    p = os.path.join(workdir, label + '.ivf')
    open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip().replace('\n', ' | ')
    print(f'  {label}: {len(frames)}f {len(out)}B -> {"DECODE OK" if not err else err[:160]}')
    return p

# Reconstruct the stream as: for each record take bytes [o+0x28, o+size) then skip padding
print('\n=== stream built by taking each record payload from +0x28 (after 24B chunk hdr + 16B meta) ===')
pay = b''.join(buf[o+0x28:o+s] for o, s in recs)
build([pay], 'stream_from_28')

print('\n=== per-record frames using bytes [o+0x28, o+size) ===')
build([buf[o+0x28:o+s] for o, s in recs], 'rec_from_28')

print('\n=== per-record frames using [o+0x28, o+size) excluding tiny records ===')
big = [(o, s) for o, s in recs if s > 0x200]
build([buf[o+0x28:o+s] for o, s in big], 'big_from_28')

# Which record offsets have a size that EXACTLY equals the next record offset?
exact = [(recs[i][0], recs[i][1], recs[i+1][0]) for i in range(200) if recs[i][0]+recs[i][1] == recs[i+1][0]]
print(f'\nexact-fit pairs among first 200: {len(exact)}')
for o, s, n in exact[:5]:
    print(f'  0x{o:x} size=0x{s:x} -> next 0x{n:x}')
