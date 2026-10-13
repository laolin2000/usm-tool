"""
CRI chunk layout, per the manalogues analysis:
   +0x00 magic 4B ('@SFV'/'@SFA'/'@UTF'/'CRID')
   +0x04 payload size 4B BE
   +0x08 payload offset 4B (relative to chunk start)
   +0x0C frame time 4B
   +0x10 frame index 4B
   +0x14 framerate*100 4B
   +0x18 zzz 4B | +0x1C zzz 4B
   +0x20 pad/size 4B | +0x24 pad 4B
   +0x28 ... payload
Records are 0x20-aligned contiguous. Extract payloads of the VIDEO chunks and decode.
"""
import sys, struct, re, os, subprocess

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0+32])

def al(n, a=0x20): return (n + a - 1) // a * a

# ---- walk chunks properly, using the declared payload offset ----
chunks = []
o = 0x800
while o + 8 <= len(buf):
    magic = buf[o:o+4]
    if magic not in (b'@SFV', b'@SFA', b'@UTF', b'@ALP', b'@SBT', b'CRID'):
        o += 0x20
        continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    poff = struct.unpack_from('>I', buf, o+8)[0]
    if size == 0 or size > 4_000_000 or o + size > len(buf):
        o += 0x20
        continue
    chunks.append((o, size, poff, magic))
    o = al(o + size)

types = {}
for o, s, p, m in chunks: types[m] = types.get(m, 0) + 1
print(f'chunks walked: {len(chunks)}  types: { {k.decode(): v for k, v in types.items()} }')
print('payload offsets seen:', {p: sum(1 for c in chunks if c[2] == p) for p in set(c[2] for c in chunks)})

sfv = [(o, s, p) for o, s, p, m in chunks if m == b'@SFV']
print(f'@SFV chunks: {len(sfv)}')

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
    print(f'  {label}: {len(frames)}f {len(out)}B -> {"DECODE OK" if not err else err[:150]}')

# payload begins at chunk+poff (relative). Try both interpretations.
for offmode in ['declared', 'fixed28', 'fixed40']:
    pays = []
    for o, s, poff in sfv:
        start = o + (poff if offmode == 'declared' else (0x28 if offmode == 'fixed28' else 0x40))
        if start < o + s:
            pays.append(buf[start:o+s])
    print(f'\n=== mode {offmode}: {len(pays)} payloads, {sum(len(x) for x in pays)} bytes ===')
    build(pays, 'p_' + offmode)
    build([b''.join(pays)], 'stream_' + offmode)
