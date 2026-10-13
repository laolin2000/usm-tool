"""
Records ARE contiguous: sum(declared sizes) == span between first and last record.

=> Each @SFV record = one contiguous blob of the video stream. Reconstruct the IVF by
walking records in order and concatenating their payloads, then try to decode.

Also test whether each record corresponds to exactly ONE frame (4418 records vs 4412 frames
in the IVF header -- a near match!) which would make the layout trivial.
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
    fidx = struct.unpack_from('>I', buf, o+0x14)[0]
    if 0 < size < 4_000_000 and o + size <= len(buf):
        recs.append((o, size, fidx))
print(f'records={len(recs)}  IVF frames=4412')

# ---- are records contiguous? walk and compare ----
contig = 0
for i in range(len(recs) - 1):
    if recs[i][0] + recs[i][1] == recs[i+1][0]:
        contig += 1
print(f'contiguous record pairs: {contig}/{len(recs)-1}')

# ---- build IVF where each record = one frame (payload = whole record bytes) ----
def build(frames, label, hdr_count=None):
    h = bytearray(IVF_HDR)
    struct.pack_into('<I', h, 24, len(frames))
    out = bytearray(h)
    for i, f in enumerate(frames):
        out += struct.pack('<IQ', len(f), i)
        out += f
    out += struct.pack('<I', len(frames))
    p = os.path.join(workdir, label + '.ivf')
    open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip().replace('\n', ' | ')
    print(f'  {label}: {len(frames)} frames, {len(out)} bytes -> {"DECODE OK" if not err else err[:180]}')
    return p

print('\n=== attempt 1: each record = one IVF frame (whole record) ===')
build([buf[o:o+s] for o, s, _ in recs], 'rec_whole')

print('\n=== attempt 2: each record = one frame, payload only (skip 0x40 header) ===')
build([buf[o+0x40:o+s] for o, s, _ in recs], 'rec_payload')

print('\n=== attempt 3: skip the first 6 container records ===')
build([buf[o+0x40:o+s] for o, s, _ in recs[6:]], 'rec_payload_skip6')

print('\n=== attempt 4: stream = concat of all payloads (single big frame) ===')
allpay = b''.join(buf[o+0x40:o+s] for o, s, _ in recs[6:])
build([allpay], 'concat_single')

print('\n=== attempt 5: only records with size > 0x400 (real frames) ===')
big = [(o, s) for o, s, _ in recs if s > 0x400]
print(f'  {len(big)} big records')
build([buf[o+0x40:o+s] for o, s in big], 'big_only')
