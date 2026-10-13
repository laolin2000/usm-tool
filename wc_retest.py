"""
Final retest with the CORRECTED WannaCRI algorithm and CHUNK-level packet boundaries.

WannaCRI treats one USM chunk payload as one packet; earlier attempts used my own
(incorrect) 64-bit-word mask. Now that the rolling-32 rolling algorithm is correct,
retest with:
   A. packet = whole '@SFV' chunk body
   B. packet = dense region (0x1960 .. first trailing @SFV)
   C. packet = per inner frame (for reference)
"""
import sys, struct, os, subprocess

src = sys.argv[1]; outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
raw = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
sys.path.insert(0, r"C:\Users\<you>\Desktop\DSHStool\usm-tool\wannacri")
import types
stub = types.ModuleType('ffmpeg')
class _P:
    def __init__(self, *a, **k): pass
    def __getattr__(self, n): return lambda *a, **k: self
    def run(self, *a, **k): return (b'', b'')
stub.input = _P(); stub.output = _P(); stub.run = lambda *a, **k: (b'', b'')
stub.probe = lambda *a, **k: {}; stub.Error = Exception
sys.modules['ffmpeg'] = stub
from wannacri.usm.tools import generate_keys, decrypt_video_packet

def al(n, a=0x20): return (n + a - 1) // a * a
KEYSTR = '7F4551499DF55E68'
vk, ak = generate_keys(int(KEYSTR, 16))
print(f'video_key[:0x20] = {vk[:0x20].hex()}')

# chunk list
chunks, o = [], 0x800
while o + 0x20 <= len(raw):
    if raw[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', raw, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(raw): o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)
print(f'chunks: {len(chunks)}')

ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]
def test(items, label):
    if len(items) < 3: return
    hh = bytearray(ivf); struct.pack_into('<I', hh, 24, len(items))
    out = bytearray(hh)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, label + '.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    e = (r.stderr or '').strip()
    ok = not e
    print(f'  {label}: {len(items)} frames -> {"DECODE OK" if ok else e[:100]}', flush=True)
    if ok: os.replace(p, os.path.join(outdir, f'OK_{label}.ivf'))

# ---------- A: decrypt each chunk body as one packet ----------
print('\n=== A: chunk-body packets ===')
dec_chunks = []
for c, s in chunks:
    body = raw[c:c+s]
    if len(body) >= 0x240:
        dec_chunks.append(bytes(decrypt_video_packet(body, vk)))
    else:
        dec_chunks.append(body)
# extract inner frames from decrypted chunks
items = []
for (c, s), body in zip(chunks, dec_chunks):
    p = 0x20
    while p + 0x0C <= len(body):
        flen = struct.unpack_from('<I', body, p)[0]
        fidx = struct.unpack_from('<I', body, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(body): break
        items.append(body[p+0x0C:p+0x0C+flen])
        p = al(p + 0x0C + flen)
print(f'  frames from decrypted chunks: {len(items)}')
test(items[:400], 'A_chunk_400')
test(items, 'A_chunk_full')

# ---------- B: dense region as one packet ----------
print('\n=== B: dense region as one packet ===')
FIRST_TRAIL = next((c for c, s in chunks if c > 0x2000), None)
dense = raw[0x1960:FIRST_TRAIL]
print(f'  dense size {len(dense)} (0x{FIRST_TRAIL-0x1960:x})')
dd = decrypt_video_packet(dense, vk)
print(f'  changed={sum(1 for a,b in zip(dense, dd) if a!=b)}')
# assemble: plaintext head frames + decrypted dense as the rest
headf = [raw[0xF0C:0xF0C+262]]
for c, s in chunks:
    if c > 0x1900: break
    flen = struct.unpack_from('<I', raw, c+0x20)[0]
    if 0 < flen <= 1_500_000 and c+0x2C+flen <= len(raw):
        headf.append(raw[c+0x2C:c+0x2C+flen])
test(headf + [dd], 'B_dense')

# ---------- C: per inner frame (reference) ----------
print('\n=== C: per inner frame ===')
frames = []
for c, s in chunks:
    flen = struct.unpack_from('<I', raw, c+0x20)[0]
    fidx = struct.unpack_from('<I', raw, c+0x24)[0]
    if 0 < flen <= 1_500_000 and c+0x2C+flen <= len(raw):
        frames.append((fidx, c+0x2C, flen))
frames.sort()
outs = [raw[0xF0C:0xF0C+262]]
for fidx, off, fl in frames:
    p = raw[off:off+fl]
    outs.append(bytes(decrypt_video_packet(p, vk)) if fl >= 0x240 else p)
test(outs[:400], 'C_frame_400')
test(outs, 'C_frame_full')
