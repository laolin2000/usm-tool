"""
Full extraction attempt with a supplied CRI key: 7F4551499DF55E68

Pipeline:
  1. walk '@SFV' video chunks (0x20-aligned, contiguous)
  2. walk inner frames: u32 LE length, u32 LE index, u32 reserved, then VP9 data
  3. apply the CRI rolling videomask to the chunk body
  4. assemble IVF and validate with ffmpeg
"""
import sys, struct, os, subprocess, re

src = sys.argv[1]
key = sys.argv[2]
outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
SIG = b'\x82\x49\x83\x42'

# ---------------- CRI videomask (exact port) ----------------
def derive_masks(key_hex):
    key = key_hex.rjust(16, '0') if len(key_hex) <= 16 else key_hex
    k1 = bytes.fromhex(key[8:]); k2 = bytes.fromhex(key[:8])
    t = bytearray(0x20)
    t[0:9] = [k1[3], k1[2], k1[1], (k1[0]-0x34) % 256, (k2[3]+0xF9) % 256,
              (k2[2] ^ 0x13) % 256, (k2[1]+0x61) % 256, (k1[3] ^ 0xFF) % 256, (k1[1]+k1[2]) % 256]
    t[9:12] = [(t[1]-t[7]) % 256, (t[2] ^ 0xFF) % 256, (t[1] ^ 0xFF) % 256]
    t[12:14] = [(t[11]+t[9]) % 256, (t[8]-t[3]) % 256]
    t[14:16] = [(t[13] ^ 0xFF) % 256, (t[10]-t[11]) % 256]
    t[16] = (t[8]-t[15]) % 256
    t[17:23] = [(t[16] ^ t[7]) % 256, (t[15] ^ 0xFF) % 256, (t[3] ^ 0x10) % 256,
                (t[4]-0x32) % 256, (t[5]+0xED) % 256, (t[6] ^ 0xF3) % 256]
    t[23:26] = [(t[19]-t[15]) % 256, (t[21]+t[7]) % 256, (0x21-t[19]) % 256]
    t[26:28] = [(t[20] ^ t[23]) % 256, (t[22]+t[22]) % 256]
    t[28:31] = [(t[23]+0x44) % 256, (t[3]+t[4]) % 256, (t[5]-t[22]) % 256]
    t[31] = (t[29] ^ t[19]) % 256
    return bytes(t), bytes(x ^ 0xFF for x in t)

def mask_body(body, v1, v2, head_len=0x40):
    """CRI VideoMask: keep body[:head_len] verbatim, roll the 64-bit mask over the rest."""
    n = len(body)
    if n <= 0x200:
        return bytes(body)
    head = bytes(body[:head_len])
    rest = body[head_len:]
    nr = len(rest)
    nq = nr // 8
    if nq < 33:
        return bytes(body)
    dq = list(struct.unpack_from('<%dQ' % nq, rest, 0))
    m2 = list(struct.unpack('<4Q', v2)); v2q = list(struct.unpack('<4Q', v2))
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]; m2[j] = dq[i] ^ v2q[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        if i + 32 >= nq: break
        j = i % 4
        m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
    return head + struct.pack('<%dQ' % nq, *dq) + rest[nq*8:]

def al(n, a=0x20): return (n + a - 1) // a * a

# ---------------- walk chunks ----------------
chunks, o = [], 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)
print(f'key: {key}')
print(f'video chunks: {len(chunks)}')
v1, v2 = derive_masks(key)
print(f'mask1: {v1.hex()}')
print(f'mask2: {v2.hex()}')

def walk_frames(blob, base):
    out, p = [], 0x20
    while p + 0x0C <= len(blob):
        flen = struct.unpack_from('<I', blob, p)[0]
        fidx = struct.unpack_from('<I', blob, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(blob): break
        out.append((base + p + 0x0C, flen, fidx))
        p = al(p + 0x0C + flen)
    return out

# ---------- strategy A: mask per chunk ----------
framesA = []
for c, s in chunks:
    masked = mask_body(buf[c:c+s], v1, v2)
    framesA += walk_frames(masked, c)
    # keep the masked bytes for assembly
print(f'\nA) per-chunk mask -> {len(framesA)} frames')

# ---------- strategy B: mask the whole video body once ----------
# body starts at the first chunk; head is the FIRST chunk's header only
first = chunks[0][0] if chunks else 0x800
whole = buf[first:]
masked_whole = mask_body(whole, v1, v2)
print(f'B) whole-body mask -> body {len(whole)} bytes (head kept = {0x40})')

def build_and_test(items, label, ivf_hdr):
    if not items: return None
    h = bytearray(ivf_hdr); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, (data) in enumerate(items):
        out += struct.pack('<IQ', len(data), i) + data
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, label + '.ivf')
    open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip().replace('\n', ' | ')
    print(f'   {label}: {len(items)} frames, {len(out)} bytes -> {"DECODE OK" if not err else err[:150]}')
    return p

ivf_hdr = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]
print(f'IVF header: {ivf_hdr.hex(" ")}')

# assemble strategy A frames (need the masked chunk data)
framesA_items = []
for c, s in chunks:
    masked = mask_body(buf[c:c+s], v1, v2)
    for off, fl, idx in walk_frames(masked, c):
        rel = off - c
        framesA_items.append(masked[rel:rel+fl])
build_and_test(framesA_items, 'key_A_perchunk', ivf_hdr)

# quick single-frame check on masked output
if framesA_items:
    build_and_test(framesA_items[:80], 'key_A_first80', ivf_hdr)

# ---------- also check key preprocessing variants ----------
print('\n=== key variant sweep (first 200 frames, per-chunk mask) ===')
variants = {
    'as-given': key,
    'swapped-halves': key[8:] + key[:8],
    'reversed-bytes': ''.join(reversed([key[i:i+2] for i in range(0, 16, 2)])),
}
for name, k in variants.items():
    try:
        a1, a2 = derive_masks(k)
    except Exception as e:
        print(f'  {name}: bad key {e}'); continue
    items = []
    for c, s in list(chunks)[:60]:
        masked = mask_body(buf[c:c+s], a1, a2)
        for off, fl, idx in walk_frames(masked, c):
            rel = off - c
            items.append(masked[rel:rel+fl])
    build_and_test(items, f'key_{name}', ivf_hdr)
