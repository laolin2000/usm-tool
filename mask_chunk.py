"""
CRI mask is applied PER CHUNK (body = bytes after the chunk header), not per frame.

Test: take each video chunk, mask its body [0x20:] with the CRI videomask, then re-walk the
inner frames and check whether their VP9 headers become valid (byte1 bit patterns) and
whether ffmpeg decodes.

Also brute-forces a small set of plausible keys.
"""
import sys, struct, os, subprocess, itertools

src = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0+32])

# ---------------- CRI mask ----------------
def derive_masks(key_hex):
    key = key_hex.rjust(16, '0')
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

def mask_body(body, v1, v2):
    n = len(body)
    if n <= 0x200:
        return body
    nq = n // 8
    dq = list(struct.unpack_from('<%dQ' % nq, body, 0))
    m2 = list(struct.unpack('<4Q', v2)); v2q = list(struct.unpack('<4Q', v2))
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]; m2[j] = dq[i] ^ v2q[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        if i + 32 >= nq: break
        j = i % 4
        m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
    return struct.pack('<%dQ' % nq, *dq) + body[nq*8:]

def al(n, a=0x20): return (n + a - 1) // a * a

chunks, o = [], 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)
print(f'chunks: {len(chunks)}')

def walk_frames(blob, start=0x20):
    """walk inner frames in a masked/unmasked chunk body"""
    out = []
    p = start
    while p + 0x0C <= len(blob):
        flen = struct.unpack_from('<I', blob, p)[0]
        fidx = struct.unpack_from('<I', blob, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(blob):
            break
        out.append((p + 0x0C, flen, fidx))
        p = al(p + 0x0C + flen)
    return out

# --- quality metric: fraction of frames whose byte1 is a valid VP9 frame-type header ---
def quality(frames, blob):
    good = 0
    for off, fl, idx in frames:
        if off + 2 > len(blob): continue
        b1 = blob[off+1]
        # VP9 uncompressed header: show_existing_frame(1) => 1; else frame_type(1) etc.
        # valid patterns are common for 0x00/0x01/0x04/0x05/0x08/0x09/0x14/0x15 ...
        if (b1 & 0xF0) in (0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70) and b1 < 0x90:
            good += 1
    return good / max(len(frames), 1)

print('\n=== baseline (no mask) on first 40 chunks ===')
base_frames = []
for c, s in chunks[6:46]:
    base_frames += [(c + off, fl, idx) for off, fl, idx in walk_frames(buf[c:c+s])]
print(f'  frames={len(base_frames)} byte1-quality={quality([(0,f,i) for _,f,i in base_frames], buf):.3f}')

KEYS = ['0000000000000000', 'FFFFFFFFFFFFFFFF', '0123456789ABCDEF']
for key in KEYS:
    v1, v2 = derive_masks(key)
    # mask each chunk body then walk
    fr = []
    for c, s in chunks[6:46]:
        body = mask_body(buf[c+0x20:c+s], v1, v2)
        chunk = buf[c:c+0x20] + body
        fr += [(c + off, fl, idx) for off, fl, idx in walk_frames(chunk)]
    print(f'  key={key}: frames={len(fr)} quality={quality([(0,f,i) for _,f,i in fr], buf):.3f}')

# --- build IVF from masked chunks and try decoding (zero key) ---
print('\n=== build IVF from masked chunks (zero key) and decode ===')
v1, v2 = derive_masks('0000000000000000')
items = []
for c, s in chunks:
    body = mask_body(buf[c+0x20:c+s], v1, v2)
    chunk = buf[c:c+0x20] + body
    for off, fl, idx in walk_frames(chunk):
        items.append((c + off, chunk[off:off+fl]))
print(f'  frames: {len(items)}')
h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, len(items))
out = bytearray(h)
for i, (_, d) in enumerate(items):
    out += struct.pack('<IQ', len(d), i) + d
out += struct.pack('<I', len(items))
p = os.path.join(outdir, 'masked_zero.ivf')
open(p, 'wb').write(out)
r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                   capture_output=True, text=True, errors='replace')
print('  decode ->', (r.stderr or '').strip().replace('\n', ' | ')[:200] or 'DECODE OK')
