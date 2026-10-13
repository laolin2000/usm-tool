"""
Extended sweep with the supplied key: also vary the mask RESET GRANULARITY.

The container applies the rolling mask per "block"; we don't know the block unit. Try
0x200 .. 0x20000 with head lengths 0x20/0x40/0x00, whole-video scope, and report which
combination makes the VP9 stream parse cleanly.
"""
import sys, struct, os, subprocess

src = sys.argv[1]; key = sys.argv[2]; outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

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

def mask_block(block, v1, v2, head_len):
    """apply the rolling mask to one block, keeping block[:head_len] verbatim"""
    n = len(block)
    if n <= head_len + 0x100: return bytes(block)
    head = bytes(block[:head_len]); rest = block[head_len:]
    nq = len(rest) // 8
    if nq < 33: return bytes(block)
    dq = list(struct.unpack_from('<%dQ' % nq, rest, 0))
    m2 = list(struct.unpack('<4Q', v2)); v2q = list(struct.unpack('<4Q', v2))
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]; m2[j] = dq[i] ^ v2q[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        if i+32 >= nq: break
        j = i % 4
        m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
    return head + struct.pack('<%dQ' % nq, *dq) + rest[nq*8:]

def al(n, a=0x20): return (n + a - 1) // a * a

chunks, o = [], 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf): o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)

def walk_frames(blob, base, start=0x20):
    out, p = [], start
    while p + 0x0C <= len(blob):
        flen = struct.unpack_from('<I', blob, p)[0]
        fidx = struct.unpack_from('<I', blob, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(blob): break
        out.append((base + p + 0x0C, flen, p))
        p = al(p + 0x0C + flen)
    return out

ivf_hdr = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]
# skip container/metadata chunks: the video stream starts at the first chunk whose body
# contains a valid inner-frame header (u32 LE length followed by a small index).
def is_video_chunk(c, s):
    if s < 0x40: return False
    flen = struct.unpack_from('<I', buf, c + 0x20)[0]
    fidx = struct.unpack_from('<I', buf, c + 0x24)[0]
    return 0 < flen <= 1_500_000 and c + 0x2C + flen <= len(buf) and 0 < fidx < 100000

vid = [(c, s) for c, s in chunks if is_video_chunk(c, s)]
FIRST = vid[0][0] if vid else chunks[0][0]
print(f'video chunks with valid inner frame header: {len(vid)}; FIRST=0x{FIRST:x}', flush=True)

def build_and_test(items, label, save_on_ok=True):
    if len(items) < 20: return False
    items = items[:4000]
    h = bytearray(ivf_hdr); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, 'probe.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip()
    if not err:
        print(f'  *** DECODE OK: {label} ({len(items)} frames) ***', flush=True)
        if save_on_ok: os.replace(p, os.path.join(outdir, f'OK_{label}.ivf'))
        return True
    return False

v1, v2 = derive_masks(key)
print(f'key={key}', flush=True)
results = []
# limit to first 3 MB of video for speed
LIMIT = FIRST + 0x300000
use_chunks = [(c, s) for c, s in chunks if c < LIMIT]

for gran in (0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0):
    for head in (0x00, 0x20, 0x40):
        body = bytearray(buf[FIRST:FIRST + 0x300000])
        if gran == 0:
            masked = mask_block(bytes(body), v1, v2, head)
            m = bytearray(masked)
        else:
            m = bytearray(body)
            for s0 in range(0, len(body), gran):
                blk = mask_block(bytes(body[s0:s0+gran]), v1, v2, head)
                m[s0:s0+len(blk)] = blk
        items = [bytes(m[off-FIRST:off-FIRST+fl]) for off, fl, rel in walk_frames(m, FIRST, 0x20)]
        ok = build_and_test(items, f'g{gran:x}_h{head:x}')
        print(f'  gran=0x{gran:x} head=0x{head:x}: frames={len(items)} {"OK" if ok else "no"}', flush=True)
        if ok: results.append((gran, head))

print('\n*** SUCCESSES:', results if results else 'none ***', flush=True)
