"""
Find the first failing frame in the FULL decrypted stream.

Also test whether the mask scope changes partway: try masking only up to N, or restart
the mask state at the '@SFV' chunk boundaries that occur inside the encrypted region.
"""
import sys, struct, os, subprocess

src = sys.argv[1]; key = sys.argv[2]; outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
raw = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

def derive_masks(key_hex):
    k = key_hex.rjust(16, '0')
    k1 = bytes.fromhex(k[8:]); k2 = bytes.fromhex(k[:8])
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

def mask_buf(data, v1, v2, off=0, head=0):
    seg = data[off:]
    n = len(seg)
    if n <= head + 0x100: return data
    dq = list(struct.unpack_from('<%dQ' % ((n-head)//8), data, off+head))
    nq = len(dq)
    if nq < 33: return data
    v2q = list(struct.unpack('<4Q', v2)); m2 = list(v2q)
    for i in range(32, nq):
        j = i & 3
        dq[i] ^= m2[j]; m2[j] = dq[i] ^ v2q[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        if i+32 >= nq: break
        j = i & 3
        m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
    struct.pack_into('<%dQ' % nq, data, off+head, *dq)
    return data

def al(n, a=0x20): return (n + a - 1) // a * a

# frame table from the ORIGINAL bytes
chunks = []
o = 0x800
while o + 0x20 <= len(raw):
    if raw[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', raw, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(raw): o += 0x20; continue
    flen = struct.unpack_from('<I', raw, o+0x20)[0]
    fidx = struct.unpack_from('<I', raw, o+0x24)[0]
    if 0 < flen <= 1_500_000 and o + 0x2C + flen <= len(raw):
        chunks.append((fidx, o+0x2C, flen, o))
    o = al(o + size)
chunks.sort()
print(f'frames: {len(chunks)}')

# where does the encrypted region actually start? find last plaintext frame
print('\n=== plaintext check on a few frames (raw bytes) ===')
def looks_vp9(d):
    return len(d) > 3 and (d[0] & 0x03) == 2
for k in (0, 20, 23, 24, 25, 100, 500, 1000, 2000, 3000, 4000):
    if k < len(chunks):
        fidx, off, fl, _ = chunks[k]
        print(f'  idx={fidx:<5} off=0x{off:x} head={raw[off:off+6].hex(" ")} {"VP9-like" if looks_vp9(raw[off:off+4]) else "?"}')

ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]
v1, v2 = derive_masks(key)

def build_items(dec, n):
    items = [(0xF0C, 262)]
    for fidx, off, fl, _ in chunks[:n]:
        items.append((off, fl))
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, (o2, fl) in enumerate(items):
        out += struct.pack('<IQ', fl, i) + bytes(dec[o2:o2+fl])
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, 'p.ivf'); open(p, 'wb').write(out)
    return p

def dec_ok(p):
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    return not (r.stderr or '').strip()

dec = mask_buf(bytearray(raw), v1, v2, off=0x1960, head=0)
print('\n=== bisect first failing frame index in the FULL stream ===')
lo, hi = 1, len(chunks)
while lo < hi:
    mid = (lo + hi) // 2
    if dec_ok(build_items(dec, mid)):
        lo = mid + 1
    else:
        hi = mid
print(f'  first failing position: {lo}  (frame idx {chunks[lo-1][0] if lo-1 < len(chunks) else "?"})')
if 1 < lo <= len(chunks):
    fidx, off, fl, chunkoff = chunks[lo-1]
    print(f'  failing frame: idx={fidx} off=0x{off:x} len={fl} chunk@0x{chunkoff:x}')
    print(f'    decrypted head: {bytes(dec[off:off+16]).hex(" ")}')
    prev = chunks[lo-2]
    print(f'  previous ok : idx={prev[0]} off=0x{prev[1]:x} len={prev[2]}')
    print(f'    decrypted head: {bytes(dec[prev[1]:prev[1]+16]).hex(" ")}')
