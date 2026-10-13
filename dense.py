"""
The bulk video data between 0x1960 and the trailing '@SFV' chunks is a DENSE frame stream
(12-byte headers, no padding). The '@SFV' chunks at 0x1020..0x1900 hold frames 1..24 as
separate records; from 0x1960 the frames are packed contiguously.

Plan:
  1. decrypt the dense region (0x1960 .. first trailing '@SFV' chunk) with the key
  2. walk frames inside it as {u32 LE len, u32 LE idx, u32 LE rsv, data[len]}
  3. prepend frames 0..24 and test decode
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
    n = len(data) - off
    if n <= head + 0x100: return data
    nq = (n-head)//8
    if nq < 33: return data
    dq = list(struct.unpack_from('<%dQ' % nq, data, off+head))
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

# --- known plaintext head: frame 0 + frames 1..24 from the '@SFV' chunks ---
head_frames = [(0xF0C, 262)]
o = 0x800
chunk_list = []
while o + 0x20 <= len(raw):
    if raw[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', raw, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(raw): o += 0x20; continue
    chunk_list.append((o, size)); o = al(o + size)
for c, s in chunk_list:
    if c > 0x1900: break
    flen = struct.unpack_from('<I', raw, c+0x20)[0]
    fidx = struct.unpack_from('<I', raw, c+0x24)[0]
    if 0 < flen <= 1_500_000 and c + 0x2C + flen <= len(raw):
        head_frames.append((c+0x2C, flen))
print(f'head frames (plaintext): {len(head_frames)}')

# --- dense region ---
FIRST_TRAILING = None
for c, s in chunk_list:
    if c > 0x2000:
        FIRST_TRAILING = c
        break
print(f'first trailing @SFV chunk: 0x{FIRST_TRAILING:x}')
DENSE_START = 0x1960
DENSE_END = FIRST_TRAILING if FIRST_TRAILING else len(raw)
print(f'dense region: 0x{DENSE_START:x}..0x{DENSE_END:x} ({DENSE_END-DENSE_START} bytes)')

dec = mask_buf(bytearray(raw), *derive_masks(key), off=DENSE_START, head=0)

# --- walk the dense frame stream ---
frames = []
p = DENSE_START
while p + 0x0C <= DENSE_END:
    flen = struct.unpack_from('<I', dec, p)[0]
    fidx = struct.unpack_from('<I', dec, p+4)[0]
    if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(dec): break
    frames.append((p+0x0C, flen, fidx))
    p = p + 0x0C + flen
print(f'\ndense frames walked: {len(frames)}')
if frames:
    print(f'  idx range {frames[0][2]}..{frames[-1][2]}')
    print(f'  first 10 idx: {[f[2] for f in frames[:10]]}')
    print(f'  strictly increasing: {sum(1 for k in range(1,len(frames)) if frames[k][2]>frames[k-1][2])}/{len(frames)-1}')
    print(f'  total bytes {sum(f[1] for f in frames)}')
    print(f'  next offset after walk: 0x{p:x} (region end 0x{DENSE_END:x})')

# --- assemble and test ---
ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]
def build(extra, label, n=1200):
    items = [bytes(dec[o2:o2+fl]) for o2, fl in head_frames]
    items += [bytes(dec[o2:o2+fl]) for o2, fl, _ in extra[:n]]
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    pth = os.path.join(outdir, label + '.ivf'); open(pth, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', pth, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    e = (r.stderr or '').strip()
    print(f'  {label}: {len(items)} frames -> {"DECODE OK" if not e else e[:130]}')
    return not e

print('\n=== decode ===')
build(frames, 'dense')
