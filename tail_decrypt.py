"""
The plaintext/encrypted boundary is frame index 24 (file offset 0x1960):
  frames 0..23  -> plaintext VP9 (decoded fine)
  frames 24..   -> encrypted   (decode fails from here)

So the mask applies only to the region from 0x1960 onward. Test the key there:
  * per-frame mask
  * continuous mask over the concatenated payload stream
  * chunk-based mask
"""
import sys, struct, os, subprocess

src = sys.argv[1]; key = sys.argv[2]; outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
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

def mask_once(data, v1, v2, state=None, head=0):
    n = len(data)
    if n <= head + 0x100: return bytes(data), state
    hd = bytes(data[:head]); rest = data[head:]
    nq = len(rest) // 8
    if nq < 33: return bytes(data), state
    dq = list(struct.unpack_from('<%dQ' % nq, rest, 0))
    v2q = list(struct.unpack('<4Q', v2))
    m2 = list(v2q) if state is None else state
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]; m2[j] = dq[i] ^ v2q[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        if i+32 >= nq: break
        j = i % 4
        m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
    return hd + struct.pack('<%dQ' % nq, *dq) + rest[nq*8:], m2

def al(n, a=0x20): return (n + a - 1) // a * a

# ---- frame list ----
chunks = []
o = 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf): o += 0x20; continue
    flen = struct.unpack_from('<I', buf, o+0x20)[0]
    fidx = struct.unpack_from('<I', buf, o+0x24)[0]
    if 0 < flen <= 1_500_000 and o + 0x2C + flen <= len(buf):
        chunks.append((fidx, o+0x2C, flen, o))
    o = al(o + size)
chunks.sort()
print(f'frames: {len(chunks)}; fidx {chunks[0][0]}..{chunks[-1][0]}')

ivf = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]
def build(items, name):
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, (off, fl) in enumerate(items):
        out += struct.pack('<IQ', fl, i) + buf[off:off+fl]
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, name); open(p, 'wb').write(out)
    return p

def decode(p):
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    return (r.stderr or '').strip()

v1, v2 = derive_masks(key)
PLAIN = [(0xF0C, 262)] + [(off, fl) for fidx, off, fl, _ in chunks if fidx <= 23]
ENCR  = [(fidx, off, fl) for fidx, off, fl, _ in chunks if fidx >= 24]
print(f'plaintext frames: {len(PLAIN)}, encrypted frames: {len(ENCR)}')

HEAD = PLAIN
def assemble(tail_bytes_list, name):
    items = list(HEAD)
    for (fidx, off, fl), data in zip(ENCR, tail_bytes_list):
        items.append((off, fl))   # placeholder, replaced below
    # build manually since decrypted data differs from file
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(HEAD) + len(tail_bytes_list))
    out = bytearray(h)
    n = 0
    for off, fl in HEAD:
        out += struct.pack('<IQ', fl, n) + buf[off:off+fl]; n += 1
    for data in tail_bytes_list:
        out += struct.pack('<IQ', len(data), n) + data; n += 1
    out += struct.pack('<I', n)
    p = os.path.join(outdir, name); open(p, 'wb').write(out)
    return p

print('\n=== A: per-frame mask on frames >= 24 (state reset each frame) ===')
tailA = [mask_once(buf[off:off+fl], v1, v2)[0] for _, off, fl in ENCR[:800]]
e = decode(assemble(tailA, 'tailA.ivf'))
print('  ->', 'DECODE OK' if not e else e[:200])

print('\n=== B: continuous mask over concatenated encrypted payloads ===')
pays = [buf[off:off+fl] for _, off, fl in ENCR[:800]]
blob = b''.join(pays)
dec, _ = mask_once(blob, v1, v2)
tailB, p2 = [], 0
for x in pays:
    tailB.append(dec[p2:p2+len(x)]); p2 += len(x)
e = decode(assemble(tailB, 'tailB.ivf'))
print('  ->', 'DECODE OK' if not e else e[:200])

print('\n=== C: continuous mask over raw file from 0x1960 (includes headers) ===')
region = buf[0x1960:0x1960 + 0x300000]
decC, _ = mask_once(region, v1, v2)
tailC = []
for _, off, fl in ENCR:
    rel = off - 0x1960
    if rel < 0 or rel + fl > len(decC): break
    tailC.append(decC[rel:rel+fl])
e = decode(assemble(tailC, 'tailC.ivf'))
print('  ->', 'DECODE OK' if not e else e[:200])
