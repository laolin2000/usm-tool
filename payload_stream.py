"""
Decisive test: build the frame-payload stream, then decrypt it.

Frame records (verified by walking):
    chunk '@SFV' header at 0x??20
      +0x20 : u32 LE frameLen | u32 LE frameIndex | u32 LE reserved | VP9 data[frameLen]
    records are 0x20-aligned; the first record of the video stream is at 0x1040
    (frame 0 lives separately at 0xF00 with len=262 and its data at 0xF0C).

Test matrix: {payload-concat, per-frame} x {mask off, mask on, mask on with carry}
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

def rolling(data, v1, v2, state=None, head=0):
    """CRI rolling 64-bit mask; state carries m2 across calls when provided."""
    n = len(data)
    if n <= head + 0x100:
        return bytes(data), state
    hd = bytes(data[:head]); rest = data[head:]
    nq = len(rest) // 8
    if nq < 33:
        return bytes(data), state
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

# ---- collect frame records by walking from 0x1040 ----
records = []
p = 0x1040
while p + 0x0C <= len(buf):
    flen = struct.unpack_from('<I', buf, p)[0]
    fidx = struct.unpack_from('<I', buf, p+4)[0]
    if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(buf):
        break
    records.append((p + 0x0C, flen, fidx))
    p = al(p + 0x0C + flen)
print(f'records walked from 0x1040: {len(records)}')
if records:
    print(f'  index range {records[0][2]}..{records[-1][2]}')
    print(f'  first 5: {[(hex(o), fl, i) for o, fl, i in records[:5]]}')
    print(f'  total payload bytes: {sum(f for _, f, _ in records)}')

ivf = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]

def test(items, label):
    if len(items) < 20: return False
    items = items[:4000]
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    pth = os.path.join(outdir, 'probe.ivf'); open(pth, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', pth, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip()
    if not err:
        print(f'  *** DECODE OK: {label} ({len(items)} frames) ***', flush=True)
        os.replace(pth, os.path.join(outdir, f'OK_{label}.ivf'))
        return True
    return False

v1, v2 = derive_masks(key)
N = 800
sel = records[:N]
pays = [buf[o:o+fl] for o, fl, _ in sel]
print(f'\npayload sizes: {[len(x) for x in pays[:8]]}')

print('\n=== 1) raw payloads (no mask) ===')
test(pays, 'raw')

print('\n=== 2) mask each payload independently ===')
test([rolling(x, v1, v2, None)[0] for x in pays], 'mask_each')

print('\n=== 3) concat payloads -> mask once -> re-split using original sizes ===')
blob = b''.join(pays)
dec, _ = rolling(blob, v1, v2, None)
out, o2 = [], 0
for x in pays:
    out.append(dec[o2:o2+len(x)]); o2 += len(x)
test(out, 'concat_mask')

print('\n=== 4) mask the whole video region continuously (from 0x1000) ===')
region = buf[0x1000:0x1000 + 0x300000]
dec4, _ = rolling(region, v1, v2, None, head=0x40)
# frames offsets relative to region
out4 = []
for o, fl, i in records:
    rel = o - 0x1000
    if rel < 0 or rel + fl > len(dec4): break
    out4.append(dec4[rel:rel+fl])
test(out4, 'region_mask')

print('\n=== 5) region mask with head=0x20 ===')
dec5, _ = rolling(region, v1, v2, None, head=0x20)
out5 = []
for o, fl, i in records:
    rel = o - 0x1000
    if rel < 0 or rel + fl > len(dec5): break
    out5.append(dec5[rel:rel+fl])
test(out5, 'region_mask20')
