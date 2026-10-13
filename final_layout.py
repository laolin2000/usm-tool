"""
FINAL layout test.

Verified structure of the video stream:
   repeated:
     chunk '@SFV' (0x20 bytes) at some offset
        +0x20 : u32 LE frameLen | u32 LE frameIndex | u32 LE reserved | VP9 data[frameLen]
     next chunk begins at align0x20(chunk + 0x20 + 0x0C + frameLen)

So we locate every '@SFV' chunk, read its inner frame record, and collect the payload.
Then test: raw concat, masked-in-place, masked-per-chunk-with-carry.
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

# ---------- locate every '@SFV' chunk and its inner frame record ----------
chunks = []
o = 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20; continue
    flen = struct.unpack_from('<I', buf, o+0x20)[0]
    fidx = struct.unpack_from('<I', buf, o+0x24)[0]
    if 0 < flen <= 1_500_000 and o + 0x2C + flen <= len(buf):
        chunks.append(dict(off=o, size=size, flen=flen, fidx=fidx, data=o+0x2C))
    o = al(o + size)
print(f'chrome chunks with inner frame: {len(chunks)}')
chunks.sort(key=lambda c: c['fidx'])
print(f'  fidx range: {chunks[0]["fidx"]}..{chunks[-1]["fidx"]}')
print(f'  total payload: {sum(c["flen"] for c in chunks)}')
missing = [i for i in range(1, chunks[-1]['fidx']) if i not in set(c['fidx'] for c in chunks)]
print(f'  missing indices: {len(missing)}  first few: {missing[:10]}')

ivf = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]
def test(items, label):
    if len(items) < 20: return False
    items = items[:3000]
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
    print(f'  {label}: {err[:100]}', flush=True)
    return False

sel = chunks[:600]
pays = [buf[c['data']:c['data']+c['flen']] for c in sel]
print(f'\nfirst payload lens: {[len(x) for x in pays[:10]]}')
v1, v2 = derive_masks(key)

print('\n=== tests ===')
test(pays, 'raw')
test([mask_once(x, v1, v2)[0] for x in pays], 'mask_each')
blob = b''.join(pays)
dec, _ = mask_once(blob, v1, v2)
out, p2 = [], 0
for x in pays:
    out.append(dec[p2:p2+len(x)]); p2 += len(x)
test(out, 'concat_mask')
