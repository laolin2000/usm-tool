"""
Frame order analysis: the frame index does NOT track the file offset, so the true sequence
must come from walking each chunk's contents in file order.

Print, for the first ~40 chunks in file order: chunk offset, its declared size, and the
frame indices found inside it. Then assemble by file order and test decode.
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

def chunk_list(data):
    out, o = [], 0x800
    while o + 0x20 <= len(data):
        if data[o:o+4] != b'@SFV':
            o += 0x20; continue
        size = struct.unpack_from('>I', data, o+4)[0]
        if size == 0 or size > 8_000_000 or o + size > len(data):
            o += 0x20; continue
        out.append((o, size)); o = al(o + size)
    return out

CL = chunk_list(raw)
print(f'chunks (file order): {len(CL)}')

print('\n=== first 30 chunks in FILE ORDER: inner frame indices ===')
for c, s in CL[:30]:
    flen = struct.unpack_from('<I', raw, c+0x20)[0]
    fidx = struct.unpack_from('<I', raw, c+0x24)[0]
    print(f'  chunk@0x{c:08x} size=0x{s:06x} innerLen={flen:<7} innerIdx={fidx}')

# ---- assemble in FILE ORDER, walking each chunk's inner frames ----
def frames_in_file_order(data, start_chunk_idx=0):
    out = []
    for c, s in CL[start_chunk_idx:]:
        end = c + s
        p = c + 0x20
        while p + 0x0C <= end:
            flen = struct.unpack_from('<I', data, p)[0]
            fidx = struct.unpack_from('<I', data, p+4)[0]
            if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(data): break
            out.append((p+0x0C, flen, fidx))
            p = al(p + 0x0C + flen)
            if p + 0x0C > end: break
    return out

print('\n=== file-order frame walk (raw) ===')
fr_raw = frames_in_file_order(raw)
print(f'  frames: {len(fr_raw)}')
if fr_raw:
    idxs = [f[2] for f in fr_raw]
    print(f'  idx range {idxs[0]}..{idxs[-1]}')
    print(f'  first 12 idx: {idxs[:12]}')
    print(f'  strictly increasing: {sum(1 for k in range(1,len(idxs)) if idxs[k]>idxs[k-1])}/{len(idxs)-1}')

v1, v2 = derive_masks(key)
dec = mask_buf(bytearray(raw), v1, v2, off=0x1960, head=0)
print('\n=== file-order frame walk (decrypted) ===')
fr_dec = frames_in_file_order(dec)
print(f'  frames: {len(fr_dec)}')
if fr_dec:
    idxs = [f[2] for f in fr_dec]
    print(f'  idx range {idxs[0]}..{idxs[-1]}  first 12: {idxs[:12]}')
    print(f'  strictly increasing: {sum(1 for k in range(1,len(idxs)) if idxs[k]>idxs[k-1])}/{len(idxs)-1}')

ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]
def test(frames, dec_src, label, prepend0=True):
    items = []
    if prepend0: items.append(bytes(dec_src[0xF0C:0xF0C+262]))
    for off, fl, idx in frames[:3000]:
        items.append(bytes(dec_src[off:off+fl]))
    if len(items) < 20: return
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, label + '.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    e = (r.stderr or '').strip()
    print(f'  {label}: {len(items)} frames -> {"DECODE OK" if not e else e[:120]}')

print('\n=== decode tests (file order) ===')
test(fr_raw, raw, 'fileorder_raw')
test(fr_dec, dec, 'fileorder_dec')
