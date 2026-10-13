"""
CBC-style chaining test: update the mask state with the CIPHERTEXT of the previous frame
rather than the plaintext, which is what a chained stream cipher looks like.

Also test chaining across frames with the state carried, and a per-frame state seeded by
the previous frame's bytes.
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

def al(n, a=0x20): return (n + a - 1) // a * a

frames = []
o = 0x800
while o + 0x20 <= len(raw):
    if raw[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', raw, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(raw): o += 0x20; continue
    flen = struct.unpack_from('<I', raw, o+0x20)[0]
    fidx = struct.unpack_from('<I', raw, o+0x24)[0]
    if 0 < flen <= 1_500_000 and o + 0x2C + flen <= len(raw):
        frames.append((fidx, o+0x2C, flen))
    o = al(o + size)
frames.sort()
ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]
head = [(0xF0C, 262)] + [(o, fl) for _, o, fl in frames[:20]]
target = frames[23:400]   # frame 24 onward

v1, v2 = derive_masks(key)
B = b'\x82\x49\x83\x42'

def decrypt_fn(ct, state, mode):
    """return (plaintext, new_state)"""
    n = len(ct)
    nq = n // 8
    if nq < 1: return bytes(ct), state
    dq = list(struct.unpack_from('<%dQ' % nq, ct, 0))
    m = list(state) if state else list(struct.unpack('<4Q', v2))
    v2q = list(struct.unpack('<4Q', v2))
    for i in range(nq):
        j = i & 3
        if mode == 'pt':        # mask ^= plaintext (standard CRI)
            dq[i] ^= m[j]; m[j] = dq[i] ^ v2q[j]
        else:                   # mask ^= ciphertext
            prev = dq[i]
            dq[i] ^= m[j]; m[j] = prev ^ v2q[j]
    return struct.pack('<%dQ' % nq, *dq) + ct[nq*8:], m

def build(items, label):
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, label + '.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    e = (r.stderr or '').strip()
    print(f'  {label}: {len(items)} frames -> {"DECODE OK" if e == "" else e[:110]}', flush=True)
    return e == ''

print('=== chains from frame 24 ===')
for mode in ('pt', 'ct'):
    for carry in (False, True):
        state = None
        out = [raw[o:o+fl] for o, fl in head]
        for fidx, off, fl in target[:300]:
            if carry:
                d, state = decrypt_fn(raw[off:off+fl], state, mode)
            else:
                d, _ = decrypt_fn(raw[off:off+fl], None, mode)
            out.append(d)
        build(out, f'mode{mode}_carry{int(carry)}')

# --- also: is the first 4 bytes of frame 24 a length/index header we should skip? ---
print('\n=== frame 24 variants (prepend/skip bytes) ===')
f24o, f24l = frames[23][1], frames[23][2]
f24 = raw[f24o:f24o+f24l]
build([raw[o:o+fl] for o, fl in head] + [f24], 'f24_raw')
d, _ = decrypt_fn(f24, None, 'pt')
build([raw[o:o+fl] for o, fl in head] + [d], 'f24_dec')
for skip in (4, 8, 12, 16):
    build([raw[o:o+fl] for o, fl in head] + [f24[skip:]], f'f24_skip{skip}')
    build([raw[o:o+fl] for o, fl in head] + [d[skip:]], f'f24_dec_skip{skip}')
