"""
Systematic frame-extraction search.

Known: frame 0 is valid VP9 at 0xF0C (size prefix 262 at 0xF00, IRAP signature 82 49 83 42).
The @SFV records carry {size, frameIdx@+16}. This script combines every plausible
payload offset/length with every plausible decryption and reports only the ones ffmpeg
accepts.
"""
import sys, struct, os, subprocess, re, itertools

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = buf[0xEE0:0xEE0+32]

def derive_masks(key_hex):
    key = key_hex.rjust(16, '0')
    key1 = bytes.fromhex(key[8:]); key2 = bytes.fromhex(key[:8])
    t = bytearray(0x20)
    t[0:9] = [key1[3], key1[2], key1[1], (key1[0]-0x34) % 256, (key2[3]+0xF9) % 256,
              (key2[2] ^ 0x13) % 256, (key2[1]+0x61) % 256, (key1[3] ^ 0xFF) % 256, (key1[1]+key1[2]) % 256]
    t[9:12] = [(t[1]-t[7]) % 256, (t[2] ^ 0xFF) % 256, (t[1] ^ 0xFF) % 256]
    t[12:14] = [(t[11]+t[9]) % 256, (t[8]-t[3]) % 256]
    t[14:16] = [(t[13] ^ 0xFF) % 256, (t[10]-t[11]) % 256]
    t[16] = (t[8]-t[15]) % 256
    t[17:23] = [(t[16] ^ t[7]) % 256, (t[15] ^ 0xFF) % 256, (t[3] ^ 0x10) % 256, (t[4]-0x32) % 256, (t[5]+0xED) % 256, (t[6] ^ 0xF3) % 256]
    t[23:26] = [(t[19]-t[15]) % 256, (t[21]+t[7]) % 256, (0x21-t[19]) % 256]
    t[26:28] = [(t[20] ^ t[23]) % 256, (t[22]+t[22]) % 256]
    t[28:31] = [(t[23]+0x44) % 256, (t[3]+t[4]) % 256, (t[5]-t[22]) % 256]
    t[31] = (t[29] ^ t[19]) % 256
    return bytes(t), bytes(x ^ 0xFF for x in t)

def video_mask(body, v1, v2):
    n = len(body)
    if n <= 0x200: return body
    nq = n // 8
    dq = list(struct.unpack_from('<%dQ' % nq, body, 0))
    m2 = list(struct.unpack('<4Q', v2)); vq2 = list(struct.unpack('<4Q', v2))
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]; m2[j] = dq[i] ^ vq2[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        j = i % 4
        m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
    return struct.pack('<%dQ' % nq, *dq) + body[nq*8:]

def ok(data, label):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, 1)
    blob = bytes(h) + struct.pack('<IQ', len(data), 0) + data
    p = os.path.join(workdir, label + '.ivf')
    open(p, 'wb').write(blob)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True)
    return not (r.stderr or '').strip()

# ---- ground truth check ----
print('sanity: frame0 @0xF0C decodes ->', ok(buf[0xF0C:0xF0C+262], 'sanity'))

# ---- @SFV records with plausible frame payloads ----
recs = []
for m in re.finditer(b'@SFV', buf):
    o = m.start()
    if o + 0x40 > len(buf): continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    fidx = struct.unpack_from('>I', buf, o+0x14)[0]
    if 0 < size < 4_000_000 and o + size <= len(buf):
        recs.append((o, size, fidx))

KEYS = ['0000000000000000', 'FFFFFFFFFFFFFFFF']
masks = {k: derive_masks(k) for k in KEYS}

tested = 0
hits = []
for (o, size, fidx) in recs[5:25]:
    for off, ln in [(o, size), (o+0x20, size-0x20), (o+0x40, size-0x40), (o+0x24, size-0x24), (o+0x28, size-0x28)]:
        if ln <= 0 or off + ln > len(buf): continue
        raw = buf[off:off+ln]
        for k, (v1, v2) in masks.items():
            dec = video_mask(raw[0x40:] if len(raw) > 0x40 else raw, v1, v2)
            for cand, tag in ((raw, 'raw'), (dec, 'mask')):
                tested += 1
                if ok(cand, f'r{o:x}_{off:x}_{tag}_{k[:4]}'):
                    hits.append((hex(o), hex(off), ln, tag, k))
print(f'tested {tested} combinations, hits: {hits if hits else "none"}')
