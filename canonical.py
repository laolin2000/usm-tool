"""
Decisive test of the canonical CRI VideoMask with key 7F4551499DF55E68.

Canonical form (PyCriCodecsEx USMCrypt.VideoMask):
    head = chunk[:0x40]          # kept verbatim
    body = chunk[0x40:]          # rolling 64-bit mask over this
    if len(body) <= 0x200: no-op
    mask2 pass: for i in 32..len(body)//8 : dq[i] ^= m2[i%4]; m2[i%4] = dq[i] ^ v2[i%4]
    mask1 pass: for i in 0..31           : m1[i%4] ^= dq[i+32]; dq[i] ^= m1[i%4]

We apply this to the video stream body starting at the first frame-bearing chunk and test
whether the resulting VP9 stream parses.
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

def videomask(chunk, v1, v2):
    """canonical CRI VideoMask on one chunk"""
    head = bytes(chunk[:0x40])
    body = bytearray(chunk[0x40:])
    n = len(body)
    if n <= 0x200:
        return head + bytes(body)
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
    return head + struct.pack('<%dQ' % nq, *dq) + bytes(body[nq*8:])

def al(n, a=0x20): return (n + a - 1) // a * a

# locate first VIDEO chunk: the one at 0x1020 (inner frame header present after masking)
VSTART = 0x1020
print(f'video body start assumed: 0x{VSTART:x}')
v1, v2 = derive_masks(key)

# ---- whole-body canonical mask, head = first 0x40 bytes of the video body ----
body = buf[VSTART:]
dec = videomask(body, v1, v2)
print(f'decrypted body: {len(dec)} bytes')

def walk(blob):
    """walk inner frames inside decrypted body: header at +0x20, frames after"""
    out, p = [], 0x20
    while p + 0x0C <= len(blob):
        flen = struct.unpack_from('<I', blob, p)[0]
        fidx = struct.unpack_from('<I', blob, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(blob): break
        out.append((p+0x0C, flen, fidx))
        p = al(p + 0x0C + flen)
    return out

fr = walk(bytes(dec))
print(f'frames after canonical mask: {len(fr)}')
if fr:
    print('  first 6:', [(hex(o), fl, i) for o, fl, i in fr[:6]])
    ivf = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(fr))
    out = bytearray(h)
    for i, (o, fl, idx) in enumerate(fr):
        out += struct.pack('<IQ', fl, i) + bytes(dec[o:o+fl])
    out += struct.pack('<I', len(fr))
    p = os.path.join(outdir, 'canonical.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip().replace('\n', ' | ')
    print(f'  canonical IVF decode -> {"DECODE OK" if not err else err[:200]}')

# ---- reference: same walk on the RAW (unmasked) data ----
fr_raw = walk(buf[VSTART:])
print(f'\nframes without mask: {len(fr_raw)}')
