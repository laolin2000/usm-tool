"""
FULL EXTRACTION - final pipeline (verified working).

Findings that made this work:
  * frames 0..23 are plaintext; encryption starts at file offset 0x1960 (frame 24 onwards)
  * the CRI rolling 64-bit videomask is applied to the raw file bytes from 0x1960 on
  * key 7F4551499DF55E68 derives mask1/mask2 via the standard CRI recipe
  * frame records keep their original positions, so the frame table stays valid after
    decryption; payloads are read from the DECRYPTED region at their original offsets

Output: complete IVF -> MP4 (H.264)
"""
import sys, struct, os, subprocess

src = sys.argv[1]; key = sys.argv[2]; outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
buf = bytearray(open(src, 'rb').read())
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

def mask_inplace(data, v1, v2, off=0, head=0):
    """CRI rolling 64-bit mask over data[off:] (in place), keeping data[off:off+head]."""
    seg = data[off:]
    n = len(seg)
    if n <= head + 0x100: return
    start = off + head
    nq = (n - head) // 8
    if nq < 33: return
    dq = list(struct.unpack_from('<%dQ' % nq, data, start))
    v2q = list(struct.unpack('<4Q', v2))
    m2 = list(v2q)
    for i in range(32, nq):
        j = i & 3
        dq[i] ^= m2[j]; m2[j] = dq[i] ^ v2q[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        if i + 32 >= nq: break
        j = i & 3
        m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
    struct.pack_into('<%dQ' % nq, data, start, *dq)

def al(n, a=0x20): return (n + a - 1) // a * a

ENC_START = 0x1960
v1, v2 = derive_masks(key)

# ---- IMPORTANT: build the frame table BEFORE decrypting (the mask scrambles the '@SFV'
#      markers, so the table must be read from the original ciphertext layout) ----
chunks = []
o = 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf): o += 0x20; continue
    flen = struct.unpack_from('<I', buf, o+0x20)[0]
    fidx = struct.unpack_from('<I', buf, o+0x24)[0]
    if 0 < flen <= 1_500_000 and o + 0x2C + flen <= len(buf):
        chunks.append((fidx, o+0x2C, flen))
    o = al(o + size)
chunks.sort()
print(f'frames in table: {len(chunks)} (idx {chunks[0][0]}..{chunks[-1][0]})')

print(f'decrypting raw bytes from 0x{ENC_START:x} .. end ({len(buf)-ENC_START} bytes)')
mask_inplace(buf, v1, v2, off=ENC_START, head=0)
print('  done')

ivf = bytes(buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32])
items = [(0xF0C, 262)] + [(off, fl) for _, off, fl in chunks]
h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
out = bytearray(h)
for i, (off, fl) in enumerate(items):
    out += struct.pack('<IQ', fl, i) + bytes(buf[off:off+fl])
out += struct.pack('<I', len(items))
ivf_path = os.path.join(outdir, '001960.ivf')
open(ivf_path, 'wb').write(out)
print(f'wrote {ivf_path} ({len(out)} bytes, {len(items)} frames)')

r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', ivf_path, '-f', 'null', '-'],
                   capture_output=True, text=True, errors='replace')
err = (r.stderr or '').strip()
print('IVF decode ->', 'DECODE OK' if not err else err[:300])

mp4 = os.path.join(outdir, '001960_TAKE_CONTROL.mp4')
r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', ivf_path,
                    '-c:v', 'libx264', '-preset', 'medium', '-crf', '16',
                    '-pix_fmt', 'yuv420p', '-movflags', '+faststart', mp4],
                   capture_output=True, text=True, errors='replace')
e2 = (r.stderr or '').strip()
print('MP4 encode ->', 'OK' if not e2 else e2[:300])
if os.path.exists(mp4):
    print(f'wrote {mp4} ({os.path.getsize(mp4)} bytes)')
