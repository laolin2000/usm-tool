"""
End-to-end: try several extraction/decryption strategies and validate each result by
asking ffmpeg to decode the VP9 stream.

Strategies
  A. concat of @SFV payloads (strip 0x40-byte record headers), raw VP9
  B. same, after CRI video_mask with candidate keys
  C. whole tail from 0x40/0xF00/0x1000 raw + CRI mask
  D. per-record CRI mask (head kept per record)
"""
import sys, struct, subprocess, os, re

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

# ---------- mask derivation (from PyCriCodecsEx) ----------
def derive_masks(key_hex):
    key = key_hex.rjust(16, '0') if len(key_hex) <= 16 else key_hex
    key1 = bytes.fromhex(key[8:]); key2 = bytes.fromhex(key[:8])
    t = bytearray(0x20)
    t[0:9] = [key1[3], key1[2], key1[1], (key1[0]-0x34) % 256, (key2[3]+0xF9) % 256,
              (key2[2] ^ 0x13) % 256, (key2[1]+0x61) % 256, (key1[3] ^ 0xFF) % 256,
              (key1[1]+key1[2]) % 256]
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

def video_mask(body, v1, v2):
    """body = bytes AFTER the 0x40 header. 8-byte rolling mask, exactly as CRI does."""
    n = len(body)
    if n <= 0x200:
        return body
    nq = n // 8
    dq = list(struct.unpack_from('<%dQ' % nq, body, 0))
    m2 = list(struct.unpack('<4Q', v2)); vq2 = list(struct.unpack('<4Q', v2))
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]
        m2[j] = dq[i] ^ vq2[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        j = i % 4
        m1[j] ^= dq[i+32]
        dq[i] ^= m1[j]
    return struct.pack('<%dQ' % nq, *dq) + body[nq*8:]

def probe_vp9(name, data):
    p = os.path.join(workdir, name + '.vpp')
    open(p, 'wb').write(data)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-f', 'ivf', '-i', p,
                        '-frames:v', '30', '-f', 'null', '-'], capture_output=True, text=True)
    err = (r.stderr or '').strip().replace('\n', ' | ')[:260]
    ok = not err
    print(f'  [{name}] {len(data)} bytes -> {"DECODE OK" if ok else err}')
    return ok, p

# Build a VP9 raw test wrapper: ffmpeg can read raw VP9 only via a container, so wrap in IVF.
IVF_HDR = buf[0xEE0:0xEE0+32]
def as_ivf(frames):
    h = bytearray(IVF_HDR)
    struct.pack_into('<I', h, 24, len(frames))
    out = bytearray(h)
    for i, f in enumerate(frames):
        out += struct.pack('<IQ', len(f), i) + f
    return bytes(out)

# ---------- gather @SFV records ----------
recs = []
for m in re.finditer(b'@SFV', buf):
    o = m.start()
    if o + 0x40 > len(buf): continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or o + size > len(buf): continue
    recs.append((o, size))
print(f'@SFV records: {len(recs)}')

# ---- A. concat payloads, treating each record as ONE frame ----
print('\n=== A. concat @SFV payloads as individual frames ===')
framesA = [buf[o+0x40:o+size] for o, size in recs]
probe_vp9('A_concat', as_ivf(framesA))

# ---- B. CRI mask on the whole video stream body ----
print('\n=== B. CRI video_mask on the whole stream ===')
KEYS = ['0000000000000000', 'FFFFFFFFFFFFFFFF', '0123456789ABCDEF',
        '9BD9A5E1A1B2C3D4', '0000000000000001']
for key in KEYS:
    v1, v2 = derive_masks(key)
    # whole tail as one body, head = first 0x40 bytes
    body = buf[0x1960:]
    dec = video_mask(body, v1, v2)
    changed = sum(1 for a, b in zip(body, dec) if a != b)
    print(f'  key={key} bytes changed={changed}')
    if changed:
        probe_vp9(f'B_{key}', as_ivf([dec[i:i+12000] for i in range(0, min(len(dec), 240000), 12000)]))
