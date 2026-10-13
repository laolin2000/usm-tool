"""
Parameter-grid brute force for the CRI video mask.

Anchor: the keyframe at 0x43F0C (VP9 sync 82 49 83 42 at chunk+0x2C). A correct
decryption MUST make that frame decodable by ffmpeg. We sweep:
   * key                 : zero, variants
   * mask head length    : 0x00,0x20,0x28,0x2C,0x30,0x40,0x48,0x60  (bytes kept verbatim)
   * per-chunk vs whole-stream application
and report any combination whose output ffmpeg accepts.
"""
import sys, struct, os, subprocess, itertools

src = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = bytearray(buf[0xEE0:0xEE0+32])

def derive_masks(key_hex):
    key = key_hex.rjust(16, '0')
    k1 = bytes.fromhex(key[8:]); k2 = bytes.fromhex(key[:8])
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

def mask_region(data, v1, v2, head_len, word=8):
    """Apply the CRI rolling mask to data[head_len:], keeping data[:head_len] verbatim."""
    head = bytes(data[:head_len])
    body = data[head_len:]
    n = len(body)
    if n < 0x40: return bytes(data)
    if word == 8:
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
        out = struct.pack('<%dQ' % nq, *dq) + body[nq*8:]
    else:
        nd = n // 4
        dd = list(struct.unpack_from('<%dI' % nd, body, 0))
        m2 = list(struct.unpack('<8I', v2 + v2)); v2q = list(struct.unpack('<8I', v2 + v2))
        for i in range(32, nd):
            j = i % 8
            dd[i] ^= m2[j]; m2[j] = dd[i] ^ v2q[j]
        m1 = list(struct.unpack('<8I', v1 + v1))
        for i in range(32):
            if i + 32 >= nd: break
            j = i % 8
            m1[j] ^= dd[i+32]; dd[i] ^= m1[j]
        out = struct.pack('<%dI' % nd, *dd) + body[nd*4:]
    return head + out

def test(data, label):
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, 1)
    blob = bytes(h) + struct.pack('<IQ', len(data), 0) + data
    p = os.path.join(outdir, 'g.ivf')
    open(p, 'wb').write(blob)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    return not (r.stderr or '').strip()

ANCHOR = 0x43F0C
LEN = 0x6000
KEYS = ['0000000000000000', 'FFFFFFFFFFFFFFFF', '0123456789ABCDEF']
HEADS = [0x00, 0x20, 0x28, 0x2C, 0x30, 0x40, 0x48, 0x60]

raw = buf[ANCHOR:ANCHOR + LEN]
print('control: raw anchor decodes ->', test(raw, 'raw'))
found = []
for key in KEYS:
    v1, v2 = derive_masks(key)
    for head in HEADS:
        for word in (8, 4):
            dec = mask_region(raw, v1, v2, head, word)
            if dec == raw: continue
            if test(dec, 'x'):
                found.append((key, hex(head), word))
print('grid hits:', found if found else 'NONE')
