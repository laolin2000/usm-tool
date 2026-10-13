"""
One more targeted variant: apply the CRI rolling mask to each frame's VP9 PAYLOAD only
(frame header kept verbatim), across the whole stream, with key 7F4551499DF55E68.
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

def mask_rolling(data, v1, v2, head=0x00, state=None):
    """rolling 64-bit CRI mask; optional carried state (m2 list) for continuous mode"""
    n = len(data)
    if n <= head + 0x100: return bytes(data), state
    hd = bytes(data[:head]); rest = data[head:]
    nq = len(rest) // 8
    if nq < 33: return bytes(data), state
    dq = list(struct.unpack_from('<%dQ' % nq, rest, 0))
    if state is None:
        m2 = list(struct.unpack('<4Q', v2))
    else:
        m2 = state
    v2q = list(struct.unpack('<4Q', v2))
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

VSTART = 0x1020
def walk_raw(blob, base=0):
    out, p = [], 0x20
    while p + 0x0C <= len(blob):
        flen = struct.unpack_from('<I', blob, p)[0]
        fidx = struct.unpack_from('<I', blob, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(blob): break
        out.append((base + p + 0x0C, flen, fidx))
        p = al(p + 0x0C + flen)
    return out

blob = buf[VSTART:]
frames = walk_raw(blob, VSTART)
print(f'frames located: {len(frames)}')

v1, v2 = derive_masks(key)
ivf = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]

def test(items, label):
    if len(items) < 20: return False
    items = items[:4000]
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, 'probe.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip()
    if not err:
        print(f'  *** DECODE OK: {label} ({len(items)} frames) ***', flush=True)
        os.replace(p, os.path.join(outdir, f'OK_{label}.ivf'))
        return True
    return False

print('\n=== A: mask each frame payload, state reset per frame ===')
items = []
for off, fl, idx in frames[:600]:
    d, _ = mask_rolling(buf[off:off+fl], v1, v2, 0x00, None)
    items.append(d)
print('  result:', test(items, 'perframe_reset'))

print('\n=== B: mask each frame payload with CARRIED state ===')
items, state = [], None
for off, fl, idx in frames[:600]:
    d, state = mask_rolling(buf[off:off+fl], v1, v2, 0x00, state)
    items.append(d)
print('  result:', test(items, 'perframe_carry'))

print('\n=== C: mask the continuous payload run (skip 12-byte headers) ===')
items, state = [], None
for off, fl, idx in frames[:600]:
    d, state = mask_rolling(buf[off:off+fl], v1, v2, 0x00, state)
    items.append(d)
print('  result:', test(items, 'carry_same'))

print('\n=== D: mask continuous stream with header kept per frame (head=0x0C) ===')
items, state = [], None
for off, fl, idx in frames[:600]:
    d, state = mask_rolling(buf[off-12:off+fl], v1, v2, 0x0C, state)
    items.append(d[12:])
print('  result:', test(items, 'head12_carry'))
