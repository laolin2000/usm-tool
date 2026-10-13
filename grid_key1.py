"""
Grid sweep for the CRI mask with the supplied key 7F4551499DF55E68:

  head_len : how many bytes of the region are left verbatim (0x00..0x60)
  scope    : per-chunk  |  whole-body-from-first-chunk  |  per-inner-frame
  word     : 64-bit (CRI standard) | 32-bit

Success metric: ffmpeg decodes without "Invalid superframe packet size" / "Invalid frame
marker", i.e. the VP9 stream parses cleanly.
"""
import sys, struct, os, subprocess

src = sys.argv[1]; key = sys.argv[2]; outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

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
    n = len(data)
    if n <= head_len + 0x100: return bytes(data)
    head = bytes(data[:head_len]); rest = data[head_len:]
    nr = len(rest)
    if word == 8:
        nq = nr // 8
        if nq < 33: return bytes(data)
        dq = list(struct.unpack_from('<%dQ' % nq, rest, 0))
        m2 = list(struct.unpack('<4Q', v2)); v2q = list(struct.unpack('<4Q', v2))
        for i in range(32, nq):
            j = i % 4
            dq[i] ^= m2[j]; m2[j] = dq[i] ^ v2q[j]
        m1 = list(struct.unpack('<4Q', v1))
        for i in range(32):
            if i+32 >= nq: break
            j = i % 4
            m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
        return head + struct.pack('<%dQ' % nq, *dq) + rest[nq*8:]
    else:
        nd = nr // 4
        if nd < 65: return bytes(data)
        dd = list(struct.unpack_from('<%dI' % nd, rest, 0))
        v1x = struct.unpack('<16I', v1+v1); v2x = struct.unpack('<16I', v2+v2)
        m2 = list(v2x)
        for i in range(32, nd):
            j = i % 16
            dd[i] ^= m2[j]; m2[j] = dd[i] ^ v2x[j]
        m1 = list(v1x)
        for i in range(32):
            if i+32 >= nd: break
            j = i % 16
            m1[j] ^= dd[i+32]; dd[i] ^= m1[j]
        return head + struct.pack('<%dI' % nd, *dd) + rest[nd*4:]

def al(n, a=0x20): return (n + a - 1) // a * a

chunks, o = [], 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV': o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf): o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)

def walk_frames(blob, base, start=0x20):
    out, p = [], start
    while p + 0x0C <= len(blob):
        flen = struct.unpack_from('<I', blob, p)[0]
        fidx = struct.unpack_from('<I', blob, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(blob): break
        out.append((base + p + 0x0C, flen, fidx, p))
        p = al(p + 0x0C + flen)
    return out

ivf_hdr = buf[buf.find(b'DKIF'):buf.find(b'DKIF')+32]

def test(items, label, quiet=True):
    if len(items) < 10: return None
    h = bytearray(ivf_hdr); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, 'g.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip()
    if not err:
        print(f'  *** {label}: DECODE OK ({len(items)} frames) ***')
        os.replace(p, os.path.join(outdir, f'OK_{label}.ivf'))
        return True
    if not quiet:
        print(f'  {label}: {err[:110]}')
    return False

v1, v2 = derive_masks(key)
print(f'key={key}\n')
print('=== grid: head_len x scope x word ===')
best = []
for head in (0x00, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x40, 0x48, 0x60):
    for word in (8, 4):
        # scope: per chunk
        items = []
        for c, s in chunks[:300]:
            m = mask_region(buf[c:c+s], v1, v2, head, word)
            for off, fl, idx, rel in walk_frames(m, c):
                items.append(m[rel:rel+fl])
        if test(items, f'chunk_h{head:x}_w{word*8}', False):
            best.append(('chunk', head, word))
        # scope: per inner frame
        items = []
        for c, s in chunks[:300]:
            for off, fl, idx, rel in walk_frames(buf[c:c+s], c):
                d = mask_region(buf[c+rel:c+rel+fl], v1, v2, head, word)
                items.append(d)
        if test(items, f'frame_h{head:x}_w{word*8}', False):
            best.append(('frame', head, word))

print('\n=== whole-body scope ===')
first = chunks[0][0]
for head in (0x00, 0x20, 0x28, 0x2C, 0x40):
    m = mask_region(buf[first:], v1, v2, head, 8)
    items = [m[off-first:off-first+fl] for off, fl, idx, rel in walk_frames(m, first, 0)]
    if test(items, f'whole_h{head:x}', False):
        best.append(('whole', head, 8))

print('\n*** SUCCESSES:', best if best else 'none ***')
