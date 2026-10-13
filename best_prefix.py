"""
Determine exactly how far the plaintext extends, then extract everything decodable.

Frames 0..24 are plaintext and verified decodable. This script walks the frame table
(sorted by index) and decodes progressively longer prefixes to find the exact first frame
whose payload is not usable, and writes the best achievable MP4.
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

# ---- frame table from the ORIGINAL ciphertext layout ----
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
print(f'frame table: {len(frames)} frames, idx {frames[0][0]}..{frames[-1][0]}')
print(f'  offsets first 6: {[(i, hex(o)) for i, o, _ in frames[:6]]}')
print(f'  offsets 23..27: {[(i, hex(o)) for i, o, _ in frames[23:28]]}')

# frame 0 = the plaintext record at 0xF00/0xF0C
items = [(0xF0C, 262)]
items += [(o, fl) for _, o, fl in frames]
ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]

def build(n, label):
    sel = items[:n]
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(sel))
    out = bytearray(h)
    for i, (o2, fl) in enumerate(sel):
        out += struct.pack('<IQ', fl, i) + raw[o2:o2+fl]
    out += struct.pack('<I', len(sel))
    p = os.path.join(outdir, label + '.ivf'); open(p, 'wb').write(out)
    return p

def dec_ok(p):
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    return not (r.stderr or '').strip()

print('\n=== progressive prefix decode (raw bytes, no mask) ===')
last_ok = 1
for n in (2, 5, 10, 20, 25, 26, 30, 40, 60, 100):
    if n > len(items): break
    ok = dec_ok(build(n, 'pre'))
    print(f'  first {n:4d} frames -> {"OK" if ok else "fail"}', flush=True)
    if ok: last_ok = n
    else: break

print(f'\nlargest fully-decodable prefix: {last_ok} frames')

# exact bisect between last_ok and next
if last_ok < len(items):
    lo, hi = last_ok, min(last_ok + 40, len(items))
    while lo < hi:
        mid = (lo + hi) // 2
        if dec_ok(build(mid, 'bis')): lo = mid + 1
        else: hi = mid
    print(f'first failing prefix length: {lo}')
    print(f'  frame at position {lo-1}: idx={frames[lo-2][0] if lo-2 < len(frames) else "?"} '
          f'off=0x{items[lo-1][0]:x} len={items[lo-1][1]}')
    print(f'    head: {raw[items[lo-1][0]:items[lo-1][0]+16].hex(" ")}')
    print(f'  previous frame idx={frames[lo-3][0] if lo-3 < len(frames) else "?"} '
          f'head: {raw[items[lo-2][0]:items[lo-2][0]+16].hex(" ")}')

# ---- write the best MP4 we can ----
best = build(last_ok, 'best')
mp4 = os.path.join(outdir, '001960_partial.mp4')
r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', best,
                    '-c:v', 'libx264', '-preset', 'medium', '-crf', '16',
                    '-pix_fmt', 'yuv420p', '-movflags', '+faststart', mp4],
                   capture_output=True, text=True, errors='replace')
print(f'\nMP4 ({last_ok} frames): {"OK" if not (r.stderr or "").strip() else (r.stderr or "").strip()[:150]}')
if os.path.exists(mp4): print(f'  {mp4} ({os.path.getsize(mp4)} bytes)')
