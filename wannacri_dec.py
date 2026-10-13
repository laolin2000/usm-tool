"""
WannaCRI-exact decryption.

From wannacri/usm/tools.py:
  key() -> int(key_str, 16)          # '7F4551499DF55E68' -> 0x685EF59D4951457F
  generate_keys(key_num) -> video_key(0x40), audio_key(0x20)
  decrypt_video_packet(packet, video_key):
      data = bytearray(packet)
      eps = len(data) - 0x40
      if eps >= 0x200:
          rolling = bytearray(video_key)
          for i in range(0x100, eps):                  # pass 2 (tail first)
              data[0x40+i] ^= rolling[0x20 + i%0x20]
              rolling[0x20 + i%0x20] = data[0x40+i] ^ video_key[0x20 + i%0x20]
          for i in range(0x100):                       # pass 1 (head)
              rolling[i % 0x20] ^= data[0x140+i]
              data[0x40+i] ^= rolling[i % 0x20]
      return bytes(data)
"""
import sys, struct, os, subprocess

src = sys.argv[1]; key_str = sys.argv[2]; outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
raw = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

# ---------------- WannaCRI exact port ----------------
def generate_keys(key_num: int):
    ck = key_num.to_bytes(8, 'little')
    k = bytearray(0x20)
    k[0x00] = ck[0]; k[0x01] = ck[1]; k[0x02] = ck[2]
    k[0x03] = (ck[3] - 0x34) & 0xFF
    k[0x04] = (ck[4] + 0xF9) & 0xFF
    k[0x05] = ck[5] ^ 0x13
    k[0x06] = (ck[6] + 0x61) & 0xFF
    k[0x07] = k[0x00] ^ 0xFF
    k[0x08] = (k[0x01] + k[0x02]) & 0xFF
    k[0x09] = (k[0x01] - k[0x07]) & 0xFF
    k[0x0A] = k[0x02] ^ 0xFF
    k[0x0B] = k[0x01] ^ 0xFF
    k[0x0C] = (k[0x0B] + k[0x09]) & 0xFF
    k[0x0D] = (k[0x08] - k[0x03]) & 0xFF
    k[0x0E] = k[0x0D] ^ 0xFF
    k[0x0F] = (k[0x0A] - k[0x0B]) & 0xFF
    k[0x10] = (k[0x08] - k[0x0F]) & 0xFF
    k[0x11] = k[0x10] ^ k[0x07]
    k[0x12] = k[0x0F] ^ 0xFF
    k[0x13] = k[0x03] ^ 0x10
    k[0x14] = (k[0x04] - 0x32) & 0xFF
    k[0x15] = (k[0x05] + 0xED) & 0xFF
    k[0x16] = k[0x06] ^ 0xF3
    k[0x17] = (k[0x13] - k[0x0F]) & 0xFF
    k[0x18] = (k[0x15] + k[0x07]) & 0xFF
    k[0x19] = (0x21 - k[0x13]) & 0xFF
    k[0x1A] = k[0x14] ^ k[0x17]
    k[0x1B] = (k[0x16] + k[0x16]) & 0xFF
    k[0x1C] = (k[0x17] + 0x44) & 0xFF
    k[0x1D] = (k[0x03] + k[0x04]) & 0xFF
    k[0x1E] = (k[0x05] - k[0x16]) & 0xFF
    k[0x1F] = k[0x1D] ^ k[0x13]
    audio_t = b'URUC'
    video_key = bytearray(0x40); audio_key = bytearray(0x20)
    for i in range(0x20):
        video_key[i] = k[i]
        video_key[0x20 + i] = k[i] ^ 0xFF
        audio_key[i] = audio_t[(i >> 1) % 4] if i % 2 != 0 else k[i] ^ 0xFF
    return bytes(video_key), bytes(audio_key)

def decrypt_video_packet(packet: bytes, video_key: bytes) -> bytes:
    data = bytearray(packet)
    eps = len(data) - 0x40
    if eps >= 0x200:
        rolling = bytearray(video_key)
        for i in range(0x100, eps):
            data[0x40 + i] ^= rolling[0x20 + i % 0x20]
            rolling[0x20 + i % 0x20] = data[0x40 + i] ^ video_key[0x20 + i % 0x20]
        for i in range(0x100):
            rolling[i % 0x20] ^= data[0x140 + i]
            data[0x40 + i] ^= rolling[i % 0x20]
    return bytes(data)

def key_to_int(s: str) -> int:
    s = s.strip()
    try:
        return int(s, 0)
    except ValueError:
        pass
    return int(s, 16)

key_num = key_to_int(key_str)
print(f'key string {key_str!r} -> int 0x{key_num:016X}')
vk, ak = generate_keys(key_num)
print(f'video_key: {vk.hex()}')
print(f'  derived 0x20: {vk[:0x20].hex()}')

def al(n, a=0x20): return (n + a - 1) // a * a

# ---------------- frame table ----------------
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
print(f'\nframe table: {len(frames)} frames')

ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]
def test(items, label):
    if len(items) < 3: return
    h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
    out = bytearray(h)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, label + '.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    e = (r.stderr or '').strip()
    print(f'  {label}: {len(items)} frames -> {"DECODE OK" if not e else e[:130]}', flush=True)
    return not e

# ---- test on frame 24 (the first encrypted frame) ----
print('\n=== frame 24 (first encrypted frame) ===')
f24 = frames[23]
pkt = raw[f24[1]:f24[1]+f24[2]]
print(f'  idx={f24[0]} off=0x{f24[1]:x} len={f24[2]}')
print(f'  raw  head: {pkt[:16].hex(" ")}')
dec = decrypt_video_packet(pkt, vk)
print(f'  dec  head: {dec[:16].hex(" ")}')
head = [raw[o:o+fl] for _, o, fl in frames[:23]]
test(head + [pkt], 'f24_raw')
test(head + [dec], 'f24_dec')

# ---- full pass over all frames ----
print('\n=== full decryption pass ===')
out_frames = [raw[0xF0C:0xF0C+262]]                      # frame 0 plaintext
for fidx, off, fl in frames:
    pkt = raw[off:off+fl]
    if fl >= 0x240:
        out_frames.append(decrypt_video_packet(pkt, vk))
    else:
        out_frames.append(pkt)
test(out_frames[:400], 'all400')
test(out_frames, 'all_full')
