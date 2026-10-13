"""
Exact port of MaiChartManager's UsmExtractor (WannaCRI.cs DefaultKey = 0x7F4551499DF55E68).

    header          = 0x20 bytes
    sizeAfterHeader = u32 BE @[4:8]
    payloadOffset   = header[9]          (usually 24)
    paddingSize     = u16 BE @[10:12]
    channelNumber   = header[12]
    payloadType     = header[15] & 3
    payloadSize     = sizeAfterHeader - payloadOffset - paddingSize
    -> skip (payloadOffset - 0x18) bytes, read payloadSize, skip paddingSize
    -> only payloadType == 0 is a stream payload
    -> '@SFV' payloads are video, '@SFA' are audio
    -> video payload is decrypted with the CRI rolling-32 mask
"""
import sys, struct, os, subprocess
try: sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception: pass

src = sys.argv[1]; outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
KEY = 0x7F4551499DF55E68

# ---------------- key derivation (exact) ----------------
def generate_keys(key_num: int):
    ck = key_num.to_bytes(8, 'little')
    k = bytearray(0x20)
    k[0x00]=ck[0]; k[0x01]=ck[1]; k[0x02]=ck[2]
    k[0x03]=(ck[3]-0x34)&0xFF; k[0x04]=(ck[4]+0xF9)&0xFF; k[0x05]=ck[5]^0x13
    k[0x06]=(ck[6]+0x61)&0xFF; k[0x07]=k[0x00]^0xFF; k[0x08]=(k[0x01]+k[0x02])&0xFF
    k[0x09]=(k[0x01]-k[0x07])&0xFF; k[0x0A]=k[0x02]^0xFF; k[0x0B]=k[0x01]^0xFF
    k[0x0C]=(k[0x0B]+k[0x09])&0xFF; k[0x0D]=(k[0x08]-k[0x03])&0xFF; k[0x0E]=k[0x0D]^0xFF
    k[0x0F]=(k[0x0A]-k[0x0B])&0xFF; k[0x10]=(k[0x08]-k[0x0F])&0xFF; k[0x11]=k[0x10]^k[0x07]
    k[0x12]=k[0x0F]^0xFF; k[0x13]=k[0x03]^0x10; k[0x14]=(k[0x04]-0x32)&0xFF
    k[0x15]=(k[0x05]+0xED)&0xFF; k[0x16]=k[0x06]^0xF3; k[0x17]=(k[0x13]-k[0x0F])&0xFF
    k[0x18]=(k[0x15]+k[0x07])&0xFF; k[0x19]=(0x21-k[0x13])&0xFF; k[0x1A]=k[0x14]^k[0x17]
    k[0x1B]=(k[0x16]+k[0x16])&0xFF; k[0x1C]=(k[0x17]+0x44)&0xFF; k[0x1D]=(k[0x03]+k[0x04])&0xFF
    k[0x1E]=(k[0x05]-k[0x16])&0xFF; k[0x1F]=k[0x1D]^k[0x13]
    vk = bytearray(0x40); ak = bytearray(0x20)
    tpl = b'URUC'
    for i in range(0x20):
        vk[i] = k[i]; vk[0x20+i] = k[i] ^ 0xFF
        ak[i] = tpl[(i >> 1) % 4] if i % 2 != 0 else (k[i] ^ 0xFF)
    return bytes(vk), bytes(ak)

def decrypt_video_packet(packet: bytes, video_key: bytes) -> bytes:
    data = bytearray(packet)
    eps = len(data) - 0x40
    if eps >= 0x200:
        rolling = bytearray(video_key)
        for i in range(0x100, eps):
            tmp = data[0x40+i]
            data[0x40+i] ^= rolling[0x20 + i % 0x20]
            rolling[0x20 + i % 0x20] = tmp ^ video_key[0x20 + i % 0x20]
        for i in range(0x100):
            rolling[i % 0x20] ^= data[0x140+i]
            data[0x40+i] ^= rolling[i % 0x20]
    return bytes(data)

def decrypt_audio_packet(packet: bytes, audio_key: bytes) -> bytes:
    data = bytearray(packet)
    if len(data) > 0x140:
        for i in range(0x140, len(data)):
            data[i] ^= audio_key[i % 0x20]
    return bytes(data)

vk, ak = generate_keys(KEY)
print(f'key 0x{KEY:016X}')
print(f'  video_key[:0x20] = {vk[:0x20].hex()}')

# ---------------- walk chunks exactly like UsmExtractor ----------------
o = 0
chunks = 0
video = bytearray()
vparts = []
while o + 0x20 <= len(buf):
    h = buf[o:o+0x20]
    size_after = struct.unpack_from('>I', h, 4)[0]
    payload_off = h[9]
    padding = struct.unpack_from('>H', h, 10)[0]
    chno = h[12]
    ptype = h[15] & 0x03
    if size_after == 0 or o + 0x20 + size_after > len(buf):
        print(f'  stop at 0x{o:x}: sizeAfter=0x{size_after:x}')
        break
    payload_size = size_after - payload_off - padding
    pstart = o + 0x20 + (payload_off - 0x18)
    payload = buf[pstart:pstart + payload_size]
    chunks += 1
    if ptype == 0 and len(payload) > 0 and h[0:4] == b'@SFV':
        dec = decrypt_video_packet(payload, vk)
        vparts.append((o, len(payload), dec))
    o = (o + 0x20 + size_after + 0x1F) & ~0x1F      # chunks are 0x20-aligned

print(f'\nchunks walked: {chunks}')
print(f'@SFV stream payloads: {len(vparts)}')
tot = sum(n for _, n, _ in vparts)
print(f'  total payload bytes: {tot}')
if vparts:
    print(f'  first payload sizes: {[n for _, n, _ in vparts[:10]]}')

# ---------------- write the concatenated stream and try to play it ----------------
blob = b''.join(d for _, _, d in vparts)
raw_blob = b''.join(buf[o+0x20+24:o+0x20+24+n] for o, n, _ in vparts)
for name, data in (('dec', blob), ('raw', raw_blob)):
    p = os.path.join(outdir, f'video_{name}.bin')
    open(p, 'wb').write(data)
    print(f'  wrote {p} ({len(data)} bytes) head={data[:8].hex(" ")}')

# try as IVF / raw VP9
for name, data in (('dec', blob), ('raw', raw_blob)):
    for label, args in (('ivf', ['-f', 'ivf']), ('vp9', ['-f', 'vp9'])):
        p = os.path.join(outdir, f'video_{name}.bin')
        outp = os.path.join(outdir, f'test_{name}_{label}.mp4')
        r = subprocess.run([FFMPEG, '-v', 'error', '-y'] + args + ['-i', p,
                            '-c:v', 'libx264', '-preset', 'ultrafast', '-frames:v', '60', outp],
                           capture_output=True, text=True, errors='replace')
        e = (r.stderr or '').strip()
        print(f'  {name}/{label}: {"OK" if not e else e[:100]}')
