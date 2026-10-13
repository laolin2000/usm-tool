"""
WannaCRI decryption, CORRECTLY ported.

Bug in my previous attempt: the rolling state must be updated with the CIPHERTEXT byte
(saved BEFORE the xor), exactly like the official C source:
    plainbyte = data[0x40 + i];
    data[0x40 + i] ^= rolling[0x20 + i % 0x20];
    rolling[0x20 + i % 0x20] = plainbyte ^ video_key[0x20 + i % 0x20];
"""
import sys, struct, os, subprocess

src = sys.argv[1]; key_str = sys.argv[2]; outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
raw = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

def generate_keys(key_num: int) -> bytes:
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
    vk = bytearray(0x40)
    for i in range(0x20):
        vk[i] = k[i]
        vk[0x20+i] = k[i] ^ 0xFF
    return bytes(vk)

def decrypt_video_packet(packet: bytes, video_key: bytes) -> bytes:
    """exact port of wannacri.usm.tools.decrypt_video_packet"""
    data = bytearray(packet)
    eps = len(data) - 0x40
    if eps >= 0x200:
        rolling = bytearray(video_key)
        for i in range(0x100, eps):
            tmp = data[0x40 + i]                                    # CIPHERTEXT first
            data[0x40 + i] ^= rolling[0x20 + i % 0x20]
            rolling[0x20 + i % 0x20] = tmp ^ video_key[0x20 + i % 0x20]
        for i in range(0x100):
            rolling[i % 0x20] ^= data[0x140 + i]
            data[0x40 + i] ^= rolling[i % 0x20]
    return bytes(data)

h = bytes.fromhex(key_str)
for label, ki in (('BE', int.from_bytes(h, 'big')), ('LE', int.from_bytes(h, 'little'))):
    vk = generate_keys(ki)
    print(f'{label} key=0x{ki:016X}  video_key[:0x20]={vk[:0x20].hex()}')

def al(n, a=0x20): return (n + a - 1) // a * a
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

f = frames[23]
pkt = raw[f[1]:f[1]+f[2]]
print(f'frame 24: off=0x{f[1]:x} len={f[2]}')
for label, ki in (('BE', int.from_bytes(h, 'big')), ('LE', int.from_bytes(h, 'little'))):
    d = decrypt_video_packet(pkt, generate_keys(ki))
    diff = sum(1 for a, b in zip(pkt, d) if a != b)
    print(f'  {label}: changed={diff}')
    print(f'    dec[0x40:0x60] = {d[0x40:0x60].hex(" ")}')
    print(f'    dec[0x40:0x80] = {d[0x40:0x80].hex(" ")}')

ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]
def test(items, label):
    hh = bytearray(ivf); struct.pack_into('<I', hh, 24, len(items))
    out = bytearray(hh)
    for i, d in enumerate(items):
        out += struct.pack('<IQ', len(d), i) + d
    out += struct.pack('<I', len(items))
    p = os.path.join(outdir, label + '.ivf'); open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    e = (r.stderr or '').strip()
    ok = not e
    print(f'  {label}: {len(items)} frames -> {"DECODE OK" if ok else e[:110]}', flush=True)
    if ok: os.replace(p, os.path.join(outdir, f'OK_{label}.ivf'))
    return ok

print('\n=== full decode tests ===')
for label, ki in (('BE', int.from_bytes(h, 'big')), ('LE', int.from_bytes(h, 'little'))):
    vk = generate_keys(ki)
    outs = [raw[0xF0C:0xF0C+262]]
    for fidx, off, fl in frames:
        p = raw[off:off+fl]
        outs.append(decrypt_video_packet(p, vk) if fl >= 0x240 else p)
    test(outs[:400], f'{label}_400')
    test(outs, f'{label}_full')
