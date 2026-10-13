"""Cross-validate with WannaCRI's own library (stubbing the optional ffmpeg-python dep)."""
import sys, os, types, traceback

sys.path.insert(0, r"C:\Users\<you>\Desktop\DSHStool\usm-tool\wannacri")

# --- stub the optional `ffmpeg` dependency ---
stub = types.ModuleType('ffmpeg')
class _P:
    def __init__(self, *a, **k): pass
    def __getattr__(self, n): return lambda *a, **k: self
    def run(self, *a, **k): return (b'', b'')
    def compile(self, *a, **k): return ([], b'')
stub.input = _P(); stub.output = _P(); stub.run = lambda *a, **k: (b'', b'')
stub.probe = lambda *a, **k: {}
stub.Error = Exception
sys.modules['ffmpeg'] = stub

src = r"D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat"
outdir = r"C:\Users\<you>\Desktop\DSHStool\usm-tool\wannacri_out"
os.makedirs(outdir, exist_ok=True)

from wannacri.usm.tools import generate_keys, decrypt_video_packet
from wannacri.usm.usm import Usm
print('WannaCRI tools imported OK')

# --- 1. compare key derivation ---
for label, ki in (('BE', int('7F4551499DF55E68', 16)),
                  ('LE', int.from_bytes(bytes.fromhex('7F4551499DF55E68'), 'little'))):
    vk, ak = generate_keys(ki)
    print(f'  {label} int=0x{ki:016X}')
    print(f'     video_key[:0x20] = {vk[:0x20].hex()}')
    print(f'     video_key[0x20:] = {vk[0x20:].hex()}')

# --- 2. run the real decrypt_video_packet on frame 24 ---
raw = open(src, 'rb').read()
import struct
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
f = frames[23]
pkt = raw[f[1]:f[1]+f[2]]
print(f'\nframe24 len={len(pkt)}')
for label, ki in (('BE', int('7F4551499DF55E68', 16)),
                  ('LE', int.from_bytes(bytes.fromhex('7F4551499DF55E68'), 'little'))):
    vk, _ = generate_keys(ki)
    d = decrypt_video_packet(pkt, vk)
    print(f'  {label}: changed={sum(1 for a,b in zip(pkt,d) if a!=b)}  dec[0x100:0x120]={d[0x100:0x120].hex(" ")}')

# --- 3. try the full Usm.open pipeline (may fail on unsupported codec) ---
print('\n=== Usm.open ===')
for keyarg in ('7F4551499DF55E68', '0x7F4551499DF55E68'):
    try:
        usm = Usm.open(src, key=keyarg)
        print(f'  key={keyarg}: videos={len(usm.videos)} audios={len(usm.audios)}')
        print(f'    video_key = {usm.video_key.hex() if usm.video_key else None}')
        out = os.path.join(outdir, 'video.h264')
        usm.save(out)
        print(f'    saved {out} ({os.path.getsize(out) if os.path.exists(out) else "?"} bytes)')
        break
    except Exception as e:
        print(f'  key={keyarg}: {type(e).__name__}: {e}')
