"""
Produce the deliverable MP4 from the fully verified decodable prefix, and re-verify the
whole chain end to end.

Verification summary of the container:
  * CRI USM (Sofrid) container, VP9 video 1080x608, 30000/1000 fps, 4412 frames
  * frame table: 4411 records (idx 1..4411) walked from '@SFV' chunks, 0x20-aligned
  * frames 0..23 are plaintext VP9 and decode cleanly
  * frame 24 onwards is protected; neither the raw bytes nor the CRI videomask with the
    supplied key yields a decodable VP9 stream
"""
import sys, struct, os, subprocess

src = sys.argv[1]; outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
raw = open(src, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
FFPROBE_INFO = None

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
print(f'source frames in table: {len(frames)}')

ivf = raw[raw.find(b'DKIF'):raw.find(b'DKIF')+32]
N = 24   # frames 0..23 (verified decodable)
items = [(0xF0C, 262)] + [(o, fl) for _, o, fl in frames[:N-1]]
h = bytearray(ivf); struct.pack_into('<I', h, 24, len(items))
out = bytearray(h)
for i, (o2, fl) in enumerate(items):
    out += struct.pack('<IQ', fl, i) + raw[o2:o2+fl]
out += struct.pack('<I', len(items))
ivf_path = os.path.join(outdir, '001960_prefix.ivf')
open(ivf_path, 'wb').write(out)
print(f'IVF: {len(items)} frames, {len(out)} bytes')

mp4 = os.path.join(outdir, '001960_TAKE_CONTROL_partial.mp4')
r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', ivf_path,
                    '-c:v', 'libx264', '-preset', 'slow', '-crf', '14',
                    '-pix_fmt', 'yuv420p', '-movflags', '+faststart', mp4],
                   capture_output=True, text=True, errors='replace')
e = (r.stderr or '').strip()
print('encode ->', 'OK' if not e else e[:200])
if os.path.exists(mp4):
    print(f'  {mp4} ({os.path.getsize(mp4)} bytes)')
    r2 = subprocess.run([FFMPEG, '-i', mp4], capture_output=True, text=True, errors='replace')
    for line in (r2.stderr or '').splitlines():
        if 'Stream #0' in line or 'Duration' in line:
            print('   ', line.strip())

# also dump frame 0 as PNG proof
png = os.path.join(outdir, 'frame000.png')
subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', ivf_path, '-frames:v', '1', png],
               capture_output=True, text=True)
png2 = os.path.join(outdir, 'frame023.png')
subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', ivf_path, '-vf', 'select=eq(n\\,23)',
                '-frames:v', '1', png2], capture_output=True, text=True)
for f in (png, png2):
    if os.path.exists(f): print(f'  {f} ({os.path.getsize(f)} bytes)')
