"""
Probe the very first frames: wrap candidate byte ranges as IVF frames and let ffmpeg
tell us which ones are valid VP9. This pinpoints the frame boundary and whether the
data is encrypted.
"""
import sys, struct, subprocess, os

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = buf[0xEE0:0xEE0+32]

def try_frames(label, frames):
    h = bytearray(IVF_HDR)
    struct.pack_into('<I', h, 24, len(frames))
    blob = bytearray(h)
    for i, f in enumerate(frames):
        blob += struct.pack('<IQ', len(f), i) + f
    p = os.path.join(workdir, label + '.ivf')
    open(p, 'wb').write(blob)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True)
    err = (r.stderr or '').strip().replace('\n', ' | ')
    print(f'  {label:<34} frames={len(frames):3d} bytes={len(blob):9d} -> {"DECODE OK" if not err else err[:150]}')

print('=== candidate interpretations of the first frames ===')
# 1. IVF records right after the DKIF header
try_frames('ivf_from_0xF00', [buf[0xF0C:0x1012]])
# 2. the 262-byte block as a frame
try_frames('blk_0xF0C_262', [buf[0xF0C:0xF0C+262]])
# 3. several small blocks around 0x1000
try_frames('blk_0x1000_32', [buf[0x1000:0x1020]])
try_frames('blk_0x1020_98', [buf[0x1020:0x1020+0x98]])
try_frames('blk_0x1060_64', [buf[0x1060:0x1060+0x40]])
try_frames('blk_0x1960_7e0', [buf[0x1960:0x1960+0x7e0]])
try_frames('blk_0x1960_1000', [buf[0x1960:0x2960]])
try_frames('blk_0x19640_21b8', [buf[0x19640:0x19640+0x21b8]])
try_frames('record_0xD3CD60', [buf[0xD3CD60:0xD3CD60+0x4958]])

# 4. the payload after stripping the 0x40 record header
try_frames('rec_payload_0xD3CDA0', [buf[0xD3CDA0:0xD3CDA0+0x4918]])

# 5. Is the 16-byte 'hash' + uint32 a suffix or prefix? Try payload minus 0x20
try_frames('rec_payload_minus20', [buf[0xD3CDA0:0xD3CDA0+0x4918-0x20]])

# 6. raw VP9 in the 0x19640 region
try_frames('blk_0x19640_all', [buf[0x19640:0x19640+0x8000]])

# 7. maybe the frames are stored inside the 0x800-stride struct at 0x1000..0x1960
frames = []
o = 0x1000
while o < 0x1960:
    frames.append(buf[o+0x40:o+0x800])
    o += 0x800
try_frames('stride800_payloads', frames)

print('\n=== entropy of individual candidate blocks (7.9+ = encrypted/compressed) ===')
import math
for label, s, e in [('0x1000-0x1020', 0x1000, 0x1020), ('0x1040-0x10c0', 0x1040, 0x10c0),
                    ('0x10c8-0x1120', 0x10c8, 0x1120), ('0x1928-0x1960', 0x1928, 0x1960),
                    ('0x1960-0x1968', 0x1960, 0x1968), ('0x1968-0x1980', 0x1968, 0x1980),
                    ('0x1020-0x1040', 0x1020, 0x1040), ('0x1040-0x1060', 0x1040, 0x1060)]:
    w = buf[s:e]
    hist = [0]*256
    for x in w: hist[x] += 1
    H = -sum((c/len(w))*math.log2(c/len(w)) for c in hist if c)
    print(f'  {label}: H={H:.2f}  {w.hex(" ")[:72]}')
