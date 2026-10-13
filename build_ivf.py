"""
Hypothesis: the IVF frame data sits AFTER the CRI index/header region (which ends at
0x1960 where zeros begin). Build a proper IVF by re-muxing frame records from 0x1960
onward, and validate with ffmpeg.
"""
import sys, struct, os, subprocess

path = sys.argv[1]
out = sys.argv[2]
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
FFPROBE = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffprobe.exe'

ivf_hdr = bytearray(buf[0xEE0:0xEE0 + 32])
nframes = struct.unpack_from('<I', ivf_hdr, 24)[0]
w, h = struct.unpack_from('<HH', ivf_hdr, 12)
num, den = struct.unpack_from('<II', ivf_hdr, 16)
print(f'target IVF: {w}x{h} {num}/{den} frames={nframes}')

candidates = [0x1000, 0x1020, 0x1220, 0x1960, 0x19640, 0x1b800]

for start in candidates:
    frames = []
    o = start
    for n in range(nframes + 64):
        if o + 4 > len(buf):
            break
        size = struct.unpack_from('<I', buf, o)[0]
        if size == 0 or size > 4_000_000:
            break
        if o + 4 + size > len(buf):
            break
        frames.append(buf[o + 4: o + 4 + size])
        o += 4 + size
    total = sum(len(f) for f in frames)
    print(f'\nstart=0x{start:x}: parsed {len(frames)} frames, {total} bytes, end=0x{o:x}')
    if len(frames) < 10:
        continue
    # build IVF
    hdr = bytearray(ivf_hdr)
    struct.pack_into('<I', hdr, 24, len(frames))
    blob = bytearray(hdr)
    for i, f in enumerate(frames):
        blob += struct.pack('<IQ', len(f), i)
        blob += f
    blob += struct.pack('<I', len(frames))          # IVF "frame count" footer
    testpath = f'{out}.start{start:x}.ivf'
    open(testpath, 'wb').write(blob)
    r = subprocess.run([FFPROBE, '-v', 'error', '-select_streams', 'v:0',
                        '-show_entries', 'stream=codec_name,width,height,nb_read_frames',
                        '-count_frames', '-of', 'default=nw=1', testpath],
                       capture_output=True, text=True)
    print(f'  -> {testpath} ({len(blob)} bytes)')
    print('  ffprobe:', (r.stdout or r.stderr).strip()[:400])
    r2 = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', testpath,
                         '-frames:v', '5', '-f', 'null', '-'],
                        capture_output=True, text=True)
    err = (r2.stderr or '').strip()
    print('  decode 5 frames ->', 'OK (no errors)' if not err else err[:300])
