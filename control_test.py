"""
Test whether some MovieData files are unencrypted (a control group).

For each sample: locate DKIF, find the first chunk, walk inner frames, and try to decode
the frames with ffmpeg. A file whose frames decode proves the container layout is right and
pinpoints exactly what is different about the encrypted ones.
"""
import sys, struct, os, subprocess, glob, re

FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

def al(n, a=0x20): return (n + a - 1) // a * a

def analyse(path):
    buf = open(path, 'rb').read()
    d = buf.find(b'DKIF')
    if d < 0: return None
    ivf = bytearray(buf[d:d+32])
    magic, ver, hsz, fourcc, w, h, num, den, nf, _ = struct.unpack('<4sHH4sHHIIII', ivf)
    # chunks from 0x800
    chunks, o = [], 0x800
    while o + 0x20 <= len(buf):
        if buf[o:o+4] != b'@SFV':
            o += 0x20; continue
        size = struct.unpack_from('>I', buf, o+4)[0]
        if size == 0 or size > 8_000_000 or o + size > len(buf):
            o += 0x20; continue
        chunks.append((o, size)); o = al(o + size)
    frames = []
    for c, s in chunks:
        end, p = c + s, c + 0x20
        while p + 0x0C <= end:
            flen = struct.unpack_from('<I', buf, p)[0]
            fidx = struct.unpack_from('<I', buf, p+4)[0]
            if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(buf): break
            frames.append((p+0x0C, flen, fidx))
            p = al(p + 0x0C + flen)
            if p + 0x0C > end: break
    return dict(buf=buf, d=d, ivf=ivf, w=w, h=h, num=num, den=den, nf=nf,
                fourcc=fourcc.decode(), chunks=chunks, frames=frames)

def decode_probe(info, n=60):
    frames = info['frames'][:n]
    if not frames: return 'no frames', 0
    hh = bytearray(info['ivf']); struct.pack_into('<I', hh, 24, len(frames))
    out = bytearray(hh)
    for i, (off, fl, idx) in enumerate(frames):
        out += struct.pack('<IQ', fl, i) + info['buf'][off:off+fl]
    p = os.path.join(os.environ['TEMP'], 'probe_test.ivf')
    open(p, 'wb').write(out)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True, errors='replace')
    err = (r.stderr or '').strip().replace('\n', ' | ')
    return ('OK' if not err else err[:110]), len(frames)

cands = sys.argv[1:]
for path in cands:
    info = analyse(path)
    if info is None:
        print(f'{os.path.basename(path)}: no DKIF'); continue
    res, n = decode_probe(info)
    print(f'\n{os.path.basename(path)}  {os.path.getsize(path)} bytes')
    print(f'  IVF: {info["fourcc"]} {info["w"]}x{info["h"]} {info["num"]}/{info["den"]} frames={info["nf"]}')
    print(f'  DKIF@0x{info["d"]:x}  chunks={len(info["chunks"])}  inner frames={len(info["frames"])}')
    if info['frames']:
        print(f'  first frames: {[(hex(o), f, i) for o, f, i in info["frames"][:5]]}')
    print(f'  decode first {n}: {res}')
