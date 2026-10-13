#!/usr/bin/env python3
"""
x11_ivf_try.py -- treat every @SFV chunk as ONE video frame and try the
candidate bitstream ranges with ffmpeg.
  A: chunk[0x40 : size-8]
  B: chunk[0x40 : size-6]
  C: chunk[0x40 : size]
  D: chunk[0x45 : size-8]   (skip a 5-byte per-frame record header)
"""
import struct, subprocess, os, os.path as p, collections, json

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
OUT = r'C:\Users\<you>\Desktop\DSHStool\usm-tool\probe'
os.makedirs(OUT, exist_ok=True)
D = open(PATH, 'rb').read(); N = len(D)
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

mk = [m.start() for m in __import__('re').finditer(b'@SFV', D)]
chunks = []
for x in mk:
    size = b32(x+4)
    if 0x20 <= size <= N-x:
        chunks.append((x, size))
print('candidate @SFV chunks with sane size: %d' % len(chunks))

first = chunks[:8]
print('\nfirst 8 chunk headers decoded:')
for off, size in first:
    print('  0x%08X size=%-7d | 0x08=0x%04X 0x0A=0x%04X 0x0C=%d 0x10=0x%X 0x14=0x%X 0x18=0x%X 0x1A=%d'
          % (off, size, struct.unpack_from('>H', D, off+8)[0], struct.unpack_from('>H', D, off+0x0A)[0],
             b32(off+0x0C), b32(off+0x10), b32(off+0x14), b32(off+0x18), struct.unpack_from('>H', D, off+0x1A)[0]))

def ivf(frames, w, h, rn, rd, path):
    b = bytearray(b'DKIF'+struct.pack('<HH', 0, 32)+b'VP90'+struct.pack('<HHIIII', w, h, rn, rd, len(frames), 0))
    for i, f in enumerate(frames):
        b += struct.pack('<IQ', len(f), i)+f
    open(path, 'wb').write(b)

def ffdec(path):
    r = subprocess.run([FFMPEG, '-hide_banner', '-v', 'error', '-i', path, '-f', 'null', '-'],
                       capture_output=True, timeout=600)
    return r.stderr.decode('utf-8', 'replace').strip()

def report(tag, frames, nf=None):
    path = p.join(OUT, 'f_%s.ivf' % tag)
    ivf(frames, 1080, 608, 30000, 1000, path)
    err = ffdec(path)
    lines = [l for l in err.splitlines() if l.strip()]
    print('  %-22s n=%-6d bytes=%-10d errlines=%-6d %s'
          % (tag, len(frames), p.getsize(path), len(lines), 'CLEAN DECODE' if not lines else lines[0][:100]))
    if lines:
        c = collections.Counter(lines[:200])
        print('      top errors:', c.most_common(3))
    return len(lines)

USE = chunks[1:]   # skip 0x800 (a @UTF metadata chunk, not video)
print('\nusing %d chunks (skipping the @UTF-carrying one)' % len(USE))

# skip the header chunk 0xEC0 (contains the nested IVF header + frame0)
VID = [(o, s) for (o, s) in USE if b32(o+0x10) >= 0x100]
print('chunks with chinfo>=0x100: %d' % len(VID))
print('  expected frame counter range: %d .. %d'
      % (b32(VID[0][0]+0x10) >> 8, b32(VID[-1][0]+0x10) >> 8))

print('\n=== candidate A: chunk[0x40 : size-8] ===')
report('A_pad8', [D[o+0x40:o+s-8] for o, s in VID])
print('=== candidate B: chunk[0x40 : size-6] ===')
report('B_pad6', [D[o+0x40:o+s-6] for o, s in VID])
print('=== candidate C: chunk[0x40 : size] ===')
report('C_full', [D[o+0x40:o+s] for o, s in VID])
print('=== candidate D: chunk[0x45 : size-8] ===')
report('D_skip5', [D[o+0x45:o+s-8] for o, s in VID])

print('\n=== first 4 frames only, each candidate (isolate frame 1) ===')
for tag, sl in (('A4', lambda o, s: D[o+0x40:o+s-8]), ('B4', lambda o, s: D[o+0x40:o+s-6]),
                ('C4', lambda o, s: D[o+0x40:o+s])):
    report(tag, [sl(o, s) for o, s in VID[:4]])

print('\n=== does the *raw* chunk bitstream of frame 1 start with a VP9 keyframe? ===')
o, s = VID[0]
print('frame1 chunk @0x%X size=%d, chinfo=%d' % (o, s, b32(o+0x10)))
print('bytes 0x40..0x60:', D[o+0x40:o+0x60].hex(' '))
print('bytes 0x40..0x60 ascii:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in D[o+0x40:o+0x60]))
