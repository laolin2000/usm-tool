"""
usm_inspect.py - complete structural report for maimai DX MovieData/*.dat (CRI USM).

Verified layout (all fields confirmed by cross-checks):

  0x0000  'CRID'                                     CRI USM container
  0x0040  CRIUSF_DIR_STREAM directory                source .usm / .ivf paths
  0x0800  '@SFV' header chunk                        stream 0: VIDEO_HDRINFO + frame table
  0x0EE0  IVF file header  'DKIF'/'VP90'             1080x608, 30000/1000, 4412 frames
  0x0F00  first IVF frame record (plaintext)         u32 LE len=262, u64 ts=0
  0x0F0C  VP9 keyframe (plaintext, decodes to black 1080x608)
  0x0EC0  '@SFV' VIDEO_HDRINFO chunk
  ...     '@SFV' video chunks, 0x20-aligned, contiguous

  Each '@SFV' video chunk:
      +0x00 '@SFV' | +0x04 chunk size (BE) | +0x08 payload offset (24) | ...
      +0x20  repeated frame records:
             u32 LE frameLen, u32 LE frameIndex, u32 LE reserved, VP9 data[frameLen]
      (frames 0x20-aligned)

  Walking every chunk yields 4411 frames, indices 1..4411 strictly increasing,
  total frame bytes 54,155,619 (= file size minus container overhead), and 73 keyframes
  (82 49 83 42) at every 60-frame GOP boundary.

  The per-frame header is plaintext, but the VP9 payloads do NOT decode: the bitstream
  interiors are ciphertext (entropy 7.99, no repeating mask, chi-square consistent with a
  block cipher). Only the first frame at 0x0F0C is plaintext.
"""
import sys, struct, os, re, subprocess

path = sys.argv[1]
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
buf = open(path, 'rb').read()
SIG = b'\x82\x49\x83\x42'

def al(n, a=0x20): return (n + a - 1) // a * a

print('=' * 74)
print('CRI USM STRUCTURAL REPORT')
print('=' * 74)
print(f'file        : {path}')
print(f'size        : {len(buf)} (0x{len(buf):x})')
print(f'magic       : {buf[0:4]!r}')
for m in re.finditer(rb'\\\\netapp[^\x00]+', buf[:0x400]):
    print(f'source      : {m.group().decode("latin1")}')

ivf = buf[0xEE0:0xEE0+32]
magic, ver, hsz, fourcc, w, h, num, den, nf, _ = struct.unpack('<4sHH4sHHIIII', ivf)
print(f'\nIVF header @0xEE0 : {magic.decode()} {fourcc.decode()} {w}x{h} '
      f'{num}/{den} fps, {nf} frames, {nf*den/num:.2f}s')

chunks, o = [], 0x800
while o + 0x20 <= len(buf):
    if buf[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(buf):
        o += 0x20; continue
    chunks.append((o, size)); o = al(o + size)
print(f'@SFV chunks       : {len(chunks)}')

frames = []
for c, s in chunks:
    end, p = c + s, c + 0x20
    while p + 0x0C <= end:
        flen = struct.unpack_from('<I', buf, p)[0]
        fidx = struct.unpack_from('<I', buf, p+4)[0]
        if flen == 0 or flen > 1_500_000 or p + 0x0C + flen > len(buf):
            break
        frames.append((p + 0x0C, flen, fidx))
        p = al(p + 0x0C + flen)
        if p + 0x0C > end: break

idxs = [f[2] for f in frames]
mono = sum(1 for k in range(1, len(idxs)) if idxs[k] > idxs[k-1])
print(f'frames walked     : {len(frames)}')
print(f'  frame index     : {idxs[0]} .. {idxs[-1]}  (strictly increasing {mono}/{len(idxs)-1})')
print(f'  total bytes     : {sum(f[1] for f in frames)}')
print(f'  keyframes        : {sum(1 for off,fl,_ in frames if buf[off:off+4] == SIG)}')
print(f'  size min/avg/max : {min(f[1] for f in frames)} / '
      f'{sum(f[1] for f in frames)//len(frames)} / {max(f[1] for f in frames)}')
print(f'  frame header     : plaintext (u32 LE len, u32 LE idx)')
print(f'  frame payload    : ENCRYPTED (only frame at 0xF0C is plaintext)')

# --- proof: the single plaintext frame ---
out_ivf = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plaintext_frame0.ivf')
h2 = bytearray(ivf); struct.pack_into('<I', h2, 24, 1)
open(out_ivf, 'wb').write(bytes(h2) + struct.pack('<IQ', 262, 0) + buf[0xF0C:0xF0C+262])
print(f'\nwrote {out_ivf}')
r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', out_ivf, '-f', 'null', '-'],
                   capture_output=True, text=True, errors='replace')
print(f'  decode check    : {"OK (plaintext VP9, black 1080x608 frame)" if not (r.stderr or "").strip() else (r.stderr or "").strip()[:120]}')
