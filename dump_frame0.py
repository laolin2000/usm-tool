"""
Dump the first IVF frame payload and look for codec markers, then scan the whole file for
frame-codec signatures to determine whether frames are raw or encrypted.
"""
import sys, re, struct

path = sys.argv[1]
buf = open(path, 'rb').read()

print('=== IVF frame #0 payload: 0xF0C..0x1012 (262 bytes) ===')
fr = buf[0xF0C:0x1012]
for i in range(0, len(fr), 32):
    chunk = fr[i:i+32]
    print(f'  0x{0xF0C+i:06x}: {chunk.hex(" "):<96} |{"".join(chr(b) if 32<=b<127 else "." for b in chunk)}|')

print('\n=== tail of frame #0 and the 0x1000..0x1020 block ===')
print('  0xF80..0x1012:', buf[0xF80:0x1012].hex(' '))

# ---- scan for JPEG / VP9 / H264 markers in the whole file ----
markers = {
    'JPEG SOI  (FFD8FF)': b'\xff\xd8\xff',
    'JPEG EOI  (FFD9)': b'\xff\xd9',
    'JPEG SOF0 (FFC0)': b'\xff\xc0',
    'JPEG SOF2 (FFC2)': b'\xff\xc2',
    'JPEG DHT  (FFC4)': b'\xff\xc4',
    'JPEG DQT  (FFDB)': b'\xff\xdb',
    'JPEG APP0 (FFE0)': b'\xff\xe0',
    'H264 SPS  (0000000167)': b'\x00\x00\x00\x01\x67',
    'H264 IDR  (0000000165)': b'\x00\x00\x00\x01\x65',
    'DKIF': b'DKIF',
    'VP90': b'VP90',
    '@SFV': b'@SFV',
    'IVF ': b'IVF ',
}
print('\n=== marker census ===')
for name, m in markers.items():
    c = buf.count(m)
    first = buf.find(m)
    print(f'  {name:<24} count={c:<7} first={"0x%x" % first if first >= 0 else "-"}')

# ---- entropy of the first 0x4000 bytes after the IVF header, 256B windows ----
print('\n=== zero-ratio + entropy of 0xF00..0x1F00 in 0x100 windows ===')
import math
for o in range(0xF00, 0x1F00, 0x100):
    w = buf[o:o+0x100]
    hist = [0]*256
    for b in w: hist[b] += 1
    H = -sum((c/len(w))*math.log2(c/len(w)) for c in hist if c)
    z = w.count(0)/len(w)
    print(f'  0x{o:06x}: H={H:.2f} zeros={z*100:.1f}%')
