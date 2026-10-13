"""
Search for per-packet markers to determine the correct packet boundaries for the
WannaCRI decryption.

If every encrypted packet carries the same 0x40-byte header prefix, that prefix repeats
throughout the encrypted region; finding its period reveals the packet size.
"""
import sys, struct, collections

src = sys.argv[1]
raw = open(src, 'rb').read()

# --- the header prefix of frame 24 ---
p = 0x192c
prefix = raw[p:p+0x40]
print(f'frame 24 prefix: {prefix[:16].hex(" ")} ...')

# --- look for repeats of the first 8/16/32 bytes of that prefix across the file ---
for n in (8, 16, 32, 64):
    needle = prefix[:n]
    hits = []
    i = raw.find(needle, 0x1960)
    while i != -1 and len(hits) < 40:
        hits.append(i)
        i = raw.find(needle, i + 1)
    print(f'\nprefix[:0x{n:x}] occurrences from 0x1960: {len(hits)}')
    if hits:
        print('  first:', [hex(x) for x in hits[:10]])
        if len(hits) > 1:
            d = [hits[k+1]-hits[k] for k in range(min(len(hits)-1, 12))]
            print('  strides:', d)

# --- generic: find the most common 16-byte block in the encrypted region ---
print('\n=== 16B block frequency in 0x1960..0x200000 ===')
c = collections.Counter()
seg = raw[0x1960:0x200000]
for i in range(0, len(seg) - 16, 1):
    c[seg[i:i+16]] += 1
for blk, n in c.most_common(8):
    if n > 3:
        print(f'  x{n} {blk.hex(" ")}  first@0x{raw.find(blk, 0x1960):x}')

# --- does the file contain repeated @SFV chunk headers inside the encrypted region? ---
print('\n=== structure: @SFV chunk offsets and their inner frame lengths (first 40) ===')
def al(n, a=0x20): return (n + a - 1) // a * a
o, cnt = 0x800, 0
while o + 0x20 <= len(raw) and cnt < 40:
    if raw[o:o+4] != b'@SFV':
        o += 0x20; continue
    size = struct.unpack_from('>I', raw, o+4)[0]
    if size == 0 or size > 8_000_000 or o + size > len(raw):
        o += 0x20; continue
    flen = struct.unpack_from('<I', raw, o+0x20)[0]
    fidx = struct.unpack_from('<I', raw, o+0x24)[0]
    print(f'  chunk@0x{o:08x} chunkSize=0x{size:07x} innerLen={flen:<8} innerIdx={fidx}')
    o = al(o + size); cnt += 1

# --- check: is the region 0x1960.. truly one big packet? measure its size ---
print(f'\nregion 0x1960 -> next @SFV chunk at 0xc2e0 = {0xc2e0-0x1960} bytes')
print(f'frame 24 data length = {43444} (0x{43444:x})')
print(f'0x1960 + 43444 = 0x{0x1960+43444:x}')
