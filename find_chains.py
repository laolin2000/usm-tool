"""
Scan the WHOLE file for chains of valid IVF frame records ({u32 LE size}{u64 LE ts}{data}).
A chain is credible when consecutive records decode. Report every chain found.
"""
import sys, struct, os, subprocess

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'

def chain_len(o, maxn=100000):
    n = 0
    start = o
    while o + 12 <= len(buf) and n < maxn:
        size, ts = struct.unpack_from('<IQ', buf, o)
        if size == 0 or size > 3_000_000:
            break
        if o + 12 + size > len(buf):
            break
        # timestamps should be sane and increasing
        n += 1
        o += 12 + size
    return n, o

print('=== scanning for IVF frame-record chains (min length 20) ===')
found = []
step = 1
o = 0xEE0 + 32
while o < len(buf) - 12:
    size, ts = struct.unpack_from('<IQ', buf, o)
    if 0 < size < 3_000_000 and ts < 10**12:
        n, end = chain_len(o)
        if n >= 20:
            found.append((o, n, end))
            print(f'  chain @0x{o:x}: {n} records, ends 0x{end:x}')
            o = end            # skip past
            continue
    o += 1

if not found:
    print('  no chains found')

# Fallback: brute-force frame sizes from the known frame-0 record and see whether
# subsequent records exist by checking that each declared size lands on a plausible spot.
print('\n=== inspect the region right after frame 0 (0x1012) ===')
print(' ', buf[0x1012:0x1060].hex(' '))
print('\n=== bytes around 0x1EDA0 (a big @SFV) ===')
print(' ', buf[0x1EDA0:0x1EE20].hex(' '))
