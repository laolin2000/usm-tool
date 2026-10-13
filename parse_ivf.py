"""
Verify whether the payload is encrypted at all, then parse the IVF structure.

Findings to test:
 1. video_mask() output == input for the probe windows (no change) -> payload may be plain.
 2. If plain: the IVF frame records should walk cleanly from 0xF00.
"""
import sys, struct

path = sys.argv[1]
buf = open(path, 'rb').read()
print(f'file {len(buf)} (0x{len(buf):x})')

# ---- 1. IVF file header at 0xEE0 ----
h = buf[0xEE0:0xEE0 + 32]
magic, ver, hsz, fourcc, w, hgt, num, den, nframes, unused = struct.unpack('<4sHH4sHHIIII', h)
print(f'IVF {magic} v{ver} hdr={hsz} {fourcc} {w}x{hgt} rate={num}/{den} frames={nframes}')

# ---- 2. walk IVF frame records from 0xF00 ----
def walk(start, limit=40):
    o = start
    rows = []
    for n in range(limit):
        if o + 12 > len(buf):
            break
        size, ts = struct.unpack_from('<IQ', buf, o)
        rows.append((n, o, size, ts))
        if size == 0 or size > 8_000_000:
            break
        o += 12 + size
    return rows, o

rows, endOff = walk(0xF00, 30)
print('\n=== IVF record walk from 0xF00 ===')
for n, o, size, ts in rows:
    print(f'  #{n:3d} @0x{o:8x} size={size:8d} ts={ts}')
print(f'  ended at 0x{endOff:x} after {len(rows)} records')

# ---- 3. where does the first *invalid* record occur? scan for the run of valid records ----
print('\n=== locate all regions where a valid IVF record chain exists ===')
o = 0xF00
good = 0
last = o
while o + 12 <= len(buf):
    size, ts = struct.unpack_from('<IQ', buf, o)
    if size == 0 or size > 2_000_000 or ts > 10 ** 12:
        break
    good += 1
    last = o
    o += 12 + size
print(f'  chain length={good} start=0xF00 end=0x{o:x}')

# ---- 4. check the 16-byte blocks that looked like cipher: compare with plaintext neighbours ----
print('\n=== bytes 0x1000..0x1020 (the suspicious 32B block) ===')
print(' ', buf[0x1000:0x1020].hex())
print('=== bytes 0xF00..0xF20 ===')
print(' ', buf[0xF00:0xF20].hex())

# ---- 5. Is the whole tail after the CRI header maybe an IVF file? find "DKIF" occurrences ----
print('\nDKIF occurrences:', [hex(i) for i in range(len(buf)) if buf[i:i+4] == b'DKIF'])

# ---- 6. count @SFV and see if the byte right after each is a plausible frame-size LE u32 ----
import re
sfv = [m.start() for m in re.finditer(b'@SFV', buf)]
print(f'\n@SFV count={len(sfv)}')
for o in sfv[:5]:
    size = struct.unpack_from('>I', buf, o + 4)[0]
    print(f'  0x{o:x} size=0x{size:x}')
