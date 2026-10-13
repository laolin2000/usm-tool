"""
Mask recovery via known plaintext.

The @SFV record at 0x800 is KNOWN plaintext (we read its full @UTF table). Nearby records
at 0x1020/0x10C0/... have the same header layout. If a per-0x800-block mask is applied,
then XORing a known-plaintext block against an unknown block at the SAME in-block offset
cancels the mask and reveals the plaintext difference.

Also: derive the keystream from the known plaintext @SFV header at 0x1960 variants and
look for the mask in the file.
"""
import sys, struct, collections

path = sys.argv[1]
buf = open(path, 'rb').read()

# Known plaintext: the record at 0x800 (first 0x40 bytes fully understood)
PT800 = buf[0x800:0x840]

print('=== compare 0x800 (plain) against later 0x800-aligned blocks ===')
for off in [0x1000, 0x1800, 0x2000, 0x2800, 0xC000, 0xC800]:
    x = bytes(a ^ b for a, b in zip(PT800, buf[off:off+0x40]))
    print(f'  0x{off:x} ^ 0x800: {x.hex(" ")}')

print('\n=== are there @SFV-identical blocks? compare record headers ===')
recs = []
i = buf.find(b'@SFV')
while i != -1:
    recs.append(i)
    i = buf.find(b'@SFV', i + 1)
# group records by their first 16 bytes after the magic
groups = collections.defaultdict(list)
for o in recs:
    if o + 0x40 <= len(buf):
        groups[bytes(buf[o+4:o+0x20])].append(o)
big = sorted(groups.items(), key=lambda kv: -len(kv[1]))[:5]
for k, v in big:
    print(f'  key={k.hex(" ")} count={len(v)} first={[hex(x) for x in v[:6]]}')

print('\n=== the 0x60-stride run @0xC2E0: full dump of 3 consecutive records ===')
o = 0xC2E0
for k in range(3):
    blo = buf[o:o+0x60]
    print(f'  @0x{o:x}: {blo.hex(" ")}')
    o += 0x60

print('\n=== mask hypothesis: same-in-block offset XOR (cancels a per-block mask) ===')
# take two records of the same shape in the 0x60-stride run and XOR their 0x60 blocks
a = buf[0xC2E0:0xC2E0+0x60]
b = buf[0xC340:0xC340+0x60]
x = bytes(p ^ q for p, q in zip(a, b))
print('  a^b:', x.hex(' '))
print('  zeros:', x.count(0), '/', len(x))

print('\n=== derive candidate keystream from known @SFV plaintext at 0x1960 and search for it ===')
# assume 0x1960 is an @SFV record with a 0x28 header identical in shape to 0xC2E0's
known_pattern = buf[0xC2E0:0xC300]     # a real @SFV record block
stream = bytes(p ^ q for p, q in zip(buf[0x1960:0x1960+0x20], known_pattern[:0x20]))
print('  derived xor:', stream.hex(' '))
cnt = buf.count(stream)
print('  occurrences of that xor in file:', cnt)

print('\n=== search for a 0x40-byte repeating mask in the file ===')
for blk in [0x40, 0x60, 0x80, 0x100]:
    hits = 0
    for o in range(0x1000, len(buf) - blk*2, blk):
        if buf[o:o+blk] == buf[o+blk:o+blk*2]:
            hits += 1
    print(f'  block=0x{blk:x} repeated-adjacent count={hits}')
