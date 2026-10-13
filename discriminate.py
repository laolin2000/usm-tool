"""
Discriminator: VP9 uncompressed headers require bits 0x10/0x20/0x40 of byte 2 to be 0
(byte2 & 0x70 == 0). Measure that across regions to tell real VP9 from encrypted data.
Also attempt mask recovery from the known-good frame 0.
"""
import sys, struct, math

path = sys.argv[1]
buf = open(path, 'rb').read()

def vp9_plausible(data, stride=1):
    """fraction of positions where data[i]&0x70==0 and data[i+1]&0xF0==0 (VP9 uncompressed hdr)"""
    n = 0; ok = 0
    for i in range(0, len(data) - 2, stride):
        n += 1
        if (data[i] & 0x70) == 0 and (data[i+1] & 0xF0) == 0:
            ok += 1
    return ok / max(n, 1)

regions = [
    ('frame0 payload 0xF0C+262', 0xF0C, 262),
    ('0x1040 block', 0x1040, 0x80),
    ('0x1960 block', 0x1960, 0x800),
    ('0x19640 block', 0x19640, 0x1000),
    ('0x1EDA0 block', 0x1EDA0, 0x1000),
    ('0xD3CDA0 block', 0xD3CDA0, 0x1000),
    ('random-ish deep 0x2000000', 0x2000000, 0x1000),
]
print('=== VP9 header plausibility (higher = more likely real VP9; random ~= 0.0625) ===')
for label, o, n in regions:
    print(f'  {label:<28} {vp9_plausible(buf[o:o+n]):.4f}')

print('\n=== byte2 & 0x70 distribution in frame0 vs 0x1960 ===')
for label, o, n in [('frame0', 0xF0C, 262), ('0x1960', 0x1960, 0x800), ('0x19640', 0x19640, 0x800)]:
    counts = {}
    for i in range(0, n, 3):
        v = buf[o+i] & 0x70
        counts[v] = counts.get(v, 0) + 1
    print(f'  {label}: {dict(sorted(counts.items()))}')

# ---- mask recovery attempt from frame 0 ----
# If the tail is CRI-masked, then for the true 64-bit key the decrypted 0x1960 block
# must start with a VP9-like header. We cannot brute 2^64, but we CAN test the
# hypothesis that the mask is the SAME as the one protecting the header tables:
# derive mask from the known plaintext table at 0x800 vs its encrypted twin (if any).
print('\n=== look for a second copy of the 0x800 table inside the file (encrypted twin) ===')
tbl = buf[0x800:0x828]
print('  table(0x800):', tbl.hex(' '))
# search for that table plaintext anywhere else
n = buf.count(tbl)
print(f'  exact plaintext copies of 0x800-table: {n}')
# search for the table XOR a constant 8-byte pattern (CRI mask is 64-bit rolling)
# try: does any 0x800-aligned position produce a constant-XOR with the table?
for cand in [0x1020, 0x10C0, 0x1960, 0x19640, 0xC2E0, 0xD3CD60]:
    x = bytes(a ^ b for a, b in zip(buf[cand:cand+0x28], tbl))
    # constant XOR would mean repeated 8-byte blocks
    blk = x[:8]
    rep = all(x[i:i+8] == blk for i in range(0, len(x) - 7, 8))
    print(f'  vs 0x{cand:x}: xor={x.hex(" ")[:48]}  const8={rep}')
