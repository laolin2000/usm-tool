"""
Look at every @SFV record's 0x40-byte header as a field table:
 [magic 4][size 4][f1 4][f2 4][f3 4][f4 4][f5 4][u32_1 4][u32_2 4][u32_3 4][u32_4 4][u32_5 4]
and check which field counts up monotonically (the frame index) and which holds sizes.
Also dump the 'footer' (last 0x20 bytes) of a big record: it ended with a u32 size + hash.
"""
import sys, re, struct, collections

path = sys.argv[1]
buf = open(path, 'rb').read()

recs = []
for m in re.finditer(b'@SFV', buf):
    o = m.start()
    if o + 0x40 > len(buf): continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if 0 < size < 4_000_000 and o + size <= len(buf):
        f = struct.unpack_from('>12I', buf, o)
        recs.append((o, size, f))
print(f'records: {len(recs)}')

# which field is monotonic?
print('\n=== monotonicity of each field across records ===')
for k in range(2, 12):
    vals = [r[2][k] for r in recs]
    inc = sum(1 for i in range(1, len(vals)) if vals[i] > vals[i-1])
    print(f'  field[{k}] inc={inc}/{len(vals)-1}  first5={vals[:5]}  max={max(vals)}')

# payload analysis: how many trailing bytes look like a footer?
print('\n=== per-record payload entropy and footer ===')
for k, (o, size, f) in enumerate(recs[:6]):
    pay = buf[o+0x40:o+size]
    print(f'  rec#{k} @0x{o:x} size=0x{size:x} payload={len(pay)} last32={pay[-32:].hex(" ")}')

# Try: payload = frame data; test a bunch of records
print('\n=== frame-size table hunt: 4-byte LE values inside records that sum to the record size ===')
for k, (o, size, f) in enumerate(recs[6:12]):
    pay = buf[o:o+size]
    # scan for u32 LE values in 8..0x20000 that could be frame sizes
    cands = [struct.unpack_from('<I', pay, i)[0] for i in range(0x40, min(len(pay)-4, 0x200), 4)]
    print(f'  rec#{k+6} @0x{o:x} size=0x{size:x} head-u32s: {cands[:16]}')
