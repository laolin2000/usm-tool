"""
Walk the USM chunk chain exactly like MaiChartManager's UsmExtractor:

    header = read 0x20
    sizeAfterHeader = u32 BE @ [4:8]
    payloadOffset   = header[9]
    paddingSize     = u16 BE @ [10:12]
    chno            = header[12]
    payloadType     = header[15] & 3
    payloadSize     = sizeAfterHeader - payloadOffset - paddingSize
    skip (payloadOffset - 0x18) bytes, read payloadSize, skip paddingSize
    process only payloadType == 0
"""
import sys, struct
try: sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception: pass

src = sys.argv[1]
buf = open(src, 'rb').read()
print(f'file size {len(buf)} (0x{len(buf):x})')

o = 0
n = 0
rows = []
while o + 0x20 <= len(buf) and n < 40:
    h = buf[o:o+0x20]
    size_after = struct.unpack_from('>I', h, 4)[0]
    payload_off = h[9]
    padding = struct.unpack_from('>H', h, 10)[0]
    chno = h[12]
    ptype = h[15] & 0x03
    payload_size = size_after - payload_off - padding
    sig = h[0:4]
    rows.append((o, sig, size_after, payload_off, padding, chno, ptype, payload_size))
    print(f'  @0x{o:08x} sig={sig!r} sizeAfter=0x{size_after:06x} payOff={payload_off} pad={padding} '
          f'chno={chno} type={ptype} paySize={payload_size}')
    if size_after == 0 or size_after > len(buf):
        print('    -> implausible size, stop'); break
    o += 0x20 + size_after      # chunk total
    n += 1

print(f'\nwalked {len(rows)} chunks, next offset 0x{o:x}')

# verify total chunk sizes sum
tot = 0
o2 = 0
cnt = 0
while o2 + 0x20 <= len(buf):
    h = buf[o2:o2+0x20]
    size_after = struct.unpack_from('>I', h, 4)[0]
    if size_after == 0 or size_after > len(buf): break
    o2 += 0x20 + size_after
    tot += size_after
    cnt += 1
print(f'chain: {cnt} chunks, sum(sizeAfter)={tot}, end=0x{o2:x} (file 0x{len(buf):x})')
