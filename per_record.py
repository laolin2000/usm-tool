"""
For each @SFV record, test the declared-size payload (and variants) as a VP9 frame,
asking ffmpeg whether it decodes. This finds the exact frame-data layout.
"""
import sys, struct, os, subprocess, re

path = sys.argv[1]
workdir = sys.argv[2]
os.makedirs(workdir, exist_ok=True)
buf = open(path, 'rb').read()
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
IVF_HDR = buf[0xEE0:0xEE0+32]

def test(offset, length, label):
    if offset + length > len(buf) or length <= 0:
        return 'skip'
    h = bytearray(IVF_HDR); struct.pack_into('<I', h, 24, 1)
    blob = bytes(h) + struct.pack('<IQ', length, 0) + buf[offset:offset+length]
    p = os.path.join(workdir, label + '.ivf')
    open(p, 'wb').write(blob)
    r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', p, '-f', 'null', '-'],
                       capture_output=True, text=True)
    err = (r.stderr or '').strip().replace('\n', ' | ')
    return 'OK' if not err else err[:100]

# collect @SFV records with their declared sizes
recs = []
for m in re.finditer(b'@SFV', buf):
    o = m.start()
    if o + 0x40 > len(buf): continue
    size = struct.unpack_from('>I', buf, o+4)[0]
    if 0 < size < 4_000_000 and o + size <= len(buf):
        recs.append((o, size))
print(f'records: {len(recs)}')

print('\n=== per-record payload tests (varies offset/length) ===')
for k, (o, size) in enumerate(recs[:14]):
    variants = [
        (o + 0x40, size - 0x40, 'after 0x40'),
        (o + 0x20, size - 0x20, 'after 0x20'),
        (o + 0x28, size - 0x28, 'after 0x28'),
        (o, size, 'whole rec'),
    ]
    line = [f'rec#{k} @0x{o:x} size=0x{size:x}']
    for off, ln, name in variants:
        r = test(off, ln, f'r{k}_{name.replace(" ","")}')
        line.append(f'{name}={r[:40]}')
    print('  ' + ' | '.join(line))
