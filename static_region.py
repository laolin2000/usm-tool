"""
DECISIVE TEST: records at 0xC2E0/0xC340/0xC3A0 have identical payloads (plaintext).
Analyse that payload: is it a repeated 4-byte pixel value (a run), or ciphertext?

Also test whether the identical-record regions are simply *static video* (same frame
repeated), which would mean the whole file is plaintext after all.
"""
import sys, collections

path = sys.argv[1]
buf = open(path, 'rb').read()

rec = buf[0xC2E0:0xC2E0+0x60]
print('record @0xC2E0 (0x60 bytes):')
print(' ', rec.hex(' '))
print('\nfield split:')
print('  @+0x00 magic      :', rec[0:4])
print('  @+0x04 size  BE   : 0x%x' % int.from_bytes(rec[4:8], 'big'))
print('  @+0x08            : 0x%x' % int.from_bytes(rec[8:10], 'big'))
print('  @+0x0A            : 0x%x' % int.from_bytes(rec[10:12], 'big'))
print('  @+0x0C            : 0x%x' % int.from_bytes(rec[12:16], 'big'))
print('  @+0x10 frameIdx   : 0x%x  <- increments per record' % int.from_bytes(rec[0x10:0x14], 'big'))
print('  @+0x14 fps*100    : 0x%x' % int.from_bytes(rec[0x14:0x18], 'big'))
print('  @+0x18..0x20      :', rec[0x18:0x20].hex(' '))
print('  @+0x20 sub-size   : 0x%x' % int.from_bytes(rec[0x20:0x24], 'big'))
print('  @+0x24 seq        : 0x%x' % int.from_bytes(rec[0x24:0x28], 'big'))
print('  @+0x28 zeros      :', rec[0x28:0x2C].hex(' '))
print('  @+0x2C payload    :', rec[0x2C:].hex(' '))

pay = rec[0x2C:]
print(f'\npayload len={len(pay)}')
words = [pay[i:i+4] for i in range(0, len(pay), 4)]
c = collections.Counter(words)
print('  4-byte word histogram:', [(w.hex(), n) for w, n in c.most_common()])

print('\n=== is that payload IDENTICAL across many records in the run? ===')
run = []
for k in range(40):
    o = 0xC2E0 + k*0x60
    r = buf[o:o+0x60]
    run.append((o, r))
same = sum(1 for _, r in run if r[0x2C:] == run[0][1][0x2C:])
print(f'  records with identical payload: {same}/{len(run)}')
idxs = [int.from_bytes(r[0x10:0x14], 'big') for _, r in run]
print('  frame indices:', idxs[:24])

print('\n=== compare payloads across the whole 0xC2E0..0xCA00 region ===')
o = 0xC2E0
while o < 0xCA00:
    if buf[o:o+4] != b'@SFV':
        print(f'  non-@SFV at 0x{o:x}: {buf[o:o+16].hex(" ")}')
        break
    size = int.from_bytes(buf[o+4:o+8], 'big')
    print(f'  0x{o:x} size=0x{size:x} idx=0x{int.from_bytes(buf[o+0x10:o+0x14],"big"):x} pay={buf[o+0x2c:o+0x2c+0x20].hex(" ")}')
    o += 0x60
