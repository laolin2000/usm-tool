"""Dump a full @SFV record from the main body and diff its inner structure."""
import sys, re, math

path = sys.argv[1]
buf = open(path, 'rb').read()

def dump(o, n, label):
    print(f'\n=== {label} @0x{o:x} ({n} bytes) ===')
    for i in range(0, n, 32):
        c = buf[o+i:o+i+32]
        if not c: break
        print(f'  0x{o+i:08x}: {c.hex(" "):<96} |{"".join(chr(b) if 32<=b<127 else "." for b in c)}|')

# main-body records
dump(0xD3CD60, 0x100, 'main-body record')
dump(0xD3CDA0, 0x60, 'main-body record +0x40')
dump(0xD3CE60, 0x60, 'main-body record +0x100')

# Compare two consecutive records' first 0x40 bytes to find where they differ
a = buf[0xD3CD60:0xD3CD60+0x40]
b = buf[0xD416C0:0xD416C0+0x40]
print('\n=== diff of two consecutive record headers (@+0) ===')
print('  recA:', a.hex(' '))
print('  recB:', b.hex(' '))
print('  diff bytes:', [i for i in range(0x40) if a[i] != b[i]])

# entropy profile across the record
print('\n=== entropy profile of record @0xD3CD60, 0x400 windows ===')
for o in range(0xD3CD60, 0xD3CD60+0x4958, 0x400):
    w = buf[o:o+0x400]
    hist = [0]*256
    for x in w: hist[x] += 1
    H = -sum((c/len(w))*math.log2(c/len(w)) for c in hist if c)
    print(f'  0x{o:08x}: H={H:.2f} zeros={w.count(0)/len(w)*100:.1f}%')

# how many @SFV in that record?
rec = buf[0xD3CD60:0xD3CD60+0x4958]
print(f'\n@SFV inside record: {rec.count(b"@SFV")}')
for m in re.finditer(b'@SFV', rec):
    print(f'   at +0x{m.start():x}')
