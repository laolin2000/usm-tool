"""
Last structural test: XOR pairs of ciphertext segments and look for repeated
short-period patterns (a weak/periodic XOR cipher would expose one).
"""
import sys, collections, math

path = sys.argv[1]
buf = open(path, 'rb').read()

pos = [0x1960, 0x19640, 0x1EDA0, 0xD3CDA0, 0xE06C00, 0x1000000, 0x2000000, 0x3000000]
N = 0x400

print('=== self-XOR periodicity of each segment (fraction of repeated 4-byte words) ===')
for p in pos:
    seg = buf[p:p+N]
    words = [seg[i:i+4] for i in range(0, N, 4)]
    c = collections.Counter(words)
    top = c.most_common(3)
    print(f'  0x{p:08x}: distinct={len(c)}/{len(words)}  top={[(w.hex(), n) for w, n in top]}')

print('\n=== XOR two distant segments (same length) ===')
for a, b in [(0x1960, 0x19640), (0x1960, 0xD3CDA0), (0x19640, 0x1EDA0), (0x1960, 0x1000000)]:
    x = bytes(p ^ q for p, q in zip(buf[a:a+N], buf[b:b+N]))
    c = collections.Counter(x[i:i+4] for i in range(0, N, 4))
    zr = x.count(0)
    print(f'  0x{a:x} ^ 0x{b:x}: distinct4={len(c)}/{N//4} zeros={zr} top={[(w.hex(), n) for w, n in c.most_common(3)]}')

print('\n=== look for the 6-byte periodic structure (0x?? 0x?? ff ff pattern) ===')
for p in pos:
    seg = buf[p:p+0x1000]
    hits = sum(1 for i in range(len(seg)-6) if seg[i+2] == 0xFF and seg[i+3] == 0xFF)
    print(f'  0x{p:08x}: "ff ff at +2" count={hits}/4093  (random ~16)')

print('\n=== byte-value distribution sanity (is data compressed or ciphered?) ===')
for p in pos:
    seg = buf[p:p+0x10000]
    hist = [0]*256
    for x in seg: hist[x] += 1
    H = -sum((c/len(seg))*math.log2(c/len(seg)) for c in hist if c)
    exp = len(seg)/256
    chi = sum((c-exp)**2/exp for c in hist)
    print(f'  0x{p:08x}: H={H:.3f} chi2={chi:7.0f} zeros={seg.count(0)}')
