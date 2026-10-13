#!/usr/bin/env python3
"""x10_regions.py -- hexdump 0x1010..0x1A00 to see the real record structure,
then run a chain-partition search over all '@SFV' candidates."""
import struct, re, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()
N = len(D)
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

print('=== HEXDUMP 0x1010 .. 0x1300 ===')
for a in range(0x1010, 0x1300, 16):
    print('  0x%08X  %s  %s' % (a, D[a:a+16].hex(' '),
          ''.join(chr(c) if 32 <= c < 127 else '.' for c in D[a:a+16])))

print('\n=== HEXDUMP 0x1940 .. 0x1A80 (first big @SFV) ===')
for a in range(0x1940, 0x1A80, 16):
    print('  0x%08X  %s  %s' % (a, D[a:a+16].hex(' '),
          ''.join(chr(c) if 32 <= c < 127 else '.' for c in D[a:a+16])))

mk = [m.start() for m in re.finditer(b'@SFV', D)]
print('\n@SFV markers: %d' % len(mk))
print('first 30 offsets:', [hex(x) for x in mk[:30]])
sizes = [b32(x+4) for x in mk]
print('first 30 declared sizes:', [hex(s) for s in sizes[:30]])
print('sum all sizes:', sum(sizes), ' file:', N, ' diff:', N-sum(sizes))

# ------------------------------------------------ chain partition search
mset = set(mk)
def successors(o, jitter=0x40):
    """possible next chunk starts after a chunk at o"""
    if o not in mset: return []
    end = o + b32(o+4)
    cands = []
    for k in range(0, jitter+1):
        if end+k in mset: cands.append(end+k)
    return cands

# greedy + backtracking DFS to reach EOF exactly
import sys
sys.setrecursionlimit(100000)
best = {'len': 0, 'path': None}
from functools import lru_cache

seen = {}
PATH_MEMO = {}
def dfs(o, depth=0):
    """return (nchunks, nextoffset) for the best chain from o that reaches EOF"""
    if o == N: return (0, o)
    if o > N: return None
    if o in PATH_MEMO: return PATH_MEMO[o]
    if o not in mset: return None
    if depth > 20000: return None
    bestr = None
    for nx in successors(o):
        r = dfs(nx, depth+1)
        if r is None: continue
        cand = (r[0]+1, nx)
        if bestr is None or cand[0] > bestr[0]:
            bestr = cand
    PATH_MEMO[o] = bestr
    return bestr

r = dfs(0)
print('\nchain from 0 ->', r)
if r:
    # reconstruct
    path = []; o = 0
    while o != N:
        path.append(o); o = PATH_MEMO[o][1]
    print('chain length:', len(path))
    print('last 5 offsets:', [hex(x) for x in path[-5:]])
    print('total declared bytes:', sum(b32(x+4) for x in path))
    # signatures along chain
    print('sigs:', collections.Counter(D[x:x+4].decode('latin1','replace') for x in path).most_common(8))
    sizes_c = [b32(x+4) for x in path]
    print('size min/max/mean:', min(sizes_c), max(sizes_c), sum(sizes_c)//len(sizes_c))
    print('first 12 chain entries:')
    for x in path[:12]:
        print('   0x%08X %r size=%d' % (x, D[x:x+4], b32(x+4)))
    print('chain offsets == @SFV offsets?', set(path) <= mset)
    import json
    open(r'C:\Users\<you>\Desktop\DSHStool\usm-tool\probe\chain.json','w').write(json.dumps(path))
    print('saved chain to probe\\chain.json')
