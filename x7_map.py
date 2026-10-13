#!/usr/bin/env python3
"""
x7_map.py -- full structural map of 001960.dat:
  * 32-byte chunk headers (size BE at 0x04)
  * every CRI @UTF table parsed (big-endian sub-header)
  * every @SFV video chunk listed with payload offset/length
  * histogram of (chunk_size - 0x40) to prove the 0x40-byte head convention
"""
import struct, collections, json, re

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read()
N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]
b64 = lambda o: struct.unpack_from('>Q', D, o)[0]
f32 = lambda o: struct.unpack_from('>f', D, o)[0]

def parse_utf(base):
    size = b32(base+4)
    rows = b16(base+0x14); ncols = b16(base+0x16); row_w = b16(base+0x18)
    str_off = b32(base+0x1A); data_off = b32(base+0x1E)
    so = base + str_off
    raw = D[so:so+0x1000]
    end = raw.index(b'\x00')
    strs = raw[:end].split(b'\x00')
    co = base + 0x20
    cols = []
    for i in range(ncols):
        nm = b32(co+1); t = D[co+5]
        s = strs[nm].decode('latin1') if nm < len(strs) else '?'
        cols.append((s, t)); co += 8
    def rd(t, ro):
        return {0: lambda: D[ro], 1: lambda: struct.unpack_from('>b', D, ro)[0],
                2: lambda: b16(ro), 3: lambda: struct.unpack_from('>h', D, ro)[0],
                4: lambda: b32(ro), 5: lambda: struct.unpack_from('>i', D, ro)[0],
                6: lambda: f32(ro), 7: lambda: b64(ro),
                8: lambda: struct.unpack_from('>d', D, ro)[0]}.get(
                t, lambda: (strs[b32(ro)].decode('latin1') if b32(ro) < len(strs) else '?'))()
    out = []
    for r in range(rows):
        br = base + data_off + r*row_w
        out.append({cols[i][0]: rd(cols[i][1], br + i*4) for i in range(ncols)})
    return dict(size=size, rows=rows, ncols=ncols, row_w=row_w, cols=cols,
                strings=[s.decode('latin1', 'replace') for s in strs], data=out)

# ---------------------------------------------------------------- chunk map
print('=== CHUNK MAP (32-byte header, BIG-ENDIAN size) ===')
chunks = []
o = 0
while o + 0x20 <= N:
    sig = D[o:o+4]
    size = b32(o+4)
    if not ((sig[:1] == b'@' and sig[1:4].isalnum()) or sig == b'CRID'):
        print('  STOP: bad sig %r at 0x%X' % (sig, o)); break
    if not (0x20 <= size <= N - o):
        print('  STOP: bad size %d at 0x%X' % (size, o)); break
    chunks.append(dict(off=o, sig=sig.decode('latin1'), size=size, payload=o+0x20,
                       plen=size-0x20, u16_8=b16(o+8), u16_a=b16(o+0x0A),
                       u32_c=b32(o+0x0C), chinfo=b32(o+0x10), ftime=b32(o+0x14),
                       frate=b32(o+0x18), chno=b16(o+0x1A)))
    nxt = o + size
    k = 0
    while k < 0x10 and D[nxt+k] == 0:
        k += 1
    o = nxt + k
print('chunks: %d   final offset 0x%X / file 0x%X  (trailing %d)' % (len(chunks), o, N, N-o))
print('sig hist:', collections.Counter(c['sig'] for c in chunks).most_common(12))
print('u16@0x08 hist:', collections.Counter(c['u16_8'] for c in chunks).most_common())
print('u16@0x0A hist:', collections.Counter(c['u16_a'] for c in chunks).most_common())
print('chinfo@0x10 hist:', collections.Counter(c['chinfo'] for c in chunks).most_common(10))
print('chno hist:', collections.Counter(c['chno'] for c in chunks).most_common(10))
print('frate hist:', collections.Counter(c['frate'] for c in chunks).most_common(6))

# group by chinfo
g = collections.defaultdict(list)
for i, c in enumerate(chunks):
    g[c['chinfo']].append(i)
print('\nchunk groups by chinfo:')
for k, v in sorted(g.items(), key=lambda kv: -len(kv[1])):
    print('  chinfo=0x%08X  n=%-6d first@0x%X(%s) sizes min=%d max=%d'
          % (k, len(v), chunks[v[0]]['off'], chunks[v[0]]['sig'],
             min(chunks[i]['size'] for i in v), max(chunks[i]['size'] for i in v)))

# ------------------------------------------------------------ all @UTF tables
print('\n=== ALL @UTF TABLES ===')
for c in chunks:
    if c['sig'] == '@UTF':
        t = parse_utf(c['off'])
        print('\n--- @UTF @0x%X size=%d rows=%d row_w=%d' % (c['off'], t['size'], t['rows'], t['row_w']))
        print('    cols:', t['cols'])
        for i, r in enumerate(t['data'][:6]):
            print('    row %d: %s' % (i, r))
        if t['rows'] > 6: print('    ... (%d more rows)' % (t['rows']-6))

# ------------------------------------------------- the VIDEO_SEEKINFO analysis
print('\n=== SEEK TABLE ANALYSIS ===')
for c in chunks:
    if c['sig'] == '@UTF':
        t = parse_utf(c['off'])
        if 'VIDEO_SEEKINFO' in t['strings']:
            rows = t['data']
            print('rows=%d' % len(rows))
            names = list(rows[0].keys())
            print('fields:', names)
            for r in rows[:12]:
                print('   ', r)
            print('    ...')
            for r in rows[-4:]:
                print('   ', r)
            # interpret: find the field with increasing 60-step frame ids
            for nm in names:
                vals = [r[nm] for r in rows]
                if all(isinstance(v, int) for v in vals):
                    diffs = [vals[i+1]-vals[i] for i in range(min(8, len(vals)-1))]
                    print('  field %-12s first=%s diffs=%s' % (nm, vals[:6], diffs))
