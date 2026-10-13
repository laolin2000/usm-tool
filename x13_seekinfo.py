#!/usr/bin/env python3
"""x13_seekinfo.py -- parse the VIDEO_SEEKINFO table precisely and correlate
its ofs_byte values with the 78 VP9 keyframe sync offsets."""
import struct, re, collections

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read(); N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

def parse_utf(base):
    size = b32(base+4)
    rows = b16(base+0x14); ncols = b16(base+0x16); row_w = b16(base+0x18)
    str_off = b32(base+0x1A); data_off = b32(base+0x1E)
    raw = D[base+str_off:base+str_off+0x2000]
    end = raw.index(b'\x00'); strs = raw[:end].split(b'\x00')
    co = base+0x20; cols = []
    for i in range(ncols):
        nm = b32(co+1); t = D[co+5]
        cols.append((strs[nm].decode('latin1') if nm < len(strs) else '?', t)); co += 8
    def rd(t, ro):
        if t == 0: return D[ro]
        if t == 1: return struct.unpack_from('>b', D, ro)[0]
        if t == 2: return b16(ro)
        if t == 3: return struct.unpack_from('>h', D, ro)[0]
        if t == 4: return b32(ro)
        if t == 5: return struct.unpack_from('>i', D, ro)[0]
        if t == 6: return struct.unpack_from('>f', D, ro)[0]
        if t == 7: return struct.unpack_from('>Q', D, ro)[0]
        if t == 8: return struct.unpack_from('>d', D, ro)[0]
        if t == 0xA:
            s = b32(ro); return strs[s].decode('latin1') if s < len(strs) else '?'
        return None
    data = []
    for r in range(rows):
        br = base+data_off+r*row_w
        data.append({cols[i][0]: rd(cols[i][1], br+i*4) for i in range(ncols)})
    return dict(size=size, rows=rows, ncols=ncols, row_w=row_w, cols=cols, data=data,
                strings=[s.decode('latin1','replace') for s in strs])

for base, name in ((0x820, 'VIDEO_HDRINFO'), (0xA60, 'VIDEO_SEEKINFO')):
    t = parse_utf(base)
    print('=== %s @0x%X  size=%d rows=%d ncols=%d row_w=%d ===' % (name, base, t['size'], t['rows'], t['ncols'], t['row_w']))
    print('cols:', t['cols'])
    print('strings:', t['strings'][:20])
    for r in t['data'][:8]:
        print('  ', r)
    if t['rows'] > 8:
        print('   ...')
        for r in t['data'][-3:]:
            print('  ', r)
    print()

# ---- correlate seek table ofs_byte with keyframe sync offsets
t = parse_utf(0xA60)
rows = t['data']
kb = [r['ofs_byte'] for r in rows]
kf = [r['ofs_frmid'] for r in rows]
ns = [r['num_skip'] for r in rows]
print('ofs_byte  :', [hex(x) for x in kb[:8]], '...')
print('ofs_frmid :', kf[:8], '...', kf[-3:])
print('num_skip  :', ns[:8], '...', ns[-3:])
print('total rows:', len(rows))
print('ofs_byte deltas:', [hex(kb[i+1]-kb[i]) for i in range(6)])
print('ofs_frmid deltas:', [kf[i+1]-kf[i] for i in range(6)])
print('last ofs_byte: 0x%X   file size: 0x%X' % (kb[-1], N))

hits = [m.start() for m in re.finditer(rb'\x49\x83\x42', D)]
off = 0xF0D
sync = [x for x in hits if (x-0xF0D) % 0x60 == 0]
print('\nkeyframe sync offsets: %d' % len(sync))
print('sync-0xF0D deltas /0x60:', [(sync[i+1]-sync[i])//0x60 for i in range(min(20, len(sync)-1))])

# frame index for each sync = (x - 0xF0D)//0x60 + ... need video start
# hypothesis: sync at 0xF0D is frame 0's keyframe; every 0x60 = one frame record
firstsync = sync[0]
print('\nframe index implied by sync: (x-0x%X)/0x60' % firstsync)
print('sync frame ids (first 20):', [(x-firstsync)//0x60 for x in sync[:20]])

# Compare ofs_byte with 'sync offset - 0xD' (frame record start) and with (x + 0x40)
for delta_name, fn in (('sync-0xD', lambda x: x-0xD), ('sync', lambda x: x), ('sync-0x40', lambda x: x-0x40)):
    matches = 0
    for i, k in enumerate(kb[:min(len(sync), len(kb))]):
        if fn(sync[i]) == k: matches += 1
    print('  ofs_byte[i] == %s(sync[i]) : %d/%d' % (delta_name, matches, min(len(sync), len(kb))))
