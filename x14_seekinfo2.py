#!/usr/bin/env python3
"""x14_seekinfo2.py -- corrected CRI @UTF parser (big-endian sub-header), prints
the VIDEO_HDRINFO and VIDEO_SEEKINFO tables and correlates with VP9 keyframes.

@UTF layout used (VERIFIED against this file):
  0x00 '@UTF' | 0x04 u32 BE table_size | 0x08 u32 unknown1 | 0x0C u32 unknown2
  0x10 u32 BE rows_pointer | 0x14 u16 BE row_count | 0x16 u16 BE column_count
  0x18 u16 BE row_width   | 0x1A u32 BE string_offset | 0x1E u32 BE data_offset
  0x20 columns[column_count]  (flags u8 | name u32 BE | type u8)
  base+string_offset : NUL-separated string pool
  base+data_offset   : row_count rows of row_width bytes
"""
import struct, re, collections, sys

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read(); N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]
def safe(s): return ''.join(c if 32 <= ord(c) < 127 else '?' for c in str(s))

def parse_utf(base):
    size = b32(base+4)
    rows = b16(base+0x14); ncols = b16(base+0x16); row_w = b16(base+0x18)
    str_off = b32(base+0x1A); data_off = b32(base+0x1E)
    raw = D[base+str_off:base+str_off+0x2000]
    end = raw.index(b'\x00'); strs = raw[:end].split(b'\x00')
    co = base+0x20; cols = []
    for i in range(ncols):
        flags = D[co]; nm = b32(co+1); t = D[co+5]
        cols.append((flags, strs[nm].decode('latin1') if nm < len(strs) else '?BAD', t))
        co += 8
    def rd(t, ro):
        try:
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
                s = b32(ro); return strs[s].decode('latin1') if s < len(strs) else '?OOB'
        except Exception:
            return None
        return None
    data = []
    for r in range(rows):
        br = base+data_off+r*row_w
        data.append({cols[i][1]: rd(cols[i][2], br+i*4) for i in range(ncols)})
    return dict(size=size, rows=rows, ncols=ncols, row_w=row_w, cols=cols, data=data,
                strings=[s.decode('latin1','replace') for s in strs])

for base, name in ((0x820, 'VIDEO_HDRINFO'), (0xA60, 'VIDEO_SEEKINFO')):
    t = parse_utf(base)
    print('=== %s @0x%X size=%d rows=%d ncols=%d row_w=%d strpool=%d ==='
          % (name, base, t['size'], t['rows'], t['ncols'], t['row_w'], len(t['strings'])))
    print('cols:', [(c[0], safe(c[1]), c[2]) for c in t['cols']])
    print('strings:', [safe(s) for s in t['strings'][:24]])
    for r in t['data'][:6]:
        print('   ', {safe(k): v for k, v in r.items()})
    if t['rows'] > 6:
        print('    ...')
        for r in t['data'][-2:]:
            print('   ', {safe(k): v for k, v in r.items()})
    globals()['T_%s' % name] = t
    print()

# ------------------------------------------------------- correlation
seek = T_VIDEO_SEEKINFO
if 'ofs_byte' in seek['data'][0]:
    kb = [r['ofs_byte'] for r in seek['data']]
    kf = [r['ofs_frmid'] for r in seek['data']]
    ns = [r.get('num_skip') for r in seek['data']]
    print('rows=%d' % len(kb))
    print('ofs_byte :', [hex(x) for x in kb[:10]], '...', [hex(x) for x in kb[-3:]])
    print('ofs_frmid:', kf[:10], '...', kf[-3:])
    print('num_skip :', ns[:10], '...', ns[-3:])
    print('ofs_byte deltas :', [hex(kb[i+1]-kb[i]) for i in range(6)])
    print('ofs_frmid deltas:', [kf[i+1]-kf[i] for i in range(6)])
    print('last ofs_byte 0x%X  ofs_frmid %d  filesize 0x%X' % (kb[-1], kf[-1], N))

    hits = [m.start() for m in re.finditer(rb'\x49\x83\x42', D)]
    sync = [x for x in hits if (x-0xF0D) % 0x60 == 0]
    print('\nVP9 keyframe sync count: %d (all spaced a multiple of 0x60 from 0xF0D)' % len(sync))
    print('implied frame ids (x-0xF0D)/0x60 :', [(x-0xF0D)//0x60 for x in sync[:20]])
    print('spacing in frames                :', [(sync[i+1]-sync[i])//0x60 for i in range(min(20, len(sync)-1))])
    for nm, fn in (('x-0xD', lambda x: x-0xD), ('x', lambda x: x), ('x-0x40', lambda x: x-0x40), ('x+0x40', lambda x: x+0x40)):
        m = sum(1 for i in range(min(len(sync), len(kb))) if fn(sync[i]) == kb[i])
        print('  ofs_byte[i] == %-8s: %d/%d' % (nm, m, min(len(sync), len(kb))))
