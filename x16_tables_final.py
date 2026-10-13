#!/usr/bin/env python3
"""
x16_tables_final.py -- CORRECT CRI @UTF parser for this file, then correlate the
VIDEO_SEEKINFO ofs_byte values with the 78 real VP9 keyframe sync offsets.

@UTF sub-header (VERIFIED byte-by-byte against 0x820 and 0xA60):
  0x00 '@UTF' | 0x04 u32 BE table_size | 0x08 u32 BE unknown1
  0x0C u32 BE unknown2 (== table_size)
  0x10 u32 BE rows_pointer | 0x14 u16 BE row_count | 0x16 u16 BE column_count
  0x18 u16 BE row_width    | 0x1A u16 BE string_offset | 0x1C u16 BE data_offset
  0x20 columns[]: {u8 flags | u32 BE name_offset | u8 type}
  base+string_offset: NUL-separated string pool
  base+data_offset  : row_count * row_width bytes
"""
import struct, re

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read(); N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]
safe = lambda s: ''.join(c if 32 <= ord(c) < 127 else '?' for c in str(s))

TYPES = {0: 'u8', 1: 's8', 2: 'u16', 3: 's16', 4: 'u32', 5: 's32', 6: 'f32',
         7: 'u64', 8: 'f64', 0xA: 'str'}

def parse_utf(base):
    size = b32(base+4)
    rows = b16(base+0x14); ncols = b16(base+0x16); row_w = b16(base+0x18)
    str_off = b16(base+0x1A); data_off = b16(base+0x1C)
    raw = D[base+str_off:base+str_off+0x2000]
    end = raw.index(b'\x00'); strs = raw[:end].split(b'\x00')
    co = base+0x20; cols = []
    for i in range(ncols):
        nm = b32(co+1); t = D[co+5]
        cols.append((strs[nm].decode('latin1') if nm < len(strs) else '?BAD', t)); co += 8
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
            s = b32(ro); return strs[s].decode('latin1') if s < len(strs) else '?OOB'
        return None
    data = []
    for r in range(rows):
        br = base+data_off+r*row_w
        data.append({cols[i][0]: rd(cols[i][1], br+i*4) for i in range(ncols)})
    return dict(size=size, rows=rows, ncols=ncols, row_w=row_w, str_off=str_off,
                data_off=data_off, cols=cols, data=data,
                strings=[s.decode('latin1', 'replace') for s in strs], base=base)

print('=== VIDEO_HDRINFO @0x820 ===')
h = parse_utf(0x820)
print('size=%d rows=%d ncols=%d row_w=%d str_off=0x%X data_off=0x%X' %
      (h['size'], h['rows'], h['ncols'], h['row_w'], h['str_off'], h['data_off']))
print('cols:', [(safe(c[0]), TYPES.get(c[1], c[1])) for c in h['cols']])
print('strings:', [safe(s) for s in h['strings']])
for r in h['data']:
    print('  ', {safe(k): v for k, v in r.items()})

print('\n=== VIDEO_SEEKINFO @0xA60 ===')
s = parse_utf(0xA60)
print('size=%d rows=%d ncols=%d row_w=%d str_off=0x%X data_off=0x%X' %
      (s['size'], s['rows'], s['ncols'], s['row_w'], s['str_off'], s['data_off']))
print('cols:', [(safe(c[0]), TYPES.get(c[1], c[1])) for c in s['cols']])
print('first 6 rows:')
for r in s['data'][:6]:
    print('  ', {safe(k): v for k, v in r.items()})
print('last 3 rows:')
for r in s['data'][-3:]:
    print('  ', {safe(k): v for k, v in r.items()})

kb = [r['ofs_byte'] for r in s['data']]
kf = [r['ofs_frmid'] for r in s['data']]
ns = [r.get('num_skip') for r in s['data']]
print('\nofs_byte monotonic:', all(kb[i] < kb[i+1] for i in range(len(kb)-1)))
print('ofs_byte deltas (first 8):', [kb[i+1]-kb[i] for i in range(8)])
print('ofs_frmid deltas (first 8):', [kf[i+1]-kf[i] for i in range(8)])
print('num_skip distinct:', set(ns))
print('ofs_byte[0]=%d (0x%X)  ofs_byte[-1]=%d (0x%X)  filesize=%d' % (kb[0], kb[0], kb[-1], kb[-1], N))

# --------------------------------------------------- correlate with VP9 sync
hits = [m.start() for m in re.finditer(rb'\x49\x83\x42', D)]
sync = sorted(x for x in hits if (x-0xF0D) % 0x60 == 0)
print('\nVP9 keyframe sync codes: %d' % len(sync))
print('sync[0]=0x%X  frame ids (x-0xF0D)/0x60 first 12: %s' % (sync[0], [(x-0xF0D)//0x60 for x in sync[:12]]))
print('deltas in frames (first 12):', [(sync[i+1]-sync[i])//0x60 for i in range(min(12, len(sync)-1))])
print('\nnum rows in seek table: %d ; num keyframes found: %d' % (len(kb), len(sync)))
print('\nper-row comparison (first 8):')
print('  idx  ofs_byte     ofs_frmid  num_skip   sync_off    sync_frame  ofs_byte-sync')
for i in range(min(8, len(kb), len(sync))):
    print('  %-4d 0x%08X  %-9d  %-8s  0x%08X  %-10d %d'
          % (i, kb[i], kf[i], ns[i], sync[i], (sync[i]-0xF0D)//0x60, kb[i]-sync[i]))

# try to find the transform: ofs_byte[i] vs sync[i]
import collections
diffs = [sync[i]-kb[i] for i in range(min(len(kb), len(sync)))]
print('\nsync[i]-ofs_byte[i] first 12:', diffs[:12])
print('distinct diffs:', collections.Counter(diffs).most_common(6))
