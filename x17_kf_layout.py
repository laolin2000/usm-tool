#!/usr/bin/env python3
"""x17_kf_layout.py -- dump raw layout around two VP9 keyframe sync codes to
reveal the per-frame table structure, and brute-force the seek-table offsets."""
import struct, re

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
D = open(PATH, 'rb').read(); N = len(D)

print('=== layout around sync[0] = 0xF0D and sync[1] = 0x43F0D ===')
for c, label in ((0xF0D, 'sync[0]'), (0x43F0D, 'sync[1]'), (0xD9E4D, 'sync[2]')):
    print('\n--- %s at 0x%X (dump 0x60 before, 0x30 after) ---' % (label, c))
    lo = c - 0x60
    for a in range(lo, c+0x30, 16):
        mark = ''
        if a <= c < a+16: mark = '   <== 49 83 42 here'
        print('  0x%08X  %s  %s%s' % (a, D[a:a+16].hex(' '),
              ''.join(chr(x) if 32 <= x < 127 else '.' for x in D[a:a+16]), mark))

# The @SFV chunk index: list chunk offsets around 0x43F0D
mk = sorted(set(m.start() for m in re.finditer(b'@SFV', D)))
import bisect
print('\n@SFV chunks near each sync:')
for c, label in ((0xF0D, 'sync0'), (0x43F0D, 'sync1'), (0xD9E4D, 'sync2')):
    i = bisect.bisect_right(mk, c) - 1
    print('  %s: containing chunk @0x%X (delta 0x%X)' % (label, mk[i], c-mk[i]))
    for j in range(max(0, i-2), min(len(mk), i+3)):
        size = struct.unpack_from('>I', D, mk[j]+4)[0]
        chinfo = struct.unpack_from('>I', D, mk[j]+0x10)[0]
        print('     @0x%08X size=%-8d chinfo=0x%08X (frame idx %d)' % (mk[j], size, chinfo, chinfo >> 8))

# --------------------------------------------------- brute force UTF offsets
print('\n=== brute-force @UTF sub-header offsets for @0x820 ===')
base = 0x820
# candidate string pool start: must begin the pool; find '<NULL>\0'
cand_str = D.find(b'<NULL>\x00', base, base+0x400)
print("'<NULL>' at 0x%X -> str_off = 0x%X" % (cand_str, cand_str-base))
# candidate data start: rows must satisfy rows*row_w + data_off <= str_off
for str_off_test in (cand_str-base,):
    print('evaluating str_off=0x%X' % str_off_test)
    for ro in range(0x10, 0x30):
        for fld_w in (2, 4):
            rows = int.from_bytes(D[base+ro:base+ro+fld_w], 'big')
            ncols = int.from_bytes(D[base+ro+fld_w:base+ro+2*fld_w], 'big')
            row_w = int.from_bytes(D[base+ro+2*fld_w:base+ro+3*fld_w], 'big')
            if not (0 < rows < 10000 and 0 < ncols < 200 and 0 < row_w < 4096):
                continue
            if abs(rows*row_w + 0x20 + ncols*8 - str_off_test) <= 8:
                print('   MATCH ro=0x%X fld=%d rows=%d ncols=%d row_w=%d  (rows*row_w=0x%X)'
                      % (ro, fld_w, rows, ncols, row_w, rows*row_w))
