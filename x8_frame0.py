#!/usr/bin/env python3
"""x8_frame0.py -- verify the KNOWN plaintext VP9 frame at 0xF0C, and measure
the structure of the first real video chunk @0xEC0."""
import struct, subprocess, os, os.path as p

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
OUT = r'C:\Users\<you>\Desktop\DSHStool\usm-tool\probe'
os.makedirs(OUT, exist_ok=True)
D = open(PATH, 'rb').read()

def ivf(frames, w, h, rn, rd, path):
    b = bytearray(b'DKIF' + struct.pack('<HH', 0, 32) + b'VP90' +
                  struct.pack('<HHIIII', w, h, rn, rd, len(frames), 0))
    for i, f in enumerate(frames):
        b += struct.pack('<IQ', len(f), i) + f
    open(path, 'wb').write(b)
    return len(b)

def dec(path):
    r = subprocess.run([FFMPEG, '-hide_banner', '-v', 'error', '-i', path,
                        '-f', 'null', '-'], capture_output=True, timeout=300)
    return r.stderr.decode('utf-8', 'replace')

print('=== IVF header @0xEE0 ===')
print(D[0xEE0:0xEE0+32].hex(' '))
w = struct.unpack_from('<H', D, 0xEEC)[0]; h = struct.unpack_from('<H', D, 0xEEE)[0]
rn = struct.unpack_from('<I', D, 0xEF0)[0]; rd = struct.unpack_from('<I', D, 0xEF4)[0]
fc = struct.unpack_from('<I', D, 0xEF8)[0]
print('w=%d h=%d rate=%d/%d frames=%d' % (w, h, rn, rd, fc))

size0 = struct.unpack_from('<I', D, 0xF00)[0]
ts0 = struct.unpack_from('<Q', D, 0xF04)[0]
print('frame0 record @0xF00: size=%d ts=%d -> payload 0xF0C..0x%X' % (size0, ts0, 0xF0C+size0))
f0 = D[0xF0C:0xF0C+size0]
print('frame0 first 24 bytes:', f0[:24].hex(' '))
f = (f0[0] << 8) | f0[1]
print('VP9 frame_marker=%d profile=%d show_existing=%d frame_type=%d(0=KEY)' %
      (f >> 6, (f >> 4) & 7, (f >> 3) & 1, (f >> 2) & 1))
print('byte2 = 0x%02X (VP9 sync code first byte must be 0x49)' % f0[2])

p1 = p.join(OUT, 'frame0_only.ivf')
ivf([f0], w, h, rn, rd, p1)
print('\n--- ffmpeg on frame0 ONLY ---')
print(dec(p1) or '(no errors)')

# what is in the rest of chunk 0xEC0 (after frame0)?
print('\n=== chunk @0xEC0 full structure ===')
print('header 0xEC0..0xEE0:', D[0xEC0:0xEE0].hex(' '))
print('.payload hdr 0xEE0 nested? no; IVF hdr at 0xEE0')
ch_end = 0xEC0 + struct.unpack_from('>I', D, 0xEC4)[0]
print('chunk size BE = %d -> ends 0x%X' % (struct.unpack_from('>I', D, 0xEC4)[0], ch_end))
print('bytes 0xF0C+%d .. 0x%X : %s' % (size0, ch_end, D[0xF0C+size0:ch_end].hex(' ')))
print('bitstream len (0xF0C..end) = 0x%X = %d' % (ch_end-0xF0C, ch_end-0xF0C))
print('frame0 size field (LE @0xF00)=%d ; remaining=%d' % (size0, ch_end-0xF0C-size0))

# next chunk: 0x1020
print('\n=== chunk @0x1020 (first ordinary video chunk) ===')
nxt = D[0x1020:0x1020+0x40]
print('full 0x40:')
print('  ', nxt[:0x20].hex(' '))
print('  ', nxt[0x20:0x40].hex(' '))
print('as ascii:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in nxt))
sz = struct.unpack_from('>I', D, 0x1024)[0]
print('size=%d ends 0x%X ; next chunk sig at 0x%X = %r' % (sz, 0x1020+sz, 0x1020+sz, D[0x1020+sz:0x1020+sz+4]))
print('bitstream would be 0x1040..0x%X = %d bytes' % (0x1020+sz, sz-0x40))
print('bitstream first 24:', D[0x1040:0x1040+24].hex(' '))
