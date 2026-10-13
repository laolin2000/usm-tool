#!/usr/bin/env python3
"""
x9_extract_test.py -- build candidate IVF streams from 001960.dat and ask
ffmpeg whether they decode.  Tests, in order:
  (1) raw payload  = chunk[0x40:chunk_size]
  (2) payload minus the 6-byte trailing pad
  (3) payload minus a 5-byte prefix (byte-aligned CRI frame header)
  (4) same three after the CRI VideoMask with a list of candidate keys
Everything is reported with the actual ffmpeg stderr.
"""
import struct, subprocess, os, os.path as p, collections, sys

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
OUT = r'C:\Users\<you>\Desktop\DSHStool\usm-tool\probe'
os.makedirs(OUT, exist_ok=True)
D = open(PATH, 'rb').read()
N = len(D)
b16 = lambda o: struct.unpack_from('>H', D, o)[0]
b32 = lambda o: struct.unpack_from('>I', D, o)[0]

# ---------------------------------------------------------------- chunk map
def map_chunks():
    sigs = [b'@SFV', b'@UTF', b'@SFA', b'@ALP', b'CRID']
    idx = set()
    for s in sigs:
        st = 0
        while True:
            q = D.find(s, st)
            if q < 0: break
            idx.add(q); st = q+1
    chunks = []; o = 0
    while o + 0x20 <= N:
        if D[o:o+4] not in sigs: break
        size = b32(o+4)
        if not (0x20 <= size <= N-o): break
        chunks.append(dict(off=o, sig=D[o:o+4].decode(), size=size, payload=o+0x20,
                           plen=size-0x20, u16a=b16(o+0x0A), cid=b32(o+0x0C),
                           chinfo=b32(o+0x10), ftime=b32(o+0x14), chno=b16(o+0x1A)))
        end = o+size; nxt = None
        for k in range(0, 0x41):
            if end+k in idx: nxt = end+k; break
        if nxt is None: break
        o = nxt
    return chunks

CH = map_chunks()
print('chunks: %d' % len(CH))

# video chunks: chinfo != 0 and != sentinel, or chno... use chinfo>=0x100
video = [c for c in CH if c['chinfo'] >= 0x100]
print('video chunks (chinfo>=0x100): %d' % len(video))
print('first 5:', [(hex(c['off']), c['size'], hex(c['chinfo']), c['u16a']) for c in video[:5]])
print('last  5:', [(hex(c['off']), c['size'], hex(c['chinfo']), c['u16a']) for c in video[-5:]])
print('u16a(a.k.a. 0x0A) hist:', collections.Counter(c['u16a'] for c in video).most_common(6))
print('size min/max:', min(c['size'] for c in video), max(c['size'] for c in video))
print('chinfo deltas:', [video[i+1]['chinfo']-video[i]['chinfo'] for i in range(5)])
print('ftime hist:', collections.Counter(c['ftime'] for c in video).most_common(5))

# ------------------------------------------------------------------- IVF io
def ivf(frames, w, h, rn, rd, path):
    b = bytearray(b'DKIF'+struct.pack('<HH', 0, 32)+b'VP90'+struct.pack('<HHIIII', w, h, rn, rd, len(frames), 0))
    for i, f in enumerate(frames):
        b += struct.pack('<IQ', len(f), i)+f
    open(path, 'wb').write(b)
    return len(b)

def ffdec(path, timeout=300):
    r = subprocess.run([FFMPEG, '-hide_banner', '-v', 'error', '-i', path, '-f', 'null', '-'],
                       capture_output=True, timeout=timeout)
    err = r.stderr.decode('utf-8', 'replace').strip()
    return err

def try_ivf(tag, frames, path, w=1080, h=608, rn=30000, rd=1000):
    sz = ivf(frames, w, h, rn, rd, path)
    err = ffdec(path)
    nlines = len([l for l in err.splitlines() if l.strip()])
    first = err.splitlines()[:3]
    print('  [%-34s] bytes=%-10d errlines=%-6d %s' % (tag, sz, nlines, ('CLEAN' if not err else first[0][:110] if first else '')))
    return nlines, err

print('\n=== TEST 1: raw payload chunk[0x40:size] ===')
frames_full = [D[c['off']+0x40:c['off']+c['size']] for c in video]
try_ivf('raw full payload', frames_full, p.join(OUT, 't1_rawfull.ivf'))

print('\n=== TEST 2: payload minus 6-byte trailing pad ===')
frames_pad = [D[c['off']+0x40:c['off']+c['size']-6] for c in video]
try_ivf('raw minus 6 pad', frames_pad, p.join(OUT, 't2_rawpad.ivf'))

print('\n=== TEST 3: payload minus 5-byte prefix ===')
frames_p5 = [D[c['off']+0x45:c['off']+c['size']] for c in video]
try_ivf('payload[5:]', frames_p5, p.join(OUT, 't3_p5.ivf'))

print('\n=== TEST 4: first 30 frames only (raw full payload) ===')
try_ivf('first30 raw full', frames_full[:30], p.join(OUT, 't4_first30.ivf'))

print('\n=== TEST 5: does frame0-chunk bitstream (0xF0C..0x1012) alone decode? ===')
try_ivf('ivf frame0 262B', [D[0xF0C:0xF0C+262]], p.join(OUT, 't5_f0.ivf'))

print('\n=== TEST 6: raw video chunks + the plaintext IVF-frame0 pair ===')
try_ivf('t2 (+f0 prepended)', [D[0xF0C:0xF0C+262]] + frames_pad[:30], p.join(OUT, 't6.ivf'))

# --------------------------------------------------------------- key search
class USMCrypt:
    def __init__(self, key):
        if isinstance(key, str):
            k = key.rjust(16, '0'); key1 = bytes.fromhex(k[8:]); key2 = bytes.fromhex(k[:8])
        else:
            key1 = (key & 0xFFFFFFFF).to_bytes(4, 'big'); key2 = (key >> 32).to_bytes(4, 'big')
        t = bytearray(0x20)
        t[0x00:0x09] = [key1[3], key1[2], key1[1], (key1[0]-0x34) % 256, (key2[3]+0xF9) % 256,
                        (key2[2] ^ 0x13) % 256, (key2[1]+0x61) % 256, (key1[3] ^ 0xFF) % 256,
                        (key1[1]+key1[2]) % 256]
        t[0x09:0x0C] = [(t[0x01]-t[0x07]) % 256, (t[0x02] ^ 0xFF) % 256, (t[0x01] ^ 0xFF) % 256]
        t[0x0C:0x0E] = [(t[0x0B]+t[0x09]) % 256, (t[0x08]-t[0x03]) % 256]
        t[0x0E:0x10] = [(t[0x0D] ^ 0xFF) % 256, (t[0x0A]-t[0x0B]) % 256]
        t[0x10] = (t[0x08]-t[0x0F]) % 256
        t[0x11:0x17] = [(t[0x10] ^ t[0x07]) % 256, (t[0x0F] ^ 0xFF) % 256, (t[0x03] ^ 0x10) % 256,
                        (t[0x04]-0x32) % 256, (t[0x05]+0xED) % 256, (t[0x06] ^ 0xF3) % 256]
        t[0x17:0x1A] = [(t[0x13]-t[0x0F]) % 256, (t[0x15]+t[0x07]) % 256, (0x21-t[0x13]) % 256]
        t[0x1A:0x1C] = [(t[0x14] ^ t[0x17]) % 256, (t[0x16]+t[0x16]) % 256]
        t[0x1C:0x1F] = [(t[0x17]+0x44) % 256, (t[0x03]+t[0x04]) % 256, (t[0x05]-t[0x16]) % 256]
        t[0x1F] = (t[0x1D] ^ t[0x13]) % 256
        self.v1 = t; self.v2 = bytearray(x ^ 0xFF for x in t)

    def mask(self, buf, head=0x40):
        buf = bytearray(buf)
        if len(buf) - head <= 0x200:
            return buf
        body = bytearray(buf[head:]); size = len(body)
        mask2 = bytearray(self.v2)
        for i in range(32, size//8):
            o = i*8; mi = (i % 4)*8
            w = int.from_bytes(body[o:o+8], 'little') ^ int.from_bytes(mask2[mi:mi+8], 'little')
            body[o:o+8] = w.to_bytes(8, 'little')
            mask2[mi:mi+8] = (w ^ int.from_bytes(self.v2[mi:mi+8], 'little')).to_bytes(8, 'little')
        mask1 = bytearray(self.v1)
        for i in range(32):
            mi = (i % 4)*8
            mask1[mi:mi+8] = (int.from_bytes(mask1[mi:mi+8], 'little') ^
                              int.from_bytes(body[(32+i)*8:(33+i)*8], 'little')).to_bytes(8, 'little')
            body[i*8:(i+1)*8] = (int.from_bytes(body[i*8:(i+1)*8], 'little') ^
                                 int.from_bytes(mask1[mi:mi+8], 'little')).to_bytes(8, 'little')
        return bytearray(buf[:head]) + body

def hx(s):
    return bytes.fromhex(s.replace(' ', ''))

KEYSTRINGS = [
    ('zeros',        '0'*16),
    ('ffff',         'F'*16),
    ('0123456789ABCDEF', '0123456789ABCDEF'),
    ('9BD9A5E1A1B2C3D4', '9BD9A5E1A1B2C3D4'),
]
# maimai-ish ASCII keys: interpret as 16 hex? they are 32 chars -> use as-is bytes via int
ASCII_KEYS = [
    'n7bx6:@Fg_:2;5E89Phy7AyIcpxEQ:R@',
    'A;mv5YUpHBK3YxTy5KB^[;5]C2AL50Bq',
]
# keys harvested from the file
FILEKEYS = [
    ('hdr 0x08..0x10', D[0x08:0x10]),
    ('hdr 0x04..0x0C', D[0x04:0x0C]),
    ('hdr 0x10..0x18', D[0x10:0x18]),
    ('hdr 0x14..0x1C', D[0x14:0x1C]),
    ('sfv hdr 0x10..0x18', D[0x10:0x18]),
]

print('\n=== TEST 7: VideoMask with candidate keys, head=0x40 (first 30 frames) ===')
for name, k in KEYSTRINGS:
    try:
        c = USMCrypt(k)
        fr = [bytes(c.mask(D[ch['off']:ch['off']+ch['size']], 0x40))[0x40:] for ch in video[:30]]
        try_ivf('mask/head40/%s' % name, fr, p.join(OUT, 't7_%s.ivf' % name))
    except Exception as e:
        print('  [%s] EXC %s' % (name, e))
