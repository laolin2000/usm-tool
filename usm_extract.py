#!/usr/bin/env python3
"""
usm_extract.py -- CRI USM (Sofdec2) frame mapper + VideoMask decryptor + IVF writer
for maimai DX movies such as 001960.dat.

VERIFIED LAYOUT (this file):
  chunk header = 32 bytes, multi-byte fields BIG-ENDIAN:
    0x00 char[4] signature   ('CRID' for block 0, else '@SFV'/'@UTF'/'@SFA'...)
    0x04 u32 BE  total chunk size (header + payload)
    0x08 u16 BE  0x18     constant
    0x0A u16 BE  0x18 or 0x20 (0x20 when the chunk carries the 8-byte trailing pad)
    0x0C u32 BE  chunk id (1,2,3,<stream id>...)
    0x10 u32 BE  channel info (0x18 | channels<<8 on real stream chunks)
    0x14 u32 BE  frame time
    0x18 u32 BE  frame rate (30)
    0x1A u16 BE  channel number
    0x1C u32 BE  reserved
  payload always starts at chunk+0x20 (u16@0x0A is NOT the payload offset).

VIDEO payload of an @SFV chunk (>= 0x40 bytes):
    0x00..0x20  the 32-byte USM chunk header
    0x20..0x40  CRI payload header (00 18 | 00 00 | frame-rate | frame-size u32)
    0x40..      bitstream -> for VP9 inside the video header chunk there is a
                nested 32-byte IVF file header then IVF frame records.
"""
import struct, sys, os, subprocess, collections, hashlib

PATH = r'D:\123pan\Downloads\SDEZ1.66\Package\Sinmai_Data\StreamingAssets\A000\MovieData\001960.dat'
FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
b16 = lambda d, o: struct.unpack_from('>H', d, o)[0]
b32 = lambda d, o: struct.unpack_from('>I', d, o)[0]
l32 = lambda d, o: struct.unpack_from('<I', d, o)[0]

# --------------------------------------------------------------------------
# 1. chunk mapper: index every possible signature, then follow size chains
# --------------------------------------------------------------------------
SIGS = [b'@SFV', b'@UTF', b'@SFA', b'@SBT', b'@SCC', b'@SES', b'@SVP',
        b'@SVR', b'@SHM', b'@SLI', b'@SPR', b'@SST', b'@SML', b'@SOV',
        b'@SCM', b'@SMC', b'@ALP', b'@AHX', b'@CUE', b'CRID']

def build_map(D):
    N = len(D)
    idx = {}
    for s in SIGS:
        start = 0
        while True:
            p = D.find(s, start)
            if p < 0: break
            idx[p] = s; start = p+1
    print('signature candidates: %d  (first %s)' % (len(idx), sorted(hex(x) for x in list(idx)[:6])))
    chunks = []
    o = 0
    stops = []
    while o + 0x20 <= N:
        sig = D[o:o+4]
        size = b32(D, o+4)
        if sig not in SIGS:
            stops.append(('brk-sig', o, sig)); break
        if not (0x20 <= size <= N - o):
            stops.append(('brk-size', o, size)); break
        chunks.append(dict(off=o, sig=sig.decode('latin1'), size=size,
                           payload=o+0x20, plen=size-0x20,
                           u16_8=b16(D, o+8), u16_a=b16(D, o+0x0A),
                           cid=b32(D, o+0x0C), chinfo=b32(D, o+0x10),
                           ftime=b32(D, o+0x14), frate=b32(D, o+0x18),
                           chno=b16(D, o+0x1A)))
        end = o + size
        # find next signature at end, or within 0x40 bytes of padding after it
        nxt = None
        for k in range(0, 0x41):
            if end + k in idx:
                nxt = end + k; break
        if nxt is None:
            stops.append(('no-next', o, D[end:end+0x10])); break
        o = nxt
    return chunks, stops

# --------------------------------------------------------------------------
# 2. CRI VideoMask (PyCriCodecsEx algorithm, 64-bit words)
# --------------------------------------------------------------------------
class USMCrypt:
    def __init__(self, key):
        if isinstance(key, str):
            k = key.rjust(16, '0')
            key1 = bytes.fromhex(k[8:]); key2 = bytes.fromhex(k[:8])
        else:
            key1 = (key & 0xFFFFFFFF).to_bytes(4, 'big')
            key2 = (key >> 32).to_bytes(4, 'big')
        self.key1, self.key2 = key1, key2
        t = bytearray(0x20)
        t[0x00:0x09] = [key1[3], key1[2], key1[1], (key1[0]-0x34) % 256,
                        (key2[3]+0xF9) % 256, (key2[2] ^ 0x13) % 256,
                        (key2[1]+0x61) % 256, (key1[3] ^ 0xFF) % 256,
                        (key1[1]+key1[2]) % 256]
        t[0x09:0x0C] = [(t[0x01]-t[0x07]) % 256, (t[0x02] ^ 0xFF) % 256, (t[0x01] ^ 0xFF) % 256]
        t[0x0C:0x0E] = [(t[0x0B]+t[0x09]) % 256, (t[0x08]-t[0x03]) % 256]
        t[0x0E:0x10] = [(t[0x0D] ^ 0xFF) % 256, (t[0x0A]-t[0x0B]) % 256]
        t[0x10] = (t[0x08]-t[0x0F]) % 256
        t[0x11:0x17] = [(t[0x10] ^ t[0x07]) % 256, (t[0x0F] ^ 0xFF) % 256,
                        (t[0x03] ^ 0x10) % 256, (t[0x04]-0x32) % 256,
                        (t[0x05]+0xED) % 256, (t[0x06] ^ 0xF3) % 256]
        t[0x17:0x1A] = [(t[0x13]-t[0x0F]) % 256, (t[0x15]+t[0x07]) % 256, (0x21-t[0x13]) % 256]
        t[0x1A:0x1C] = [(t[0x14] ^ t[0x17]) % 256, (t[0x16]+t[0x16]) % 256]
        t[0x1C:0x1F] = [(t[0x17]+0x44) % 256, (t[0x03]+t[0x04]) % 256, (t[0x05]-t[0x16]) % 256]
        t[0x1F] = (t[0x1D] ^ t[0x13]) % 256
        self.videomask1 = t
        self.videomask2 = bytearray(x ^ 0xFF for x in t)

    def videomask(self, data, head=0x40, guard=0x200):
        """data must be bytearray. head=0 disables the plaintext head."""
        data = bytearray(data)
        if len(data) - head <= guard:
            return data
        return video_mask_apply(data, self.videomask1, self.videomask2, head)

def video_mask_apply(buf, vmask1, vmask2, head=0x40):
    """In-place CRI video mask on buf[head:]; buf is bytearray, len multiple of 8."""
    body = bytearray(buf[head:])
    size = len(body)
    assert size % 8 == 0, size
    mask2 = bytearray(vmask2)
    for i in range(32, size//8):
        off = i*8
        w = int.from_bytes(body[off:off+8], 'little') ^ int.from_bytes(mask2[(i % 4)*8:(i % 4)*8+8], 'little')
        body[off:off+8] = w.to_bytes(8, 'little')
        m = mask2[(i % 4)*8:(i % 4)*8+8]
        v = vmask2[(i % 4)*8:(i % 4)*8+8]
        mask2[(i % 4)*8:(i % 4)*8+8] = (w ^ int.from_bytes(v, 'little')).to_bytes(8, 'little')
    mask1 = bytearray(vmask1)
    for i in range(32):
        mi = i % 4
        m = mask1[mi*8:mi*8+8]
        d = body[32+i]
        mask1[mi*8:mi*8+8] = (int.from_bytes(m, 'little') ^ int.from_bytes(body[(32+i)*8:(32+i)*8+8], 'little')).to_bytes(8, 'little')
        body[i*8:(i+1)*8] = (int.from_bytes(body[i*8:(i+1)*8], 'little') ^ int.from_bytes(mask1[mi*8:mi*8+8], 'little')).to_bytes(8, 'little')
    return bytearray(buf[:head]) + body

# --------------------------------------------------------------------------
# 3. IVF writer + ffmpeg verify
# --------------------------------------------------------------------------
def write_ivf(frames, w, h, rate_n, rate_d, path):
    out = bytearray()
    out += b'DKIF' + struct.pack('<HH', 0, 32) + b'VP90' + \
           struct.pack('<HHIIII', w, h, rate_n, rate_d, len(frames), 0)
    for i, f in enumerate(frames):
        out += struct.pack('<IQ', len(f), i)
        out += f
    open(path, 'wb').write(out)
    return len(out)

def ffmpeg_probe(path):
    try:
        r = subprocess.run([FFMPEG, '-hide_banner', '-v', 'error', '-i', path,
                            '-f', 'null', '-'], capture_output=True, timeout=300)
        err = r.stderr.decode('utf-8', 'replace')
    except Exception as e:
        return None, str(e)
    # count frames
    r2 = subprocess.run([FFMPEG, '-hide_banner', '-v', 'error', '-i', path,
                         '-f', 'null', '-'], capture_output=True, timeout=300)
    return err, None

def count_frames(path):
    r = subprocess.run([FFMPEG, '-hide_banner', '-v', 'error', '-i', path,
                        '-map', '0:v:0', '-f', 'null', '-'],
                       capture_output=True, timeout=600)
    return r.stderr.decode('utf-8', 'replace')

def main():
    D = open(PATH, 'rb').read()
    print('file: %s  (%d bytes)' % (os.path.basename(PATH), len(D)))
    chunks, stops = build_map(D)
    print('chunks mapped: %d' % len(chunks))
    for s in stops: print('  stop:', s)
    print('sig hist:', collections.Counter(c['sig'] for c in chunks).most_common(12))
    print('chinfo hist:', collections.Counter(c['chinfo'] for c in chunks).most_common(8))
    print('chno hist:', collections.Counter(c['chno'] for c in chunks).most_common(8))
    print('u16@0x0A hist:', collections.Counter(c['u16_a'] for c in chunks).most_common())
    print('size hist (top):', collections.Counter(c['size'] for c in chunks).most_common(6))
    print('\nfirst 12 chunks:')
    for c in chunks[:12]:
        print('  0x%08X %-5s size=%-8d plen=%-8d u16a=0x%04X chinfo=0x%08X chno=%-3d ftime=%-6d frate=%d'
              % (c['off'], c['sig'], c['size'], c['plen'], c['u16_a'], c['chinfo'], c['chno'], c['ftime'], c['frate']))
    print('\nlast 6 chunks:')
    for c in chunks[-6:]:
        print('  0x%08X %-5s size=%-8d plen=%-8d u16a=0x%04X chinfo=0x%08X chno=%-3d ftime=%-6d frate=%d'
              % (c['off'], c['sig'], c['size'], c['plen'], c['u16_a'], c['chinfo'], c['chno'], c['ftime'], c['frate']))

if __name__ == '__main__':
    main()
