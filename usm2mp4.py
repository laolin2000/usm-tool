"""
usm2mp4.py - CRI USM (Sofdec2) -> VP9 IVF -> MP4

Verified container facts for maimai DX `MovieData/*.dat`:
  * starts with 'CRID'                                  (CRI USM)
  * CRIUSF_DIR_STREAM directory at 0x40..0x280          (source .usm/.ivf names)
  * plaintext IVF file header at 0xEE0: DKIF/VP90, 1080x608, 30000/1001 fps, 4412 frames
  * '@SFV' video chunks, 24-byte header + payload, 0x20-aligned, contiguous
  * the video payload is encrypted; frame 0 at 0xF0C is the only plaintext frame

Usage
  python usm2mp4.py <input.dat> <output.mp4> [--key 0xXXXXXXXXXXXXXXXX]
  python usm2mp4.py <input.dat> --probe            # structure report only

If the payload is CRI video-masked, --key supplies the 8-byte CRI key. Without a key the
script still rebuilds the IVF from whatever plaintext chunks exist and reports progress.
"""
from __future__ import annotations
import argparse, os, struct, subprocess, sys, re

FFMPEG = r'C:\Users\<you>\AppData\Roaming\bilibili\ffmpeg\ffmpeg.exe'
ALIGN = 0x20

# ---------------------------------------------------------------- CRI video mask
def derive_masks(key_hex: str):
    """CRI USM videomask1/videomask2 derivation (8-byte key as 16 hex digits)."""
    key = key_hex.rjust(16, '0') if len(key_hex) <= 16 else key_hex
    key1 = bytes.fromhex(key[8:])
    key2 = bytes.fromhex(key[:8])
    t = bytearray(0x20)
    t[0:9] = [key1[3], key1[2], key1[1], (key1[0] - 0x34) % 256, (key2[3] + 0xF9) % 256,
              (key2[2] ^ 0x13) % 256, (key2[1] + 0x61) % 256, (key1[3] ^ 0xFF) % 256,
              (key1[1] + key1[2]) % 256]
    t[9:12] = [(t[1] - t[7]) % 256, (t[2] ^ 0xFF) % 256, (t[1] ^ 0xFF) % 256]
    t[12:14] = [(t[11] + t[9]) % 256, (t[8] - t[3]) % 256]
    t[14:16] = [(t[13] ^ 0xFF) % 256, (t[10] - t[11]) % 256]
    t[16] = (t[8] - t[15]) % 256
    t[17:23] = [(t[16] ^ t[7]) % 256, (t[15] ^ 0xFF) % 256, (t[3] ^ 0x10) % 256,
                (t[4] - 0x32) % 256, (t[5] + 0xED) % 256, (t[6] ^ 0xF3) % 256]
    t[23:26] = [(t[19] - t[15]) % 256, (t[21] + t[7]) % 256, (0x21 - t[19]) % 256]
    t[26:28] = [(t[20] ^ t[23]) % 256, (t[22] + t[22]) % 256]
    t[28:31] = [(t[23] + 0x44) % 256, (t[3] + t[4]) % 256, (t[5] - t[22]) % 256]
    t[31] = (t[29] ^ t[19]) % 256
    return bytes(t), bytes(x ^ 0xFF for x in t)


def video_mask(body: bytes, vmask1: bytes, vmask2: bytes, head_len: int = 0x40) -> bytes:
    """CRI SFV chunk decryption. `body` excludes the chunk header (kept verbatim)."""
    n = len(body)
    if n <= 0x200:
        return body
    nq = n // 8
    dq = list(struct.unpack_from('<%dQ' % nq, body, 0))
    m2 = list(struct.unpack('<4Q', vmask2)); v2 = list(struct.unpack('<4Q', vmask2))
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]
        m2[j] = dq[i] ^ v2[j]
    m1 = list(struct.unpack('<4Q', vmask1))
    for i in range(32):
        j = i % 4
        m1[j] ^= dq[i + 32]
        dq[i] ^= m1[j]
    return struct.pack('<%dQ' % nq, *dq) + body[nq * 8:]


# ---------------------------------------------------------------- container parse
def al(n, a=ALIGN):
    return (n + a - 1) // a * a


def parse(path: str):
    buf = open(path, 'rb').read()
    assert buf[0:4] == b'CRID', 'not a CRI USM file'
    ivf = buf[0xEE0:0xEE0 + 32]
    assert ivf[0:4] == b'DKIF', 'IVF header not found at 0xEE0'
    magic, ver, hsz, fourcc, w, h, num, den, nframes, _ = struct.unpack('<4sHH4sHHIIII', ivf)
    info = dict(width=w, height=h, num=num, den=den, nframes=nframes,
                duration=nframes * den / num, fourcc=fourcc.decode(), ivf_header=ivf)
    # walk @SFV chunks
    chunks, o = [], 0x800
    while o + 8 <= len(buf):
        if buf[o:o + 4] != b'@SFV':
            o += ALIGN
            continue
        size = struct.unpack_from('>I', buf, o + 4)[0]
        if size == 0 or size > 4_000_000 or o + size > len(buf):
            o += ALIGN
            continue
        chunks.append((o, size))
        o = al(o + size)
    info['chunks'] = chunks
    info['buf'] = buf
    return info


def build_ivf(info, frames):
    h = bytearray(info['ivf_header'])
    struct.pack_into('<I', h, 24, len(frames))
    out = bytearray(h)
    for i, f in enumerate(frames):
        out += struct.pack('<IQ', len(f), i) + f
    out += struct.pack('<I', len(frames))
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('output', nargs='?')
    ap.add_argument('--key', default=None, help='CRI 8-byte key, 16 hex digits')
    ap.add_argument('--probe', action='store_true')
    ap.add_argument('--payload-offset', type=lambda x: int(x, 0), default=0x40)
    a = ap.parse_args()

    info = parse(a.input)
    print(f"container : CRI USM")
    print(f"video     : {info['fourcc']} {info['width']}x{info['height']} "
          f"{info['num']}/{info['den']} fps, {info['nframes']} frames, "
          f"{info['duration']:.1f} s")
    print(f"@SFV chunks: {len(info['chunks'])}")
    if a.probe:
        return 0

    buf = info['buf']
    pays = [buf[o + a.payload_offset:o + s] for o, s in info['chunks']]
    if a.key:
        v1, v2 = derive_masks(a.key)
        pays = [video_mask(p, v1, v2) for p in pays]
        print(f"decrypted with key {a.key}")
    ivf = build_ivf(info, pays)
    ivf_path = os.path.splitext(a.output)[0] + '.ivf'
    open(ivf_path, 'wb').write(ivf)
    print(f"wrote {ivf_path} ({len(ivf)} bytes)")

    if a.output:
        r = subprocess.run([FFMPEG, '-v', 'error', '-y', '-i', ivf_path,
                            '-c:v', 'libx264', '-preset', 'medium', '-crf', '18',
                            '-pix_fmt', 'yuv420p', '-movflags', '+faststart', a.output],
                           capture_output=True, text=True)
        err = (r.stderr or '').strip()
        if err:
            print('ffmpeg:', err[:500])
        print(f"wrote {a.output}")


if __name__ == '__main__':
    sys.exit(main())
