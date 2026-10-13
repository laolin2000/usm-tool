"""
USM (CRI Sofdec2) video decryption - exact port of the CRI/PyCriCodecsEx algorithm.

Key insight (from PyCriCodecsEx/usm.py USMCrypt):
  * videomask1/videomask2 (32B each) are derived from an 8-byte key.
  * The SFV chunk is decrypted as ONE body:
        head = body[:0x40]                      # chunk+meta, left alone
        data = body[0x40:]
        if len(data) <= 0x200: nothing
        else:
            # mask2: rolling 64-bit feedback over the WHOLE body
            for i in 32 .. size//8:
                data_q[i] ^= mask_q[i % 4]
                mask_q[i % 4] = data_q[i] ^ vmask2_q[i % 4]
            # mask1: rolling 64-bit feedback over the first 32 qwords
            for i in 0 .. 31:
                mask_q[i % 4] ^= data_q[i + 32]
                data_q[i] ^= mask_q[i % 4]
"""
import sys, struct

VIDEO_SIZE_THRESHOLD = 0x200


def derive_masks(key_hex: str):
    key = key_hex.rjust(16, '0') if len(key_hex) <= 16 else key_hex
    key1 = bytes.fromhex(key[8:])     # 4 bytes
    key2 = bytes.fromhex(key[:8])     # 4 bytes
    t = bytearray(0x20)
    t[0x00:0x09] = [
        key1[3], key1[2], key1[1],
        (key1[0] - 0x34) % 0x100,
        (key2[3] + 0xF9) % 0x100,
        (key2[2] ^ 0x13) % 0x100,
        (key2[1] + 0x61) % 0x100,
        (key1[3] ^ 0xFF) % 0x100,
        (key1[1] + key1[2]) % 0x100,
    ]
    t[0x09:0x0C] = [(t[0x01] - t[0x07]) % 0x100, (t[0x02] ^ 0xFF) % 0x100, (t[0x01] ^ 0xFF) % 0x100]
    t[0x0C:0x0E] = [(t[0x0B] + t[0x09]) % 0x100, (t[0x08] - t[0x03]) % 0x100]
    t[0x0E:0x10] = [(t[0x0D] ^ 0xFF) % 0x100, (t[0x0A] - t[0x0B]) % 0x100]
    t[0x10] = (t[0x08] - t[0x0F]) % 0x100
    t[0x11:0x17] = [
        (t[0x10] ^ t[0x07]) % 0x100,
        (t[0x0F] ^ 0xFF) % 0x100,
        (t[0x03] ^ 0x10) % 0x100,
        (t[0x04] - 0x32) % 0x100,
        (t[0x05] + 0xED) % 0x100,
        (t[0x06] ^ 0xF3) % 0x100,
    ]
    t[0x17:0x1A] = [(t[0x13] - t[0x0F]) % 0x100, (t[0x15] + t[0x07]) % 0x100, (0x21 - t[0x13]) % 0x100]
    t[0x1A:0x1C] = [(t[0x14] ^ t[0x17]) % 0x100, (t[0x16] + t[0x16]) % 0x100]
    t[0x1C:0x1F] = [(t[0x17] + 0x44) % 0x100, (t[0x03] + t[0x04]) % 0x100, (t[0x05] - t[0x16]) % 0x100]
    t[0x1F] = (t[0x1D] ^ t[0x13]) % 0x100
    videomask1 = bytes(t)
    videomask2 = bytes(x ^ 0xFF for x in t)
    return videomask1, videomask2


def video_mask(mem: bytearray, vmask1: bytes, vmask2: bytes) -> bytearray:
    """Decrypt an SFV chunk body in place (keeps the first 0x40 bytes intact)."""
    head = bytes(mem[:0x40])
    body = bytearray(mem[0x40:])
    size = len(body)
    if size <= VIDEO_SIZE_THRESHOLD:
        return head + body
    nq = size // 8
    dq = list(struct.unpack_from('<%dQ' % nq, body, 0))
    m2 = list(struct.unpack('<4Q', vmask2))
    v2 = list(struct.unpack('<4Q', vmask2))

    # --- mask 2 ---
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]
        m2[j] = dq[i] ^ v2[j]

    # --- mask 1 ---
    m1 = list(struct.unpack('<4Q', vmask1))
    for i in range(32):
        j = i % 4
        m1[j] ^= dq[i + 32]
        dq[i] ^= m1[j]

    out = bytearray(struct.pack('<%dQ' % nq, *dq))
    out += body[nq * 8:]
    return head + out


def score(pt: bytes) -> dict:
    tags = {}
    for t in (b'@SFV', b'@SFA', b'DKIF', b'VP90', b'#METADATA', b'#CONTENTS', b'@UTF', b'HCA\x00', b'@ALP'):
        c = pt.count(t)
        if c:
            tags[t.decode('latin1')] = c
    return tags


if __name__ == '__main__':
    path = sys.argv[1]
    keys = sys.argv[2:] if len(sys.argv) > 2 else []
    buf = bytearray(open(path, 'rb').read())
    print(f'file size {len(buf)} (0x{len(buf):x})')

    # The video stream body starts right after the IVF header (0xEE0+0x20).
    # Try both the whole tail and a small probe window.
    for key in keys:
        v1, v2 = derive_masks(key)
        print(f'\n=== key {key} : mask1={v1.hex()} mask2={v2.hex()} ===')
        probe = bytearray(buf[0xF00:0xF00 + 0x2000])
        pt = video_mask(probe, v1, v2)
        s = score(pt)
        print(f'  probe@0xF00 tags: {s if s else "none"}')
        print(f'  head: {pt[:48].hex()}')
        # also probe the first @SFV frame chunk region
        probe2 = bytearray(buf[0x1960:0x1960 + 0x2000])
        pt2 = video_mask(probe2, v1, v2)
        s2 = score(pt2)
        print(f'  probe@0x1960 tags: {s2 if s2 else "none"}')
        print(f'  head: {pt2[:48].hex()}')
