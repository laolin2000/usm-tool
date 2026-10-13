"""
Use the KNOWN plaintext at 0x1020 ('@SFV' + 98 00 00 00 ...) as a checksum.

The mask output at that exact position must equal that plaintext. We test:
  * canonical CRI mask on the chunk starting at 0x1020 (head 0x40)
  * head lengths 0x00/0x20 and offsets 0x1000/0x1020
  * several keys
and report the first bytes of the result for each, so the correct combination is obvious.
"""
import sys, struct, os

src = sys.argv[1]; outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
buf = open(src, 'rb').read()

TARGET = bytes(buf[0x1020:0x1040])
print('target plaintext @0x1020:', TARGET.hex(' '))

def derive_masks(key_hex):
    k = key_hex.rjust(16, '0')
    k1 = bytes.fromhex(k[8:]); k2 = bytes.fromhex(k[:8])
    t = bytearray(0x20)
    t[0:9] = [k1[3], k1[2], k1[1], (k1[0]-0x34) % 256, (k2[3]+0xF9) % 256,
              (k2[2] ^ 0x13) % 256, (k2[1]+0x61) % 256, (k1[3] ^ 0xFF) % 256, (k1[1]+k1[2]) % 256]
    t[9:12] = [(t[1]-t[7]) % 256, (t[2] ^ 0xFF) % 256, (t[1] ^ 0xFF) % 256]
    t[12:14] = [(t[11]+t[9]) % 256, (t[8]-t[3]) % 256]
    t[14:16] = [(t[13] ^ 0xFF) % 256, (t[10]-t[11]) % 256]
    t[16] = (t[8]-t[15]) % 256
    t[17:23] = [(t[16] ^ t[7]) % 256, (t[15] ^ 0xFF) % 256, (t[3] ^ 0x10) % 256,
                (t[4]-0x32) % 256, (t[5]+0xED) % 256, (t[6] ^ 0xF3) % 256]
    t[23:26] = [(t[19]-t[15]) % 256, (t[21]+t[7]) % 256, (0x21-t[19]) % 256]
    t[26:28] = [(t[20] ^ t[23]) % 256, (t[22]+t[22]) % 256]
    t[28:31] = [(t[23]+0x44) % 256, (t[3]+t[4]) % 256, (t[5]-t[22]) % 256]
    t[31] = (t[29] ^ t[19]) % 256
    return bytes(t), bytes(x ^ 0xFF for x in t)

def mask(data, v1, v2, head=0x40, off=0):
    """apply canonical CRI rolling mask to data[off:], keeping data[off:off+head] verbatim"""
    out = bytearray(data)
    seg = bytes(data[off:])
    if len(seg) <= head + 0x100: return bytes(out)
    hd = seg[:head]; rest = seg[head:]
    nq = len(rest) // 8
    if nq < 33: return bytes(out)
    dq = list(struct.unpack_from('<%dQ' % nq, rest, 0))
    m2 = list(struct.unpack('<4Q', v2)); v2q = list(struct.unpack('<4Q', v2))
    for i in range(32, nq):
        j = i % 4
        dq[i] ^= m2[j]; m2[j] = dq[i] ^ v2q[j]
    m1 = list(struct.unpack('<4Q', v1))
    for i in range(32):
        if i+32 >= nq: break
        j = i % 4
        m1[j] ^= dq[i+32]; dq[i] ^= m1[j]
    res = hd + struct.pack('<%dQ' % nq, *dq) + rest[nq*8:]
    out[off:] = res
    return bytes(out)

print('\n=== checksum tests ===')
for key in ('7F4551499DF55E68', '0000000000000000'):
    v1, v2 = derive_masks(key)
    for off in (0x1020, 0x1000, 0x0F00):
        for head in (0x00, 0x20, 0x28, 0x40):
            d = mask(buf, v1, v2, head, off)
            got = d[0x1020:0x1040]
            ok = got == TARGET
            print(f'  key={key} off=0x{off:x} head=0x{head:x}: {"*** MATCH ***" if ok else "no"}  got={got[:16].hex(" ")}')
