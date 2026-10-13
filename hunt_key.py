"""
Hunt for the decryption key inside the game's binaries.

Strategy:
 1. Locate the AES S-box (63 7C 77 7B F2 6B 6F C5 ...) -> crypto code present.
 2. Dump printable/hex-looking strings near the video-loading code.
 3. Look for 16-byte high-entropy constants that could be the USM key.
"""
import sys, re, os

paths = sys.argv[1:]
SBOX = bytes([0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76])
RCON = bytes([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36])
INTERESTING = [b'usm', b'USM', b'SFV', b'SFA', b'CriWare', b'CRIWARE', b'cri_', b'key', b'Key',
               b'aes', b'AES', b'MovieData', b'.dat', b'ivf', b'IVF', b'vp9', b'VP9', b'decrypt',
               b'Decrypt', b'\xe9\x92\xa5\xe5\x8c\x99', b'movie']

for path in paths:
    if not os.path.isfile(path):
        print(f'!! missing {path}'); continue
    data = open(path, 'rb').read()
    name = os.path.basename(path)
    print(f'\n===== {name} ({len(data)} bytes) =====')

    # 1. AES S-box
    pos = data.find(SBOX)
    print(f'  AES S-box at: {"0x%x" % pos if pos >= 0 else "not found"}')
    pos2 = data.find(RCON)
    print(f'  AES Rcon  at: {"0x%x" % pos2 if pos2 >= 0 else "not found"}')

    # 2. interesting strings
    print('  --- keyword hits (offset, context) ---')
    seen = set()
    for kw in INTERESTING:
        start = 0
        cnt = 0
        while cnt < 6:
            i = data.find(kw, start)
            if i < 0: break
            ctx = data[max(0, i-40):i+60]
            ctx_s = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            key = ctx_s[:50]
            if key not in seen:
                seen.add(key)
                print(f'    {kw.decode("latin1","replace"):<12} @0x{i:x}: {ctx_s}')
            start = i + 1
            cnt += 1

    # 3. USM key formats seen in the wild: 16-hex-digit strings near crypto code
    hexes = set(re.findall(rb'\b[0-9A-Fa-f]{16}\b', data))
    if pos >= 0 and hexes:
        print('  --- 16-char hex strings in binary (possible keys) ---')
        for h in list(hexes)[:40]:
            print('    ', h.decode())
