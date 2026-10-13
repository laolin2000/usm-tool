"""
Hunt the CRI USM videomask key derivation across EVERY binary in the game folder.

The derivation recipe uses the byte constants 0x34, 0xF9, 0x13, 0x61, 0xED, 0xF3 in a
short code sequence. We look for that cluster plus USM/mask/key strings, in every
PE/DLL/EXE, and report the strongest hits with context.
"""
import sys, os, re

ROOT = sys.argv[1]
TARGET = {0x34, 0xF9, 0x13, 0x61, 0xED, 0xF3}
KWS = [b'usm', b'Usm', b'USM', b'videomask', b'VideoMask', b'criKey', b'CriKey',
       b'SOFDEC', b'Sofdec', b'sofdec', b'mask_key', b'key_table', b'sfv', b'SFV']

files = []
for dirpath, _, names in os.walk(ROOT):
    for n in names:
        if n.lower().endswith(('.dll', '.exe', '.so', '.bin')):
            files.append(os.path.join(dirpath, n))

print(f'scanning {len(files)} binaries under {ROOT}\n')
results = []
for f in files:
    try:
        d = open(f, 'rb').read()
    except Exception:
        continue
    name = os.path.basename(f)
    # 1) key-recipe constant cluster
    hits = []
    for i in range(0, len(d) - 10, 1):
        w = d[i:i+10]
        if sum(1 for b in w if b in TARGET) >= 6:
            hits.append(i)
            if len(hits) > 6: break
    # 2) keyword hits
    kws = []
    for k in KWS:
        c = d.count(k)
        if c: kws.append((k.decode('latin1'), c))
    if hits or kws:
        results.append((name, f, hits, kws, len(d)))

for name, f, hits, kws, size in sorted(results, key=lambda r: (-len(r[2]), -len(r[3]))):
    print(f'{name}  ({size} bytes)')
    if hits: print(f'   const-cluster offsets: {[hex(h) for h in hits[:6]]}')
    if kws:  print(f'   keywords: {kws}')
    if hits:
        i = hits[0]
        d = open(f, 'rb').read()
        print(f'   ctx: {d[max(0,i-24):i+34].hex(" ")}')
