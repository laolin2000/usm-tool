"""
Analyse cri_mana_vpx.dll (CRI Mana / Sofdec2 VP9 decoder) to locate the decryption logic.

Targets:
  1. ASCII strings mentioning key / crypt / mask / decrypt / sofdec / usm
  2. The CRI mask derivation constant 0x34 / 0xF9 / 0x13 / 0x61 / 0xED / 0xF3 (key recipe)
  3. 8-byte / 16-byte high-entropy constants that could be the USM key table
"""
import sys, re, os, collections

path = sys.argv[1]
data = open(path, 'rb').read()
print(f'{os.path.basename(path)}: {len(data)} bytes')

# ---- 1. strings ----
print('\n=== interesting ASCII strings ===')
PAT = re.compile(rb'[ -~]{5,80}')
seen = set()
KWS = ['key', 'Key', 'KEY', 'crypt', 'Crypt', 'CRYPT', 'mask', 'Mask', 'sofdec', 'Sofdec',
       'SOFDEC', 'usm', 'USM', 'Mana', 'mana', 'vpx', 'VPX', 'ivf', 'IVF', 'movie', 'Movie',
       'chunk', 'Chunk', '.dat', 'Sofdec2', 'sfd', 'SFD']
for m in PAT.finditer(data):
    s = m.group().decode('latin1')
    if any(k in s for k in KWS) and s not in seen:
        seen.add(s)
        print(f'  0x{m.start():x}: {s}')
        if len(seen) > 90: break

# ---- 2. the CRI key-recipe constants ----
print('\n=== key-recipe byte cluster (0x34,0xF9,0x13,0x61,0xED,0xF3) ===')
# search for any 6-byte window containing several of these
TARGET = bytes([0x34, 0xF9, 0x13, 0x61, 0xED, 0xF3])
hits = 0
for i in range(len(data) - 6):
    w = data[i:i+6]
    if sum(1 for b in w if b in TARGET) >= 4:
        print(f'  0x{i:x}: {w.hex(" ")}  ctx={data[max(0,i-12):i+18].hex(" ")}')
        hits += 1
        if hits > 25: break
if not hits: print('  none')

# ---- 3. 16-byte constants with high entropy (possible key material) ----
print('\n=== candidate 16-byte key constants (.rdata style) ===')
import math
def ent(b):
    h = collections.Counter(b); n = len(b)
    return -sum((c/n)*math.log2(c/n) for c in h.values())
cands = []
for i in range(0, len(data) - 16, 1):
    b = data[i:i+16]
    if ent(b) > 3.8 and len(set(b)) >= 13:
        cands.append((i, b))
# cluster nearby ones (key tables appear as runs)
print(f'  raw high-entropy 16B positions: {len(cands)}')
for i, b in cands[:25]:
    print(f'  0x{i:x}: {b.hex(" ")}')
