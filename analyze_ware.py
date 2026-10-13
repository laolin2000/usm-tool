"""
Analyse cri_ware_unity.dll (CRI Mana container layer) for USM key handling.

Look for:
  * exported/diagnostic names mentioning key, crypt, mask, Sofdec, Usm
  * the CRI key recipe constants (0x34, 0xF9, 0x13, 0x61, 0xED, 0xF3) referenced in code
  * any readable 8-byte default key
"""
import sys, re, os, collections

path = sys.argv[1]
data = open(path, 'rb').read()
print(f'{os.path.basename(path)}: {len(data)} bytes')

print('\n=== strings: key/crypt/mask/sofdec/usm/dat/decrypt ===')
PAT = re.compile(rb'[ -~]{5,120}')
KWS = ['key', 'Key', 'KEY', 'crypt', 'Crypt', 'mask', 'Mask', 'Sofdec', 'sofdec', 'SOFDEC',
       'usm', 'Usm', 'USM', 'Usm', 'decrypt', 'Decrypt', '.dat', 'movie', 'Movie', 'cri',
       'Cri', 'CRI', 'Man', 'mana']
seen = set(); n = 0
for m in PAT.finditer(data):
    s = m.group().decode('latin1')
    if any(k in s for k in KWS) and s not in seen:
        seen.add(s); n += 1
        print(f'  0x{m.start():06x}: {s}')
        if n > 130: break

print('\n=== key-recipe constant bytes (0x34/0xF9/0x13/0x61/0xED/0xF3) clusters ===')
TARGET = {0x34, 0xF9, 0x13, 0x61, 0xED, 0xF3}
hits = 0
for i in range(len(data) - 8):
    w = data[i:i+8]
    if sum(1 for b in w if b in TARGET) >= 5:
        print(f'  0x{i:x}: {w.hex(" ")}   ctx={data[max(0,i-16):i+24].hex(" ")}')
        hits += 1
        if hits > 20: break
if not hits: print('  none')

print('\n=== ASCII that looks like a hex key (16+ hex chars) ===')
for m in re.finditer(rb'(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,64}(?![0-9A-Fa-f])', data):
    s = m.group().decode()
    print(f'  0x{m.start():06x}: {s}')
