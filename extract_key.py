"""
Extract the AES key from the game's managed assembly.

Assembly-CSharp.dll contains the string field `c_aesKey` and `CipherAES`, so the key is a
hardcoded string literal. .NET user-string literals are stored UTF-16LE in the #US heap.
This script extracts all UTF-16LE strings and filters for key-like candidates.
"""
import sys, re, os

path = sys.argv[1]
data = open(path, 'rb').read()
print(f'{os.path.basename(path)}: {len(data)} bytes')

# --- UTF-16LE strings ---
s = data.decode('utf-16-le', errors='ignore')
runs = re.findall(r'[ -~]{6,}', s)
print(f'utf16 strings: {len(runs)}')

KEYISH = re.compile(r'^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]{16,48}$')
cands = []
for r in runs:
    if KEYISH.match(r) and not r.isalpha() and not r.isdigit():
        # heuristic: contains mixed classes -> likely a key
        has_u = any(ch.isupper() for ch in r)
        has_l = any(ch.islower() for ch in r)
        has_d = any(ch.isdigit() for ch in r)
        has_s = any(not ch.isalnum() for ch in r)
        score = sum([has_u, has_l, has_d, has_s])
        if score >= 3:
            cands.append((score, r))
cands.sort(key=lambda x: -x[0])
print(f'\n=== key-like UTF-16 strings ({len(cands)}) ===')
seen = set()
for sc, r in cands[:60]:
    if r in seen: continue
    seen.add(r)
    print(f'  score={sc} len={len(r):2d}  {r!r}')

# --- also look for the c_aesKey field name and nearby strings ---
print('\n=== context around "c_aesKey"/"CipherAES"/"MovieData" ===')
for kw in ['c_aesKey', 'CipherAES', 'MovieData', 'movie', 'usm', 'CriWare']:
    idx = 0
    hits = 0
    while hits < 3:
        i = s.find(kw, idx)
        if i < 0: break
        ctx = s[max(0, i-80):i+120]
        ctx = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in ctx)
        print(f'  [{kw}] {ctx}')
        idx = i + 1
        hits += 1
