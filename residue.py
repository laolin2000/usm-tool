"""
Locate the encrypted layer by measuring per-offset-modulo zero density.

If a rolling/block cipher with a period P was applied, plaintext zeros (padding, headers)
show up at fixed residues mod P. Looking at which residues are zero-rich reveals both the
period and the alignment, and comparing against the plaintext frame 0 gives the mask.
"""
import sys, collections

path = sys.argv[1]
buf = open(path, 'rb').read()

# ---- 1. per-residue zero density in the main video region ----
S, L = 0x1960, 0x40000
print(f'=== per-residue zero density in 0x{S:x}..0x{S+L:x} ===')
for P in [8, 16, 32, 64, 128, 256, 0x800]:
    res = collections.Counter()
    tot = collections.Counter()
    for i in range(P):
        res[i] = 0; tot[i] = 0
    for i in range(L):
        r = i % P
        tot[r] += 1
        if buf[S+i] == 0:
            res[r] += 1
    dens = [(r, res[r]/tot[r]) for r in range(P)]
    top = sorted(dens, key=lambda x: -x[1])[:5]
    avg = sum(d for _, d in dens)/P
    print(f'  P=0x{P:<5x} avg={avg:.4f}  top residues: ' + ' '.join(f'{r}:{d:.3f}' for r, d in top))

# ---- 2. run-length histogram of zero bytes (frame padding chunks are zeros) ----
print('\n=== zero run-length histogram (whole payload 0x1960..end) ===')
runs = collections.Counter()
run = 0
for i in range(0x1960, len(buf)):
    if buf[i] == 0:
        run += 1
    else:
        if run: runs[run] += 1
        run = 0
for n, c in sorted(runs.items(), key=lambda x: -x[1])[:15]:
    print(f'  run={n:5d} x{c}')

# ---- 3. In the main video region, where exactly are the 4-byte "00 00 00 xx" patterns? ----
print('\n=== positions of "00 00 00" in 0x1960..0x2160 ===')
hits = [i for i in range(0x1960, 0x2160) if buf[i:i+3] == b'\x00\x00\x00']
print(' ', [hex(x) for x in hits])
if len(hits) > 2:
    print('  diffs:', [hits[k+1]-hits[k] for k in range(len(hits)-1)])

# ---- 4. same for the plaintext frame-0 area (control) ----
print('\n=== positions of "00 00 00" in 0xF0C..0x1012 (plaintext control) ===')
hits2 = [i for i in range(0xF0C, 0x1012) if buf[i:i+3] == b'\x00\x00\x00']
print(' ', [hex(x) for x in hits2])
