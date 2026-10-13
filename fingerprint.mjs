// Final format fingerprinting + encryption-scheme discriminator.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const size = buf.length

function findAll(tag, limit = 20, from = 0) {
  const b = Buffer.from(tag, 'latin1'); const out = []
  let i = buf.indexOf(b, from)
  while (i !== -1 && out.length < limit) { out.push(i); i = buf.indexOf(b, i + 1) }
  return out
}
console.log('=== magic scan ===')
const MAGICS = ['DKIF', 'ftyp', 'moov', 'mdat', 'EBML', 'BIK', 'BZh', 'IVF', 'HCA', 'SFA', 'SFV', 'RIFF', 'OggS', 'FTYP']
for (const m of MAGICS) { const h = findAll(m, 12); console.log(`  ${m.padEnd(6)} n=${h.length} ${h.slice(0, 6).map(x => '0x' + x.toString(16)).join(' ')}`) }
// compression magics
const zlib = []
for (let i = 0; i + 2 < size; i++) if (buf[i] === 0x78 && (buf[i + 1] === 0x9c || buf[i + 1] === 0x01 || buf[i + 1] === 0xda)) { zlib.push('0x' + i.toString(16)); if (zlib.length > 6) break }
console.log('  zlib-ish:', zlib.join(' ') || 'none')
const lz4 = findAll('\x04\x22\x4D\x18', 5)
console.log('  lz4:', lz4.map(x => '0x' + x.toString(16)).join(' ') || 'none')

// === repeated 16-byte block detection (AES-ECB style / repeated key frames) ===
console.log('\n=== repeated 16B blocks (top repeats, sampling every 0x10 in payload) ===')
const counts = new Map()
const firstAt = new Map()
const STEP = 0x10
for (let o = 0x1960; o + 16 <= size; o += STEP) {
  const key = buf.toString('hex', o, o + 16)
  counts.set(key, (counts.get(key) || 0) + 1)
  if (!firstAt.has(key)) firstAt.set(key, o)
}
const top = [...counts.entries()].filter(([, c]) => c > 50).sort((a, b) => b[1] - a[1]).slice(0, 10)
if (top.length) for (const [k, c] of top) console.log(`  x${c}  ${k}  first@0x${firstAt.get(k).toString(16)}`)
else console.log('  none above threshold 50')

// === key-slot reuse statistics: how often does each header-derived 32B window appear in the payload? ===
console.log('\n=== 32B header-window reuse inside payload ===')
for (let s = 0; s < 16; s++) {
  const w = buf.subarray(0x40 + s * 32, 0x40 + s * 32 + 32)
  let n = 0, first = -1
  let i = buf.indexOf(w, 0x1960)
  while (i !== -1 && i < 0x200000) { n++; if (first < 0) first = i; i = buf.indexOf(w, i + 1) }
  console.log(`  slot${String(s).padStart(2)} occurrences in first 2MB of payload: ${n}${first >= 0 ? ' first@0x' + first.toString(16) : ''}`)
}

// === byte-value histogram of the payload head (is it XOR-encrypted, ciphered, or compressed?) ===
console.log('\n=== payload head byte histogram 0x1960..0x21960 ===')
const hist = new Uint32Array(256)
const N = 0x20000
for (let i = 0; i < N; i++) hist[buf[0x1960 + i]]++
let mn = Infinity, mx = -Infinity
for (let i = 0; i < 256; i++) { if (hist[i] < mn) mn = hist[i]; if (hist[i] > mx) mx = hist[i] }
console.log(`  min=${mn} max=${mx} expected_uniform=${(N / 256).toFixed(0)}  ratio=${(mx / (N / 256)).toFixed(2)}`)
const interesting = [...hist].map((c, i) => [i, c]).filter(([, c]) => c > (N / 256) * 2.2 || c < (N / 256) * 0.25)
console.log('  outliers(byte:count):', interesting.slice(0, 20).map(([b, c]) => `${b.toString(16).padStart(2, '0')}:${c}`).join(' ') || 'none')
