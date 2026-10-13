// Numeric discriminator: is the payload a repeating-key XOR (short period) or a real
// cipher? Also test the IVF-header known-plaintext hypothesis to recover the mask.
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

const buf = readFileSync(process.argv[2])
const S = 0x1960

// ---- known-plaintext mask recovery: assume payload starts with a CRI USM chunk header
//      or an IVF header. Derive mask candidates and check for internal repetition. ----
const hypotheses = {
  'IVF header (DKIF..VP90)': Buffer.from('DKIF\u0000\u0000 \u0000\u0002\u0000\u0002\u0005\u0000\u0002\u0002VP90\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000', 'latin1'),
  'CRI chunk header (@SFV)': Buffer.concat([Buffer.from('@SFV'), Buffer.from([0, 0, 0x40, 0x00, 0, 0x18, 0x06, 0x60, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x1e, 0, 0, 0, 0, 0, 0, 0, 0])]),
}
for (const [name, pt] of Object.entries(hypotheses)) {
  const mask = Buffer.alloc(pt.length)
  for (let i = 0; i < pt.length; i++) mask[i] = buf[S + i] ^ pt[i]
  // check periodicity of the mask itself (candidate key length)
  const periods = []
  for (const p of [4, 8, 16, 32, 64, 128, 256]) {
    let same = 0, n = 0
    for (let i = 0; i + p < mask.length; i++) { n++; if (mask[i] === mask[i + p]) same++ }
    if (n && same / n > 0.7) periods.push(`p=${p}:${(same / n).toFixed(2)}`)
  }
  console.log(`hypothesis "${name}": mask=${mask.toString('hex')} periodic=${periods.join(',') || 'no'}`)
}

// ---- periodicity of the payload itself under XOR ----
console.log('\n=== payload self-XOR match ratio (a repeating key gives a spike) ===')
const L = 0x100000
for (const p of [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 0x1000, 0x2000]) {
  let same = 0, n = 0
  for (let i = 0; i + p < L; i += 11) { n++; if (buf[S + i] === buf[S + i + p]) same++ }
  const r = same / n
  if (r > 0.006) console.log(`  period 0x${p.toString(16)}: ${r.toFixed(4)}  <== elevated (random=0.0039)`)
}
console.log('  (no line above = no short-period repeating key)')

// ---- 16-byte block repetition over the WHOLE payload (not just 0x1960+) ----
console.log('\n=== 16B block repetition over whole file (sampling every 16B) ===')
const seen = new Map()
for (let o = 0; o + 16 <= buf.length; o += 16) {
  const h = buf.toString('hex', o, o + 16)
  seen.set(h, (seen.get(h) || 0) + 1)
}
const rep = [...seen.entries()].filter(([, c]) => c > 30).sort((a, b) => b[1] - a[1]).slice(0, 12)
console.log(rep.length ? rep.map(([h, c]) => `x${c}:${h}`).join('\n') : '  none')

// ---- where are the zeros in the payload? (a cipher would leave plaintext zero-runs if XOR) ----
console.log('\n=== zero-byte density, 1MB buckets over whole file ===')
let line = []
for (let o = 0; o < buf.length; o += 0x100000) {
  const n = Math.min(0x100000, buf.length - o)
  let z = 0
  for (let i = 0; i < n; i++) if (buf[o + i] === 0) z++
  line.push(`0x${o.toString(16)}:${(z / n * 100).toFixed(1)}%`)
  if (line.length === 6) { console.log('  ' + line.join(' ')); line = [] }
}
if (line.length) console.log('  ' + line.join(' '))
