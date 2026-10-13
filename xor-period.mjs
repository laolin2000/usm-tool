// The IVF frame data begins right after the DKIF header (0xEE0+32 = 0xF00).
// Determine whether that region is XOR-encrypted with a short-period key by testing
// self-XOR match ratios at many periods, and by measuring structure after each candidate
// decryption.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const S = 0xF00
const L = 0x40000
console.log(`analysing 0x${S.toString(16)}..0x${(S + L).toString(16)}`)

console.log('\n=== self-XOR identical-byte ratio at many periods (random baseline 0.0039) ===')
const cands = [4, 8, 12, 16, 20, 24, 32, 40, 48, 56, 64, 96, 128, 160, 192, 256, 320, 384, 512, 640, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 0x800 * 2, 0x800 * 4, 0x800 * 8, 0x8000, 0x10000]
const out = []
for (const p of cands) {
  let same = 0, n = 0
  for (let i = 0; i + p < L; i += 13) { n++; if (buf[S + i] === buf[S + i + p]) same++ }
  out.push({ p, r: same / n })
}
out.sort((a, b) => b.r - a.r)
for (const { p, r } of out.slice(0, 10)) console.log(`  period 0x${p.toString(16).padStart(6)}: ${r.toFixed(5)}${r > 0.006 ? '  <== elevated' : ''}`)

// === KEY TEST: if the region is XOR with a length-P key, then for the correct P the
//     derived keystream is *periodic*, meaning data[i]^data[i+P] equals pt[i]^pt[i+P].
//     For VP9 plaintext that XOR is usually not constant... instead test the far simpler
//     invariant: a repeating-key XOR of a *compressed* stream leaves no zeros. Use the
//     zero-run structure as the signal: find offsets whose XOR yields long zero runs. ===
console.log('\n=== search for long zero runs produced by XOR against a periodic key of period P ===')
function zeroRunAfterXor(p) {
  const n = 0x20000
  let best = 0, bestAt = -1, run = 0, runStart = 0
  for (let i = 0; i + p < n; i++) {
    const v = buf[S + i] ^ buf[S + i + p]
    if (v === 0) { if (run === 0) runStart = i; run++ } else { if (run > best) { best = run; bestAt = runStart } run = 0 }
  }
  return { p, best, bestAt }
}
const zr = []
for (const p of [16, 20, 24, 28, 32, 36, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 0x800, 0x1000]) zr.push(zeroRunAfterXor(p))
zr.sort((a, b) => b.best - a.best)
console.log('  longest zero runs after XOR at period P:')
for (const z of zr.slice(0, 6)) console.log(`    P=0x${z.p.toString(16)}: run=${z.best} at +0x${z.bestAt.toString(16)}`)

// === Examine the first 0x200 bytes of the frame data for an IVF record header ===
console.log('\n=== first 0x120 bytes of IVF frame data (0xF00) as LE uint32 ===')
for (let o = S; o < S + 0x60; o += 16) {
  const vals = []
  for (let j = 0; j < 16; j += 4) vals.push(buf.readUInt32LE(o + j))
  console.log(`  0x${o.toString(16)}: ${vals.map(v => '0x' + v.toString(16).padStart(8, '0')).join(' ')}   |${buf.toString('latin1', o, o + 16).replace(/[^\x20-\x7e]/g, '.')}|`)
}

// === Hypothesis: 4B length prefix in LE at 0xF00? 0x00000106 = 262 -> matches tryWalk earlier ===
console.log('\n=== walk with 4B LE size prefix from 0xF00 (no timestamp) ===')
{
  let o = S, n = 0, sizes = []
  while (o + 4 <= buf.length && n < 20) {
    const s = buf.readUInt32LE(o)
    if (s === 0 || s > 0x200000) break
    sizes.push(s); n++; o += 4 + s
  }
  console.log(`  frames=${n} offsets consumed -> 0x${o.toString(16)} sizes=${sizes.join(',')}`)
}
