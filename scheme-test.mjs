// Discriminate the encryption scheme used on the 0x1960.. payload:
//  - if simple repeating-key XOR -> chi-square / repeated-key autocorrelation shows structure
//  - if block cipher (AES) -> perfectly uniform, no periodicity
//  - if it is actually *plain* VP9 -> we'd see ... unlikely; but test decode anyway
import { readFileSync, writeFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const START = Number(process.argv[3] ?? 0x1960)
const LEN = 0x40000
const data = buf.subarray(START, START + LEN)

console.log(`region 0x${START.toString(16)}..0x${(START + LEN).toString(16)}`)

// 1) autocorrelation at candidate key periods (find repeated keystream)
console.log('\n=== match ratio at candidate XOR key periods (1.0 = identical = plaintext, ~0.004 = random) ===')
const results = []
for (const p of [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 0x20, 0x40, 0x800, 0x1000, 0x4000]) {
  let same = 0, n = 0
  for (let i = 0; i + p < LEN; i += 7) { n++; if (data[i] === data[i + p]) same++ }
  const r = same / n
  results.push({ p, r })
}
for (const { p, r } of results) console.log(`  period 0x${p.toString(16).padStart(5)}: ${r.toFixed(4)}${r > 0.02 ? '   <== STRUCTURED' : ''}`)

// 2) chi-square vs uniform (block cipher / already-encrypted => uniform)
const hist = new Uint32Array(256)
for (let i = 0; i < LEN; i++) hist[data[i]]++
const exp = LEN / 256
let chi = 0
for (let i = 0; i < 256; i++) chi += (hist[i] - exp) ** 2 / exp
console.log(`\nchi-square = ${chi.toFixed(1)} (df=255; uniform ~255, encrypted data ~255)`)

// 3) try XOR against every 32-byte window of the 512-byte header key area (full-file offsets),
//    and score by "does the result look like VP9 (low entropy / high zero ratio)".
console.log('\n=== exhaustively XOR the region against each 32B window of the 0x40..0x240 key area ===')
const best = []
for (let base = 0x40; base + 32 <= 0x240; base++) {
  let zeros = 0, sum = 0
  const hist2 = new Uint32Array(256)
  for (let i = 0; i < 0x4000; i++) {
    const v = data[i] ^ buf[base + (i % 32)]
    if (v === 0) zeros++
    hist2[v]++
  }
  let H = 0
  for (let i = 0; i < 256; i++) if (hist2[i]) { const p = hist2[i] / 0x4000; H -= p * Math.log2(p) }
  best.push({ base, zeros, H })
}
best.sort((a, b) => a.H - b.H)
for (const b of best.slice(0, 8)) console.log(`  key@0x${b.base.toString(16)}: entropy=${b.H.toFixed(2)} zeros=${b.zeros}`)
console.log(`  (random baseline entropy ~7.95, zeros ~64)`)

// 4) write a raw probe file so ffmpeg can try to sniff it as VP9/whatever
writeFileSync(process.argv[4] ?? 'probe-raw.bin', data)
console.log(`\nwrote raw probe (${LEN} bytes)`)
