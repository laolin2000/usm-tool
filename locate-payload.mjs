// Locate the true encrypted payload region by scanning for long zero runs and
// entropy transitions (blocked, 0x40 granularity).
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const size = buf.length

// 1) long zero runs
console.log('=== zero runs >= 0x100 bytes (first 40) ===')
let run = 0, runStart = 0, shown = 0
for (let i = 0; i < size; i++) {
  if (buf[i] === 0) { if (run === 0) runStart = i; run++ }
  else { if (run >= 0x100) { console.log(`  0x${runStart.toString(16)} .. 0x${(i - 1).toString(16)}  len=${run} (0x${run.toString(16)})`); if (++shown >= 40) break } run = 0 }
}
if (run >= 0x100) console.log(`  0x${runStart.toString(16)} .. EOF len=${run}`)

// 2) entropy of 0x1000 blocks in the first 0x20000 bytes (fine view of the head)
function entropyAt(o, n) {
  const hist = new Uint32Array(256)
  for (let i = 0; i < n; i++) hist[buf[o + i]]++
  let H = 0
  for (let i = 0; i < 256; i++) if (hist[i]) { const p = hist[i] / n; H -= p * Math.log2(p) }
  return H
}
console.log('\n=== fine entropy 0x1000..0x20000 (0x200 blocks, 256B) ===')
let line = []
for (let o = 0x1000; o < 0x20000; o += 0x200) {
  const H = entropyAt(o, 0x200)
  line.push(`0x${o.toString(16)}:${H.toFixed(1)}`)
  if (line.length === 8) { console.log('  ' + line.join('  ')); line = [] }
}
if (line.length) console.log('  ' + line.join('  '))

// 3) find the encrypted region start/end via rolling entropy in 0x10000 blocks
console.log('\n=== coarse scan 0x0..0x200000 (64KB blocks) ===')
line = []
for (let o = 0; o < 0x200000 && o < size; o += 0x10000) {
  const n = Math.min(0x10000, size - o)
  let zeros = 0
  for (let i = 0; i < n; i++) if (buf[o + i] === 0) zeros++
  line.push(`0x${o.toString(16)}:H=${entropyAt(o, n).toFixed(2)}/z=${(zeros / n * 100).toFixed(0)}%`)
  if (line.length === 3) { console.log('  ' + line.join('   ')); line = [] }
}
if (line.length) console.log('  ' + line.join('   '))

// 4) dump around 0x1900..0x1A00 to see the header->payload transition
console.log('\n=== 0x1900..0x1A40 raw ===')
for (let o = 0x1900; o < 0x1A40; o += 32) {
  const row = []
  for (let j = 0; j < 32; j++) row.push(buf[o + j].toString(16).padStart(2, '0'))
  console.log(`0x${o.toString(16)}: ${row.join(' ')}  |${buf.toString('latin1', o, o + 32).replace(/[^\x20-\x7e]/g, '.')}|`)
}
