// Parse ALL 4418 '@SFV' records across the file and analyse the layout:
// offsets, declared sizes, frame indices. Determine where the real VP9 payload lives.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const recs = []
{
  const tag = Buffer.from('@SFV', 'latin1')
  let i = buf.indexOf(tag)
  while (i !== -1) {
    if (i + 0x28 <= buf.length) {
      recs.push({
        off: i,
        size: buf.readUInt32BE(i + 4),
        a: buf.readUInt32BE(i + 8),
        b: buf.readUInt32BE(i + 12),
        c: buf.readUInt32BE(i + 16),
        d: buf.readUInt32BE(i + 20),
        e: buf.readUInt32BE(i + 24),
      })
    }
    i = buf.indexOf(tag, i + 1)
  }
}
console.log(`parsed ${recs.length} records`)

// group by the field at +4 (declared size) to see distinct record types
const byD = {}
for (const r of recs) byD[r.d] = (byD[r.d] || 0) + 1
console.log('\n=== distinct field@+16 (looks like a frame index) — count / range ===')
const idxVals = [...new Set(recs.map(r => r.d))].sort((a, b) => a - b)
console.log(`  distinct=${idxVals.length} min=${idxVals[0]} max=${idxVals[idxVals.length - 1]}`)
console.log(`  first 20: ${idxVals.slice(0, 20).join(' ')}`)
console.log(`  last 10 : ${idxVals.slice(-10).join(' ')}`)
let mono = 0, bad = 0
for (let i = 1; i < recs.length; i++) (recs[i].d > recs[i - 1].d ? mono++ : bad++)
console.log(`  monotonic increasing steps: ${mono}/${recs.length - 1} (non-increasing ${bad})`)

// do the declared sizes sum to something meaningful?
const sizeHist = {}
for (const r of recs) sizeHist[r.size] = (sizeHist[r.size] || 0) + 1
const topSizes = Object.entries(sizeHist).sort((a, b) => b[1] - a[1]).slice(0, 15)
console.log('\n=== field@+4 (declared size) histogram, top 15 ===')
for (const [s, c] of topSizes) console.log(`  size=0x${(+s).toString(16).padStart(8)} (${s}) x${c}`)
const totalSize = recs.reduce((a, r) => a + r.size, 0)
console.log(`  SUM of all declared sizes = ${totalSize} (0x${totalSize.toString(16)})  file=0x${buf.length.toString(16)}`)

// offsets stride analysis
console.log('\n=== offset stride histogram (top 12) ===')
const sh = {}
for (let i = 1; i < recs.length; i++) { const s = recs[i].off - recs[i - 1].off; sh[s] = (sh[s] || 0) + 1 }
for (const [s, c] of Object.entries(sh).sort((a, b) => b[1] - a[1]).slice(0, 12)) console.log(`  0x${(+s).toString(16)} x${c}`)

// print the first 40 records fully
console.log('\n=== first 40 records ===')
for (const r of recs.slice(0, 40)) {
  console.log(`  0x${r.off.toString(16).padStart(7)} size=0x${r.size.toString(16).padStart(6)} a=0x${r.a.toString(16)} b=0x${r.b.toString(16)} frameIdx=0x${r.d.toString(16)}(${r.d}) e=0x${r.e.toString(16)}`)
}
console.log('\n=== records 1000..1040 ===')
for (const r of recs.slice(1000, 1040)) {
  console.log(`  0x${r.off.toString(16).padStart(7)} size=0x${r.size.toString(16).padStart(6)} a=0x${r.a.toString(16)} b=0x${r.b.toString(16)} frameIdx=0x${r.d.toString(16)}(${r.d}) e=0x${r.e.toString(16)}`)
}
console.log('\n=== last 12 records ===')
for (const r of recs.slice(-12)) {
  console.log(`  0x${r.off.toString(16).padStart(7)} size=0x${r.size.toString(16).padStart(6)} a=0x${r.a.toString(16)} b=0x${r.b.toString(16)} frameIdx=0x${r.d.toString(16)}(${r.d}) e=0x${r.e.toString(16)}`)
}
