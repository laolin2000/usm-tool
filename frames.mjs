// Reconstruct an IVF container from the USM video stream and test several payload
// offsets. IVF layout: 32B file header + per-frame {4B size LE, 8B timestamp LE, data}
// + optional 12B 'frame count' footer.
//
// The container gives us:
//   - IVF/VP9 file header template at 0xEE0 (DKIF..VP90), width=0x438=1080? see below
//   - frame-group index table (offset, size, frameCount) at 0x848..0x8A8
//   - total frames = 2397, framerate = 30000/1001
import { readFileSync, writeFileSync } from 'node:fs'

const src = process.argv[2]
const buf = readFileSync(src)

// ---- parse the frame-group index table (7 entries, 20 bytes each) ----
console.log('=== frame-group index table ===')
const groups = []
for (let i = 0; i < 7; i++) {
  const o = 0x848 + i * 0x14
  const a = buf.readUInt32BE(o), b = buf.readUInt32BE(o + 4), c = buf.readUInt32BE(o + 8), d = buf.readUInt32BE(o + 12), e = buf.readUInt32BE(o + 16)
  console.log(`  #${i}: ${a} 0x${(a * 0x20).toString(16)} | ${b} | ${c} | 0x${c.toString(16)} frames=${e} | ${d}`)
  groups.push({ raw: a, off: a * 0x20, size: c, frames: e })
}

// ---- interpret the IVF header at 0xEE0 ----
const ivf = buf.subarray(0xEE0, 0xEE0 + 32)
console.log('\n=== IVF header template @0xEE0 ===')
console.log('  magic      :', ivf.toString('latin1', 0, 4))
console.log('  version    :', ivf.readUInt16LE(4))
console.log('  headerSize :', ivf.readUInt16LE(6))
console.log('  fourcc     :', ivf.toString('latin1', 8, 12))
console.log('  width      :', ivf.readUInt16LE(12))
console.log('  height     :', ivf.readUInt16LE(14))
console.log('  framerateN :', ivf.readUInt32LE(16))
console.log('  framerateD :', ivf.readUInt32LE(20))
console.log('  frameCount :', ivf.readUInt32LE(24))
console.log('  unused     :', ivf.readUInt32LE(28))

// ---- extract every 4-byte little-endian size field in the header region that could be
//      a frame size, and see if they sum to the payload span ----
console.log('\n=== candidate per-frame size table? scan 0x1290..0x1900 for 4B ascending records ===')
let recs = 0
for (let o = 0x1290; o < 0x1900; o += 4) {
  const v = buf.readUInt32LE(o)
  if (v > 0 && v < 0x100000) recs++
}
console.log(`  plausible small 4B values: ${recs}`)

// ---- hypothesis: the frame data is the per-frame-interleaved layout where each frame is
//      prefixed by a 4B size. Verify by checking that walking the region lands exactly on
//      0x1960 or other known boundaries. ----
function walk(start, end, label) {
  let o = start, n = 0, sum = 0
  const sizes = []
  while (o + 4 <= end && n < 100000) {
    const s = buf.readUInt32LE(o)
    if (s === 0 || s > 0x200000 || o + 4 + s > buf.length) break
    sizes.push(s); sum += s; n++; o += 4 + s
  }
  console.log(`  ${label}: start=0x${start.toString(16)} frames=${n} consumed=${sum} nextOff=0x${o.toString(16)} (target 0x${end.toString(16)})`)
  if (sizes.length) console.log(`    first sizes: ${sizes.slice(0, 10).join(' ')}  last: ${sizes.slice(-5).join(' ')}`)
}
console.log('\n=== per-frame size-prefix walks (LE and BE) ===')
walk(0x1960, 0x19640, 'LE 0x1960')
walk(0x19640, 0x1b800, 'LE 0x19640')
// BE variant
{
  let o = 0x19640, n = 0
  const sizes = []
  while (o + 4 <= buf.length && n < 100000) {
    const s = buf.readUInt32BE(o)
    if (s === 0 || s > 0x200000) break
    sizes.push(s); n++; o += 4 + s
  }
  console.log(`  BE 0x19640: frames=${n} nextOff=0x${o.toString(16)} first=${sizes.slice(0, 8).join(' ')}`)
}
