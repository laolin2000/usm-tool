// Reconstruct the IVF file: 32B IVF header (from 0xEE0) + IVF frame records.
// IVF frame record = {uint32 LE size, uint64 LE timestamp, payload}.
// Goal: walk the region and see whether frame records parse; report where it breaks.
import { readFileSync, writeFileSync } from 'node:fs'

const src = process.argv[2]
const buf = readFileSync(src)

const IVF_HDR = buf.subarray(0xEE0, 0xEE0 + 32)
const W = IVF_HDR.readUInt16LE(12), H = IVF_HDR.readUInt16LE(14)
const N = IVF_HDR.readUInt32LE(24), NUM = IVF_HDR.readUInt32LE(16), DEN = IVF_HDR.readUInt32LE(20)
console.log(`IVF: ${W}x${H} fourcc=${IVF_HDR.toString('latin1', 8, 12)} frames=${N} rate=${NUM}/${DEN} (${(NUM / DEN).toFixed(3)} fps, ${(N / (NUM / DEN)).toFixed(1)}s)`)
const expectedBytes = buf.length - 0x1000
console.log(`payload available 0x1000..end = ${expectedBytes} bytes; avg/frame = ${(expectedBytes / N).toFixed(0)}`)

// ---- Try to walk IVF records from several candidate starts ----
function tryWalk(start, endian) {
  let o = start, n = 0, ok = 0
  const sizes = []
  while (o + 12 <= buf.length && n < N + 10) {
    const size = endian === 'LE' ? buf.readUInt32LE(o) : buf.readUInt32BE(o)
    if (size === 0 || size > 4_000_000) break
    sizes.push(size)
    o += 12 + size
    n++; ok++
    if (n > 5000) break
  }
  return { start, endian, n, endOff: o, sizes }
}
const starts = [0x1000, 0x1020, 0x1960, 0x19640, 0xEE0 + 32]
console.log('\n=== IVF record walk attempts ===')
for (const s of starts) {
  for (const e of ['LE']) {
    const r = tryWalk(s, e)
    console.log(`  start=0x${s.toString(16)} ${e}: frames=${r.n} end=0x${r.endOff.toString(16)} firstSizes=[${r.sizes.slice(0, 8).join(',')}]`)
  }
}

// ---- Inspect the plausible frame-boundary structure: the @SFV chunks with stride 0x800
//      in 0x1000..0x1960 look like 4412-frame index entries? count them ----
console.log('\n=== ASCII-marker census over whole file ===')
const markers = {}
const tags = ['@SFV', '@SFA', 'DKIF', 'VP90', 'FRM ', 'IDX ', 'HCA', '#HEADER END', '#METADATA END', 'CRIUSF']
for (const t of tags) {
  const b = Buffer.from(t, 'latin1'); let i = buf.indexOf(b), c = 0, first = -1
  while (i !== -1) { if (first < 0) first = i; c++; i = buf.indexOf(b, i + 1) }
  markers[t] = { c, first }
  console.log(`  ${t.padEnd(14)} count=${String(c).padStart(6)} first=0x${first.toString(16)}`)
}

// ---- Dump a well-formed @SFV chunk to fully understand the frame record layout ----
console.log('\n=== full dump of the @SFV chunk at 0xC2E0 (plaintext, 0x800 block) ===')
for (let o = 0xC2E0; o < 0xC2E0 + 0x100; o += 32) {
  const row = []; for (let j = 0; j < 32; j++) row.push(buf[o + j].toString(16).padStart(2, '0'))
  console.log(`0x${o.toString(16)}: ${row.join(' ')}  |${buf.toString('latin1', o, o + 32).replace(/[^\x20-\x7e]/g, '.')}|`)
}

// ---- Hypothesis test: is the video payload XOR'd with a key derived from the @SFV index
//      header at the start of each 0x800 block? Derive the mask from a plaintext block. ----
console.log('\n=== mask derivation from a *plaintext* @SFV block (0xC2E0) vs neighbours ===')
{
  // take the plaintext header bytes at 0xC2E0 and the (assumed encrypted) next block at 0xC300
  const a = buf.subarray(0xC2E0, 0xC2E0 + 32)
  const b = buf.subarray(0xC300, 0xC300 + 32)
  const m = Buffer.alloc(32); for (let i = 0; i < 32; i++) m[i] = a[i] ^ b[i]
  console.log('  xor:', m.toString('hex'))
}
