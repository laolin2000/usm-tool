// Decisive test: find the rolling-key variant that (a) reproduces the plaintext
// header table at 0x800 exactly and (b) yields a findable 'DKIF' VP9 frame header.
//
// Encrypted region starts right after the plain header chunk at 0x1000.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const PLAIN = buf.subarray(0x800, 0x800 + 0x228)
const ENC_OFF = 0x1020          // first chunk header inside the encrypted stream
const RANGE = 0x800 + 0x2000    // decrypt this much for the DKIF search

function slot(s) { return Buffer.from(buf.subarray(0x40 + (s % 16) * 32, 0x40 + (s % 16) * 32 + 32)) }

// Rolling decrypt across a whole region, with configurable global chunk counter start.
// enc region is inside the file starting at ENC_OFF; chunk n covers [ENC_OFF + n*0x800, ...)
function decryptRegion({ startSlot, chunkLen, counterStart, limit = RANGE, encStart = ENC_OFF }) {
  const out = Buffer.alloc(limit)
  const total = Math.floor((limit + chunkLen - 1) / chunkLen)
  let counter = counterStart
  for (let c = 0; c < total; c++) {
    const base = c * chunkLen
    let slotIdx = startSlot + counter   // key material position advances per stored chunk
    const k = slot(slotIdx)
    for (let i = 0; i < chunkLen && base + i < limit; i++) {
      const src = buf[encStart + base + i]
      if (src === undefined) break
      const idx = i % 32
      k[idx] ^= src
      out[base + i] = k[32 - 32 + idx]  // out = k (post-xor)
    }
    counter += 2
  }
  return out
}

function matchesPlainText(out) {
  // out[0..] corresponds to the region at ENC_OFF; compare against the known table
  // by searching for the table signature anywhere in out
  const sig = Buffer.from('VIDEO_HDRINFO', 'latin1')
  const at = out.indexOf(sig)
  return at
}

const results = []
for (let s = 0; s < 16; s++) {
  for (const chunkLen of [0x800, 0x2000, 0x400]) {
    for (const counterStart of [0, 1, 2, -2]) {
      const out = decryptRegion({ startSlot: s, chunkLen, counterStart })
      const dkif = out.indexOf(Buffer.from('DKIF', 'latin1'))
      const vp90 = out.indexOf(Buffer.from('VP90', 'latin1'))
      const hdrinfo = out.indexOf(Buffer.from('VIDEO_HDRINFO', 'latin1'))
      const criusf = out.indexOf(Buffer.from('CRIUSF', 'latin1'))
      if (dkif !== -1 || vp90 !== -1 || hdrinfo !== -1) {
        results.push({ s, chunkLen, counterStart, dkif, vp90, hdrinfo, criusf })
      }
    }
  }
}

console.log('hits:')
for (const r of results) console.log(`  startSlot=${String(r.s).padStart(2)} chunkLen=0x${r.chunkLen.toString(16)} counterStart=${r.counterStart}  DKIF@${r.dkif} VP90@${r.vp90} VIDEO_HDRINFO@${r.hdrinfo} CRIUSF@${r.criusf}`)
if (!results.length) {
  console.log('  (none)')
  // dump raw entropy structure for manual analysis
  console.log('\n--- raw encrypted bytes at 0x1000..0x1120 ---')
  for (let o = 0x1000; o < 0x1120; o += 16) {
    const row = []
    for (let j = 0; j < 16; j++) row.push(buf[o + j].toString(16).padStart(2, '0'))
    console.log(`0x${o.toString(16)}: ${row.join(' ')}`)
  }
}
