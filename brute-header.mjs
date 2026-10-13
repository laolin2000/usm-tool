// Brute-force decrypt the 0x20-byte chunk header at 0x1000 and validate by structure:
// plaintext must be '@SFV' + <sizes>. Also validate a larger window by looking for
// DHT/DQT/SOF markers if the payload turns out to be JPEG.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const KEY_MAT = buf.subarray(0x40, 0x40 + 512)   // 16 x 32B slots

function slotBytes(s) { const i = (s % 16) * 32; return Buffer.from(KEY_MAT.subarray(i, i + 32)) }

// --- A. single-chunk key test on the 0x20-byte header at 0x1000 ---
console.log('=== A. 32-byte chunk header at 0x1000 ===')
const hdrEnc = buf.subarray(0x1000, 0x1020)
console.log('enc:', hdrEnc.toString('hex'))
for (let s = 0; s < 16; s++) {
  const plain = Buffer.alloc(32)
  for (let i = 0; i < 32; i++) plain[i] = hdrEnc[i] ^ slotBytes(s)[i]
  const asc = plain.toString('latin1').replace(/[^\x20-\x7e]/g, '.')
  console.log(`  slot${String(s).padStart(2)}: ${plain.toString('hex')}  '${asc}'`)
}

// --- B. rolling decrypt and search for structural markers ---
console.log('\n=== B. rolling decrypt, marker search ===')
const START = 0x1000
const WINDOW = 0x10000

function rollingDecrypt(startSlot, chunkLen, counterStep) {
  const out = Buffer.alloc(WINDOW)
  let counter = 0
  for (let base = 0; base < WINDOW; base += chunkLen) {
    const k = slotBytes(startSlot + counter)
    for (let i = 0; i < chunkLen && base + i < WINDOW; i++) {
      const src = buf[START + base + i]
      if (src === undefined) break
      const idx = i % 32
      k[idx] ^= src
      out[base + i] = k[idx]
    }
    counter += counterStep
  }
  return out
}

const MARKERS = {
  'FFD8FF(SOI)': Buffer.from([0xff, 0xd8, 0xff]),
  'DHT(FFC4)': Buffer.from([0xff, 0xc4]),
  'DQT(FFDB)': Buffer.from([0xff, 0xdb]),
  'SOF0(FFC0)': Buffer.from([0xff, 0xc0]),
  'SFV': Buffer.from('@SFV', 'latin1'),
  'DKIF': Buffer.from('DKIF', 'latin1'),
  'CRIUSF': Buffer.from('CRIUSF', 'latin1'),
}
const found = []
for (let s = 0; s < 16; s++) {
  for (const chunkLen of [0x800, 0x20, 0x40]) {
    for (const step of [1, 2]) {
      const out = rollingDecrypt(s, chunkLen, step)
      const hits = {}
      let any = false
      for (const [name, m] of Object.entries(MARKERS)) {
        const at = out.indexOf(m)
        if (at !== -1) { hits[name] = at; any = true }
      }
      if (any) found.push({ s, chunkLen, step, hits })
    }
  }
}
if (found.length) {
  for (const f of found) console.log(`  slot=${f.s} chunkLen=0x${f.chunkLen.toString(16)} step=${f.step}  ${JSON.stringify(f.hits)}`)
} else {
  console.log('  no marker hits')
}

// --- C. dump the raw 0x1000..0x1100 region for manual eyeballing ---
console.log('\n=== C. raw bytes 0x1000..0x1200 ===')
for (let o = 0x1000; o < 0x1200; o += 32) {
  const row = []
  for (let j = 0; j < 32; j++) row.push(buf[o + j].toString(16).padStart(2, '0'))
  console.log(`0x${o.toString(16)}: ${row.join(' ')}  |${buf.toString('latin1', o, o + 32).replace(/[^\x20-\x7e]/g, '.')}|`)
}
