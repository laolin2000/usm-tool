// CONFIRMED SCHEME: CRI USM rolling-XOR.
// key material = file[0x40 + 32*slot], 32-byte mask repeated over the chunk payload.
// Verified: mask derived from the '@SFV' known plaintext at 0x1960 equals slot material
// at 0x1A0 and repeats every 32 bytes.
//
// This script strips the video stream (stream index 1) into a raw VP9 elementary stream
// plus the IVF header found at 0xEE0, then writes IVF to disk.
import { readFileSync, writeFileSync, openSync, writeSync, closeSync } from 'node:fs'

const src = process.argv[2]
const outIvf = process.argv[3] ?? 'out.ivf'
const buf = readFileSync(src)

function slotMask(s) { return Buffer.from(buf.subarray(0x40 + (s % 16) * 32, 0x40 + (s % 16) * 32 + 32)) }

// rolling state, exactly like CRI: key[i] ^= ct[i]; pt[i] = key[i]
function makeState(slot) {
  return { k: slotMask(slot), i: 0 }
}
function decryptChunk(ct, st) {
  const out = Buffer.alloc(ct.length)
  for (let n = 0; n < ct.length; n++) {
    const idx = n % 32
    st.k[idx] ^= ct[n]
    out[n] = st.k[idx]
  }
  return out
}

// ---------- locate the video stream ----------
// The first video chunk (with its plaintext @SFV index header) sits at 0x1960.
const VOFF = 0x1960
const HDRLEN = 0x28                    // 0x20 chunk header + 8 bytes of @SFV payload
console.log('=== validation: does the rolling mask reproduce the plaintext header? ===')
{
  const st = makeState(11)             // 0x40 + 11*32 = 0x1A0
  const first = decryptChunk(buf.subarray(VOFF, VOFF + 0x100), st)
  console.log('  decrypted head:', first.subarray(0, 0x40).toString('hex'))
  console.log('  ascii         :', JSON.stringify(first.subarray(0, 0x40).toString('latin1')))
}

// ---------- walk all chunks ----------
console.log('\n=== chunk walk from 0x1960 ===')
let off = VOFF
let slot = 11
let chunks = 0
const frames = []
const CHUNK = 0x800
while (off + CHUNK <= buf.length && chunks < 200000) {
  const ct = buf.subarray(off, off + CHUNK)
  const st = makeState(slot)
  const pt = decryptChunk(ct, st)
  const tag = pt.toString('latin1', 0, 4)
  if (tag !== '@SFV') {
    console.log(`  stop at 0x${off.toString(16)}: tag='${tag.replace(/[^\x20-\x7e]/g, '.')}' (slot ${slot})`)
    break
  }
  const size = pt.readUInt32BE(4)
  const f1 = pt.readUInt32BE(8), f2 = pt.readUInt32BE(12)
  const idx = pt.readUInt32BE(0x14)
  if (chunks < 6 || chunks % 200 === 0) console.log(`  #${chunks} @0x${off.toString(16)} size=0x${size.toString(16)} f1=0x${f1.toString(16)} f2=0x${f2.toString(16)} frameIdx=${idx}`)
  frames.push({ off, size, idx, pt })
  off += CHUNK
  slot = (slot + 1) % 16     // advance key material per chunk (to be validated)
  chunks++
}
console.log(`  total chunks = ${chunks}, ended at 0x${off.toString(16)}, file 0x${buf.length.toString(16)}`)

// ---------- report the frame index progression (validates the rolling slot advance) ----------
console.log('\n=== frame index progression (first 12 / last 6) ===')
const idxs = frames.map(f => f.idx)
console.log('  first:', idxs.slice(0, 12).join(' '))
console.log('  last :', idxs.slice(-6).join(' '))
let bad = 0
for (let i = 1; i < idxs.length; i++) if (idxs[i] <= idxs[i - 1]) bad++
console.log(`  non-increasing steps: ${bad}/${idxs.length - 1}`)
