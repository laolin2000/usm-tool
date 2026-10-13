// Brute-force the USM chunk-key derivation using known plaintext.
// Known plaintext: the header stream for "001960.ivf" contains the literal
// ASCII path "\\netapp\maimai2\Design\user\uchibori\movie\v1.65\001960 TAKE CONTROL\001960.ivf"
// Encrypted copy of that string lives later in the header.
import { readFileSync } from 'node:fs'

const path = process.argv[2]
const buf = readFileSync(path)
const HDR = buf.subarray(0, 0x1000)

const KEY_SLOTS = 16, KEY_LEN = 32
const slots = []
for (let s = 0; s < KEY_SLOTS; s++) slots.push(Buffer.from(HDR.subarray(0x40 + s * KEY_LEN, 0x40 + (s + 1) * KEY_LEN)))

// --- 1. locate known plaintext occurrences in the plaintext header ---
const needle = Buffer.from('001960.ivf', 'latin1')
const u16 = Buffer.from('0\x000\x000\x001\x009\x006\x000\x00.\x00i\x00v\x00f\x00', 'latin1')
const hits = []
let i = buf.indexOf(needle, 0)
while (i !== -1 && i < 0x2000) { hits.push(i); i = buf.indexOf(needle, i + 1) }
console.log('plaintext "001960.ivf" (latin1) at:', hits.map(h => '0x' + h.toString(16)).join(', ') || 'none')
console.log('plaintext "001960.ivf" (utf16)  :', buf.indexOf(u16) === -1 ? 'none' : '0x' + buf.indexOf(u16).toString(16))

const fullNeedle = Buffer.from('\\\\netapp\\maimai2\\Design\\user\\uchibori\\movie\\v1.65\\001960 TAKE CONTROL\\001960.ivf', 'latin1')
const fullHits = []
i = buf.indexOf(fullNeedle, 0)
while (i !== -1 && i < 0x4000) { fullHits.push(i); i = buf.indexOf(fullNeedle, i + 1) }
console.log(`full path (${fullNeedle.length}B) at:`, fullHits.map(h => '0x' + h.toString(16)).join(', ') || 'none')

if (!fullHits.length) { console.error('no known plaintext found; abort'); process.exit(3) }

// --- 2. look for the encrypted counterpart: same-length high-entropy region in the header ---
// The encrypted header chunk contains the same table structure; search for a run whose
// XOR against the plaintext gives a repeating 32-byte key.
function candidateEncryptedOffsets(plainOff, plain) {
  const res = []
  for (let off = 0; off + plain.length <= 0x4000; off++) {
    if (off === plainOff) continue
    // quick entropy filter: encrypted data must differ a lot from plaintext
    let diff = 0
    for (let k = 0; k < plain.length; k++) if (buf[off + k] !== plain[k]) diff++
    if (diff < plain.length * 0.9) continue
    res.push(off)
  }
  return res
}

const cands = candidateEncryptedOffsets(fullHits[0], fullNeedle)
console.log(`\ncandidate encrypted offsets for the path string: ${cands.length}`)

for (const off of cands.slice(0, 40)) {
  // derive keystream, check periodicity of 32 (or 0x20 alignment)
  const ks = Buffer.alloc(fullNeedle.length)
  for (let k = 0; k < fullNeedle.length; k++) ks[k] = buf[off + k] ^ fullNeedle[k]
  let per32 = true, per64 = true
  for (let k = 32; k < ks.length; k++) if (ks[k] !== ks[k % 32]) { per32 = false; break }
  for (let k = 64; k < ks.length; k++) if (ks[k] !== ks[k % 64]) { per64 = false; break }
  if (per32 || per64) {
    console.log(`*** offset 0x${off.toString(16)} keystream period=${per32 ? 32 : 64}`)
    console.log(`    ks[0..31] = ${ks.subarray(0, 32).toString('hex')}`)
    for (let s = 0; s < 16; s++) {
      if (slots[s].equals(ks.subarray(0, 32))) console.log(`    == key slot ${s} (base 0x${(0x40 + s * 32).toString(16)})`)
    }
  }
}

// --- 3. Also test: XOR of consecutive 32B windows in the source region (delta encoding)
// (some CRI containers delta-encrypt: key[i] ^= prev)
