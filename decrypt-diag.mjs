// Decisive diagnostic: apply CRI's exact chunk decryption to the encrypted region and
// report (a) whether the keystream equals known key material, (b) whether plaintext
// structure (VP9/IVF) appears.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const KEYB = buf.subarray(0x40, 0x40 + 512)   // full key material area
const keyA = Buffer.from(KEYB.subarray(0, 32))

function decryptInPlace(data, keyState, index, keyLen = 32) {
  // exact CRI/vgmstream style: key[i] ^= src[i]; out[i] = key[i]
  for (let i = 0; i < data.length; i++) {
    const ki = i % keyLen
    keyState[(index % 2) * keyLen + ki] ^= data[i]
    data[i] = keyState[(index % 2) * keyLen + ki]
  }
}

// --- A. first 0x40 bytes of the payload at 0x1960, both 32B and 64B variants ---
console.log('=== A. payload head 0x1960, test signatures ===')
for (const keyLen of [32, 64]) {
  for (const slotOfs of [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352]) {
    const ks = Buffer.concat([KEYB.subarray(slotOfs, slotOfs + keyLen), Buffer.alloc(keyLen)])
    const d = Buffer.from(buf.subarray(0x1960, 0x1960 + 0x60))
    decryptInPlace(d, ks, 1, keyLen)
    const hex = d.toString('hex')
    if (d.includes(Buffer.from('DKIF')) || d.includes(Buffer.from('SFV')) || d.includes(Buffer.from('IVF'))) {
      console.log(`  *** keyLen=${keyLen} keyOfs=0x${slotOfs.toString(16)} -> ${hex}`)
    }
  }
}

// --- B. compare decrypted output against key material (detect "plaintext == key" pathology) ---
console.log('\n=== B. decrypted 0x1960 (32B slots, key from slot 11) ===')
for (const k of [10, 11, 12, 13, 14, 15]) {
  const ks = Buffer.concat([KEYB.subarray(k * 32, k * 32 + 32), Buffer.alloc(32)])
  const d = Buffer.from(buf.subarray(0x1960, 0x1980))
  decryptInPlace(d, ks, 1, 32)
  console.log(`  slot${k}: ${d.toString('hex')}  |${d.toString('latin1').replace(/[^\x20-\x7e]/g, '.')}|`)
}

// --- C. what is the raw ciphertext? show first 64 bytes and check repeating patterns ---
console.log('\n=== C. raw payload head 0x1960..0x1A00 ===')
for (let o = 0x1960; o < 0x1A00; o += 32) {
  const row = []
  for (let j = 0; j < 32; j++) row.push(buf[o + j].toString(16).padStart(2, '0'))
  console.log(`0x${o.toString(16)}: ${row.join(' ')}`)
}

// --- D. is the payload XOR of two shifted copies of the key material? ---
console.log('\n=== D. payload head XOR key-material windows (all 1024 offsets) — lowest popcount ===')
const target = buf.subarray(0x1960, 0x1960 + 0x20)
const scored = []
for (let off = 0; off + 32 <= 512; off++) {
  let same = 0
  for (let i = 0; i < 32; i++) if ((target[i] ^ KEYB[off + i]) === 0) same++
  scored.push({ off, same })
}
scored.sort((a, b) => b.same - a.same)
console.log('  top matches (same-byte count of 32):', scored.slice(0, 5).map(s => `0x${s.off.toString(16)}:${s.same}`).join(' '))

// --- E. check whether payload head equals the XOR of the key material and the plaintext table at 0x800 ---
console.log('\n=== E. payload ^ plaintext-table 0x800 (first 32B) ===')
const pt = buf.subarray(0x800, 0x820)
const x = Buffer.alloc(32)
for (let i = 0; i < 32; i++) x[i] = target[i] ^ pt[i]
console.log('  xor:', x.toString('hex'))
// does that xor equal any key slot?
for (let s = 0; s < 16; s++) {
  if (KEYB.subarray(s * 32, s * 32 + 32).equals(x)) console.log(`  == slot ${s}`)
}
