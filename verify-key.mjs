// Verify the USM rolling-key decryption against known plaintext.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])

// key material: two consecutive 32B slots starting at 0x40 (verified: 0x40/0x60 == keystream
// found by XORing the encrypted utf16 path against the plaintext utf16 path at 0x1040)
function keyRel(base, chunkIdx) {
  const s0 = (base + chunkIdx) % 16
  const s1 = (base + chunkIdx + 1) % 16
  const k = Buffer.alloc(64)
  buf.copy(k, 0, 0x40 + s0 * 32, 0x40 + s0 * 32 + 32)
  buf.copy(k, 32, 0x40 + s1 * 32, 0x40 + s1 * 32 + 32)
  return k
}

function decryptChunkAt(off, base, chunkIdx, len) {
  const k = keyRel(base, chunkIdx)
  const rel = chunkIdx * 0x20
  const out = Buffer.alloc(len)
  for (let i = 0; i < len; i++) {
    k[rel + (i % 32)] ^= buf[off + i]
    out[i] = k[32 + (i % 32)]
  }
  return out
}

// slot-2..3 material directly
const k2 = Buffer.concat([buf.subarray(0x80, 0xa0), buf.subarray(0xa0, 0xc0)])
console.log('slot2:', k2.subarray(0, 32).toString('hex'))
console.log('slot3:', k2.subarray(32).toString('hex'))

for (const [off, idx, label] of [[0x1020, 0, 'header chunk @0x1020'], [0x1420, 2, 'chunk @0x1420']]) {
  const out = decryptChunkAt(off, 2, idx, 0x60)
  console.log(`\n--- ${label} (base=2, idx=${idx}) ---`)
  console.log('hex:', out.toString('hex'))
  console.log('asc:', JSON.stringify(out.toString('latin1')))
  const u16 = out.toString('utf16le').replace(/\0/g, '')
  console.log('u16:', JSON.stringify(u16))
}
