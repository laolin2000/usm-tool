// Verify the key-slot mapping with exact 64-byte rolling key material.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])

const enc = buf.subarray(0x1960, 0x1990)
console.log('ciphertext@0x1960:', enc.toString('hex'))
console.log('slot10 @0x180   :', buf.subarray(0x180, 0x1a0).toString('hex'))
console.log('slot11 @0x1a0   :', buf.subarray(0x1a0, 0x1c0).toString('hex'))
console.log('slot12 @0x1c0   :', buf.subarray(0x1c0, 0x1e0).toString('hex'))
console.log('slot13 @0x1e0   :', buf.subarray(0x1e0, 0x200).toString('hex'))

const TARGET = Buffer.from('@SFV')
console.log('\nXOR of ciphertext with each 32B slot; looking for "@SFV":')
for (let s = 0; s < 16; s++) {
  const slot = buf.subarray(0x40 + s * 32, 0x40 + s * 32 + 32)
  const x = Buffer.alloc(32)
  for (let i = 0; i < 32; i++) x[i] = enc[i] ^ slot[i]
  const tag = x.toString('latin1', 0, 4)
  console.log(`  slot${String(s).padStart(2)} @0x${(0x40 + s * 32).toString(16)}: ${x.toString('hex')} '${tag.replace(/[^\x20-\x7e]/g, '.')}'${tag === '@SFV' ? '   <== MATCH' : ''}`)
}

// Also try: key material located right after the stream directory (various bases)
console.log('\nXOR with 32B windows at other candidate bases:')
for (const base of [0x1a0, 0x1c0, 0x1e0, 0x200, 0x220, 0x80, 0xa0, 0xc0]) {
  const slot = buf.subarray(base, base + 32)
  const x = Buffer.alloc(32)
  for (let i = 0; i < 32; i++) x[i] = enc[i] ^ slot[i]
  const tag = x.toString('latin1', 0, 4)
  console.log(`  base 0x${base.toString(16)}: '${tag.replace(/[^\x20-\x7e]/g, '.')}'  ${x.toString('hex', 0, 8)}`)
}
