// Systematic brute force over CRI USM decryption variants.
// Success criterion: decrypted chunk at 0x1960 starts with '@SFV' AND the sequence of
// decrypted chunks yields strictly increasing frame indices.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const VOFF = 0x1960
const CHUNK = 0x800

// --- ground truth: the plaintext @SFV header at 0x800 (known-good plaintext) ---
console.log('plaintext @SFV header at 0x800:')
console.log(' ', buf.subarray(0x800, 0x828).toString('hex'))
console.log('cipher region head at 0x1960:')
console.log(' ', buf.subarray(VOFF, VOFF + 0x28).toString('hex'))
console.log(' xor of the two (candidate 32B mask if 0x1960 were also an @SFV header):')
{
  const m = Buffer.alloc(32)
  for (let i = 0; i < 32; i++) m[i] = buf[VOFF + i] ^ buf[0x800 + i]
  console.log(' ', m.toString('hex'))
  console.log('  period32 self-consistency:', m.subarray(0, 16).equals(m.subarray(16, 32)) ? 'YES' : 'NO')
  // where does this mask appear in the file?
  const at = buf.indexOf(m)
  console.log('  mask found in file at:', at === -1 ? 'nowhere' : '0x' + at.toString(16))
  // is it derivable as XOR of two key slots?
  for (let a = 0; a < 16; a++) for (let b = 0; b < 16; b++) {
    const x = Buffer.alloc(32)
    for (let i = 0; i < 32; i++) x[i] = buf[0x40 + a * 32 + i] ^ buf[0x40 + b * 32 + i]
    if (x.equals(m)) console.log(`  mask == slot${a} ^ slot${b}`)
  }
}

// --- variant sweep ---
function slots() { const out = []; for (let s = 0; s < 16; s++) out.push(Buffer.from(buf.subarray(0x40 + s * 32, 0x40 + s * 32 + 32))); return out }

const variants = []
// A: single 32B slot, no rolling
for (let s = 0; s < 16; s++) variants.push({ name: `xor-slot${s}`, fn: (ct, n) => { const k = slots()[s]; const o = Buffer.alloc(ct.length); for (let i = 0; i < ct.length; i++) o[i] = ct[i] ^ k[i % 32]; return o } })
// B: rolling 32B, key[i] ^= ct[i]; out = key[i]
for (let s = 0; s < 16; s++) variants.push({ name: `roll32-slot${s}`, fn: (ct) => { const k = slots()[s]; const o = Buffer.alloc(ct.length); for (let i = 0; i < ct.length; i++) { const j = i % 32; k[j] ^= ct[i]; o[i] = k[j] } return o } })
// C: rolling 64B (two slots)
for (let s = 0; s < 16; s++) variants.push({ name: `roll64-slot${s}`, fn: (ct) => { const k = Buffer.concat([slots()[s], slots()[(s + 1) % 16]]); const o = Buffer.alloc(ct.length); for (let i = 0; i < ct.length; i++) { const j = i % 64; k[j] ^= ct[i]; o[i] = k[j] } return o } })

let winners = []
for (const v of variants) {
  const pt = v.fn(buf.subarray(VOFF, VOFF + 0x800), 0)
  const tag = pt.toString('latin1', 0, 4)
  if (tag === '@SFV') winners.push({ v: v.name, idx: pt.readUInt32BE(0x14) })
  else if (pt.toString('latin1', 0, 8).includes('SFV')) winners.push({ v: v.name, partial: pt.toString('latin1', 0, 0x30).replace(/[^\x20-\x7e]/g, '.') })
}
console.log('\nvariants producing @SFV at 0x1960:', winners.length ? JSON.stringify(winners) : 'NONE')

// --- which slot, when XORed at 0x1960, gives the *max* printable ASCII? ---
console.log('\n=== printable-ASCII score of single-slot XOR at 0x1960 ===')
const scored = []
for (let s = 0; s < 16; s++) {
  const k = slots()[s]
  let pr = 0
  for (let i = 0; i < 0x200; i++) { const c = buf[VOFF + i] ^ k[i % 32]; if (c >= 0x20 && c < 0x7f) pr++ }
  scored.push({ s, pr })
}
scored.sort((a, b) => b.pr - a.pr)
console.log(' ', scored.map(x => `slot${x.s}:${x.pr}`).join(' '))

// --- Is 0x1960 maybe NOT encrypted, and the real payload elsewhere? Check whether the
//     0x1960 bytes XOR 32B-shifted version of themselves gives high structure. ---
console.log('\n=== self-XOR of the 0x7E0 frame payload (32B shift) sanity ===')
{
  const a = buf.subarray(VOFF, VOFF + 0x7E0)
  let same = 0
  for (let i = 0; i + 32 < a.length; i++) if (a[i] === a[i + 32]) same++
  console.log(`  identical bytes at +32: ${same}/${a.length - 32} (random ~${((a.length - 32) / 256).toFixed(0)})`)
}
