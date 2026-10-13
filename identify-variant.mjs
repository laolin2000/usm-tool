// Identify the exact rolling-key variant by comparing the decrypted header chunk
// against the plaintext header chunk at 0x800 (both are the same CRIUSF table).
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const PLAIN_OFF = 0x800
const ENC_OFF = 0x1020
const N = 0x228

const plain = buf.subarray(PLAIN_OFF, PLAIN_OFF + N)
console.log('PLAINTEXT @0x800:')
console.log(JSON.stringify(plain.toString('latin1')))

function slot(s) { return buf.subarray(0x40 + (s % 16) * 32, 0x40 + (s % 16) * 32 + 32) }

// variant A: rolling 32B window, key[i] ^= enc[i]; out[i] = key[i]; one roll per 32B block, start slot S
function variantRolling(enc, startSlot, blockLen = 32) {
  const out = Buffer.alloc(N)
  let idx = 0
  let k = Buffer.from(slot(startSlot))
  for (let b = 0; b < N; b += blockLen) {
    const n = Math.min(blockLen, N - b)
    for (let i = 0; i < n; i++) {
      k[i] ^= enc[b + i]
      out[b + i] = k[i]
    }
    idx++
    k = Buffer.from(slot(startSlot + idx))
  }
  return out
}

// variant B: 64B window (two slots), key[i] ^= enc[i]; out[i] = key[i]
function variantRolling64(enc, startSlot) {
  const out = Buffer.alloc(N)
  let idx = 0
  let k = Buffer.concat([slot(startSlot), slot(startSlot + 1)])
  for (let b = 0; b < N; b += 64) {
    const n = Math.min(64, N - b)
    for (let i = 0; i < n; i++) {
      k[i] ^= enc[b + i]
      out[b + i] = k[i]
    }
    idx += 2
    k = Buffer.concat([slot(startSlot + idx), slot(startSlot + idx + 1)])
  }
  return out
}

const enc = buf.subarray(ENC_OFF, ENC_OFF + N)

function score(out) {
  let same = 0
  for (let i = 0; i < N; i++) if (out[i] === plain[i]) same++
  return same
}

const results = []
for (let s = 0; s < 16; s++) {
  for (const [name, fn] of [['roll32', variantRolling], ['roll64', variantRolling64]]) {
    const out = fn(enc, s)
    results.push({ name, s, same: score(out), out })
  }
}
results.sort((a, b) => b.same - a.same)
console.log(`\nN=${N}  best matches:`)
for (const r of results.slice(0, 6)) console.log(`  ${r.name} startSlot=${r.s} matched ${r.same}/${N} bytes`)

const best = results[0]
if (best.same === N) {
  console.log(`\n*** EXACT MATCH: ${best.name} startSlot=${best.s} ***`)
} else {
  console.log('\nbest-effort output (first 200B):', JSON.stringify(best.out.subarray(0, 200).toString('latin1')))
  // show byte-level diff pattern of the best variant to understand the offset
  const out = best.out
  let firstDiff = -1
  for (let i = 0; i < N; i++) if (out[i] !== plain[i]) { firstDiff = i; break }
  console.log(`first differing byte: ${firstDiff} (0x${firstDiff.toString(16)})`)
  if (firstDiff >= 0) {
    console.log('plain:', plain.subarray(Math.max(0, firstDiff - 16), firstDiff + 48).toString('hex'))
    console.log('got  :', out.subarray(Math.max(0, firstDiff - 16), firstDiff + 48).toString('hex'))
  }
}
