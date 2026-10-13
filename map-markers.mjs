// Map all plaintext markers inside the container-header region and find where the
// real encrypted payload begins. Also report chi-square per region to see if the
// "encryption" is uniform (block cipher) or structured.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])

function findIn(tag, from, to, limit = 60) {
  const b = Buffer.from(tag, 'latin1'); const out = []
  let i = buf.indexOf(b, from)
  while (i !== -1 && i < to && out.length < limit) { out.push(i); i = buf.indexOf(b, i + 1) }
  return out
}

console.log('=== all @SFV in 0x0..0x20000 ===')
const sfv = findIn('@SFV', 0, 0x20000, 200)
console.log(`count=${sfv.length}`)
for (const o of sfv) {
  const size = buf.readUInt32BE(o + 4)
  const meta = buf.readUInt32BE(o + 12) & 0xffff   // frame index field observed
  console.log(`  0x${o.toString(16).padStart(6)}  size=0x${size.toString(16).padStart(6)} field@+12=0x${buf.readUInt32BE(o + 12).toString(16)} field@+16=0x${buf.readUInt32BE(o + 16).toString(16)} field@+20=0x${buf.readUInt32BE(o + 20).toString(16)} field@+24=0x${buf.readUInt32BE(o + 24).toString(16)}`)
  if (sfv.indexOf(o) > 60) break
}

console.log('\n=== marker positions across whole file (plaintext leakage) ===')
for (const tag of ['@SFV', '@SFA', 'CRIUSF', '#HEADER END', 'DKIF', 'VIDEO_HDRINFO']) {
  const all = findIn(tag, 0, buf.length, 40)
  console.log(`  ${tag.padEnd(14)} n=${all.length} ${all.slice(0, 12).map(x => '0x' + x.toString(16)).join(' ')}`)
}

// chi-square in successive 0x20000 regions to find where randomness starts
console.log('\n=== chi-square per 0x20000 region ===')
for (let o = 0; o < 0x140000; o += 0x20000) {
  const n = Math.min(0x20000, buf.length - o)
  const hist = new Uint32Array(256)
  for (let i = 0; i < n; i++) hist[buf[o + i]]++
  const exp = n / 256
  let chi = 0
  for (let i = 0; i < 256; i++) chi += (hist[i] - exp) ** 2 / exp
  console.log(`  0x${o.toString(16).padStart(6)}: chi=${chi.toFixed(0)}`)
}

// check the 0x1A20 region: does the encrypted payload contain its own @SFV index later?
console.log('\n=== deeper @SFV occurrences (beyond 0x20000) ===')
const deep = findIn('@SFV', 0x20000, buf.length, 30)
console.log(deep.length ? deep.map(x => '0x' + x.toString(16)).join(' ') : 'none')
