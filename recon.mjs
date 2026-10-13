// Full structural recon: locate plaintext markers, chunk-header cadence, encrypted regions.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])
const size = buf.length
console.log(`file size 0x${size.toString(16)} (${size})`)

function findAll(tag, limit = 40) {
  const b = Buffer.from(tag, 'latin1')
  const out = []
  let i = buf.indexOf(b, 0)
  while (i !== -1 && out.length < limit) { out.push(i); i = buf.indexOf(b, i + 1) }
  return out
}
for (const tag of ['DKIF', 'VP90', 'CRIUSF_DIR_STREAM', 'VIDEO_HDRINFO', 'AUDIO_HDRINFO', 'CRID', '#HEADER END', '#METADATA END', 'IVF', 'SFA', 'HCA']) {
  const hits = findAll(tag)
  console.log(`${tag.padEnd(20)} count=${hits.length}${hits.length ? '  first: ' + hits.slice(0, 8).map(h => '0x' + h.toString(16)).join(', ') : ''}`)
}

// scan the whole file for '@SFV' occurrences, and report the stride pattern
const sfv = findAll('@SFV', 100000)
console.log(`\n@SFV total occurrences: ${sfv.length}`)
if (sfv.length > 2) {
  const strides = []
  for (let i = 1; i < sfv.length; i++) strides.push(sfv[i] - sfv[i - 1])
  const hist = {}
  for (const s of strides) hist[s] = (hist[s] || 0) + 1
  console.log('stride histogram (top 12):', Object.entries(hist).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => `0x${(+k).toString(16)}x${v}`).join(' '))
  console.log('last @SFV at 0x' + sfv[sfv.length - 1].toString(16))
}

// entropy profile: 4KB windows, report mean byte value and zero ratio
console.log('\nentropy / zero-ratio profile (1MB windows):')
const WIN = 0x100000
for (let o = 0; o < size; o += WIN) {
  const n = Math.min(WIN, size - o)
  let zeros = 0, sum = 0
  const hist = new Uint32Array(256)
  for (let i = 0; i < n; i++) { const b = buf[o + i]; if (b === 0) zeros++; sum += b; hist[b]++ }
  // crude entropy
  let H = 0
  for (let i = 0; i < 256; i++) if (hist[i]) { const p = hist[i] / n; H -= p * Math.log2(p) }
  console.log(`  0x${o.toString(16).padStart(7)}  zero=${(zeros / n * 100).toFixed(1)}%  entropy=${H.toFixed(2)}  mean=${(sum / n).toFixed(1)}`)
}

// chunk header cadence: check whether 0x20-byte records repeat at 0x800 stride with '@SFV'-style tag at +0
console.log('\nchunk-header cadence check (tag at offset+0 of 0x20-byte records, stride 0x800):')
let n = 0
for (let o = 0x800; o + 0x20 <= Math.min(size, 0x800 + 0x800 * 40); o += 0x800) {
  const tag = buf.toString('latin1', o, o + 4)
  const f1 = buf.readUInt32BE(o + 4), f2 = buf.readUInt32BE(o + 8), f3 = buf.readUInt32BE(o + 12), f4 = buf.readUInt32BE(o + 16)
  console.log(`  0x${o.toString(16)}: tag='${tag.replace(/[^\x20-\x7e]/g, '.')}' f1=0x${f1.toString(16)} f2=0x${f2.toString(16)} f3=0x${f3.toString(16)} f4=0x${f4.toString(16)}`)
  if (++n > 24) break
}
