// USM (CRI Sofdec2) container parser + header key extraction
// Usage: node parse-usm.mjs <file.usm|dat>
import { readFileSync } from 'node:fs'

const path = process.argv[2]
if (!path) { console.error('usage: node parse-usm.mjs <file>'); process.exit(1) }
const buf = readFileSync(path)
console.log(`file: ${path}`)
console.log(`size: ${buf.length} (0x${buf.length.toString(16)})`)

const magic = buf.toString('latin1', 0, 4)
if (magic !== 'CRID') { console.error(`not CRID: ${JSON.stringify(magic)}`); process.exit(2) }

const beaconSize = buf.readUInt32BE(4)
const headerSize = buf.readUInt32BE(8)   // chunk payload size of the first @SFV (usually 0x800)
const dataOffset = buf.readUInt32BE(12)
const version    = buf.readUInt32BE(16)
const headerSize2= buf.readUInt32BE(20)
const chunkCount = buf.readUInt32BE(24)
const headerSize3= buf.readUInt32BE(28)
console.log(`beaconSize=0x${beaconSize.toString(16)} chunkPayload=0x${headerSize.toString(16)} (${headerSize}) crilaylaDataOff=0x${dataOffset.toString(16)} version=0x${version.toString(16)} headerSize2=0x${headerSize2.toString(16)} chunkCount=${chunkCount} headerSize3=0x${headerSize3.toString(16)}`)

// --- scan for '@SFV' / '@SFA' / '@ALP' blocks in the header ---
function findAll(tag, from = 0, to = buf.length) {
  const out = []
  const b = Buffer.from(tag, 'latin1')
  let i = buf.indexOf(b, from)
  while (i !== -1 && i < to) { out.push(i); i = buf.indexOf(b, i + 1) }
  return out
}

const sfvOffs = findAll('@SFV', 0, 0x4000)
const sfaOffs = findAll('@SFA', 0, 0x4000)
const alpOffs = findAll('@ALP', 0, 0x4000)
console.log(`\n@SFV at: ${sfvOffs.map(o => '0x' + o.toString(16)).join(', ') || '(none)'}`)
console.log(`@SFA at: ${sfaOffs.map(o => '0x' + o.toString(16)).join(', ') || '(none)'}`)
console.log(`@ALP at: ${alpOffs.map(o => '0x' + o.toString(16)).join(', ') || '(none)'}`)

function dumpStreamTable(base, label) {
  // base points at '@SFV' (4 bytes) then payload
  const p = base + 4
  const w = buf.readUInt16BE(p)
  const h = buf.readUInt16BE(p + 2)
  const framerateRaw = buf.readUInt32BE(p + 4)   // 0x03E8 = 1000 -> /1000
  const nFrames = buf.readUInt32BE(p + 8)
  const nFields = buf.readUInt32BE(p + 12)
  console.log(`\n[${label}] @0x${base.toString(16)}  width=${w} height=${h} framerateRaw=0x${framerateRaw.toString(16)}(${framerateRaw}) nFrames=${nFrames} nFields=${nFields}`)
  const bytes = []
  for (let i = 0; i < Math.min(0x40, 0x100); i += 16) {
    const row = []
    for (let j = 0; j < 16; j++) row.push(buf[p + i + j].toString(16).padStart(2, '0'))
    bytes.push(`  0x${(p + i).toString(16)}: ${row.join(' ')}`)
  }
  console.log(bytes.join('\n'))
  // try to locate an embedded 'SFA'/'SFV' codec tag right after the header block
  for (const tag of ['SFA', 'SFV', 'ALP', 'HCA', 'ADX']) {
    const at = buf.indexOf(Buffer.from(tag, 'latin1'), p)
    if (at !== -1 && at < p + 0x300) console.log(`  inner tag '${tag}' at 0x${at.toString(16)}`)
  }
  return { w, h, framerateRaw, nFrames, nFields, payloadStart: p }
}

const streams = []
for (const o of sfvOffs) streams.push(dumpStreamTable(o, 'SFV(video)'))
for (const o of sfaOffs) streams.push(dumpStreamTable(o, 'SFA(audio)'))
for (const o of alpOffs) streams.push(dumpStreamTable(o, 'ALP(alpha)'))

// --- key material slots: base + 0x40 .. +0x240 ---
const KEY_SLOTS = 16, KEY_LEN = 32
console.log(`\n--- key material (base 0x40, ${KEY_SLOTS} slots x ${KEY_LEN}B) ---`)
for (let s = 0; s < KEY_SLOTS; s++) {
  const off = 0x40 + s * KEY_LEN
  const slot = buf.subarray(off, off + KEY_LEN)
  const nonzero = slot.some(b => b !== 0)
  console.log(`slot ${s.toString().padStart(2)} @0x${off.toString(16)} nonzero=${nonzero}  ${slot.toString('hex')}`)
}

// --- walk chunks ---
console.log(`\n--- chunk walk (first 12 + stats) ---`)
let off = headerSize          // first chunk starts right after the 0x800 header
const CHUNK_ALIGN = 0x20
const chunks = []
let guard = 0
while (off + 0x20 <= buf.length && guard++ < 10_000_000) {
  const sig = buf.readUInt32BE(off)
  const typ = buf.toString('latin1', off + 4, off + 8)
  const payloadSize = buf.readUInt32BE(off + 8)
  const padSize = buf.readUInt32BE(off + 12)
  const rawSize = buf.readUInt32BE(off + 16)
  const encType = buf.readUInt32BE(off + 20)
  chunks.push({ off, sig, typ, payloadSize, padSize, rawSize, encType })
  const total = (0x20 + payloadSize + padSize + CHUNK_ALIGN - 1) & ~(CHUNK_ALIGN - 1)
  if (total <= 0x20) { console.log(`!! zero-advance chunk at 0x${off.toString(16)}`); break }
  off += total
  if (chunks.length > 400000) break
}
for (const c of chunks.slice(0, 12)) {
  console.log(`  @0x${c.off.toString(16).padStart(9)} sig=0x${c.sig.toString(16).padStart(8, '0')} type='${c.typ}' payload=${c.payloadSize} pad=${c.padSize} raw=${c.rawSize} enc=0x${c.encType.toString(16)}`)
}
const byType = {}
for (const c of chunks) { byType[c.typ] = byType[c.typ] || { n: 0, bytes: 0, enc: new Set() }; byType[c.typ].n++; byType[c.typ].bytes += c.payloadSize; byType[c.typ].enc.add(c.encType) }
console.log(`\n--- chunk summary (total ${chunks.length}) ---`)
for (const [t, v] of Object.entries(byType)) console.log(`  '${t}': count=${v.n} payloadBytes=${v.bytes} encTypes=[${[...v.enc].map(x => '0x' + x.toString(16))}]`)
console.log(`end offset=0x${off.toString(16)} fileSize=0x${buf.length.toString(16)} leftover=${buf.length - off} bytes`)

// tiny sanity: last chunk
const last = chunks[chunks.length - 1]
if (last) console.log(`last chunk: @0x${last.off.toString(16)} type='${last.typ}' payload=${last.payloadSize}`)
