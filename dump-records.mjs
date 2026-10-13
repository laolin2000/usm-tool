// Dump every distinct record inside the container header region and classify it,
// looking for an unencrypted IVF/VP9 data area.
import { readFileSync } from 'node:fs'

const buf = readFileSync(process.argv[2])

function region(start, len, label) {
  console.log(`\n===== ${label}: 0x${start.toString(16)}..0x${(start + len).toString(16)} =====`)
  for (let o = start; o < start + len; o += 32) {
    const row = []
    for (let j = 0; j < 32; j++) row.push(buf[o + j].toString(16).padStart(2, '0'))
    const asc = buf.toString('latin1', o, o + 32).replace(/[^\x20-\x7e]/g, '.')
    console.log(`0x${o.toString(16).padStart(7)}: ${row.join(' ')}  |${asc}|`)
  }
}

region(0x0, 0x40, 'CLI header (32B)')
region(0x40, 0xc0, 'stream 0 header table')
region(0x100, 0xa0, 'stream 0 header table (cont)')
region(0x800, 0x230, 'stream 0 first chunk payload = @SFV index')
region(0xa30, 0x30, 'after #HEADER END')
region(0xa60, 0xE0, 'AUDIO/VIDEO HDRINFO area')
region(0xb40, 0x40, 'more table')
region(0xb80, 0x60, 'utf16 filenames')
region(0xec0, 0x40, 'DKIF/VP90 area')
region(0xee0, 0x40, 'DKIF/VP90 area 2')
region(0xf00, 0x80, 'after DKIF')
region(0xf80, 0x80, 'after DKIF (cont)')
region(0x1900, 0x60, 'video index chunk')
region(0x1960, 0x60, 'video payload start')
