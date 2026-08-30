// Restore the conformance fixture's exact bytes into dist/.
//
// `tsc` re-indents JSON it resolves through `resolveJsonModule`, so the emitted copy is
// semantically identical and byte-wise different — 7477 bytes instead of 6901. That breaks
// the one property the fixture is supposed to have: being the same artifact everywhere.
// A consumer diffing the installed copy against the published one would see a difference
// and have no way to tell whether it is cosmetic or real, and the pinned digest would be
// pinning a file nobody actually ships.
//
// So the pristine file is copied over the emitted one, and the digest is asserted here
// rather than trusted — a silent failure would leave the published package carrying a
// reformatted fixture again.
import { createHash } from 'node:crypto'
import { copyFileSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const src = fileURLToPath(new URL('../src/conformance-vectors.json', import.meta.url))
const dist = fileURLToPath(new URL('../dist/conformance-vectors.json', import.meta.url))

copyFileSync(src, dist)

const digest = (path) => createHash('sha256').update(readFileSync(path)).digest('hex')
const before = digest(src)
const after = digest(dist)
if (before !== after) {
  console.error(`the copied fixture does not match the source\n  src:  ${before}\n  dist: ${after}`)
  process.exit(1)
}
console.log(`conformance fixture copied verbatim (sha256:${after})`)
