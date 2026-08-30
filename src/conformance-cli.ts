#!/usr/bin/env node
/**
 * Verify an installed copy of this SDK against the packaged conformance vectors.
 *
 *     npx credenshare-conformance          # summary
 *     npx credenshare-conformance -v       # one line per vector
 *
 * Exits non-zero on any failure, so it works as a deployment gate. Worth running in the
 * environment that will actually do the encrypting: a client that fails these produces
 * content nothing else can read, and that failure is otherwise invisible until somebody
 * opens a link.
 */

import { run } from './conformance.js'

const args = process.argv.slice(2)
const verbose = args.includes('-v') || args.includes('--verbose')

const { passed, failures } = await run({ verbose })

if (verbose) console.log('')

if (failures.length === 0) {
  console.log(`${passed} passed. This installation conforms to the wire specification.`)
  process.exit(0)
}

for (const failure of failures) {
  console.error(`FAIL ${failure.name}`)
  for (const line of failure.reason.split('\n')) console.error(`     ${line}`)
}
console.error('')
console.error(`${passed} passed, ${failures.length} FAILED`)
console.error(
  'This installation does not implement the wire specification correctly. Content it ' +
    'encrypts may be unreadable by every other client, including the web application.',
)
process.exit(1)
