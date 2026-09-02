/**
 * The serialization sweep: every path an object plausibly reaches a log through, run against
 * a real `SecureRequest` carrying a known seed, with each rendering searched for those bytes.
 *
 * Both halves of this are load-bearing, and the first draft of each was wrong in a way that
 * reported success:
 *
 * 1. The CAPTURE. A duck-typed `{ write }` passed to `new Console(...)` throws
 *    `stream.removeListener is not a function`. The harness then stored the exception text as
 *    the "rendering", found no seed in it, and called all seven console paths clean — a suite
 *    passing while testing nothing. `captured()` uses a real Writable for that reason.
 *
 * 2. The DETECTOR. `util.inspect` wraps a Uint8Array into columns:
 *
 *      Uint8Array(32) [
 *        200,  29, 164, 243,   7, 155, 226,  84,
 *        102, 177,  44, 255, 147,  10, 119, 214,
 *        ...
 *
 *    so a rendering showing all 32 bytes contains no base64, no hex, and no contiguous
 *    `Array.from(seed).join(', ')` substring either. A spelling-only search calls that CLEAN.
 *    So the bytes are also looked for as a contiguous run of integers, however inspect chose
 *    to wrap them.
 *
 * Run: npm run seed-sweep
 */

import util from 'node:util'
import { Console } from 'node:console'
import { Writable } from 'node:stream'
import { CredenShare } from '../src/client.js'
import * as crypto from '../src/crypto.js'

const CREDENTIAL = 'crs_sk_live_abc123.authsecretvalue.custodysecretvalue'

/** Distinctive bytes, so no run of them occurs by coincidence. */
const SEED = new Uint8Array([
  0xc8, 0x1d, 0xa4, 0xf3, 0x07, 0x9b, 0xe2, 0x54, 0x66, 0xb1, 0x2c, 0xff, 0x93, 0x0a, 0x77,
  0xd6, 0x41, 0x8e, 0x35, 0xba, 0x69, 0x02, 0xcd, 0x50, 0xe7, 0x1c, 0xab, 0x84, 0x3f, 0xf0,
  0x59, 0x96,
])

const hex = (join: string, upper = false) =>
  Array.from(SEED, (b) => {
    const h = b.toString(16).padStart(2, '0')
    return upper ? h.toUpperCase() : h
  }).join(join)

/** Every text spelling the seed could plausibly be rendered in. */
const SPELLINGS: Array<[string, string]> = [
  ['base64url', crypto.b64url(SEED)],
  ['base64 unpadded', crypto.b64(SEED).replace(/=+$/, '')],
  ['base64 padded', crypto.b64(SEED)],
  ['hex', hex('')],
  ['hex upper', hex('', true)],
  ['hex spaced', hex(' ')],
  ['latin1', Buffer.from(SEED).toString('latin1')],
]

/** The seed as a run of decimal bytes, found however util.inspect chose to wrap them. */
function decimalRunPresent(output: string): boolean {
  const numbers = (output.match(/\d+/g) ?? []).map(Number)
  outer: for (let i = 0; i + SEED.length <= numbers.length; i++) {
    for (let j = 0; j < SEED.length; j++) if (numbers[i + j] !== SEED[j]) continue outer
    return true
  }
  return false
}

function leaksIn(output: string): string[] {
  const hits = SPELLINGS.filter(([, spelling]) => output.includes(spelling)).map(([n]) => n)
  if (decimalRunPresent(output)) hits.push('decimal byte run')
  return hits
}

/**
 * A real Console writing into a string rather than to stdout.
 *
 * A duck-typed `{ write }` is NOT enough: Console reaches for stream.removeListener and
 * throws, every case reports "clean" because the output is an exception rather than a
 * rendering, and the sweep passes while testing nothing. It has to be a genuine Writable.
 */
function captured(): { console: Console; text: () => string } {
  const chunks: Buffer[] = []
  const sink = new Writable({
    write(chunk, _encoding, done) {
      chunks.push(Buffer.from(chunk))
      done()
    },
  })
  return {
    console: new Console({ stdout: sink, colorMode: false }),
    text: () => Buffer.concat(chunks).toString('utf8').trimEnd(),
  }
}

function tableOf(value: unknown): string {
  const { console: c, text } = captured()
  c.table(value as never)
  return text()
}

function consoleOf(method: 'log' | 'dir', ...args: unknown[]): string {
  const { console: c, text } = captured()
  ;(c[method] as (...a: unknown[]) => void)(...args)
  return text()
}

function* forIn(value: object): Generator<string> {
  for (const key in value) yield key
}

const fetchImpl = (async () =>
  new Response(JSON.stringify({ short_code: 'aB3dEf12', public_key: 'PUBKEY' }), {
    status: 201,
    headers: { 'content-type': 'application/json' },
  })) as unknown as typeof globalThis.fetch

const request = await new CredenShare(CREDENTIAL, { fetch: fetchImpl }).requests.create({
  title: 't',
  fields: [{ item: 'Password', type: 'password' }],
  seed: SEED,
})

const cases: Array<[string, () => string]> = [
  ['JSON.stringify(request)', () => JSON.stringify(request)],
  ['JSON.stringify({ nested: request })', () => JSON.stringify({ nested: request })],
  ['spread, inspected', () => util.inspect({ ...request }, { depth: null })],
  ['spread, stringified', () => JSON.stringify({ ...request })],
  [
    'structuredClone(request)',
    () => {
      try {
        return util.inspect(structuredClone(request), { depth: null })
      } catch (error) {
        return `THREW ${(error as Error).name}: ${(error as Error).message}`
      }
    },
  ],
  ['console.log(request)', () => consoleOf('log', request)],
  ['console.log with %o', () => consoleOf('log', '%o', request)],
  ['console.log with %s', () => consoleOf('log', '%s', request)],
  ['console.dir(request, { depth: null })', () => consoleOf('dir', request, { depth: null })],
  ['console.table(request)', () => tableOf(request)],
  ['console.table([request])', () => tableOf([request])],
  ['console.table([request, request])', () => tableOf([request, request])],
  [
    'util.inspect(request, { customInspect: false })',
    () => util.inspect(request, { customInspect: false, depth: null }),
  ],
  [
    'util.inspect(request, { customInspect: false, showHidden: true })',
    () => util.inspect(request, { customInspect: false, showHidden: true, depth: null }),
  ],
  [
    'util.inspect(request, { getters: true })',
    () => util.inspect(request, { getters: true, depth: null }),
  ],
  [
    'util.inspect(request, { getters: true, customInspect: false })',
    () => util.inspect(request, { getters: true, customInspect: false, depth: null }),
  ],
  ['for..in', () => [...forIn(request)].join(', ')],
  [
    'Object.keys and Object.entries',
    () => `${Object.keys(request).join(', ')} | ${util.inspect(Object.entries(request))}`,
  ],
  [
    'Object.getOwnPropertyDescriptors(request)',
    () => util.inspect(Object.getOwnPropertyDescriptors(request), { depth: null }),
  ],
  ['template interpolation', () => `request=${request}`],
  ['String(request) and .toString()', () => `${String(request)} | ${request.toString()}`],
  [
    'util.inspect(request, { getters: true, showHidden: true })',
    () => util.inspect(request, { getters: true, showHidden: true, depth: null }),
  ],
  [
    'THE DOCUMENTED CAVEAT: getters + customInspect:false + showHidden',
    () =>
      util.inspect(request, {
        getters: true,
        customInspect: false,
        showHidden: true,
        depth: null,
      }),
  ],
]

console.log(`node ${process.version}`)
console.log('seed under test:')
for (const [name, spelling] of SPELLINGS.slice(0, 4)) {
  console.log(`  ${name.padEnd(16)} ${spelling}`)
}
console.log(`  ${'decimal'.padEnd(16)} ${Array.from(SEED).join(', ')}`)
console.log('')

let leaks = 0
for (const [name, run] of cases) {
  let out: string
  try {
    out = run()
  } catch (error) {
    out = `THREW ${(error as Error).name}: ${(error as Error).message}`
  }
  const hits = leaksIn(out)
  if (hits.length) leaks++
  console.log(`-- ${name}`)
  console.log(`   ${hits.length ? `SEED VISIBLE via ${hits.join(', ')}` : 'clean'}`)
  console.log(`   ${out.replace(/\n/g, '\n   ')}`)
  console.log('')
}

console.log(`${cases.length} paths swept, ${leaks} yielded the seed.`)
if (leaks !== 1) {
  console.log(
    'EXPECTED exactly one -- the documented caveat. Any other count means the class or the ' +
      'sweep changed and the documentation no longer matches the code.',
  )
  process.exitCode = 1
}
