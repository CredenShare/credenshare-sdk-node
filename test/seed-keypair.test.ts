import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { inspect } from 'node:util'
import { keypairFromSeed, custodyKeypair, newSeed } from '../src/index.js'

/**
 * The seed-keypair leak that blocked 0.2.0.
 *
 * `keypairFromSeed` and `custodyKeypair` shipped at 0.1.4 returning a plain object literal, so
 * `seed`, `scalar` and `privateKey` were own ENUMERABLE properties. Go, Rust and Python all
 * redact their equivalent; Node was the last one that did not, and an interface has nothing to
 * hang a redaction on. The three secrets are now non-enumerable.
 *
 * The seed is the read capability for every submission a request will ever collect, and the
 * scalar IS the private key. Either one in a log is the whole feature undone.
 */
const SEED = new Uint8Array(32).fill(0x7f)
const HEX = Buffer.from(SEED).toString('hex')
const B64 = Buffer.from(SEED).toString('base64')
const B64URL = B64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

const leaks = (text: string) =>
  [HEX, B64, B64URL, B64.replace(/=+$/, '')].filter((r) => r.length > 8 && text.includes(r))

describe('SeedKeypair does not leak on any enumerating path', () => {
  it('keeps direct access working — the reason the function exists', async () => {
    const kp = await keypairFromSeed(SEED)
    // Not a formality: requests.create and decryptSubmission both read .seed, and any consumer
    // written against 0.1.4 does too. Hiding it from enumeration must not hide it from them.
    assert.equal(Buffer.from(kp.seed).toString('hex'), HEX)
    assert.equal(typeof kp.scalar, 'bigint')
    assert.ok(kp.privateKey)
    assert.equal(kp.publicKeyB64url.length, 87)
  })

  it('withholds the secrets from every path that WALKS the object', async () => {
    const kp = await keypairFromSeed(SEED)
    const paths: Record<string, string> = {
      'JSON.stringify': JSON.stringify(kp),
      spread: JSON.stringify({ ...kp }),
      'Object.keys': JSON.stringify(Object.keys(kp)),
      'Object.entries': JSON.stringify(Object.entries(kp).map(([k]) => k)),
      'for..in': (() => { const seen: string[] = []; for (const k in kp) seen.push(k); return seen.join(',') })(),
      String: String(kp),
      'template literal': `${kp}`,
      inspect: inspect(kp),
      'inspect depth null': inspect(kp, { depth: null }),
      'inspect customInspect false': inspect(kp, { customInspect: false }),
      'inspect showHidden': inspect(kp, { showHidden: true, customInspect: false }),
      'getOwnPropertyNames(enumerable only)': JSON.stringify(
        Object.getOwnPropertyNames(kp).filter((k) => Object.getOwnPropertyDescriptor(kp, k)?.enumerable),
      ),
    }
    for (const [name, out] of Object.entries(paths)) {
      assert.deepEqual(leaks(out), [], `${name} leaked the seed: ${out.slice(0, 200)}`)
      assert.ok(!out.includes('57896044'), `${name} leaked the scalar in decimal`)
    }
  })

  it('enumerates exactly the two public members', async () => {
    const kp = await keypairFromSeed(SEED)
    assert.deepEqual(Object.keys(kp).sort(), ['publicKeyB64url', 'publicKeyRaw'])
  })

  it('covers custodyKeypair too, which delegates here', async () => {
    const kp = await custodyKeypair('a-custody-secret')
    assert.deepEqual(Object.keys(kp).sort(), ['publicKeyB64url', 'publicKeyRaw'])
    assert.deepEqual(leaks(JSON.stringify(kp) + inspect(kp) + String(kp)), [])
    assert.ok(kp.seed instanceof Uint8Array)
  })

  it('a random seed is not accidentally exempt', async () => {
    const seed = newSeed()
    const kp = await keypairFromSeed(seed)
    const hex = Buffer.from(seed).toString('hex')
    for (const out of [JSON.stringify(kp), JSON.stringify({ ...kp }), inspect(kp, { customInspect: false }), String(kp)]) {
      assert.ok(!out.includes(hex), 'a random seed leaked as hex')
      assert.ok(!out.includes(Buffer.from(seed).toString('base64').replace(/=+$/, '')), 'a random seed leaked as base64')
    }
  })
})
