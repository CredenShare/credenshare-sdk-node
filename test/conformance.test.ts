/**
 * The conformance suite. This is the only meaningful definition of correct.
 *
 * The vectors are normative. The application, this SDK and the three others share no code by
 * design, so nothing but these vectors holds the five implementations together — and drift
 * between them does not produce a test failure in normal use, it produces content that can
 * never be decrypted.
 *
 * The derivation cases catch drift early. The decrypt and unwrap cases are the ones that
 * actually prove interoperability, because passing them means this implementation can read
 * what a *different* one wrote.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { checks, load } from '../src/conformance.js'
import * as crypto from '../src/crypto.js'
import { MalformedKeyError, MissingKeyError, WireFormatError } from '../src/errors.js'

const vectors = load()

function unhex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

describe('the packaged vectors', () => {
  it('is the version this code was written against', () => {
    // A silent version bump would mean everything below asserts against a contract nobody
    // wrote it for.
    assert.equal(vectors.version, 1)
  })

  for (const check of checks()) {
    it(check.name, async () => {
      await check.run()
    })
  }
})

describe('properties of this implementation, not of the fixture', () => {
  it('treats an empty salt as zero-length, not as a block of zeros', async () => {
    // RFC 5869 makes an empty salt and a 32-zero-byte salt equivalent for SHA-256 — both pad
    // to the same 64-byte HMAC block — but an implementation that padded to some other
    // length would silently produce different output, and the failure would appear as
    // undecryptable content rather than as a test failure.
    const ikm = new Uint8Array(32).map((_, i) => i)
    const empty = await crypto.hkdf(ikm, new Uint8Array(0), 'x', 32)
    const zeros = await crypto.hkdf(ikm, new Uint8Array(32), 'x', 32)
    assert.deepEqual(empty, zeros)
  })

  it('distinguishes a missing key from a damaged one', () => {
    // Not pedantry: "your link is incomplete" and "this share expired" look identical on
    // screen and have opposite remedies.
    assert.throws(() => crypto.decodeFragment(''), MissingKeyError)
    assert.throws(() => crypto.decodeFragment(null), MissingKeyError)
    assert.throws(() => crypto.decodeFragment('#'), MissingKeyError)
    assert.throws(() => crypto.decodeFragment('1AAAA'), MalformedKeyError)
    assert.throws(() => crypto.decodeFragment('9AAAA'), MalformedKeyError)
  })

  it('strips a leading hash, because that is how a fragment arrives from location.hash', () => {
    const key = unhex(vectors.fragment.key)
    assert.deepEqual(crypto.decodeFragment('#' + vectors.fragment.encoded), key)
  })

  it('reports a truncated blob as truncated rather than as a decryption failure', async () => {
    // Checked before anything else, so nobody goes looking for a wrong passcode.
    await assert.rejects(
      () => crypto.decryptContent(new Uint8Array(32), btoa('short')),
      (error: Error) => error instanceof WireFormatError && /smallest possible/.test(error.message),
    )
  })

  it('gives the same error for a wrong passcode and for altered content', async () => {
    // Telling them apart would hand an attacker an oracle.
    const key = unhex(vectors.content[0].key)
    const blob = vectors.content[1].blob
    // Thunks, not eagerly-created promises. Building both up front leaves the second one
    // floating until the first assertion resolves, and if it rejects in that window Node
    // reports an unhandledRejection and fails the test. It is timing-dependent, so it passed
    // on Linux and Windows and failed on a macOS runner - which is the worst kind of flake:
    // one that looks like a platform difference in the crypto.
    await assert.rejects(() => crypto.decryptContent(key, blob, 'not-hunter2'), WireFormatError)
    await assert.rejects(
      () => crypto.decryptContent(key, vectors.content[0].blob.slice(0, -4) + 'AAAA'),
      WireFormatError,
    )
  })

  it('refuses a field that uses label, name or title instead of key', () => {
    // Stricter than the wire contract, deliberately. 'Silently ignored' means the share
    // encrypts, posts, decrypts and renders with every label blank and nothing erroring.
    for (const wrong of ['label', 'name', 'title']) {
      assert.throws(
        () => crypto.validateFields([{ [wrong]: 'Password', value: 'v', type: 'password' } as never]),
        (error: Error) => new RegExp(`the member is 'key'`).test(error.message),
        `a field using ${wrong} should be refused`,
      )
    }
  })

  it('preserves unknown members, so a newer sender does not break an older reader', async () => {
    const key = crypto.newContentKey()
    const fields = [{ key: 'k', value: 'v', type: 'text', futureThing: { a: 1 } }]
    const blob = await crypto.encryptContent(key, fields)
    assert.deepEqual(await crypto.decryptContent(key, blob), fields)
  })

  it('never emits the same IV twice for the same key', async () => {
    // The one mistake that destroys AES-GCM outright. Cheap to assert, catastrophic to miss.
    const key = crypto.newContentKey()
    const seen = new Set<string>()
    for (let i = 0; i < 24; i += 1) {
      const raw = crypto.unb64(await crypto.encryptContent(key, [{ key: 'k', value: String(i), type: 'text' }]))
      seen.add(Array.from(raw.subarray(16, 28)).join(','))
    }
    assert.equal(seen.size, 24)
  })

  it('rejects a recipient public key that is not an uncompressed P-256 point', async () => {
    await assert.rejects(
      () => crypto.wrapToPublicKey(new Uint8Array(32), new Uint8Array(65)),
      /uncompressed P-256 point/,
    )
    await assert.rejects(
      () => crypto.wrapToPublicKey(new Uint8Array(32), new Uint8Array(64).fill(4)),
      /uncompressed P-256 point/,
    )
  })

  it('refuses to unwrap with the wrong seed', async () => {
    const wrong = new Uint8Array(32).fill(9)
    await assert.rejects(
      () => crypto.unwrapWithSeed(vectors.ecdh_wrap.wrapped, wrong),
      WireFormatError,
    )
  })
})
