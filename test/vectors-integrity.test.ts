/**
 * The vendored fixture must not drift from the published one.
 *
 * Nothing but the conformance vectors holds five independent implementations together — the
 * application and four SDKs, which share no code by design. If a vendored copy can be edited
 * to make a failing test pass, that guarantee is gone: the fixture stops being a contract and
 * becomes a mirror of whatever this SDK happens to do.
 *
 * So the copy is pinned by digest here, and CI additionally re-fetches the published artifact
 * when it is configured to. The digest catches the local edit; the fetch catches the case
 * where the published spec moved and this SDK has not.
 */

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'

const VECTORS_PATH = fileURLToPath(new URL('../src/conformance-vectors.json', import.meta.url))

/**
 * SHA-256 of `src/conformance-vectors.json`.
 *
 * Updating this by hand is a deliberate act. If a conformance test fails, the fix is almost
 * never to re-pin this — it is to fix the implementation. Re-pin only when intentionally
 * adopting a newly published fixture, in a commit that says so and nothing else.
 */
const EXPECTED_SHA256 = '91e70661be51edbc4522d202c533292d1eac92691d1fbb02e9eaa13eb23a582c'

function digest(): string {
  // Read as bytes, not as text. Reading as a string and re-encoding would paper over exactly
  // the line-ending conversion this is meant to catch.
  return createHash('sha256').update(readFileSync(VECTORS_PATH)).digest('hex')
}

describe('the vendored fixture', () => {
  it('has not been edited', () => {
    assert.equal(
      digest(),
      EXPECTED_SHA256,
      'the packaged conformance-vectors.json does not match its pinned digest.\n' +
        'If a conformance test was failing, fix the implementation rather than the fixture. ' +
        'Re-pin only to adopt a newly published fixture, deliberately.\n' +
        'If this fails only on Windows, check .gitattributes: the digest is of the LF bytes.',
    )
  })

  it('is well formed and carries every section this SDK implements', () => {
    const data = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as Record<string, unknown>
    assert.equal(data.version, 1)
    // A fixture that quietly lost a section would turn a real conformance gap into a passing
    // run.
    for (const section of [
      'hkdf',
      'fragment',
      'access_token',
      'passcode_verifier',
      'content',
      'seed_keypair',
      'custody_keypair',
      'ecdh_wrap',
    ]) {
      assert.ok(section in data, `the fixture is missing the ${section} vectors`)
    }
  })

  it(
    'matches the published fixture byte for byte',
    { skip: process.env.CREDENSHARE_VECTORS_URL ? false : 'set CREDENSHARE_VECTORS_URL' },
    async () => {
      // Byte-for-byte, not semantically: a whitespace-only difference still means the two
      // files came from different generator runs, and that is worth knowing before it becomes
      // a difference that matters.
      const response = await fetch(process.env.CREDENSHARE_VECTORS_URL!)
      assert.ok(response.ok, `fetching the published fixture returned HTTP ${response.status}`)
      const published = new Uint8Array(await response.arrayBuffer())
      assert.deepEqual(
        published,
        new Uint8Array(readFileSync(VECTORS_PATH)),
        'the vendored fixture differs from the published one. The spec has moved; update ' +
          'src/conformance-vectors.json and re-pin its digest.',
      )
    },
  )
})
