/**
 * The conformance fixture, and a self-check that runs against it.
 *
 * `conformance-vectors.json` is normative. It is imported into the bundle rather than read
 * from disk so it works everywhere this SDK does — a Worker has no filesystem — and so an
 * installed copy can verify itself:
 *
 *     npx credenshare-conformance
 *
 * That matters more here than in most libraries. The application and the four SDKs share no
 * code by design — a package the production application depended on would mean a compromised
 * publish is a compromised application — so nothing but these vectors holds the five
 * implementations together. Drift between them does not surface as a test failure in normal
 * use. It surfaces as content that can never be decrypted.
 */

import vectors from './conformance-vectors.json' with { type: 'json' }
import * as crypto from './crypto.js'
import { MalformedKeyError, MissingKeyError } from './errors.js'

/**
 * The fixture version this code was written against. A silent bump would mean every check
 * below is asserting against a contract nobody wrote it for, which is worse than failing.
 */
export const SUPPORTED_VERSION = 1

export interface Check {
  name: string
  run: () => Promise<void>
}

export function load(): typeof vectors {
  if (vectors.version !== SUPPORTED_VERSION) {
    throw new Error(
      `the packaged fixture is version ${vectors.version}, but this SDK implements ` +
        `version ${SUPPORTED_VERSION}`,
    )
  }
  return vectors
}

function unhex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function expect(what: string, got: unknown, want: unknown): void {
  const a = typeof got === 'string' ? got : JSON.stringify(got)
  const b = typeof want === 'string' ? want : JSON.stringify(want)
  if (a !== b) {
    throw new Error(`${what}\n  expected: ${b}\n  actual:   ${a}`)
  }
}

/**
 * Every vector, as an individually named check.
 *
 * Returned as a list rather than run, so a caller — the CLI, or a test runner — can report
 * them one by one instead of stopping at the first, which matters when a derivation change
 * breaks a whole section at once.
 */
export function checks(): Check[] {
  const v = load()
  const out: Check[] = []

  for (const c of v.hkdf) {
    out.push({
      name: `hkdf/${c.name}`,
      run: async () => {
        const got = await crypto.hkdf(unhex(c.ikm), unhex(c.salt), c.info, c.length)
        expect('HKDF output', hex(got), c.out)
      },
    })
  }

  out.push({
    name: 'fragment/encode',
    run: async () => expect('encoded fragment', crypto.encodeFragment(unhex(v.fragment.key)), v.fragment.encoded),
  })
  out.push({
    name: 'fragment/decode',
    run: async () => expect('decoded content key', hex(crypto.decodeFragment(v.fragment.encoded)), v.fragment.key),
  })

  v.fragment.rejects.forEach((reject, index) => {
    // Refusals are part of the contract, not extra credit: a client that accepts a truncated
    // fragment produces a key that decrypts nothing, and reports it as a content error
    // somewhere far away from the mangled link that caused it.
    const wanted = reject.reason === 'missing-key' ? MissingKeyError : MalformedKeyError
    out.push({
      name: `fragment/rejects/${index}/${reject.reason}`,
      run: async () => {
        try {
          crypto.decodeFragment(reject.input)
        } catch (error) {
          if (error instanceof wanted) return
          // The distinction is not pedantry. "Your link is incomplete" and "this link is
          // damaged" have different remedies, and both look identical on screen.
          throw new Error(
            `expected ${wanted.name} for ${JSON.stringify(reject.input)}, got ` +
              `${(error as Error).name}: ${(error as Error).message}`,
          )
        }
        throw new Error(
          `${JSON.stringify(reject.input)} was accepted; the fixture requires ${wanted.name}`,
        )
      },
    })
  })

  out.push({
    name: 'access_token',
    run: async () =>
      expect('access token', await crypto.accessToken(unhex(v.access_token.key)), v.access_token.token),
  })

  v.passcode_verifier.forEach((c, index) => {
    // Numbered rather than named after the passcode: one of these cases is deliberately
    // non-ASCII, and a legacy console code page would turn printing its name into a crash
    // in the tool that is meant to be diagnosing crashes.
    out.push({
      name: `passcode_verifier/${index}`,
      run: async () =>
        expect('passcode verifier', await crypto.passcodeVerifier(c.passcode), c.verifier),
    })
  })

  for (const c of v.content) {
    out.push({
      name: `content/${c.name}/encrypt`,
      run: async () => {
        const blob = await crypto.encryptContent(unhex(c.key), JSON.parse(c.plaintext), {
          passcode: 'passcode' in c ? (c as { passcode: string }).passcode : undefined,
          __salt: unhex(c.salt),
          __iv: unhex(c.iv),
        })
        // Byte-identical, not merely decryptable. A blob that differs while still decrypting
        // here would hide a JSON-serialisation difference — key order, separators — that
        // another implementation may not tolerate.
        expect('content blob', blob, c.blob)
      },
    })
    out.push({
      // The decrypt direction is the one that proves interoperability: the blob in the
      // fixture was produced by a different implementation, so reading it means this client
      // can read what that one wrote.
      name: `content/${c.name}/decrypt`,
      run: async () => {
        const fields = await crypto.decryptContent(
          unhex(c.key),
          c.blob,
          'passcode' in c ? (c as { passcode: string }).passcode : undefined,
        )
        expect('decrypted fields', fields, JSON.parse(c.plaintext))
      },
    })
  }

  for (const c of v.seed_keypair) {
    out.push({
      name: `seed_keypair/${c.name}`,
      run: async () => {
        const pair = await crypto.keypairFromSeed(unhex(c.seed))
        // The scalar is checked as well as the public key. Both would have to be wrong
        // together for a bias in the reduction to slip through unnoticed.
        expect('scalar', pair.scalar.toString(16).padStart(64, '0'), c.scalar)
        expect('public key', hex(pair.publicKeyRaw), c.public_key)
        expect('public key (base64url)', pair.publicKeyB64url, c.public_key_b64url)
      },
    })
  }

  out.push({
    name: 'custody_keypair',
    run: async () => {
      const pair = await crypto.custodyKeypair(v.custody_keypair.custody_secret)
      // The seed is checked too: it is the value a different implementation has to arrive at
      // independently, and a mismatch here explains a public-key mismatch below it.
      expect('custody seed', hex(pair.seed), v.custody_keypair.seed)
      expect('custody public key', hex(pair.publicKeyRaw), v.custody_keypair.public_key)
      expect('custody public key (base64url)', pair.publicKeyB64url, v.custody_keypair.public_key_b64url)
    },
  })

  const w = v.ecdh_wrap
  out.push({
    name: 'ecdh_wrap/wrap',
    run: async () => {
      const wrapped = await crypto.wrapToPublicKey(unhex(w.payload), unhex(w.recipient_public_key), {
        __ephemeralSeed: unhex(w.ephemeral_seed),
        __salt: unhex(w.salt),
        __iv: unhex(w.iv),
      })
      expect('wrapped blob', wrapped, w.wrapped)
    },
  })
  out.push({
    name: 'ecdh_wrap/unwrap',
    run: async () =>
      expect('unwrapped payload', hex(await crypto.unwrapWithSeed(w.wrapped, unhex(w.recipient_seed))), w.payload),
  })
  out.push({
    name: 'ecdh_wrap/roundtrip',
    run: async () => {
      const recipient = await crypto.keypairFromSeed(unhex(w.recipient_seed))
      const payload = unhex(w.payload)
      const wrapped = await crypto.wrapToPublicKey(payload, recipient.publicKeyRaw)
      // 1 version + 65 public + 16 salt + 12 iv + payload + 16 tag. A 32-byte payload wraps
      // to exactly 142 bytes, which is a useful field check when something downstream
      // rejects a wrap without saying why.
      expect('wrap length', crypto.unb64(wrapped).length, 1 + 65 + 16 + 12 + payload.length + 16)
      expect('version byte', crypto.unb64(wrapped)[0], w.wrap_version)
      expect(
        'unwrapped payload',
        hex(await crypto.unwrapWithSeed(wrapped, unhex(w.recipient_seed))),
        w.payload,
      )
    },
  })

  return out
}

export interface RunResult {
  passed: number
  failures: Array<{ name: string; reason: string }>
}

/** Run every check, collecting failures rather than stopping at the first. */
export async function run(options: { verbose?: boolean; log?: (line: string) => void } = {}): Promise<RunResult> {
  const log = options.log ?? ((line: string) => console.log(line))
  let passed = 0
  const failures: Array<{ name: string; reason: string }> = []

  for (const check of checks()) {
    try {
      await check.run()
      passed += 1
      if (options.verbose) log(`ok   ${check.name}`)
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      failures.push({ name: check.name, reason })
      if (options.verbose) log(`FAIL ${check.name}\n${reason}`)
    }
  }

  return { passed, failures }
}
