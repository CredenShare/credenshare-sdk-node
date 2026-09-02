/**
 * Client-side cryptography for CredenShare.
 *
 * This module implements the published wire specification. The specification is normative —
 * not this file, and not any other implementation. Where they disagree, the specification is
 * right and this is a bug.
 *
 * Nothing here talks to the network, and nothing here writes to disk. Encryption happens on
 * your machine, and the content key never leaves it: that is the entire point of the
 * product, and an SDK that quietly sent a key would be worse than no SDK.
 *
 * WHY THIS IS WRITTEN FROM THE SPEC RATHER THAN PORTED
 * The application, this SDK and the three others are independent implementations that share
 * no code. That is a supply-chain decision: a package the production application depended on
 * would mean a compromised publish is a compromised application. The cost is drift, and
 * drift here does not produce a test failure — it produces content that can never be
 * decrypted. The conformance vectors are what hold the implementations together, and they
 * include cases that decrypt material produced by a *different* implementation. Passing them
 * is the only meaningful definition of correct.
 *
 * WHY WEBCRYPTO
 * `globalThis.crypto.subtle` is the one API present in Node 20+, Deno, Bun, Cloudflare
 * Workers and browsers alike. (Node 18 HAS WebCrypto but does not expose it globally without
 * a flag, so 20 is the floor - CI found that after the package had claimed 18+ for a while.) Reaching for `node:crypto` would make this package
 * Node-only, and the runtimes this is most useful in — edge functions, CI runners — are
 * exactly the ones that do not have it.
 */

import {
  InvalidFieldError,
  MalformedKeyError,
  MissingKeyError,
  WireFormatError,
} from './errors.js'

/** Field types the recipient view knows how to render (section 2.2.1). */
export const FIELD_TYPES = [
  'text',
  'password',
  'date',
  'multiline',
  'markdown',
  'source_code',
] as const

export type FieldType = (typeof FIELD_TYPES)[number]

export interface Field {
  /**
   * The VISIBLE LABEL. Not `label`, `name` or `title` — those are silently ignored by the
   * recipient view, which renders the field with a blank label and no error anywhere.
   */
  key: string
  value: string
  type: FieldType | string
  [extra: string]: unknown
}

// Lengths are exact, per section 0. Named rather than inlined so a truncated blob is
// rejected by arithmetic that reads like the specification.
const SALT_LEN = 16
const IV_LEN = 12
const TAG_LEN = 16
const KEY_LEN = 32

/** A content key is 32 bytes. Exported so callers can check one before using it. */
export const CONTENT_KEY_LENGTH = KEY_LEN

/**
 * A seed is 32 bytes too, and the same length as a content key on purpose: both are raw
 * CSPRNG output that has to survive a trip through a URL fragment. Exported so a
 * caller-supplied seed can be checked before a keypair is derived from it.
 */
export const SEED_LENGTH = KEY_LEN
const PUBKEY_LEN = 65 // 0x04 || X(32) || Y(32)
const WRAP_VERSION = 1

const P256_ORDER = BigInt(
  '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
)

const subtle = (): SubtleCrypto => {
  const c = globalThis.crypto
  if (!c?.subtle) {
    throw new Error(
      'WebCrypto is unavailable. This SDK needs Node 20+, Deno, Bun, a Worker runtime or a ' +
        'browser. Node 18 has WebCrypto but does not expose it as `globalThis.crypto` without ' +
        'a flag; there, `globalThis.crypto = require("node:crypto").webcrypto` works.',
    )
  }
  return c.subtle
}

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

/**
 * HKDF-SHA-256, with `info` encoded as UTF-8.
 *
 * An empty salt is passed through as a zero-length byte string rather than being replaced
 * with a block of zeros. RFC 5869 makes those equivalent for HMAC-SHA-256 — a zero-length
 * HMAC key and a 32-zero-byte one both pad to the same 64-byte block — but the specification
 * calls it out because an implementation that pads to some *other* length silently produces
 * different output and fails conformance.
 */
export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length: number,
): Promise<Uint8Array> {
  const key = await subtle().importKey('raw', asBufferSource(ikm), 'HKDF', false, ['deriveBits'])
  const bits = await subtle().deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: asBufferSource(salt),
      info: asBufferSource(textEncoder.encode(info)),
    },
    key,
    length * 8,
  )
  return new Uint8Array(bits)
}

// ── encoding ────────────────────────────────────────────────────────────────────────

function asBufferSource(bytes: Uint8Array): ArrayBuffer {
  // A copy, because a Uint8Array may be a view onto a larger buffer — passing the backing
  // ArrayBuffer directly would silently hand WebCrypto the wrong bytes.
  return bytes.slice().buffer as ArrayBuffer
}

/** Standard base64 with padding (RFC 4648 §4). Used for blobs, which travel in JSON. */
export function b64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export function unb64(text: string): Uint8Array {
  // The alphabet is checked first. `atob` tolerates some malformed input, so without this a
  // mangled blob decodes to *something* and fails later as a decryption error rather than
  // as the malformed input it is.
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) {
    throw new WireFormatError('the value is not valid base64')
  }
  const binary = atob(text)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
  return out
}

/** URL-safe base64, no padding (RFC 4648 §5). Used for anything that travels in a URL. */
export function b64url(bytes: Uint8Array): string {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function unb64url(text: string): Uint8Array {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/')
  return unb64(padded + '='.repeat((4 - (padded.length % 4)) % 4))
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length)
  globalThis.crypto.getRandomValues(out)
  return out
}

// ── section 2.1: the content key and the fragment ───────────────────────────────────

/** A fresh 32-byte content key from the platform CSPRNG. */
export function newContentKey(): Uint8Array {
  return randomBytes(KEY_LEN)
}

/**
 * Encode a content key as a URL fragment: `"1" + base64url(key)`.
 *
 * Bare, with a single leading version character and no `k=` prefix. A key=value appendix
 * reads as optional and invites link-mangling clients to truncate it, and a truncated
 * fragment must fail closed rather than look like a well-formed link missing a part.
 */
export function encodeFragment(contentKey: Uint8Array): string {
  if (contentKey.length !== KEY_LEN) {
    throw new Error(`a content key is ${KEY_LEN} bytes, got ${contentKey.length}`)
  }
  return '1' + b64url(contentKey)
}

/**
 * Parse a fragment back into a content key.
 *
 * Throws `MissingKeyError` when there is no fragment at all and `MalformedKeyError` when
 * there is one but it is not usable. The distinction is not pedantry: "your link is
 * incomplete" and "this share expired" look identical on screen and have opposite remedies.
 */
export function decodeFragment(fragment: string | null | undefined): Uint8Array {
  if (fragment === null || fragment === undefined) {
    throw new MissingKeyError('no key fragment was supplied')
  }
  const text = fragment.replace(/^#+/, '')
  if (text === '') throw new MissingKeyError('no key fragment was supplied')

  if (text[0] !== '1') {
    throw new MalformedKeyError(
      `unsupported fragment version ${JSON.stringify(text[0])}; this link needs a newer client`,
    )
  }

  let raw: Uint8Array
  try {
    raw = unb64url(text.slice(1))
  } catch {
    throw new MalformedKeyError('the key fragment is not valid base64url')
  }

  if (raw.length !== KEY_LEN) {
    throw new MalformedKeyError(
      `a content key is ${KEY_LEN} bytes; this fragment decoded to ${raw.length}, so the ` +
        'link is probably truncated',
    )
  }
  return raw
}

// ── section 2.2: content encryption ─────────────────────────────────────────────────

async function contentKeyFor(
  contentKey: Uint8Array,
  salt: Uint8Array,
  passcode?: string,
): Promise<CryptoKey> {
  // The passcode goes into `info`, never into the salt. They serve different purposes, and a
  // salt built from the passcode would make the derivation depend on a value that has to
  // stay reproducible from stored data alone.
  const info = passcode === undefined ? 'content' : `content|${passcode}`
  const derived = await hkdf(contentKey, salt, info, KEY_LEN)
  return subtle().importKey('raw', asBufferSource(derived), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

/**
 * Check a field array against section 2.2.1 before it is encrypted.
 *
 * This exists because getting it wrong is invisible. A field object using `label` instead of
 * `key` still encrypts, still posts, still decrypts and still renders — with every label
 * blank and no error anywhere. The specification gained a section about it after that cost
 * somebody an afternoon, so this SDK refuses rather than letting it through.
 *
 * Unknown members are allowed and preserved: a newer sender must not break an older reader.
 */
export function validateFields(fields: readonly Field[]): void {
  fields.forEach((field, index) => {
    if (typeof field !== 'object' || field === null || Array.isArray(field)) {
      throw new InvalidFieldError(`field ${index} is not an object`)
    }
    if (!('key' in field)) {
      for (const wrong of ['label', 'name', 'title']) {
        if (wrong in field) {
          throw new InvalidFieldError(
            `field ${index} uses ${JSON.stringify(wrong)} for its label; the member is 'key'. ` +
              `${JSON.stringify(wrong)} is silently ignored, and the field would render with ` +
              'a blank label and no error.',
          )
        }
      }
      throw new InvalidFieldError(`field ${index} has no 'key' (its visible label)`)
    }
    if (!('value' in field)) throw new InvalidFieldError(`field ${index} has no 'value'`)
    if (!('type' in field)) {
      throw new InvalidFieldError(`field ${index} has no 'type'; one of ${FIELD_TYPES.join(', ')}`)
    }
  })
}

export interface EncryptOptions {
  passcode?: string
  /**
   * Fixed salt and IV, for the conformance vectors only. Production code must never pass
   * them — a reused IV under the same key destroys AES-GCM's guarantees outright.
   */
  __salt?: Uint8Array
  __iv?: Uint8Array
}

/**
 * Encrypt a field array, returning the base64 blob the API accepts.
 *
 * The blob uses standard base64, not base64url: it travels in a JSON body, never in a URL.
 */
export async function encryptContent(
  contentKey: Uint8Array,
  fields: readonly Field[],
  options: EncryptOptions = {},
): Promise<string> {
  validateFields(fields)
  const salt = options.__salt ?? randomBytes(SALT_LEN)
  const iv = options.__iv ?? randomBytes(IV_LEN)

  const key = await contentKeyFor(contentKey, salt, options.passcode)
  // JSON.stringify produces no spaces and preserves insertion order, which matches the
  // canonical form the other implementations produce. The conformance vectors compare the
  // blob byte for byte, so a difference here fails loudly rather than quietly.
  const plaintext = textEncoder.encode(JSON.stringify(fields))
  const body = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv: asBufferSource(iv) }, key, asBufferSource(plaintext)),
  )

  const out = new Uint8Array(salt.length + iv.length + body.length)
  out.set(salt, 0)
  out.set(iv, salt.length)
  out.set(body, salt.length + iv.length)
  return b64(out)
}

/**
 * Decrypt a blob back into the field array.
 *
 * A wrong passcode and a tampered blob are indistinguishable, deliberately: both surface as
 * `WireFormatError`. Telling them apart would hand an attacker an oracle.
 */
export async function decryptContent(
  contentKey: Uint8Array,
  blob: string,
  passcode?: string,
): Promise<Field[]> {
  let raw: Uint8Array
  try {
    raw = unb64(blob)
  } catch {
    throw new WireFormatError('the content blob is not valid base64')
  }

  const minimum = SALT_LEN + IV_LEN + TAG_LEN
  if (raw.length < minimum) {
    // Checked before anything else, so a truncated blob is reported as truncated rather than
    // as a decryption failure that sends somebody looking for a wrong passcode.
    throw new WireFormatError(
      `the content blob is ${raw.length} bytes; the smallest possible one is ${minimum}`,
    )
  }

  const salt = raw.subarray(0, SALT_LEN)
  const iv = raw.subarray(SALT_LEN, SALT_LEN + IV_LEN)
  const body = raw.subarray(SALT_LEN + IV_LEN)

  const key = await contentKeyFor(contentKey, salt, passcode)
  let plaintext: ArrayBuffer
  try {
    plaintext = await subtle().decrypt(
      { name: 'AES-GCM', iv: asBufferSource(iv) },
      key,
      asBufferSource(body),
    )
  } catch {
    throw new WireFormatError(
      'could not decrypt: the passcode is wrong, or the content was altered',
    )
  }

  const parsed: unknown = JSON.parse(textDecoder.decode(plaintext))
  if (!Array.isArray(parsed)) throw new WireFormatError('decrypted content is not a field array')
  return parsed as Field[]
}

// ── sections 2.3 and 2.4: tokens derived from the key ───────────────────────────────

/**
 * The access token the server uses to admit a reader.
 *
 * The salt is empty so this is reproducible from the fragment alone, on any device, with
 * nothing stored. The server keeps only a hash of it and learns nothing about the content
 * key, because HKDF's domain separation makes the `access` output independent of the
 * `content` one.
 */
export async function accessToken(contentKey: Uint8Array): Promise<string> {
  return b64url(await hkdf(contentKey, new Uint8Array(0), 'access', KEY_LEN))
}

/** A one-way verifier that lets the server check a passcode it cannot use. */
export async function passcodeVerifier(passcode: string): Promise<string> {
  return b64url(
    await hkdf(textEncoder.encode(passcode), new Uint8Array(0), 'verify', KEY_LEN),
  )
}

// ── section 3: seed-derived P-256 keypairs ──────────────────────────────────────────

/**
 * A fresh 32-byte seed from the platform CSPRNG.
 *
 * The bytes are drawn exactly as `newContentKey()` draws them, and this exists as a separate
 * name anyway: a seed becomes a P-256 keypair (section 3) and a content key becomes an AES
 * key (section 2.2), so a reader should not have to know the two are interchangeable at the
 * point where one is minted. Using a single value as both would tie a share's content to a
 * request's identity, which is precisely the kind of coupling the info strings exist to
 * prevent.
 */
export function newSeed(): Uint8Array {
  return randomBytes(KEY_LEN)
}

export interface SeedKeypair {
  seed: Uint8Array
  scalar: bigint
  privateKey: CryptoKey
  publicKeyRaw: Uint8Array
  publicKeyB64url: string
}

/**
 * Assemble a SeedKeypair whose three secret members are non-enumerable.
 *
 * `keypairFromSeed` and `custodyKeypair` shipped at 0.1.4 returning a plain object literal, so
 * `seed`, `scalar` and `privateKey` were own enumerable properties — which means they came out of
 * `JSON.stringify`, `{...keypair}`, `console.table`, `console.dir`, `for..in` and
 * `Object.entries`. The seed is the read capability for every submission a request will ever
 * collect and the scalar IS the private key, so all three had to stop appearing.
 *
 * Non-enumerable rather than `#private` deliberately. `keypair.seed` keeps working — it is the
 * whole reason the function exists, and `requests.create` and `decryptSubmission` both read it —
 * while every path that WALKS the object stops seeing it. Making them private fields instead
 * would have broken direct access for existing 0.1.4 consumers; this only changes what
 * enumeration yields, which is the leak.
 *
 * `toJSON` is the belt to that braces: without it `JSON.stringify` returns `{"publicKeyRaw":…,
 * "publicKeyB64url":…}` and a reader might not notice the omission was deliberate.
 */
function sealKeypair(parts: {
  seed: Uint8Array
  scalar: bigint
  privateKey: CryptoKey
  publicKeyRaw: Uint8Array
  publicKeyB64url: string
}): SeedKeypair {
  const kp = {
    publicKeyRaw: parts.publicKeyRaw,
    publicKeyB64url: parts.publicKeyB64url,
  } as SeedKeypair

  for (const [key, value] of [
    ['seed', parts.seed],
    ['scalar', parts.scalar],
    ['privateKey', parts.privateKey],
  ] as const) {
    Object.defineProperty(kp, key, { value, enumerable: false, writable: false, configurable: false })
  }

  const redacted = () =>
    `SeedKeypair(${parts.publicKeyB64url.slice(0, 12)}…, seed/scalar/privateKey withheld)`
  for (const [key, value] of [
    ['toJSON', () => ({ publicKeyB64url: parts.publicKeyB64url, seed: '[redacted]', scalar: '[redacted]', privateKey: '[redacted]' })],
    ['toString', redacted],
    [Symbol.for('nodejs.util.inspect.custom'), redacted],
  ] as const) {
    Object.defineProperty(kp, key, { value, enumerable: false, writable: false, configurable: false })
  }

  return kp
}

function bigintToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length)
  let v = value
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/**
 * Derive a P-256 keypair from a 32-byte seed (section 3).
 *
 * 48 bytes of HKDF output rather than 32 is deliberate: the extra 128 bits make the modular
 * bias negligible. Reducing mod `n-1` and adding one yields a scalar in `[1, n-1]`,
 * excluding zero, which is not a valid private key.
 *
 * WebCrypto has no "import a raw scalar" call, so the key is imported as a JWK. That means
 * computing the public point here — WebCrypto will not do it from the private half alone,
 * and a JWK missing `x`/`y` is rejected.
 */
export async function keypairFromSeed(seed: Uint8Array): Promise<SeedKeypair> {
  if (seed.length !== KEY_LEN) {
    throw new Error(`a seed is ${KEY_LEN} bytes, got ${seed.length}`)
  }

  const wide = await hkdf(seed, new Uint8Array(0), 'crs-ecdh-p256-scalar', 48)
  let acc = 0n
  for (const byte of wide) acc = (acc << 8n) | BigInt(byte)
  const scalar = (acc % (P256_ORDER - 1n)) + 1n

  const point = scalarMultiplyBase(scalar)
  const publicKeyRaw = new Uint8Array(PUBKEY_LEN)
  publicKeyRaw[0] = 0x04
  publicKeyRaw.set(bigintToBytes(point.x, 32), 1)
  publicKeyRaw.set(bigintToBytes(point.y, 32), 33)

  const privateKey = await subtle().importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      d: b64url(bigintToBytes(scalar, 32)),
      x: b64url(bigintToBytes(point.x, 32)),
      y: b64url(bigintToBytes(point.y, 32)),
      ext: true,
    },
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  )

  return sealKeypair({
    seed,
    scalar,
    privateKey,
    publicKeyRaw,
    publicKeyB64url: b64url(publicKeyRaw),
  })
}

/**
 * Derive the custody keypair from the third part of an API credential (section 3.1).
 *
 * The custody secret is never transmitted. It is a *separate* secret from the auth secret
 * precisely so that the server cannot reconstruct this private key: the auth secret goes
 * over the wire on every request, so deriving custody from it would mean the server *could*
 * decrypt. Not that it would — that it could, which is what zero-knowledge is meant to
 * remove.
 *
 * The empty salt is deliberate: the derivation has to be reproducible from the credential
 * alone, on any machine, with nothing stored.
 */
export async function custodyKeypair(custodySecret: string): Promise<SeedKeypair> {
  const seed = await hkdf(
    textEncoder.encode(custodySecret),
    new Uint8Array(0),
    'custody',
    KEY_LEN,
  )
  return keypairFromSeed(seed)
}

// ── P-256 scalar multiplication ─────────────────────────────────────────────────────
//
// Present only because WebCrypto cannot derive a public point from a private scalar, and the
// whole design rests on keys being reproducible from a seed. It is used exclusively on
// values this process generated or was handed by its own operator, never on attacker-chosen
// input, so the constant-time properties a general-purpose library needs do not apply here.
// If that ever stops being true, this is the code to replace first.

const P256_P = BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF')
const P256_A = BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC')
const P256_GX = BigInt('0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296')
const P256_GY = BigInt('0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5')

interface Point {
  x: bigint
  y: bigint
}

function mod(a: bigint, m: bigint = P256_P): bigint {
  const r = a % m
  return r >= 0n ? r : r + m
}

function invert(a: bigint, m: bigint = P256_P): bigint {
  let [old_r, r] = [mod(a, m), m]
  let [old_s, s] = [1n, 0n]
  while (r !== 0n) {
    const q = old_r / r
    ;[old_r, r] = [r, old_r - q * r]
    ;[old_s, s] = [s, old_s - q * s]
  }
  return mod(old_s, m)
}

function pointDouble(p: Point | null): Point | null {
  if (p === null || p.y === 0n) return null
  const lambda = mod((3n * p.x * p.x + P256_A) * invert(2n * p.y))
  const x = mod(lambda * lambda - 2n * p.x)
  return { x, y: mod(lambda * (p.x - x) - p.y) }
}

function pointAdd(p: Point | null, q: Point | null): Point | null {
  if (p === null) return q
  if (q === null) return p
  if (p.x === q.x) return p.y === q.y ? pointDouble(p) : null
  const lambda = mod((q.y - p.y) * invert(q.x - p.x))
  const x = mod(lambda * lambda - p.x - q.x)
  return { x, y: mod(lambda * (p.x - x) - p.y) }
}

function scalarMultiplyBase(scalar: bigint): Point {
  let result: Point | null = null
  let addend: Point | null = { x: P256_GX, y: P256_GY }
  let k = scalar
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend)
    addend = pointDouble(addend)
    k >>= 1n
  }
  if (result === null) throw new Error('scalar multiplication produced the point at infinity')
  return result
}

// ── section 4: ECDH wrapping ────────────────────────────────────────────────────────

export interface WrapOptions {
  /** Fixed values, for the conformance vectors only. Never pass these in production. */
  __ephemeralSeed?: Uint8Array
  __salt?: Uint8Array
  __iv?: Uint8Array
}

/**
 * Wrap a payload to a published P-256 public key.
 *
 * Layout: `base64(0x01 || ephemeralPublic(65) || salt(16) || iv(12) || ciphertext+tag)`.
 * Wrapping a 32-byte payload gives exactly 142 bytes, which is a useful field check.
 *
 * The ephemeral keypair is fresh per wrap. Reusing one across wraps leaks the relationship
 * between them.
 */
export async function wrapToPublicKey(
  payload: Uint8Array,
  recipientPublicKey: Uint8Array,
  options: WrapOptions = {},
): Promise<string> {
  if (recipientPublicKey.length !== PUBKEY_LEN || recipientPublicKey[0] !== 0x04) {
    throw new Error(
      'a recipient public key is a 65-byte uncompressed P-256 point starting with 0x04',
    )
  }

  const ephemeral = await keypairFromSeed(options.__ephemeralSeed ?? randomBytes(KEY_LEN))
  const salt = options.__salt ?? randomBytes(SALT_LEN)
  const iv = options.__iv ?? randomBytes(IV_LEN)

  const peer = await subtle().importKey(
    'raw',
    asBufferSource(recipientPublicKey),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
  const shared = new Uint8Array(
    await subtle().deriveBits({ name: 'ECDH', public: peer }, ephemeral.privateKey, 256),
  )
  const wrappingKeyBytes = await hkdf(shared, salt, 'crs-request-submission', KEY_LEN)
  const wrappingKey = await subtle().importKey(
    'raw',
    asBufferSource(wrappingKeyBytes),
    'AES-GCM',
    false,
    ['encrypt'],
  )
  const body = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv: asBufferSource(iv) },
      wrappingKey,
      asBufferSource(payload),
    ),
  )

  const out = new Uint8Array(1 + PUBKEY_LEN + SALT_LEN + IV_LEN + body.length)
  out[0] = WRAP_VERSION
  out.set(ephemeral.publicKeyRaw, 1)
  out.set(salt, 1 + PUBKEY_LEN)
  out.set(iv, 1 + PUBKEY_LEN + SALT_LEN)
  out.set(body, 1 + PUBKEY_LEN + SALT_LEN + IV_LEN)
  return b64(out)
}

/** Unwrap a payload with the seed whose public key it was wrapped to. */
export async function unwrapWithSeed(wrapped: string, seed: Uint8Array): Promise<Uint8Array> {
  const raw = unb64(wrapped)
  const header = 1 + PUBKEY_LEN + SALT_LEN + IV_LEN
  if (raw.length < header + TAG_LEN) {
    throw new WireFormatError(
      `a wrap is at least ${header + TAG_LEN} bytes; this one is ${raw.length}`,
    )
  }
  if (raw[0] !== WRAP_VERSION) {
    throw new WireFormatError(`unsupported wrap version ${raw[0]}; this needs a newer client`)
  }

  const ephemeralPublic = raw.subarray(1, 1 + PUBKEY_LEN)
  const salt = raw.subarray(1 + PUBKEY_LEN, 1 + PUBKEY_LEN + SALT_LEN)
  const iv = raw.subarray(1 + PUBKEY_LEN + SALT_LEN, header)
  const body = raw.subarray(header)

  const recipient = await keypairFromSeed(seed)
  const peer = await subtle().importKey(
    'raw',
    asBufferSource(ephemeralPublic),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
  const shared = new Uint8Array(
    await subtle().deriveBits({ name: 'ECDH', public: peer }, recipient.privateKey, 256),
  )
  const keyBytes = await hkdf(shared, salt, 'crs-request-submission', KEY_LEN)
  const key = await subtle().importKey('raw', asBufferSource(keyBytes), 'AES-GCM', false, [
    'decrypt',
  ])

  try {
    return new Uint8Array(
      await subtle().decrypt({ name: 'AES-GCM', iv: asBufferSource(iv) }, key, asBufferSource(body)),
    )
  } catch {
    throw new WireFormatError('could not unwrap: wrong recipient key, or the wrap was altered')
  }
}

/**
 * Open a secure-request submission with the seed kept when the request was created.
 *
 * A submission blob is a section 4 wrap whose payload is the same JSON field array a share
 * carries, so this is `unwrapWithSeed` plus the parse. The parse is here rather than left to
 * the caller because a primitive returning bytes invites a hand-rolled `TextDecoder` at
 * every call site, and one of them will forget that the result is a field array and not an
 * object.
 *
 * THE ENCODING, which is the trap on this feature. A submission's `data` is STANDARD base64,
 * padded, because it travels inside a JSON body. A request's `public_key` is base64url,
 * UNPADDED, because it was minted to travel in a URL. Two alphabets on two halves of one
 * feature: feed this the base64url decoder and you get bytes that will not open, and the
 * failure reads as a wrong key rather than as a wrong decoder.
 */
export async function decryptSubmission(data: string, seed: Uint8Array): Promise<Field[]> {
  const plaintext = await unwrapWithSeed(data, seed)
  const parsed: unknown = JSON.parse(textDecoder.decode(plaintext))
  if (!Array.isArray(parsed)) {
    throw new WireFormatError('a decrypted submission is not a field array')
  }
  return parsed as Field[]
}
