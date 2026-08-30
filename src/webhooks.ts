/**
 * Verifying webhook deliveries.
 *
 * A signature you do not check is decoration. This module exists so that checking one is
 * easier than not checking it — including the parts people usually skip, which are the parts
 * that matter.
 */

import { CredenShareError } from './errors.js'

export const SIGNATURE_HEADER = 'X-CredenShare-Signature'

/**
 * How far a delivery's timestamp may sit from your clock, in either direction.
 *
 * Symmetric because a receiver's clock can be behind OR ahead, and rejecting only one
 * direction fails for half the machines that are wrong. Five minutes is long enough to
 * survive ordinary drift and short enough that a captured delivery is not replayable for
 * long.
 */
export const DEFAULT_TOLERANCE_SECONDS = 300

/** A delivery did not verify. Treat it as a forgery, not as a transient error. */
export class WebhookVerificationError extends CredenShareError {
  constructor(message: string) {
    super(message)
    this.name = 'WebhookVerificationError'
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

export interface VerifyOptions {
  toleranceSeconds?: number
  /** Unix seconds. For tests; defaults to the current clock. */
  now?: number
}

const encoder = new TextEncoder()

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/**
 * Compare two byte strings without leaking where they differ.
 *
 * A short-circuiting comparison leaks how much of a guess was right, which is enough to forge
 * a signature given enough attempts. The length is folded into the result rather than
 * returned early, for the same reason.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length
  const length = Math.max(a.length, b.length)
  for (let i = 0; i < length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  return diff === 0
}

function parseHeader(header: string): { timestamp: number; signatures: string[] } {
  if (!header || !header.trim()) {
    throw new WebhookVerificationError(`the ${SIGNATURE_HEADER} header is missing`)
  }

  let timestamp: number | null = null
  const signatures: string[] = []

  for (const part of header.split(',')) {
    const trimmed = part.trim()
    const index = trimmed.indexOf('=')
    if (index === -1) continue
    const key = trimmed.slice(0, index)
    const value = trimmed.slice(index + 1)
    if (key === 't') {
      if (!/^-?\d+$/.test(value)) {
        throw new WebhookVerificationError(
          `the timestamp ${JSON.stringify(value)} is not a unix time`,
        )
      }
      timestamp = Number(value)
    } else if (key === 'v1') {
      // Several v1 entries is normal, not an error: it is how a rotation grace window is
      // expressed, so a receiver holding either secret keeps verifying.
      signatures.push(value)
    }
  }

  if (timestamp === null) {
    throw new WebhookVerificationError('the signature header carries no timestamp')
  }
  if (signatures.length === 0) {
    throw new WebhookVerificationError('the signature header carries no v1 signature')
  }
  return { timestamp, signatures }
}

/**
 * Verify a delivery signature.
 *
 * `payload` must be the RAW request body, exactly as received — a string or the bytes. Do
 * NOT re-serialise parsed JSON: that changes the bytes (key order, spacing, unicode escapes)
 * and the signature will not match. It is the single most common reason a correct
 * implementation appears broken. In Express, that means `express.raw()`, not `express.json()`.
 *
 * `secrets` accepts one secret or several. Pass BOTH during a rotation: for 24 hours after
 * you rotate, deliveries are signed with the old and new secrets together, so a receiver
 * holding either keeps working while you roll your configuration.
 *
 * Resolves to `true` or REJECTS with a `WebhookVerificationError` carrying a reason. It never
 * resolves to `false` — a falsy result is too easy to drop on the floor with
 * `if (await verify(...))` and no else, which produces a receiver that accepts everything and
 * looks like it checks.
 */
export async function verify(
  payload: Uint8Array | string,
  header: string,
  secrets: string | readonly string[],
  options: VerifyOptions = {},
): Promise<true> {
  const candidates = (typeof secrets === 'string' ? [secrets] : secrets).filter(
    (s) => s && s.trim(),
  )
  if (candidates.length === 0) {
    throw new WebhookVerificationError('no signing secret was supplied')
  }
  // The filter above accepts a secret that only LOOKS non-empty after trimming, while the
  // HMAC below keys with the untrimmed bytes. A secret read from a file or an env var with a
  // trailing newline then fails every delivery, and the message blames the signature rather
  // than the whitespace - which is where the hours go.
  const untrimmed = candidates.find((s) => s !== s.trim())
  if (untrimmed !== undefined) {
    throw new WebhookVerificationError(
      'a signing secret has leading or trailing whitespace (probably a trailing newline ' +
        'from a file or an environment variable). The HMAC is keyed with the exact bytes, ' +
        'so this would fail every delivery. Trim it at the source.',
    )
  }

  const { timestamp, signatures } = parseHeader(header)

  // The timestamp is checked BEFORE the signatures, and it is inside the signed material, so
  // it cannot be swapped for a fresh one without invalidating the MAC. Verifying the
  // signature but ignoring the timestamp would let anyone who captured one delivery replay it
  // forever.
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS
  const current = options.now ?? Math.floor(Date.now() / 1000)
  const drift = Math.abs(current - timestamp)
  if (drift > tolerance) {
    throw new WebhookVerificationError(
      `the delivery timestamp is ${drift}s from this clock, outside the ${tolerance}s ` +
        'window; it may be a replay, or a clock may be wrong',
    )
  }

  const body = typeof payload === 'string' ? encoder.encode(payload) : payload
  const prefix = encoder.encode(`${timestamp}.`)
  const signed = new Uint8Array(prefix.length + body.length)
  signed.set(prefix, 0)
  signed.set(body, prefix.length)

  const subtle = globalThis.crypto.subtle
  const provided = signatures.map(hexToBytes)

  for (const secret of candidates) {
    const key = await subtle.importKey(
      'raw',
      encoder.encode(secret).slice().buffer as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const expected = new Uint8Array(
      await subtle.sign('HMAC', key, signed.slice().buffer as ArrayBuffer),
    )
    for (const candidate of provided) {
      if (candidate && timingSafeEqual(expected, candidate)) return true
    }
  }

  throw new WebhookVerificationError(
    'no signature matched. If you are mid-rotation, pass both secrets; otherwise check you ' +
      'are verifying the RAW body rather than re-serialised JSON',
  )
}
