/**
 * Webhook verification.
 *
 * Most of these assert refusals. A verifier that accepts too much is worse than none, because
 * it produces a system that looks verified and is not.
 */

import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { describe, it } from 'node:test'

import { DEFAULT_TOLERANCE_SECONDS, WebhookVerificationError, verify } from '../src/webhooks.js'

const SECRET = 'whsec_5NIQiWnzkbjIRSAX0ilnFLBOoIfnDMi16D3F5jrhSbo'
const OTHER = 'whsec_someone-elses-secret-entirely-different-value'
const BODY = '{"event":"share.created","short_code":"abc123"}'
const NOW = 1_700_000_000

/** Signed with node:crypto, deliberately — a different implementation from the one under test. */
function mac(secret: string, body = BODY, at = NOW): string {
  return createHmac('sha256', secret).update(`${at}.${body}`).digest('hex')
}

function sign(secret: string, body = BODY, at = NOW): string {
  return `t=${at},v1=${mac(secret, body, at)}`
}

describe('a genuine delivery', () => {
  it('verifies', async () => {
    assert.equal(await verify(BODY, sign(SECRET), SECRET, { now: NOW }), true)
  })

  it('verifies from raw bytes as well as a string', async () => {
    const bytes = new TextEncoder().encode(BODY)
    assert.equal(await verify(bytes, sign(SECRET), SECRET, { now: NOW }), true)
  })
})

describe('forgeries', () => {
  it('refuses a signature made with another secret', async () => {
    await assert.rejects(() => verify(BODY, sign(OTHER), SECRET, { now: NOW }), /no signature matched/)
  })

  it('refuses a tampered body', async () => {
    await assert.rejects(() => verify(BODY + ' ', sign(SECRET), SECRET, { now: NOW }), WebhookVerificationError)
  })

  it('refuses re-serialised JSON', async () => {
    // The most common reason a correct implementation appears broken: re-serialising parsed
    // JSON changes the bytes — key order, spacing, escapes — so the MAC no longer matches.
    const reserialised = JSON.stringify(JSON.parse(BODY) as unknown, null, 2)
    assert.notEqual(reserialised, BODY)
    await assert.rejects(() => verify(reserialised, sign(SECRET), SECRET, { now: NOW }), /RAW body/)
  })
})

describe('the replay window', () => {
  it('refuses an old delivery even though its signature is valid', async () => {
    // Without a timestamp check, anyone who captured one delivery could replay it forever.
    const old = NOW - (DEFAULT_TOLERANCE_SECONDS + 60)
    await assert.rejects(() => verify(BODY, sign(SECRET, BODY, old), SECRET, { now: NOW }), /outside the/)
  })

  it('is symmetric, because a receiver clock can be ahead as easily as behind', async () => {
    const future = NOW + (DEFAULT_TOLERANCE_SECONDS + 60)
    await assert.rejects(() => verify(BODY, sign(SECRET, BODY, future), SECRET, { now: NOW }), /outside the/)

    const inside = NOW + (DEFAULT_TOLERANCE_SECONDS - 10)
    assert.equal(await verify(BODY, sign(SECRET, BODY, inside), SECRET, { now: NOW }), true)
  })

  it('will not accept a timestamp swapped for a fresh one', async () => {
    // It is inside the signed material, so moving it invalidates the MAC.
    const header = sign(SECRET, BODY, NOW - 10_000)
    const forward = header.replace(`t=${NOW - 10_000}`, `t=${NOW}`)
    await assert.rejects(() => verify(BODY, forward, SECRET, { now: NOW }), /no signature matched/)
  })
})

describe('the rotation grace window', () => {
  const dual = `${sign(SECRET)},v1=${mac(OTHER)}`

  it('accepts either secret on a dual-signed delivery', async () => {
    // For 24 hours after a rotation, deliveries carry both signatures. That is what lets a
    // receiver roll its configuration without dropping anything — without it, the moment of
    // rotation IS an outage.
    assert.equal(await verify(BODY, dual, SECRET, { now: NOW }), true)
    assert.equal(await verify(BODY, dual, OTHER, { now: NOW }), true)
    assert.equal(await verify(BODY, dual, [OTHER, SECRET], { now: NOW }), true)
  })

  it('still refuses an unrelated secret', async () => {
    // Two signatures widen WHO can verify, not WHAT verifies.
    await assert.rejects(() => verify(BODY, dual, 'whsec_a-third-secret', { now: NOW }), WebhookVerificationError)
  })
})

describe('malformed input', () => {
  const cases: Array<[string, RegExp]> = [
    ['', /missing/],
    ['   ', /missing/],
    [`v1=${'0'.repeat(64)}`, /no timestamp/],
    [`t=${NOW}`, /no v1 signature/],
    [`t=notanumber,v1=${'0'.repeat(64)}`, /not a unix time/],
  ]

  for (const [header, match] of cases) {
    it(`refuses ${JSON.stringify(header)} with a reason`, async () => {
      await assert.rejects(() => verify(BODY, header, SECRET, { now: NOW }), match)
    })
  }

  it('refuses a v1 value that is not hex', async () => {
    await assert.rejects(() => verify(BODY, `t=${NOW},v1=zzzz`, SECRET, { now: NOW }), WebhookVerificationError)
  })

  it('treats no secret as an error, not a pass', async () => {
    for (const secrets of ['', [], ['', '  ']] as Array<string | string[]>) {
      await assert.rejects(() => verify(BODY, sign(SECRET), secrets, { now: NOW }), /no signing secret/)
    }
  })

  it('never resolves to false', async () => {
    // A falsy result is too easy to drop with `if (await verify(...))` and no else, which
    // produces a receiver that accepts everything and looks like it checks.
    await assert.rejects(async () => {
      const result = await verify(BODY, sign(OTHER), SECRET, { now: NOW })
      assert.fail(`expected a rejection, resolved to ${String(result)}`)
    }, WebhookVerificationError)
  })
})
