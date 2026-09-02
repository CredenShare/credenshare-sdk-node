/**
 * Client behaviour, against a stub fetch.
 *
 * The properties worth testing here are not "does it call the right URL" but the ones where
 * being wrong is silent or dangerous: the custody secret never leaving the machine, the
 * content key never appearing in a request, and error types that imply the right remedy.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { readFileSync } from 'node:fs'
import { inspect } from 'node:util'

import { CredenShare, Credential } from '../src/client.js'
import { VERSION } from '../src/index.js'
import * as crypto from '../src/crypto.js'
import {
  ApiError,
  AuthenticationError,
  CredentialFormatError,
  DeliveryUnknownError,
  IdempotencyConflictError,
  MalformedKeyError,
  NetworkError,
  NotFoundError,
  PermissionError,
  QuotaExceededError,
  RateLimitError,
  ServiceUnavailableError,
} from '../src/errors.js'
import { CREDENTIAL, TWO_PART, client, recordOf, recorder, type Recorded } from './harness.js'

const FIELD = { key: 'k', value: 'v', type: 'text' as const }

// -- credential handling --------------------------------------------------------------

describe('the credential', () => {
  it('parses both forms', () => {
    assert.equal(Credential.parse(CREDENTIAL).keyId, 'abc123')
    assert.equal(Credential.parse(CREDENTIAL).hasCustody, true)
    assert.equal(Credential.parse(TWO_PART).hasCustody, false)
  })

  for (const bad of ['', 'nope', 'crs_sk_live_onepart', 'crs_sk_live_a.b.c.d', 'crs_sk_live_a..c']) {
    it(`refuses ${JSON.stringify(bad)}`, () => {
      assert.throws(() => Credential.parse(bad), CredentialFormatError)
    })
  }

  it('never appears in its string form', () => {
    // A credential in a log line is a credential that has to be rotated.
    const text = String(Credential.parse(CREDENTIAL))
    assert.ok(!text.includes('authsecretvalue'))
    assert.ok(!text.includes('custodysecretvalue'))
    assert.ok(text.includes('abc123'))
  })

  it('derives the custody public key locally', async () => {
    const expected = (await crypto.custodyKeypair('custodysecretvalue')).publicKeyB64url
    assert.equal(await Credential.parse(CREDENTIAL).custodyPublicKey(), expected)
  })

  it('has no custody keypair without a custody secret', async () => {
    await assert.rejects(() => Credential.parse(TWO_PART).custodyPublicKey(), CredentialFormatError)
  })

  it('never transmits the custody secret', async () => {
    // THE property of the split credential. The custody half exists so the server CANNOT
    // reconstruct the private key. If it reaches the wire that guarantee is gone.
    const { requests, fetchImpl } = recorder({ status: 201, body: { short_code: 'abc123' } })
    await client(fetchImpl).shares.create({ title: 't', fields: [FIELD] })

    const everything = JSON.stringify(requests[0])
    assert.ok(!everything.includes('custodysecretvalue'))
    assert.equal(requests[0].headers.authorization, `Bearer ${TWO_PART}`)
  })
})

// -- create ---------------------------------------------------------------------------

describe('create', () => {
  it('sends ciphertext and never the key', async () => {
    const { requests, fetchImpl } = recorder({ status: 201, body: { short_code: 'xy12' } })
    const share = await client(fetchImpl).shares.create({
      title: 'Staging deploy credentials',
      fields: [{ key: 'Password', value: 'correct horse', type: 'password' }],
    })

    const body = JSON.parse(requests[0].body!)
    assert.equal(body.encryption_type, 'e2ee-aes256-gcm')
    assert.ok(!requests[0].body!.includes('correct horse'))
    assert.ok(!requests[0].body!.includes(crypto.b64url(share.contentKey)))

    // But the blob must decrypt with the key the caller was handed.
    assert.deepEqual(await crypto.decryptContent(share.contentKey, body.data), [
      { key: 'Password', value: 'correct horse', type: 'password' },
    ])
  })

  it('puts the key in the link fragment', async () => {
    const { fetchImpl } = recorder({ status: 201, body: { short_code: 'xy12' } })
    const share = await client(fetchImpl).shares.create({ title: 't', fields: [FIELD] })
    assert.ok(share.link.startsWith('https://crs.sh/xy12#'))
    assert.deepEqual(crypto.decodeFragment(share.link.split('#')[1]), share.contentKey)
  })

  it('always sends an Idempotency-Key', async () => {
    // Required by the API. A retried automation must not silently create a second copy of a
    // credential in the world, with its own link and audit trail.
    const { requests, fetchImpl } = recorder({ status: 201, body: { short_code: 'xy12' } })
    await client(fetchImpl).shares.create({ title: 't', fields: [FIELD] })
    assert.ok(requests[0].headers['idempotency-key'])
  })

  it('sends a passcode verifier and never the passcode', async () => {
    const { requests, fetchImpl } = recorder({ status: 201, body: { short_code: 'xy12' } })
    await client(fetchImpl).shares.create({ title: 't', fields: [FIELD], passcode: 'hunter2' })
    const body = JSON.parse(requests[0].body!)
    assert.equal(body.passcode_verifier, await crypto.passcodeVerifier('hunter2'))
    assert.ok(!requests[0].body!.includes('hunter2'))
  })

  it('refuses a field using label before any request is made', async () => {
    const { requests, fetchImpl } = recorder({ status: 201, body: {} })
    await assert.rejects(
      () =>
        client(fetchImpl).shares.create({
          title: 't',
          fields: [{ label: 'Password', value: 'v', type: 'password' } as never],
        }),
      /the member is 'key'/,
    )
    assert.equal(requests.length, 0, 'nothing should have been sent')
  })
})

// -- idempotency ----------------------------------------------------------------------

describe('idempotency', () => {
  it('names a replayed key for what it is', async () => {
    // Passing the same key to two creates cannot work: each draws a fresh salt and IV, so
    // the bodies differ and the API refuses. The error has to say that, because "409
    // conflict" sends people looking for a duplicate share that does not exist.
    const { fetchImpl } = recorder({
      status: 409,
      body: { message: 'already used', error_code: 105 },
    })
    await assert.rejects(
      () => client(fetchImpl).shares.create({ title: 't', fields: [FIELD], idempotencyKey: 'fixed' }),
      IdempotencyConflictError,
    )
  })

  it('a supplied content key fixes the link but not the body', async () => {
    // The distinction a live run had to teach: a fixed content key gives both calls the same
    // link and access token, but the ciphertext still differs, because the salt and IV are
    // fresh every time and must be.
    const { requests, fetchImpl } = recorder([
      { status: 201, body: { short_code: 'xy12' } },
      { status: 201, body: { short_code: 'xy12' } },
    ])
    const crs = client(fetchImpl)
    const contentKey = new Uint8Array(32).map((_, i) => i)
    const a = await crs.shares.create({ title: 't', fields: [FIELD], contentKey })
    const b = await crs.shares.create({ title: 't', fields: [FIELD], contentKey })

    assert.equal(a.link, b.link)
    const [first, second] = requests.map((r) => JSON.parse(r.body!))
    assert.equal(first.access_token, second.access_token)
    assert.notEqual(first.data, second.data, 'a repeated IV would be the real bug here')
  })
})

// -- reads ----------------------------------------------------------------------------

describe('reads', () => {
  it('returns metadata only, with the paging figures attached', async () => {
    const { fetchImpl } = recorder({
      status: 200,
      body: {
        shares: [{ short_code: 'a1', expired_at: null }],
        pagination: { page: 1, limit: 2, total: 5, total_pages: 3 },
      },
    })
    const rows = await client(fetchImpl).shares.list({ limit: 2 })
    assert.equal(rows.shares[0].shortCode, 'a1')
    assert.equal(rows.total, 5)
    assert.equal(rows.hasMore, true)
    // An attribute that is always undefined reads as a broken field rather than an absent
    // one, so the API's silence about titles is reflected in the shape.
    assert.ok(!('title' in rows.shares[0]))
  })

  it('does not stop iterating on a short middle page', async () => {
    // The bug in every hand-rolled version of this loop. A server may return a page shorter
    // than the limit in the MIDDLE of a result set; stopping there silently truncates.
    const page = (codes: string[], p: number) => ({
      status: 200,
      body: {
        shares: codes.map((c) => ({ short_code: c })),
        pagination: { page: p, limit: 2, total: 5, total_pages: 3 },
      },
    })
    const { requests, fetchImpl } = recorder([page(['a1', 'a2'], 1), page(['b1'], 2), page(['c1', 'c2'], 3)])

    const seen: string[] = []
    for await (const row of client(fetchImpl).shares.iterateAll({ limit: 2 })) seen.push(row.shortCode)

    assert.deepEqual(seen, ['a1', 'a2', 'b1', 'c1', 'c2'])
    assert.equal(requests.length, 3)
  })

  it('issues a DELETE to expire, and carries no Idempotency-Key on it', async () => {
    // The header is asserted ABSENT, and that is the point of the assertion rather than an
    // omission from it. This call shipped at 0.1.4 as a bare DELETE; the endpoint does not
    // read the header, a repeated delete is idempotent by construction, and adding one would
    // change the bytes of a published call to buy nothing. The auto-key covers POST, PUT and
    // PATCH only.
    const { requests, fetchImpl } = recorder({ status: 200, body: {} })
    await client(fetchImpl).shares.expire('a1')
    assert.equal(requests[0].method, 'DELETE')
    assert.ok(requests[0].url.endsWith('/shares/a1'))
    assert.equal(requests[0].headers['idempotency-key'], undefined)
  })

  it('refuses the recipient read path with a reason', async () => {
    const { fetchImpl } = recorder({ status: 200, body: {} })
    await assert.rejects(() => client(fetchImpl).readLink('https://crs.sh/abc#1AAA'), /by design/)
  })
})

// -- errors imply remedies -------------------------------------------------------------

describe('errors', () => {
  const cases: Array<[number, Record<string, unknown>, new (...args: never[]) => Error]> = [
    [401, { message: 'bad credential' }, AuthenticationError],
    [403, { message: 'no api access' }, PermissionError],
    [403, { message: 'limit reached', error_code: 61 }, QuotaExceededError],
    [404, { message: 'not found' }, NotFoundError],
    [503, { message: 'unavailable' }, ServiceUnavailableError],
    [500, { message: 'boom' }, ApiError],
  ]

  for (const [status, body, expected] of cases) {
    it(`maps ${status}${body.error_code ? `/${String(body.error_code)}` : ''} to ${expected.name}`, async () => {
      const { fetchImpl } = recorder({ status, body })
      await assert.rejects(() => client(fetchImpl).shares.list(), expected)
    })
  }

  it('a spent quota is not a rate limit', async () => {
    // Both are refusals, but waiting fixes one and not the other.
    const { fetchImpl } = recorder({ status: 403, body: { message: 'limit', error_code: 61 } })
    await assert.rejects(
      () => client(fetchImpl).shares.list(),
      (error: Error) => error instanceof QuotaExceededError && !(error instanceof RateLimitError),
    )
  })

  it('exposes retryAfter on a rate limit', async () => {
    const { fetchImpl } = recorder({
      status: 429,
      body: { message: 'slow down' },
      headers: { 'retry-after': '42' },
    })
    await assert.rejects(
      () => client(fetchImpl).shares.list(),
      (error: Error) => error instanceof RateLimitError && error.retryAfter === 42,
    )
  })
})

// -- transport retries -----------------------------------------------------------------

describe('retries', () => {
  it('repeats a dropped connection with the byte-identical request', async () => {
    // The case the mandatory header exists for. The retry must repeat the identical body, or
    // the server sees a new one under a used key and refuses — turning a recoverable blip
    // into a hard failure.
    const seen: Recorded[] = []
    const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
      seen.push(recordOf(url, init))
      if (seen.length === 1) throw new TypeError('fetch failed')
      return new Response(JSON.stringify({ short_code: 'xy12' }), { status: 201 })
    }) as unknown as typeof globalThis.fetch

    const share = await new CredenShare(CREDENTIAL, { fetch: fetchImpl }).shares.create({
      title: 't',
      fields: [FIELD],
    })

    assert.equal(share.shortCode, 'xy12')
    assert.equal(seen.length, 2)
    assert.equal(seen[0].headers['idempotency-key'], seen[1].headers['idempotency-key'])
    assert.equal(seen[0].body, seen[1].body)
  })

  it('does not retry an HTTP 500', async () => {
    // It may have committed, and this client cannot tell. Retrying would risk a second copy
    // of a credential in the world under a caller who believes one was created.
    const { requests, fetchImpl } = recorder({ status: 500, body: { message: 'boom' } })
    await assert.rejects(() => client(fetchImpl).shares.create({ title: 't', fields: [FIELD] }), ApiError)
    assert.equal(requests.length, 1)
  })

  it('bounds retries and reports that nothing was ever sent', async () => {
    // NetworkError, not ServiceUnavailableError. A 503 is an answer from the API; this is
    // the absence of one, and only the first tells you the API decided anything.
    let attempts = 0
    const fetchImpl = (async () => {
      attempts += 1
      throw new TypeError('fetch failed')
    }) as unknown as typeof globalThis.fetch

    await assert.rejects(
      () => new CredenShare(CREDENTIAL, { fetch: fetchImpl, maxRetries: 1 }).shares.list(),
      NetworkError,
    )
    assert.equal(attempts, 2)
  })

  it('separates a delivered request whose body never arrived', async () => {
    // Headers arrived, so the server may have committed. Reporting that as "nothing was
    // created" is what makes a caller retry with a fresh key and end up with two secrets.
    let attempts = 0
    const fetchImpl = (async () => {
      attempts += 1
      return new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error('connection reset mid-body'))
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )
    }) as unknown as typeof globalThis.fetch

    await assert.rejects(
      () => new CredenShare(CREDENTIAL, { fetch: fetchImpl, maxRetries: 1 }).shares.list(),
      DeliveryUnknownError,
    )
    assert.equal(attempts, 2)
  })

  it('refuses a wrong-length content key before anything reaches the network', async () => {
    // The only length check used to be in encodeFragment, which runs after the POST: the
    // share existed on the server, holding a real secret, and the caller lost its short code.
    const { requests, fetchImpl } = recorder({
      status: 201,
      body: { short_code: 'aB3dEf12' },
    })
    await assert.rejects(
      () =>
        client(fetchImpl).shares.create({
          title: 't',
          fields: [FIELD],
          contentKey: new Uint8Array(16),
        }),
      MalformedKeyError,
    )
    assert.equal(requests.length, 0, 'no request may be made for a key that cannot work')
  })

  it('does not print the link or the key when logged', async () => {
    const { fetchImpl } = recorder({ status: 201, body: { short_code: 'aB3dEf12' } })
    const share = await client(fetchImpl).shares.create({ title: 't', fields: [FIELD] })

    const fragment = share.link.split('#')[1]
    assert.ok(fragment && fragment.length > 10)
    for (const rendered of [
      String(share),
      JSON.stringify(share),
      inspect(share),
      inspect({ share }),
    ]) {
      assert.ok(!rendered.includes(fragment), `the key fragment leaked into ${rendered}`)
    }
    // The properties are still reachable by name - this redacts rendering, not access.
    assert.ok(share.link.includes('#'))
    assert.equal(share.contentKey.length, 32)
  })

  it('surfaces the idempotency key it generated', async () => {
    const { requests, fetchImpl } = recorder({ status: 201, body: { short_code: 'aB3dEf12' } })
    const share = await client(fetchImpl).shares.create({ title: 't', fields: [FIELD] })

    // The documented recovery is to repeat the identical request with the same key, which
    // is impossible for a key the caller was never told.
    assert.equal(typeof share.idempotencyKey, 'string')
    assert.equal(requests[0].headers['idempotency-key'], share.idempotencyKey)
  })

  it("uses the server's echoed limit, not the caller's, to decide hasMore", async () => {
    // A server free to cap page size returns fewer rows than asked for on a page that is
    // nonetheless full. Comparing against the REQUEST makes that look like the end of the
    // result set, and iterateAll stops with most of the account unvisited.
    const pages = [
      { shares: Array.from({ length: 50 }, (_, i) => ({ short_code: `a${i}` })), pagination: { page: 1, limit: 50 } },
      { shares: Array.from({ length: 20 }, (_, i) => ({ short_code: `b${i}` })), pagination: { page: 2, limit: 50 } },
    ]
    // A fresh stub per assertion: the two walks must not share a page cursor.
    const stub = () => {
      let call = 0
      return (async () =>
        new Response(JSON.stringify(pages[Math.min(call++, pages.length - 1)]), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })) as unknown as typeof globalThis.fetch
    }

    const first = await new CredenShare(CREDENTIAL, { fetch: stub() }).shares.list({ limit: 100 })
    assert.equal(first.limit, 50, 'the page reports the limit the server applied')
    assert.equal(first.hasMore, true, 'a full 50-row page under a server cap is not the end')

    const seen: string[] = []
    const walker = new CredenShare(CREDENTIAL, { fetch: stub() }).shares
    for await (const s of walker.iterateAll({ limit: 100 })) seen.push(s.shortCode)
    assert.equal(seen.length, 70, 'iterateAll must not stop at the server-capped first page')
  })

  it('surfaces the server per-field detail on a validation error', async () => {
    // Without this a 4xx never names the field it rejected, and for a create the only way to
    // find out is to encrypt and send the secret a second time.
    const { fetchImpl } = recorder({
      status: 400,
      body: {
        message: 'invalid request',
        error_code: 7,
        additional_data: { field: 'expired_at', reason: 'must be in the future' },
      },
    })
    await assert.rejects(
      () => client(fetchImpl).shares.create({ title: 't', fields: [FIELD] }),
      (error: unknown) => {
        assert.ok(error instanceof ApiError)
        assert.deepEqual(error.additionalData, {
          field: 'expired_at',
          reason: 'must be in the future',
        })
        return true
      },
    )
  })

  it('terminates when the server echoes limit: 0', async () => {
    // The regression the previous fix introduced: resolvedLimit became 0, `rows.length >= 0`
    // was true for every page including empty ones, and iterateAll issued requests forever.
    // Silent truncation traded for a non-terminating loop is not an improvement.
    let calls = 0
    const fetchImpl = (async () => {
      calls += 1
      if (calls > 10) throw new Error('iterateAll is looping: ' + calls + ' requests')
      const body = { shares: [{ short_code: 'a' }], pagination: { page: calls, limit: 0, total: 120 } }
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }) as unknown as typeof globalThis.fetch

    const shares = new CredenShare(CREDENTIAL, { fetch: fetchImpl }).shares
    const seen: string[] = []
    for await (const s of shares.iterateAll({ limit: 50 })) seen.push(s.shortCode)
    // limit: 0 is ignored, so the caller's 50 governs: 1*50 < 120, 2*50 < 120, 3*50 !< 120.
    assert.ok(calls <= 10, `must terminate promptly, made ${calls} requests`)
    assert.ok(seen.length >= 1)
  })

  it('uses total when total_pages is absent', async () => {
    // The middle rung of the ladder. A server capping pages to 30 while reporting total: 120
    // and echoing limit: 50 must not read as the end after one page.
    let calls = 0
    const fetchImpl = (async () => {
      calls += 1
      const rows = calls <= 4
        ? Array.from({ length: 30 }, (_, i) => ({ short_code: `p${calls}r${i}` }))
        : []
      const body = { shares: rows, pagination: { page: calls, limit: 30, total: 120 } }
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }) as unknown as typeof globalThis.fetch

    const first = await new CredenShare(CREDENTIAL, { fetch: fetchImpl }).shares.list({ limit: 50 })
    assert.equal(first.hasMore, true, 'page 1 of 120 rows at 30 per page is not the end')

    calls = 0
    const shares = new CredenShare(CREDENTIAL, { fetch: fetchImpl }).shares
    const seen: string[] = []
    for await (const s of shares.iterateAll({ limit: 50 })) seen.push(s.shortCode)
    assert.equal(seen.length, 120, 'the whole account must be walked')
  })

  it('refuses a server that echoes a constant page number', async () => {
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          shares: [{ short_code: 'a' }, { short_code: 'b' }],
          pagination: { page: 1, limit: 2, total_pages: 9 },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )) as unknown as typeof globalThis.fetch

    const shares = new CredenShare(CREDENTIAL, { fetch: fetchImpl }).shares
    await assert.rejects(
      async () => {
        let guard = 0
        for await (const _ of shares.iterateAll({ limit: 2 })) {
          if (++guard > 500) throw new Error('looping instead of erroring')
        }
      },
      (e: unknown) => {
        assert.ok(e instanceof ApiError)
        assert.match(String(e), /page/)
        return true
      },
    )
  })

  it('refuses a non-object additional_data rather than mistyping it', async () => {
    // typeof [] === 'object'. Without the Array check an array arrives behind a declared
    // Record<string, unknown>, and nothing downstream can detect it.
    for (const value of [['a', 'b'], 'a string', 42] as unknown[]) {
      const { fetchImpl } = recorder({
        status: 400,
        body: { message: 'invalid', additional_data: value },
      })
      await assert.rejects(
        () => client(fetchImpl).shares.create({ title: 't', fields: [FIELD] }),
        (error: unknown) => {
          assert.ok(error instanceof ApiError)
          assert.equal(error.additionalData, undefined, `accepted ${JSON.stringify(value)}`)
          return true
        },
      )
    }
  })

  it('leaves additionalData undefined when the body has no such key', async () => {
    const { fetchImpl } = recorder({ status: 400, body: { message: 'invalid' } })
    await assert.rejects(
      () => client(fetchImpl).shares.create({ title: 't', fields: [FIELD] }),
      (error: unknown) => {
        assert.ok(error instanceof ApiError)
        assert.equal(error.additionalData, undefined)
        return true
      },
    )
  })

  it('keeps paging when the server omits total_pages', async () => {
    // Treating an absent pagination block as "no more" made iterateAll return page one and
    // stop, silently reporting a fraction of the account as all of it.
    const pages = [
      { shares: [{ short_code: 'a' }, { short_code: 'b' }] },
      { shares: [{ short_code: 'c' }] },
    ]
    let call = 0
    const fetchImpl = (async () =>
      new Response(JSON.stringify(pages[Math.min(call++, pages.length - 1)]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as unknown as typeof globalThis.fetch

    const seen: string[] = []
    const shares = new CredenShare(CREDENTIAL, { fetch: fetchImpl }).shares
    for await (const summary of shares.iterateAll({ limit: 2 })) {
      seen.push(summary.shortCode)
    }
    assert.deepEqual(seen, ['a', 'b', 'c'])
  })
})

describe('the package version', () => {
  it('matches package.json', () => {
    // VERSION is a second copy of a number that also lives in package.json, so it drifts: it
    // said '0.1.0' while 0.1.3 was on npm. The release guard compared the TAG to package.json
    // and never to this, so nothing noticed. Now something does, and it runs in the release
    // verification too.
    const manifest = JSON.parse(
      readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
    ) as { version: string }
    assert.equal(VERSION, manifest.version, 'src/index.ts VERSION has drifted from package.json')
  })
})
