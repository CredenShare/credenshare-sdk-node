/**
 * Secure requests, submissions and stats, against a stub fetch.
 *
 * The properties worth testing here are the ones where being wrong is silent. A request
 * whose seed reached the server still works — it returns a 201, collects submissions and
 * renders correctly, and is simply no longer zero-knowledge. A submission decoded with the
 * wrong base64 alphabet fails as "wrong key" rather than as "wrong decoder". Neither shows
 * up in a happy-path integration run, so both are asserted directly.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { inspect } from 'node:util'

import { CredenShare } from '../src/client.js'
import * as crypto from '../src/crypto.js'
import {
  ApiError,
  InvalidFieldError,
  MalformedKeyError,
  RequestSeedTransmittedError,
  WireFormatError,
} from '../src/errors.js'
import { CREDENTIAL, client, recorder } from './harness.js'

const PROMPT = { item: 'Staging database password', type: 'password' as const }

/** A fixed seed, so a body can be compared byte for byte across two calls. */
const FIXED_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff)

const created = (shortCode = 'xy12') => ({
  status: 201,
  body: { short_code: shortCode, expired_at: null },
})

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function* forIn(value: object): Generator<string> {
  for (const key in value) yield key
}

/**
 * Whether a rendering contains the seed in ANY spelling it could be printed in.
 *
 * The decimal-run check is the one that matters and the one a hand-written version omits.
 * `util.inspect` wraps a Uint8Array into columns, so a rendering that shows all 32 bytes
 * contains no base64, no hex, and no contiguous `Array.from(seed).join(', ')` substring
 * either — `inspect(seed)` on its own is enough to demonstrate it. A spelling-only search
 * calls that CLEAN while the leak it exists to catch is happening. So the bytes are also
 * looked for as a contiguous run of integers, however inspect chose to wrap them.
 */
function containsSeed(rendered: string, seed: Uint8Array): boolean {
  const spellings = [
    crypto.b64url(seed),
    crypto.b64(seed).replace(/=+$/, ''),
    crypto.b64(seed),
    hex(seed),
    hex(seed).toUpperCase(),
    Array.from(seed, (b) => b.toString(16).padStart(2, '0')).join(' '),
  ]
  if (spellings.some((spelling) => rendered.includes(spelling))) return true

  const numbers = (rendered.match(/\d+/g) ?? []).map(Number)
  outer: for (let i = 0; i + seed.length <= numbers.length; i++) {
    for (let j = 0; j < seed.length; j++) if (numbers[i + j] !== seed[j]) continue outer
    return true
  }
  return false
}

/**
 * Seal a field array to a request's public key exactly as a submitter's browser does:
 * the section 4 wrap, emitted as STANDARD base64.
 */
async function sealTo(publicKeyB64url: string, fields: crypto.Field[]): Promise<string> {
  return crypto.wrapToPublicKey(
    new TextEncoder().encode(JSON.stringify(fields)),
    crypto.unb64url(publicKeyB64url),
  )
}

// -- create ---------------------------------------------------------------------------

describe('creating a secure request', () => {
  it('sends the public half and never the seed', async () => {
    // THE property of the feature. A request whose seed reached the server still works in
    // every visible way and is simply no longer zero-knowledge, so nothing but an assertion
    // like this one would ever notice.
    const { requests, fetchImpl } = recorder(created())
    const request = await client(fetchImpl).requests.create({
      title: 'Onboarding credentials',
      fields: [PROMPT],
    })

    assert.equal(request.seed.length, 32)
    const everything = JSON.stringify(requests[0])
    for (const rendering of [
      crypto.b64url(request.seed),
      crypto.b64(request.seed),
      hex(request.seed),
    ]) {
      assert.ok(!everything.includes(rendering), 'the seed reached the wire')
    }

    // And the public half that was sent is the one the seed derives.
    const body = JSON.parse(requests[0].body!)
    assert.equal(body.public_key, (await crypto.keypairFromSeed(request.seed)).publicKeyB64url)
  })

  it('sends the public key as unpadded base64url', async () => {
    // The other half of the encoding trap. 65 raw bytes are 87 base64url characters with no
    // padding; the server's own validator rejects anything that is not a P-256 point, and a
    // standard-alphabet key with '=' on the end is not one.
    const { requests, fetchImpl } = recorder(created())
    await client(fetchImpl).requests.create({ title: 't', fields: [PROMPT] })

    const body = JSON.parse(requests[0].body!)
    assert.match(body.public_key, /^[A-Za-z0-9_-]{87}$/)
    assert.ok(!body.public_key.includes('='))
    assert.equal(crypto.unb64url(body.public_key).length, 65)
    assert.equal(crypto.unb64url(body.public_key)[0], 0x04)
  })

  it('accepts a caller-supplied seed and stays reproducible', async () => {
    // The custody-derived case: a runner that wants the same keypair on every container
    // passes its own seed, and the request body is then byte-identical — which is what makes
    // repeating a create under one idempotency key a replay rather than a conflict.
    const { requests, fetchImpl } = recorder([created(), created()])
    const crs = client(fetchImpl)
    const a = await crs.requests.create({ title: 't', fields: [PROMPT], seed: FIXED_SEED })
    const b = await crs.requests.create({ title: 't', fields: [PROMPT], seed: FIXED_SEED })

    assert.deepEqual(a.seed, FIXED_SEED)
    assert.equal(a.publicKey, b.publicKey)
    assert.equal(requests[0].body, requests[1].body, 'a supplied seed must fix the body')
  })

  it('refuses a wrong-length seed before anything reaches the network', async () => {
    const { requests, fetchImpl } = recorder(created())
    await assert.rejects(
      () =>
        client(fetchImpl).requests.create({
          title: 't',
          fields: [PROMPT],
          seed: new Uint8Array(16),
        }),
      MalformedKeyError,
    )
    assert.equal(requests.length, 0, 'no request may be made for a seed that cannot work')
  })

  it('refuses a share-shaped field before anything reaches the network', async () => {
    // The easy mistake, because this one SDK carries both spellings: a share's field labels
    // itself `key` and a request's prompt is `item`. The wrong one creates a live collect
    // link whose form has no prompts on it.
    const { requests, fetchImpl } = recorder(created())
    await assert.rejects(
      () =>
        client(fetchImpl).requests.create({
          title: 't',
          fields: [{ key: 'Password', value: 'v', type: 'password' } as never],
        }),
      (error: unknown) => {
        assert.ok(error instanceof InvalidFieldError)
        assert.match(String(error), /member is 'item'/)
        return true
      },
    )
    assert.equal(requests.length, 0, 'nothing should have been sent')
  })

  it('refuses an empty field list, which the API would accept', async () => {
    // A 201 and a live short code, and then "Unable to Load Request" for whoever it was sent
    // to. The server permits it; this client does not.
    const { requests, fetchImpl } = recorder(created())
    await assert.rejects(
      () => client(fetchImpl).requests.create({ title: 't', fields: [] }),
      InvalidFieldError,
    )
    assert.equal(requests.length, 0)
  })

  it('catches a seed smuggled into the body through another field', async () => {
    // The boundary assertion, not the field list. This is the failure mode the field list
    // cannot see: the seed is in the body, just not under a member called `seed`.
    const { requests, fetchImpl } = recorder(created())
    await assert.rejects(
      () =>
        client(fetchImpl).requests.create({
          title: crypto.b64url(FIXED_SEED),
          fields: [PROMPT],
          seed: FIXED_SEED,
        }),
      RequestSeedTransmittedError,
    )
    assert.equal(requests.length, 0, 'the body must not be sent once the seed is in it')
  })

  it('catches a seed passed as the Idempotency-Key, which travels as a header', async () => {
    // The body is not the only thing that goes on the wire, and the assertion used to scan
    // only the body. `seed` and `idempotencyKey` are adjacent members of the same options
    // object, the reproducible-keypair recipe pushes callers towards determinism, and a
    // caller who wants a deterministic KEY to match their deterministic SEED has the seed in
    // hand — so this is the shape the mistake actually takes.
    const { requests, fetchImpl } = recorder(created())
    await assert.rejects(
      () =>
        client(fetchImpl).requests.create({
          title: 't',
          fields: [PROMPT],
          seed: FIXED_SEED,
          idempotencyKey: crypto.b64url(FIXED_SEED),
        }),
      RequestSeedTransmittedError,
    )
    assert.equal(requests.length, 0, 'nothing may be sent once the seed is in a header')
  })

  it('catches the unpadded standard-base64 spelling of a seed', async () => {
    // The renderings list read as complete at three entries while covering two spellings:
    // base64url, and standard base64 WITH padding. 32 bytes are 43 characters plus one '=',
    // so a 43-character standard-base64 seed matched neither — unless its alphabet happened
    // to contain no '+' or '/', which is the only reason the gap was ever invisible. This
    // seed's alphabet does contain one.
    const seed = new Uint8Array(32).fill(0xff)
    const unpadded = crypto.b64(seed).replace(/=+$/, '')
    assert.ok(unpadded.includes('/'), 'this seed must exercise the standard alphabet')
    assert.ok(!unpadded.endsWith('='))
    assert.notEqual(unpadded, crypto.b64url(seed))

    const { requests, fetchImpl } = recorder(created())
    await assert.rejects(
      () => client(fetchImpl).requests.create({ title: unpadded, fields: [PROMPT], seed }),
      RequestSeedTransmittedError,
    )
    assert.equal(requests.length, 0)
  })

  it('always sends an Idempotency-Key and surfaces the one it generated', async () => {
    // A duplicate collect link is not inert the way a duplicate share is: a human can fill
    // it in. And the documented recovery is to repeat the request with the SAME key, which
    // is impossible for a key the caller was never told.
    const { requests, fetchImpl } = recorder(created())
    const request = await client(fetchImpl).requests.create({ title: 't', fields: [PROMPT] })
    assert.ok(requests[0].headers['idempotency-key'])
    assert.equal(requests[0].headers['idempotency-key'], request.idempotencyKey)
  })

  it('builds both links, and the access link carries the seed', async () => {
    const { fetchImpl } = recorder(created('aB3dEf12'))
    const request = await client(fetchImpl).requests.create({ title: 't', fields: [PROMPT] })

    assert.equal(request.collectLink, 'https://crs.sh/r/aB3dEf12')
    assert.ok(request.accessLink.startsWith('https://crs.sh/r/aB3dEf12#'))
    // The fragment is the whole private key, so it must round-trip exactly.
    assert.deepEqual(crypto.decodeFragment(request.accessLink.split('#')[1]), request.seed)
    // The collect link is keyless on purpose: holding it lets you submit, never read.
    assert.ok(!request.collectLink.includes('#'))
  })

  it('does not print the seed or the access link on any reflexive path', async () => {
    // Every path a TypeScript developer reaches for without thinking about it, including the
    // two a hand-written String()/inspect() check does not actually exercise: template
    // interpolation, and console.log — which ignores toJSON and goes through util.inspect,
    // which is why the class carries an inspect symbol as well as toJSON and toString.
    const { fetchImpl } = recorder(created())
    const request = await client(fetchImpl).requests.create({ title: 't', fields: [PROMPT] })

    const fragment = request.accessLink.split('#')[1]
    assert.ok(fragment && fragment.length > 10)

    const captured: string[] = []
    const stdout = process.stdout as unknown as { write: (chunk: unknown) => boolean }
    const realWrite = stdout.write.bind(process.stdout)
    stdout.write = (chunk: unknown) => {
      captured.push(String(chunk))
      return true
    }
    try {
      console.log(request)
      console.log({ nested: request })
      console.log('%s', request)
      console.log('%o', request)
      console.log(`${request}`)
      // The two that ignore all three redaction hooks, and printed the seed's 32 bytes and
      // the access link in full until `seed` and `accessLink` became private fields:
      // console.dir passes customInspect: false, and console.table builds its columns from
      // own properties without asking the value anything.
      console.dir(request, { depth: null })
      console.table(request)
      console.table([request])
    } finally {
      stdout.write = realWrite
    }
    assert.ok(captured.length >= 8, 'the console output must actually have been captured')

    // Not own properties at all, which is what makes the two paths above safe rather than
    // merely redacted: there is nothing for an enumerator to find.
    assert.deepEqual(Object.keys(request), [
      'shortCode',
      'publicKey',
      'collectLink',
      'expiredAt',
      'idempotencyKey',
    ])
    assert.deepEqual([...forIn(request)], Object.keys(request))
    assert.equal(
      Object.getOwnPropertyDescriptor(request, 'seed'),
      undefined,
      'seed must not be an own property',
    )

    for (const rendered of [
      String(request),
      JSON.stringify(request),
      JSON.stringify({ nested: [request] }),
      JSON.stringify({ ...request }),
      `${request}`,
      inspect(request),
      inspect({ request }),
      inspect({ ...request }, { depth: null }),
      inspect(structuredClone(request), { depth: null }),
      inspect(Object.getOwnPropertyDescriptors(request), { depth: null }),
      inspect(request, { depth: null, showHidden: true }),
      inspect(request, { customInspect: false, depth: null }),
      inspect(request, { customInspect: false, showHidden: true, depth: null }),
      // `getters: true` alone does not reach a prototype accessor: without showHidden,
      // util.inspect walks own properties only. Asserted so that the caveat documented on
      // `SecureRequest.seed` stays precise about which flags are load-bearing.
      inspect(request, { getters: true, depth: null }),
      inspect(request, { getters: true, customInspect: false, depth: null }),
      inspect(request, { getters: true, showHidden: true, depth: null }),
      ...captured,
    ]) {
      assert.ok(!rendered.includes(fragment), `the access link leaked into ${rendered}`)
      assert.ok(!containsSeed(rendered, request.seed), `the seed leaked into ${rendered}`)
    }
    // Redacts rendering, not access. The collect link is safe and stays visible.
    assert.equal(request.seed.length, 32)
    assert.ok(JSON.stringify(request).includes(request.collectLink))
  })

  it('DOES print the seed under getters + showHidden + customInspect:false', async () => {
    // The one documented exception, asserted rather than merely written down, so that the
    // doc comment on `SecureRequest.seed` and the README section cannot quietly become
    // wrong in either direction.
    //
    // If this test ever FAILS, the leak was closed and both of those texts need updating —
    // it is not a regression. All three flags are required: the two earlier assertions in
    // the test above pin the two-flag combinations as clean.
    const { fetchImpl } = recorder(created())
    const request = await client(fetchImpl).requests.create({ title: 't', fields: [PROMPT] })

    const rendered = inspect(request, {
      getters: true,
      showHidden: true,
      customInspect: false,
      depth: null,
    })
    assert.ok(
      containsSeed(rendered, request.seed),
      'the documented caveat no longer reproduces; update the seed getter doc and the README',
    )
    assert.ok(rendered.includes(request.accessLink.split('#')[1]), 'the access link too')
  })
})

// -- reads and paging -----------------------------------------------------------------

describe('reading secure requests', () => {
  it('returns metadata with the paging figures attached', async () => {
    const { fetchImpl } = recorder({
      status: 200,
      body: {
        requests: [{ short_code: 'a1', expired_at: null, public_key: 'BJ...' }],
        pagination: { page: 1, limit: 2, total: 5, total_pages: 3 },
      },
    })
    const page = await client(fetchImpl).requests.list({ limit: 2 })
    assert.equal(page.requests[0].shortCode, 'a1')
    // The PUBLIC half comes back, unlike a share's key material, so a caller can confirm
    // what was stored.
    assert.equal(page.requests[0].publicKey, 'BJ...')
    assert.equal(page.total, 5)
    assert.equal(page.hasMore, true)
  })

  it('does not stop iterating on a short middle page', async () => {
    // The same walk the shares list uses, and the same bug it exists to avoid: a server may
    // return a page shorter than the limit in the MIDDLE of a result set.
    const page = (codes: string[], p: number) => ({
      status: 200,
      body: {
        requests: codes.map((c) => ({ short_code: c })),
        pagination: { page: p, limit: 2, total: 5, total_pages: 3 },
      },
    })
    const { requests, fetchImpl } = recorder([
      page(['a1', 'a2'], 1),
      page(['b1'], 2),
      page(['c1', 'c2'], 3),
    ])

    const seen: string[] = []
    for await (const row of client(fetchImpl).requests.iterateAll({ limit: 2 })) {
      seen.push(row.shortCode)
    }
    assert.deepEqual(seen, ['a1', 'a2', 'b1', 'c1', 'c2'])
    assert.equal(requests.length, 3)
  })

  it('refuses a server that echoes a constant page number', async () => {
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          requests: [{ short_code: 'a' }, { short_code: 'b' }],
          pagination: { page: 1, limit: 2, total_pages: 9 },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )) as unknown as typeof globalThis.fetch

    await assert.rejects(
      async () => {
        let guard = 0
        for await (const _ of client(fetchImpl).requests.iterateAll({ limit: 2 })) {
          if (++guard > 500) throw new Error('looping instead of erroring')
        }
      },
      (error: unknown) => {
        assert.ok(error instanceof ApiError)
        assert.match(String(error), /page/)
        return true
      },
    )
  })

  it('falls back to the path short code without inventing one', async () => {
    const { requests, fetchImpl } = recorder({ status: 200, body: { expired_at: null } })
    const summary = await client(fetchImpl).requests.get('aB3dEf12')
    assert.equal(summary.shortCode, 'aB3dEf12')
    assert.equal(summary.publicKey, null)
    assert.ok(requests[0].url.endsWith('/requests/aB3dEf12'))
  })

  it('reports which of expire-then-delete happened', async () => {
    // Two steps, and they are not interchangeable: the first preserves the submissions
    // already received and the second destroys them.
    const { requests, fetchImpl } = recorder([
      { status: 200, body: { short_code: 'a1', outcome: 'expired' } },
      { status: 200, body: { short_code: 'a1', outcome: 'deleted' } },
    ])
    const crs = client(fetchImpl)
    assert.equal((await crs.requests.delete('a1')).outcome, 'expired')
    assert.equal((await crs.requests.delete('a1')).outcome, 'deleted')
    assert.equal(requests[0].method, 'DELETE')
    assert.ok(requests[0].url.endsWith('/requests/a1'))
    // No Idempotency-Key on a DELETE. The auto-key covers POST, PUT and PATCH only.
    assert.equal(requests[0].headers['idempotency-key'], undefined)
  })

  it('reads an unrecognised or absent outcome as null', async () => {
    // Not as the less destructive of the two, which is what it used to do behind a closed
    // 'expired' | 'deleted' union. An outcome this SDK invented is then indistinguishable
    // from one the server sent, on the only destructive call in this surface — and a TS union
    // cannot be widened after publication without breaking every consumer.
    const absent = recorder({ status: 200, body: { short_code: 'a1' } })
    assert.equal((await client(absent.fetchImpl).requests.delete('a1')).outcome, null)
    const unknown = recorder({ status: 200, body: { short_code: 'a1', outcome: 'vanished' } })
    assert.equal((await client(unknown.fetchImpl).requests.delete('a1')).outcome, null)
  })
})

// -- submissions ----------------------------------------------------------------------

describe('submissions', () => {
  it('round-trips a sealed submission through the seed', async () => {
    // The composition story end to end: a submitter seals to the published public key, the
    // API hands back something it cannot open, and the seed opens it here.
    const fields: crypto.Field[] = [
      { key: 'Staging database password', value: 'correct horse battery', type: 'password' },
      { key: 'Host', value: 'db.internal.example', type: 'text' },
    ]

    const { fetchImpl } = recorder(created())
    const crs = client(fetchImpl)
    const request = await crs.requests.create({ title: 't', fields: [PROMPT] })
    const blob = await sealTo(request.publicKey, fields)

    const reader = recorder({
      status: 200,
      body: {
        submissions: [
          {
            short_code: 's1',
            created_at: '2026-01-01T00:00:00Z',
            data: blob,
            encryption_type: 'e2ee-aes256-gcm',
          },
        ],
      },
    })
    const page = await client(reader.fetchImpl).requests.submissions(request.shortCode)

    // Sealed on arrival, verbatim. Decrypting on fetch would put every credential a human
    // handed over into memory for a caller who only wanted to count them.
    assert.equal(page.submissions[0].data, blob)
    assert.equal(page.submissions[0].shortCode, 's1')

    const opened = await client(reader.fetchImpl).requests.decryptSubmission(
      page.submissions[0],
      request.seed,
    )
    assert.deepEqual(opened, fields)
  })

  it('opens a bare blob too, and refuses the wrong seed', async () => {
    const seed = crypto.newSeed()
    const other = crypto.newSeed()
    const keypair = await crypto.keypairFromSeed(seed)
    const fields: crypto.Field[] = [{ key: 'k', value: 'v', type: 'text' }]
    const blob = await sealTo(keypair.publicKeyB64url, fields)

    assert.deepEqual(await crypto.decryptSubmission(blob, seed), fields)
    // A wrong seed and an altered blob are indistinguishable, deliberately.
    await assert.rejects(() => crypto.decryptSubmission(blob, other), WireFormatError)
  })

  it('refuses a blob handed over in the wrong base64 alphabet', async () => {
    // THE encoding trap. A submission's data is STANDARD base64 and a request's public key
    // is base64url; they are two halves of one feature. Re-encoding the blob the other way
    // has to fail as bad input, not as a decryption failure that sends somebody hunting for
    // a wrong key.
    const seed = crypto.newSeed()
    const keypair = await crypto.keypairFromSeed(seed)
    const blob = await sealTo(keypair.publicKeyB64url, [{ key: 'k', value: 'v', type: 'text' }])
    const mangled = crypto.b64url(crypto.unb64(blob))

    assert.notEqual(mangled, blob, 'the two encodings must actually differ')
    await assert.rejects(
      () => crypto.decryptSubmission(mangled, seed),
      (error: unknown) => {
        assert.ok(error instanceof WireFormatError)
        assert.match(String(error), /base64/)
        return true
      },
    )
  })

  it('surfaces the submissions the server withheld', async () => {
    // A pre-E2EE request collects server-encrypted submissions, and returning those over a
    // bearer-authenticated API would make this the one place a credential yields readable
    // secrets. They are withheld and counted, so a short page is not read as the end.
    const { fetchImpl } = recorder({
      status: 200,
      body: {
        submissions: [{ short_code: 's1', data: 'AAAA' }],
        skipped_not_end_to_end_encrypted: 4,
      },
    })
    const page = await client(fetchImpl).requests.submissions('a1')
    assert.equal(page.skippedNotEndToEndEncrypted, 4)
    assert.equal(page.submissions.length, 1)
  })

  it('leaves the withheld count undefined when the server sent none', async () => {
    const { fetchImpl } = recorder({ status: 200, body: { submissions: [] } })
    const page = await client(fetchImpl).requests.submissions('a1')
    assert.equal(page.skippedNotEndToEndEncrypted, undefined)
    assert.deepEqual(page.submissions, [])
    assert.equal(page.count, undefined)
  })

  it('makes ONE call for the whole set and stops', async () => {
    // THE regression, and the reason this file exists in its current form. The deployed
    // handler ignores `page` and `limit` and answers `{submissions, count}` with no
    // pagination block, so the shared paging ladder's last rung — "a page as long as the
    // limit means there is more" — was true forever: the walk re-requested page one up to
    // MAX_PAGES times, handing every sealed submission back on each pass, and then threw.
    // A request holding at least the walk's own page size was all it took.
    const rows = Array.from({ length: 100 }, (_, i) => ({
      short_code: `s${i}`,
      created_at: '2026-01-01T00:00:00Z',
      data: 'AAAA',
      encryption_type: 'e2ee-aes256-gcm',
    }))
    const { requests, fetchImpl } = recorder({
      status: 200,
      body: { submissions: rows, count: rows.length },
    })

    const seen: string[] = []
    for await (const row of client(fetchImpl).requests.iterateSubmissions('a1')) {
      seen.push(row.shortCode)
      if (seen.length > 200) throw new Error('looping instead of stopping')
    }
    assert.equal(seen.length, 100)
    assert.deepEqual(seen.slice(0, 2), ['s0', 's1'])
    assert.equal(requests.length, 1, 'not paginated: one call is the whole answer')
    assert.ok(requests[0].url.includes('/requests/a1/submissions'))
    // And neither figure is sent, because the handler reads neither.
    assert.ok(!requests[0].url.includes('page='), 'page is not a parameter of this endpoint')
    assert.ok(!requests[0].url.includes('limit='), 'limit is not a parameter of this endpoint')
  })

  it('surfaces the API count and attaches no paging envelope', async () => {
    const { fetchImpl } = recorder({
      status: 200,
      body: { submissions: [{ short_code: 's1', data: 'AAAA' }], count: 1 },
    })
    const all = await client(fetchImpl).requests.submissions('a1')
    assert.equal(all.count, 1)
    assert.equal(all.submissions.length, 1)
    // Nothing that reads as an invitation to ask for a second page, because there is none.
    for (const absent of ['page', 'limit', 'total', 'totalPages', 'hasMore']) {
      assert.ok(!(absent in all), `${absent} has no meaning on an unpaginated answer`)
    }
  })

  it('ignores a pagination block this endpoint never sends', async () => {
    // Belt and braces. openapi.yaml documents a paging envelope here and the handler does not
    // send one; if some future gateway ever did, one answer is still one answer.
    const { requests, fetchImpl } = recorder({
      status: 200,
      body: {
        submissions: [
          { short_code: 's1', data: 'AAAA' },
          { short_code: 's2', data: 'AAAA' },
        ],
        count: 2,
        pagination: { page: 1, limit: 2, total: 9, total_pages: 5 },
      },
    })

    const seen: string[] = []
    for await (const row of client(fetchImpl).requests.iterateSubmissions('a1')) {
      seen.push(row.shortCode)
      if (seen.length > 50) throw new Error('looping instead of stopping')
    }
    assert.deepEqual(seen, ['s1', 's2'])
    assert.equal(requests.length, 1)
  })
})

// -- stats ----------------------------------------------------------------------------

describe('stats', () => {
  it('maps the counts and the daily series', async () => {
    const { requests, fetchImpl } = recorder({
      status: 200,
      body: {
        shares: { active: 12, expired: 3, total_viewed: 47 },
        daily_views: [
          { date: '2026-08-31', count: 0 },
          { date: '2026-09-01', count: 5 },
        ],
      },
    })
    const stats = await client(fetchImpl).stats.get()
    assert.deepEqual(stats.shares, { active: 12, expired: 3, totalViewed: 47 })
    assert.deepEqual(stats.dailyViews, [
      { date: '2026-08-31', count: 0 },
      { date: '2026-09-01', count: 5 },
    ])
    assert.ok(requests[0].url.endsWith('/stats'))
    assert.equal(requests[0].method, 'GET')
  })

  it('reads absent figures as zero and an absent series as empty', async () => {
    // Not as undefined. A caller has to distinguish "no data" from "field absent" otherwise,
    // and will get it wrong — a new account genuinely has no views yet.
    const { fetchImpl } = recorder({ status: 200, body: {} })
    const stats = await client(fetchImpl).stats.get()
    assert.deepEqual(stats.shares, { active: 0, expired: 0, totalViewed: 0 })
    assert.deepEqual(stats.dailyViews, [])
  })
})

// -- the escape hatch ------------------------------------------------------------------

/** A fetch that records the header object exactly as it was handed over, spellings intact. */
function rawHeaderRecorder(status = 200) {
  const seen: Array<Record<string, string>> = []
  const fetchImpl = (async (_url: string | URL, init?: RequestInit) => {
    seen.push({ ...((init?.headers ?? {}) as Record<string, string>) })
    return new Response('{}', { status, headers: { 'content-type': 'application/json' } })
  }) as unknown as typeof globalThis.fetch
  return { seen, fetchImpl }
}

const idempotencyKeysIn = (headers: Record<string, string>): string[] =>
  Object.entries(headers)
    .filter(([key]) => key.toLowerCase() === 'idempotency-key')
    .map(([, value]) => value)

describe('the generic request() escape hatch', () => {
  it('adds an Idempotency-Key to a POST, PUT or PATCH the caller did not key', async () => {
    // The three methods where a retry could create a second thing, and the ones the API
    // consults the header on. A caller reaching past the typed methods to an endpoint this
    // SDK does not model yet should not have to learn that from a 400.
    for (const method of ['POST', 'PUT', 'PATCH']) {
      const { seen, fetchImpl } = rawHeaderRecorder()
      await client(fetchImpl).request(method, '/something-new', { body: { a: 1 } })
      assert.equal(idempotencyKeysIn(seen[0]).length, 1, `no key on ${method}`)
      assert.match(idempotencyKeysIn(seen[0])[0], /^[0-9a-f-]{36}$/)
    }
  })

  it('never adds one to a GET', async () => {
    const { seen, fetchImpl } = rawHeaderRecorder()
    await client(fetchImpl).request('GET', '/something-new')
    assert.deepEqual(idempotencyKeysIn(seen[0]), [])
  })

  it('never adds one to a DELETE', async () => {
    // Narrower than "every non-GET" on purpose, and the narrowing is a compatibility
    // guarantee: DELETE /shares/{code} shipped at 0.1.4 with no such header, the endpoint
    // does not read it, and a repeated delete is idempotent by construction. Adding one
    // would change the bytes of an already-published call to buy nothing.
    const { seen, fetchImpl } = rawHeaderRecorder()
    await client(fetchImpl).request('DELETE', '/something-new')
    assert.deepEqual(idempotencyKeysIn(seen[0]), [])
  })

  it('forwards a caller-supplied key on a DELETE, which it would not have added', async () => {
    // The SDK declining to mint one must not become the SDK dropping one. A caller who has a
    // reason to key a delete keeps that ability.
    const { seen, fetchImpl } = rawHeaderRecorder()
    await client(fetchImpl).request('DELETE', '/something-new', {
      headers: { 'Idempotency-Key': 'mine' },
    })
    assert.deepEqual(idempotencyKeysIn(seen[0]), ['mine'])
  })

  it('leaves a caller-supplied key alone, whatever its spelling', async () => {
    // Header names are case-insensitive, so a caller who wrote 'idempotency-key' must not
    // end up sending two headers under two spellings — which is worse than sending none,
    // and which a lower-casing assertion would hide.
    for (const spelling of ['Idempotency-Key', 'idempotency-key', 'IDEMPOTENCY-KEY']) {
      const { seen, fetchImpl } = rawHeaderRecorder()
      await client(fetchImpl).request('POST', '/something-new', {
        body: {},
        headers: { [spelling]: 'mine' },
      })
      assert.deepEqual(idempotencyKeysIn(seen[0]), ['mine'], `overwrote ${spelling}`)
    }
  })

  it('sends one key, not two, on a typed create', async () => {
    // The typed method supplies its own so it can hand the value back to the caller. The
    // escape hatch must recognise that and stay out of the way.
    const { seen, fetchImpl } = rawHeaderRecorder(201)
    await new CredenShare(CREDENTIAL, { fetch: fetchImpl }).requests.create({
      title: 't',
      fields: [PROMPT],
    })
    assert.equal(idempotencyKeysIn(seen[0]).length, 1)
  })

  it('repeats a generated key across a retry rather than minting a second', async () => {
    // The whole reason the header is attached before the retry loop. A key per attempt makes
    // the retry a NEW request under a new key, which is the exact duplicate the header
    // exists to prevent.
    const seen: Array<Record<string, string>> = []
    const fetchImpl = (async (_url: string | URL, init?: RequestInit) => {
      seen.push({ ...((init?.headers ?? {}) as Record<string, string>) })
      if (seen.length === 1) throw new TypeError('fetch failed')
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
    }) as unknown as typeof globalThis.fetch

    await new CredenShare(CREDENTIAL, { fetch: fetchImpl }).request('POST', '/something-new', {
      body: { a: 1 },
    })
    assert.equal(seen.length, 2)
    assert.deepEqual(idempotencyKeysIn(seen[0]), idempotencyKeysIn(seen[1]))
    assert.equal(idempotencyKeysIn(seen[0]).length, 1)
  })
})
