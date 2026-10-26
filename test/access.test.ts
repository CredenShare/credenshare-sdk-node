/**
 * The /v1 additions of Gitea #404: the access log, capabilities, the expired lists and
 * notifyOn, against a stub fetch.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { FIELD_TYPES } from '../src/crypto.js'
import { NOTIFY_ON_EVENTS, UNLIMITED } from '../src/client.js'
import { ApiError, InvalidArgumentError, NotFoundError, PermissionError } from '../src/errors.js'
import { client, recorder } from './harness.js'

const FIELD = { key: 'k', value: 'v', type: 'text' as const }

function accessLogBody(next: string | null) {
  return {
    short_code: 'AbC123',
    entries: [
      {
        accessed_at: '2026-10-25T18:00:00Z',
        accessed_ip: '203.0.113.7',
        platform: 'macOS',
        user_agent: 'Mozilla/5.0',
        failed_passcode: false,
        signed_in: true,
      },
      {
        accessed_at: '2026-10-25T17:00:00Z',
        accessed_ip: '198.51.100.2',
        platform: 'Linux',
        user_agent: null,
        failed_passcode: true,
        signed_in: false,
      },
    ],
    next_cursor: next,
    retention_days: 90,
    effective_from: '2026-07-27T18:00:00Z',
    effective_to: '2026-10-25T18:00:00Z',
  }
}

const query = (url: string) => new URL(url).searchParams

describe('the access log', () => {
  it('reads a page, its window and its ETag', async () => {
    const { requests, fetchImpl } = recorder({
      status: 200,
      body: accessLogBody('c1'),
      headers: { ETag: 'W/"abc"' },
    })
    const page = await client(fetchImpl).shares.accessLog('AbC123', {
      limit: 10,
      cursor: 'prev',
      from: new Date(Date.UTC(2026, 9, 1)),
      to: '2026-10-31T23:59:59Z',
    })
    assert.equal(page.shortCode, 'AbC123')
    assert.equal(page.entries.length, 2)
    assert.deepEqual(page.entries[0], {
      accessedAt: '2026-10-25T18:00:00Z',
      accessedIp: '203.0.113.7',
      platform: 'macOS',
      userAgent: 'Mozilla/5.0',
      failedPasscode: false,
      signedIn: true,
    })
    // A null user agent stays null rather than becoming a string a caller would match on.
    assert.equal(page.entries[1]!.userAgent, null)
    assert.equal(page.nextCursor, 'c1')
    assert.equal(page.hasMore, true)
    assert.equal(page.retentionDays, 90)
    assert.equal(page.effectiveFrom, '2026-07-27T18:00:00Z')
    assert.equal(page.etag, 'W/"abc"')
    assert.equal(page.notModified, false)

    const sent = requests[0]!
    assert.match(sent.url, /\/shares\/AbC123\/access-log\?/)
    const q = query(sent.url)
    // A Date goes out in UTC, RFC 3339, without milliseconds.
    assert.equal(q.get('from'), '2026-10-01T00:00:00Z')
    assert.equal(q.get('to'), '2026-10-31T23:59:59Z')
    assert.equal(q.get('limit'), '10')
    assert.equal(q.get('cursor'), 'prev')
    assert.equal(sent.headers['if-none-match'], undefined)
    assert.equal(sent.headers['idempotency-key'], undefined)
  })

  it('sends no query when nothing narrows it, and ends on a null cursor', async () => {
    const { requests, fetchImpl } = recorder({ status: 200, body: accessLogBody(null) })
    const page = await client(fetchImpl).shares.accessLog('a/b')
    assert.equal(page.nextCursor, null)
    assert.equal(page.hasMore, false)
    assert.match(requests[0]!.url, /\/shares\/a%2Fb\/access-log$/)
  })

  it('answers an unchanged page with notModified rather than an error', async () => {
    const { requests, fetchImpl } = recorder({ status: 304, body: null, headers: { ETag: 'W/"abc"' } })
    const page = await client(fetchImpl).shares.accessLog('AbC123', { ifNoneMatch: 'W/"abc"' })
    assert.equal(page.notModified, true)
    assert.equal(page.etag, 'W/"abc"')
    assert.deepEqual(page.entries, [])
    assert.equal(page.shortCode, 'AbC123')
    assert.equal(requests[0]!.headers['if-none-match'], 'W/"abc"')
  })

  it('maps refusals to their errors', async () => {
    for (const [status, type] of [
      [403, PermissionError],
      [404, NotFoundError],
      [400, ApiError],
    ] as const) {
      const { fetchImpl } = recorder({ status, body: { message: 'no', error_code: 1 } })
      await assert.rejects(client(fetchImpl).shares.accessLog('AbC123'), type)
    }
  })

  it('checks its options before any request', async () => {
    for (const options of [
      { limit: 101 },
      { limit: 0 },
      { limit: 2.5 },
      { from: '2026-10-02T00:00:00Z', to: '2026-10-01T00:00:00Z' },
      { from: new Date('not a date') },
    ]) {
      const { requests, fetchImpl } = recorder({ status: 200, body: accessLogBody(null) })
      await assert.rejects(client(fetchImpl).shares.accessLog('AbC123', options), InvalidArgumentError)
      assert.equal(requests.length, 0)
    }
  })

  it('walks every page by its cursor, and never revalidates', async () => {
    const { requests, fetchImpl } = recorder([
      { status: 200, body: accessLogBody('c1') },
      { status: 200, body: accessLogBody('c2') },
      { status: 200, body: accessLogBody(null) },
    ])
    let seen = 0
    for await (const _entry of client(fetchImpl).shares.iterateAccessLog('AbC123', { limit: 2 })) {
      seen += 1
    }
    assert.equal(seen, 6)
    assert.equal(requests.length, 3)
    assert.equal(query(requests[1]!.url).get('cursor'), 'c1')
    assert.equal(query(requests[2]!.url).get('cursor'), 'c2')
    for (const sent of requests) {
      assert.equal(sent.headers['if-none-match'], undefined)
      assert.equal(query(sent.url).get('limit'), '2')
    }
  })

  it('refuses a cursor that does not move', async () => {
    const { requests, fetchImpl } = recorder({ status: 200, body: accessLogBody('same') })
    await assert.rejects(async () => {
      for await (const _entry of client(fetchImpl).shares.iterateAccessLog('AbC123')) {
        // drain
      }
    }, ApiError)
    assert.equal(requests.length, 2)
  })
})

describe('the expired lists', () => {
  const pageBody = {
    shares: [{ short_code: 'old1', expired_at: '2026-10-20T00:00:00Z' }],
    requests: [{ short_code: 'req1', expired_at: '2026-10-20T00:00:00Z' }],
    pagination: { page: 1, limit: 25, total: 1, total_pages: 1 },
  }

  it('leaves the old calls exactly as they were', async () => {
    const { requests, fetchImpl } = recorder({ status: 200, body: pageBody })
    const crs = client(fetchImpl)
    await crs.shares.list()
    await crs.requests.list()
    for (const sent of requests) assert.equal(query(sent.url).has('status'), false)
  })

  it('asks for the expired half, in lists and walks', async () => {
    const { requests, fetchImpl } = recorder({ status: 200, body: pageBody })
    const crs = client(fetchImpl)
    const shares = await crs.shares.list({ status: 'expired' })
    assert.equal(shares.shares[0]!.shortCode, 'old1')
    await crs.requests.list({ status: 'expired' })
    for await (const _s of crs.shares.iterateAll({ status: 'expired' })) {
      // drain
    }
    for await (const _r of crs.requests.iterateAll({ status: 'active' })) {
      // drain
    }
    assert.deepEqual(
      requests.map((r) => query(r.url).get('status')),
      ['expired', 'expired', 'expired', 'active'],
    )
  })

  it('refuses an unknown status before any request', async () => {
    const { requests, fetchImpl } = recorder({ status: 200, body: pageBody })
    const crs = client(fetchImpl)
    await assert.rejects(crs.shares.list({ status: 'archived' as never }), InvalidArgumentError)
    await assert.rejects(crs.requests.list({ status: 'Expired' as never }), InvalidArgumentError)
    await assert.rejects(async () => {
      for await (const _s of crs.shares.iterateAll({ status: '' as never })) {
        // drain
      }
    }, InvalidArgumentError)
    assert.equal(requests.length, 0)
  })
})

function capabilitiesBody(org: string | null, policy: unknown) {
  return {
    api_version: '1',
    key: {
      key_id: 'abc123',
      scopes: ['shares:write', 'audit:read'],
      custody_level: 1,
      organization_id: org,
      rate_limit_rpm: 100,
    },
    plan: { code: 'business', name: 'Business' },
    limits: {
      max_shares: -1,
      remaining_shares: -1,
      max_fields: 20,
      max_days_access_logs: 90,
      max_api_keys: 10,
      max_webhooks: 5,
    },
    features: { secure_requests: true, zero_knowledge: false },
    sharing_policy: policy,
    field_types: ['text', 'password', 'date', 'multiline', 'markdown', 'source_code', 'url', 'qr'],
    notify_on_events: ['viewed', 'denied', 'expired', 'deleted'],
  }
}

describe('capabilities', () => {
  it('reads a personal key', async () => {
    const { requests, fetchImpl } = recorder({
      status: 200,
      body: capabilitiesBody(null, null),
      headers: { ETag: 'W/"cap"' },
    })
    const caps = await client(fetchImpl).capabilities.get()
    assert.equal(caps.apiVersion, '1')
    assert.deepEqual(caps.key, {
      keyId: 'abc123',
      scopes: ['shares:write', 'audit:read'],
      custodyLevel: 1,
      organizationId: null,
      rateLimitRpm: 100,
    })
    assert.deepEqual(caps.plan, { code: 'business', name: 'Business' })
    assert.equal(caps.limits.maxShares, UNLIMITED)
    assert.equal(caps.limits.maxDaysAccessLogs, 90)
    assert.deepEqual(caps.features, { secure_requests: true, zero_knowledge: false })
    assert.equal(caps.sharingPolicy, null)
    // The API publishes the lists this SDK carries; they must agree.
    assert.deepEqual(caps.fieldTypes, [...FIELD_TYPES])
    assert.deepEqual(caps.notifyOnEvents, [...NOTIFY_ON_EVENTS])
    assert.equal(caps.etag, 'W/"cap"')
    assert.equal(caps.notModified, false)
    assert.match(requests[0]!.url, /\/capabilities$/)
  })

  it("carries a team key's organization and policy", async () => {
    const { fetchImpl } = recorder({
      status: 200,
      body: capabilitiesBody('org-1', { require_passcode: true }),
    })
    const caps = await client(fetchImpl).capabilities.get()
    assert.equal(caps.key.organizationId, 'org-1')
    assert.deepEqual(caps.sharingPolicy, { require_passcode: true })
  })

  it('answers an unchanged read with notModified', async () => {
    const { requests, fetchImpl } = recorder({ status: 304, body: null, headers: { ETag: 'W/"cap"' } })
    const caps = await client(fetchImpl).capabilities.get({ ifNoneMatch: 'W/"cap"' })
    assert.equal(caps.notModified, true)
    assert.equal(caps.etag, 'W/"cap"')
    assert.equal(requests[0]!.headers['if-none-match'], 'W/"cap"')
  })

  it('still fails a 304 on a read that did not ask for one', async () => {
    // Only the conditional reads accept it. Elsewhere an empty answer would read as a real one.
    const { fetchImpl } = recorder({ status: 304, body: null })
    await assert.rejects(client(fetchImpl).stats.get(), ApiError)
    await assert.rejects(client(fetchImpl).request('GET', '/capabilities'), ApiError)
  })
})

describe('notifyOn', () => {
  it('is sent when set and absent otherwise', async () => {
    const { requests, fetchImpl } = recorder({ status: 201, body: { short_code: 'abc' } })
    const crs = client(fetchImpl)
    await crs.shares.create({ title: 't', fields: [FIELD], notifyOn: ['viewed', 'denied'] })
    await crs.shares.create({ title: 't', fields: [FIELD] })
    await crs.shares.create({ title: 't', fields: [FIELD], notifyOn: [] })
    assert.deepEqual(JSON.parse(requests[0]!.body!).notify_on, ['viewed', 'denied'])
    assert.equal('notify_on' in JSON.parse(requests[1]!.body!), false)
    assert.equal('notify_on' in JSON.parse(requests[2]!.body!), false)
  })

  it('is checked as the API checks it, before anything is sent', async () => {
    for (const events of [
      ['opened'],
      ['viewed', 'viewed'],
      ['Viewed'],
      ['viewed', 'denied', 'expired', 'deleted', 'viewed'],
    ]) {
      const { requests, fetchImpl } = recorder({ status: 201, body: { short_code: 'abc' } })
      await assert.rejects(
        client(fetchImpl).shares.create({ title: 't', fields: [FIELD], notifyOn: events as never }),
        InvalidArgumentError,
      )
      assert.equal(requests.length, 0)
    }
  })
})
