/**
 * Links on a team's custom domain (Gitea #412): the origin comes from configuration, else from
 * /v1/capabilities once per client, else the default.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { CredenShare, DEFAULT_LINK_ORIGIN } from '../src/client.js'
import { CREDENTIAL, recorder, type StubResponse } from './harness.js'

const FIELD = { key: 'k', value: 'v', type: 'text' as const }
const CREATED = (code: string): StubResponse => ({ status: 201, body: { short_code: code } })
const CAPABILITIES = (linkOrigin: unknown): StubResponse => ({
  status: 200,
  body: { api_version: '1', key: { key_id: 'abc123', organization_id: 'org-1' }, link_origin: linkOrigin },
})

function unconfigured(fetchImpl: typeof globalThis.fetch): CredenShare {
  return new CredenShare(CREDENTIAL, { fetch: fetchImpl, maxRetries: 0 })
}

const capabilityCalls = (requests: Array<{ url: string }>) =>
  requests.filter((r) => r.url.endsWith('/capabilities')).length

describe('links on a team domain', () => {
  it("puts a team key's links on its custom domain, asking once", async () => {
    const { requests, fetchImpl } = recorder([
      CREATED('abc123'),
      CAPABILITIES('https://cd-test.credenshare.io'),
      CREATED('def456'),
    ])
    const crs = unconfigured(fetchImpl)
    const first = await crs.shares.create({ title: 't', fields: [FIELD] })
    const second = await crs.shares.create({ title: 't', fields: [FIELD] })
    for (const share of [first, second]) {
      assert.ok(
        share.link.startsWith(`https://cd-test.credenshare.io/${share.shortCode}#1`),
        share.link,
      )
    }
    assert.equal(capabilityCalls(requests), 1)
    // The link helpers agree with what the creates returned.
    assert.equal(crs.linkFor(first.shortCode, first.contentKey), first.link)
    assert.equal(await crs.linkOrigin(), 'https://cd-test.credenshare.io')
    assert.equal(capabilityCalls(requests), 1)
  })

  it('lets a configured origin win, and asks nothing', async () => {
    const { requests, fetchImpl } = recorder([CREATED('abc123')])
    const crs = new CredenShare(CREDENTIAL, { fetch: fetchImpl, linkOrigin: 'https://links.example.com/' })
    const share = await crs.shares.create({ title: 't', fields: [FIELD] })
    assert.ok(share.link.startsWith('https://links.example.com/abc123#'), share.link)
    assert.equal(requests.length, 1)
    assert.equal(capabilityCalls(requests), 0)
  })

  const fallbacks: Array<[string, StubResponse]> = [
    ['a null origin', CAPABILITIES(null)],
    ['no member at all', { status: 200, body: { api_version: '1' } }],
    ['a refusal', { status: 403, body: { message: 'no', error_code: 78 } }],
    ['a server error', { status: 500, body: { message: 'boom' } }],
    ['a path, not an origin', CAPABILITIES('https://cd.example.com/evil')],
    ['plain http', CAPABILITIES('http://cd.example.com')],
    ['credentials in it', CAPABILITIES('https://user@cd.example.com')],
    ['a query', CAPABILITIES('https://cd.example.com?x=1')],
    ['not a string', CAPABILITIES(42)],
  ]
  for (const [name, capabilities] of fallbacks) {
    it(`falls back to the default on ${name}, and asks only once`, async () => {
      const { requests, fetchImpl } = recorder([CREATED('abc123'), capabilities, CREATED('def456')])
      const crs = unconfigured(fetchImpl)
      for (let i = 0; i < 2; i++) {
        const share = await crs.shares.create({ title: 't', fields: [FIELD] })
        assert.ok(share.link.startsWith(`${DEFAULT_LINK_ORIGIN}/`), share.link)
      }
      assert.equal(capabilityCalls(requests), 1)
    })
  }

  it("puts a secure request's links on the team domain too", async () => {
    const { fetchImpl } = recorder([
      { status: 201, body: { short_code: 'rq01' } },
      CAPABILITIES('https://cd-test.credenshare.io'),
    ])
    const request = await unconfigured(fetchImpl).requests.create({
      title: 't',
      fields: [{ item: 'Password', type: 'password' }],
    })
    assert.equal(request.collectLink, 'https://cd-test.credenshare.io/r/rq01')
    assert.ok(request.accessLink.startsWith('https://cd-test.credenshare.io/r/rq01#1'))
  })

  it('reads link_origin into the capabilities type', async () => {
    const team = await unconfigured(recorder(CAPABILITIES('https://cd-test.credenshare.io')).fetchImpl)
      .capabilities.get()
    assert.equal(team.linkOrigin, 'https://cd-test.credenshare.io')
    const personal = await unconfigured(recorder(CAPABILITIES(null)).fetchImpl).capabilities.get()
    assert.equal(personal.linkOrigin, null)
  })
})
