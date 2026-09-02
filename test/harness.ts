/**
 * The stub fetch every client test is written against.
 *
 * Shared rather than copied into each test file, because a second copy drifts: the recorder
 * lower-cases header names so an assertion cannot pass by matching the SDK's own spelling,
 * and a divergent copy would quietly stop checking that.
 */

import { CredenShare } from '../src/client.js'

/** Three parts, so the custody boundary is exercised by default. */
export const CREDENTIAL = 'crs_sk_live_abc123.authsecretvalue.custodysecretvalue'
/** The two parts that may reach the wire. Asserted against, never sent by choice. */
export const TWO_PART = 'crs_sk_live_abc123.authsecretvalue'

export interface Recorded {
  url: string
  method: string
  headers: Record<string, string>
  body?: string
}

export interface StubResponse {
  status: number
  body: unknown
  headers?: Record<string, string>
}

/** One `Recorded` from a fetch call, with header names folded to lower case. */
export function recordOf(url: string | URL, init?: RequestInit): Recorded {
  return {
    url: String(url),
    method: init?.method ?? 'GET',
    headers: Object.fromEntries(
      Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [
        k.toLowerCase(),
        v,
      ]),
    ),
    body: typeof init?.body === 'string' ? init.body : undefined,
  }
}

/**
 * A fetch that answers from a queue (or the same response forever) and records what it was
 * asked for.
 */
export function recorder(responses: StubResponse[] | StubResponse) {
  const queue = Array.isArray(responses) ? [...responses] : null
  const single = Array.isArray(responses) ? null : responses
  const requests: Recorded[] = []

  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    requests.push(recordOf(url, init))
    const next = single ?? queue!.shift()!
    return new Response(JSON.stringify(next.body), {
      status: next.status,
      headers: { 'content-type': 'application/json', ...(next.headers ?? {}) },
    })
  }) as unknown as typeof globalThis.fetch

  return { requests, fetchImpl }
}

export function client(
  fetchImpl: typeof globalThis.fetch,
  credential = CREDENTIAL,
): CredenShare {
  return new CredenShare(credential, { fetch: fetchImpl, linkOrigin: 'https://crs.sh' })
}
