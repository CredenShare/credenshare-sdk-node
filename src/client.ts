/**
 * The CredenShare API client.
 *
 * Everything sensitive happens before a request is built. By the time anything reaches the
 * network it is ciphertext plus metadata, and the content key exists only in the link this
 * client hands back to you.
 */

import * as crypto from './crypto.js'
import type { Field } from './crypto.js'
import {
  ApiError,
  AuthenticationError,
  CredentialFormatError,
  CustodySecretTransmittedError,
  IdempotencyConflictError,
  NotFoundError,
  PermissionError,
  QuotaExceededError,
  RateLimitError,
  ServiceUnavailableError,
} from './errors.js'

export const DEFAULT_BASE_URL = 'https://api.credenshare.io/v1'
export const DEFAULT_LINK_ORIGIN = 'https://crs.sh'

/**
 * The only accepted encryption type. Plaintext creates are refused by the server, and this
 * client has no way to express one.
 */
const ENCRYPTION_TYPE = 'e2ee-aes256-gcm'

/**
 * The API's numeric code for an exhausted plan allowance. Distinguished from other 403s
 * because waiting does not help and the remedy is a plan change, not a retry.
 */
const QUOTA_EXCEEDED_CODE = 61

/** The API's numeric code for an Idempotency-Key replayed with a different body. */
const IDEMPOTENCY_CONFLICT_CODE = 105

/**
 * Retries for network failures. Only connection and timeout errors are retried, never an
 * HTTP status: a 5xx may have committed, and this client cannot tell. A create is safe to
 * retry because the Idempotency-Key and the body are both identical on the second attempt —
 * which is the entire reason the header is mandatory.
 */
export const DEFAULT_MAX_RETRIES = 2

const CREDENTIAL_PREFIX = 'crs_sk_live_'

/**
 * A parsed API credential: `crs_sk_live_<keyId>.<authSecret>[.<custodySecret>]`.
 *
 * The custody secret is held here but is NEVER placed in a request. It is a separate secret
 * precisely so the server cannot reconstruct the custody private key — deriving it from the
 * auth secret, which is transmitted on every call, would mean the server *could* decrypt.
 * Not that it would; that it could.
 */
export class Credential {
  readonly keyId: string
  readonly #authSecret: string
  readonly #custodySecret?: string

  private constructor(keyId: string, authSecret: string, custodySecret?: string) {
    this.keyId = keyId
    this.#authSecret = authSecret
    this.#custodySecret = custodySecret
  }

  static parse(raw: string): Credential {
    const text = (raw ?? '').trim()
    if (!text.startsWith(CREDENTIAL_PREFIX)) {
      throw new CredentialFormatError(
        `a credential starts with '${CREDENTIAL_PREFIX}'; this does not look like one`,
      )
    }
    const parts = text.split('.')
    if ((parts.length !== 2 && parts.length !== 3) || parts.some((p) => !p)) {
      throw new CredentialFormatError(
        `a credential is '${CREDENTIAL_PREFIX}<keyId>.<authSecret>' with an optional ` +
          `'.<custodySecret>'; this has ${parts.length} part(s)`,
      )
    }
    return new Credential(
      parts[0].slice(CREDENTIAL_PREFIX.length),
      parts[1],
      parts.length === 3 ? parts[2] : undefined,
    )
  }

  get hasCustody(): boolean {
    return this.#custodySecret !== undefined
  }

  /**
   * The two-part value sent in the Authorization header.
   *
   * Assembled from the parts rather than by trimming the original string, so a third part
   * cannot survive a formatting mistake and reach the wire.
   */
  get bearer(): string {
    return `${CREDENTIAL_PREFIX}${this.keyId}.${this.#authSecret}`
  }

  /** True when the given text contains the custody secret. Used for the boundary assertion. */
  leaksCustodyInto(text: string): boolean {
    return this.#custodySecret !== undefined && text.includes(this.#custodySecret)
  }

  /**
   * The base64url custody public key to register for account custody.
   *
   * Only the public half leaves this machine. Any machine holding the credential derives the
   * same keypair, so ephemeral runners need no local state.
   */
  async custodyPublicKey(): Promise<string> {
    if (this.#custodySecret === undefined) {
      throw new CredentialFormatError(
        'this credential has no custody secret, so no custody keypair exists',
      )
    }
    return (await crypto.custodyKeypair(this.#custodySecret)).publicKeyB64url
  }

  /** Never render the secrets. A credential in a log line is a credential that must be rotated. */
  toJSON(): string {
    return `<Credential ${this.keyId} (${this.hasCustody ? 'with custody' : 'no custody'})>`
  }

  toString(): string {
    return this.toJSON()
  }
}

/** A created share, and the only place its link exists. */
export interface Share {
  shortCode: string
  /**
   * The full recipient link, INCLUDING the key fragment. Treat this as the secret itself:
   * anyone holding it can read the content, and CredenShare cannot.
   */
  link: string
  /** The content key, if you need to build your own link or decrypt later. */
  contentKey: Uint8Array
  expiredAt?: string | null
  custody?: string | null
}

/**
 * Metadata for a share. Never content, and never a key.
 *
 * Deliberately thin, because the API is: `/v1` returns the short code and the expiry and
 * nothing else. There is no `title` here even though you supply one on create — the server
 * does not return it, and a property that is always undefined reads as a broken field rather
 * than as an absent one.
 */
export interface ShareSummary {
  shortCode: string
  expiredAt?: string | null
}

/**
 * A page of shares, with the paging figures attached.
 *
 * A plain array would leave a caller guessing whether more exists, and a caller who has to
 * guess guesses wrong — usually by stopping at the first short page.
 */
export interface SharePage {
  shares: ShareSummary[]
  page: number
  limit: number
  total?: number
  totalPages?: number
  hasMore: boolean
}

export interface CreateOptions {
  title: string
  fields: readonly Field[]
  description?: string
  passcode?: string
  expiredAt?: string
  accessCountsLeft?: number
  timedView?: number
  /**
   * Passing your own does NOT make a second call a no-op: encryption is randomised per call,
   * so the body differs and the API refuses with `IdempotencyConflictError`. That is the
   * header working, not failing. What it protects is a network retry, which this client
   * performs itself. Pass a key to control the value for your own tracing.
   */
  idempotencyKey?: string
  /**
   * Create a share under a key you already hold — a link you handed out before the create,
   * or a fixed key in a test. It does not make the request body reproducible.
   */
  contentKey?: Uint8Array
}

export interface ClientOptions {
  baseUrl?: string
  linkOrigin?: string
  timeoutMs?: number
  maxRetries?: number
  /** Injectable for tests. Defaults to the platform `fetch`. */
  fetch?: typeof globalThis.fetch
}

interface ApiPayload {
  [key: string]: unknown
}

export class CredenShare {
  readonly credential: Credential
  readonly #baseUrl: string
  readonly #linkOrigin: string
  readonly #timeoutMs: number
  readonly #maxRetries: number
  readonly #fetch: typeof globalThis.fetch

  readonly shares: Shares

  constructor(credential: string, options: ClientOptions = {}) {
    this.credential = Credential.parse(credential)
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '')
    this.#linkOrigin = (options.linkOrigin ?? DEFAULT_LINK_ORIGIN).replace(/\/+$/, '')
    this.#timeoutMs = options.timeoutMs ?? 30_000
    this.#maxRetries = Math.max(0, options.maxRetries ?? DEFAULT_MAX_RETRIES)
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
    this.shares = new Shares(this)
  }

  /**
   * Assemble a recipient link.
   *
   * The key lives in the fragment, which browsers never send to a server. That is what makes
   * the link readable by its holder and opaque to us.
   */
  linkFor(shortCode: string, contentKey: Uint8Array): string {
    return `${this.#linkOrigin}/${shortCode}#${crypto.encodeFragment(contentKey)}`
  }

  /**
   * Fetch and decrypt a share from a full link.
   *
   * Not implemented against `/v1`: the recipient path is deliberately absent from the API,
   * because bearer auth skips the proof-of-work and captcha gates that protect it, and
   * exposing it to a credential would be an enumeration bypass. Open the link in a browser,
   * or decrypt a blob you already hold with `decryptContent`.
   */
  async readLink(_link: string): Promise<never> {
    throw new Error(
      'the recipient read path is not exposed over the API by design; open the link in a ' +
        'browser, or use decryptContent() on a blob you already have',
    )
  }

  /** @internal */
  async request(
    method: string,
    path: string,
    init: { body?: unknown; query?: Record<string, string | number>; headers?: Record<string, string> } = {},
  ): Promise<ApiPayload> {
    const authorization = `Bearer ${this.credential.bearer}`
    // Belt and braces. `bearer` is assembled from parts so a custody secret cannot reach the
    // header, but this asserts the property at the boundary rather than trusting a
    // constructor in another file.
    if (this.credential.leaksCustodyInto(authorization)) {
      throw new CustodySecretTransmittedError(
        'the custody secret was about to be transmitted; rotate this credential',
      )
    }

    const url = new URL(this.#baseUrl + path)
    for (const [key, value] of Object.entries(init.query ?? {})) {
      url.searchParams.set(key, String(value))
    }

    const headers: Record<string, string> = {
      Authorization: authorization,
      Accept: 'application/json',
      'User-Agent': userAgent(),
      ...init.headers,
    }
    const body = init.body === undefined ? undefined : JSON.stringify(init.body)
    if (body !== undefined) headers['Content-Type'] = 'application/json'

    let attempt = 0
    for (;;) {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), this.#timeoutMs)
      let response: Response
      try {
        response = await this.#fetch(url.toString(), {
          method,
          headers,
          body,
          signal: controller.signal,
        })
      } catch (error) {
        // Retry only the failures that prove nothing was received. A 5xx might have
        // committed and this client cannot tell, so it is surfaced rather than repeated.
        if (attempt >= this.#maxRetries) {
          throw new ServiceUnavailableError(
            `could not reach the API after ${attempt + 1} attempt(s): ${String(error)}`,
          )
        }
        // Plain exponential backoff, no jitter: the retry count is 2 by default, so a
        // thundering herd is not the failure mode worth complicating this for.
        await new Promise((resolve) => setTimeout(resolve, 500 * 2 ** attempt))
        attempt += 1
        continue
      } finally {
        clearTimeout(timer)
      }

      const text = await response.text()
      let parsed: ApiPayload = {}
      if (text) {
        try {
          parsed = JSON.parse(text) as ApiPayload
        } catch {
          parsed = {}
        }
      }
      if (response.ok) return parsed
      throw errorFor(response, parsed, text)
    }
  }
}

class Shares {
  readonly #client: CredenShare

  constructor(client: CredenShare) {
    this.#client = client
  }

  /**
   * Encrypt `fields` locally and create a share.
   *
   * Each field is `{ key, value, type }`. `key` is the visible label — not `label`, `name` or
   * `title`, which are silently ignored and would render every field blank. This client
   * refuses those rather than letting the mistake through.
   */
  async create(options: CreateOptions): Promise<Share> {
    const contentKey = options.contentKey ?? crypto.newContentKey()
    const blob = await crypto.encryptContent(contentKey, options.fields, {
      passcode: options.passcode,
    })

    const body: ApiPayload = {
      title: options.title,
      encryption_type: ENCRYPTION_TYPE,
      data: blob,
      access_token: await crypto.accessToken(contentKey),
    }
    if (options.description !== undefined) body.description = options.description
    if (options.passcode !== undefined) {
      body.passcode_verifier = await crypto.passcodeVerifier(options.passcode)
    }
    if (options.expiredAt !== undefined) body.expired_at = options.expiredAt
    if (options.accessCountsLeft !== undefined) body.access_counts_left = options.accessCountsLeft
    if (options.timedView !== undefined) body.timed_view = options.timedView

    // Required by the API, not optional. A retried automation must not create a second copy
    // of a credential in the world, with its own link and audit trail, that the caller does
    // not know exists.
    const headers = { 'Idempotency-Key': options.idempotencyKey ?? globalThis.crypto.randomUUID() }

    const data = await this.#client.request('POST', '/shares', { body, headers })
    const shortCode = String(data.short_code)
    return {
      shortCode,
      link: this.#client.linkFor(shortCode, contentKey),
      contentKey,
      expiredAt: (data.expired_at as string | null) ?? null,
      custody: (data.custody as string | null) ?? null,
    }
  }

  /**
   * One page of the account's shares, newest first. Metadata only.
   *
   * Use `iterateAll()` to walk every page.
   */
  async list(options: { limit?: number; page?: number } = {}): Promise<SharePage> {
    const limit = options.limit ?? 25
    const page = options.page ?? 1
    const data = await this.#client.request('GET', '/shares', { query: { limit, page } })
    const rows = (data.shares ?? data.data ?? []) as Array<Record<string, unknown>>
    const pagination = (data.pagination ?? {}) as Record<string, number | undefined>
    const totalPages = pagination.total_pages
    const resolvedPage = pagination.page ?? page
    return {
      shares: rows.map((row) => ({
        shortCode: String(row.short_code),
        expiredAt: (row.expired_at as string | null) ?? null,
      })),
      page: resolvedPage,
      limit: pagination.limit ?? limit,
      total: pagination.total,
      totalPages,
      hasMore: totalPages === undefined ? false : resolvedPage < totalPages,
    }
  }

  /**
   * Every share, page by page.
   *
   * Written here because the hand-rolled version is usually wrong in the same way: it stops
   * on the first page shorter than `limit`, which is a page the server is entitled to return
   * in the middle of a result set.
   */
  async *iterateAll(options: { limit?: number } = {}): AsyncGenerator<ShareSummary> {
    let page = 1
    for (;;) {
      const batch = await this.list({ limit: options.limit ?? 100, page })
      yield* batch.shares
      if (!batch.hasMore) return
      page += 1
    }
  }

  /**
   * One share's metadata.
   *
   * Does not consume a view, evaluate a passcode, or return content. A share belonging to
   * another account reports exactly as one that does not exist.
   */
  async get(shortCode: string): Promise<ShareSummary> {
    const data = await this.#client.request('GET', `/shares/${encodeURIComponent(shortCode)}`)
    return {
      shortCode: String(data.short_code ?? shortCode),
      expiredAt: (data.expired_at as string | null) ?? null,
    }
  }

  /**
   * Expire a share immediately.
   *
   * Irreversible: afterwards the content is unrecoverable by anyone, including CredenShare —
   * the key was never ours, and now the ciphertext is gone too.
   *
   * The share is REMOVED, not flagged. A later `get()` throws `NotFoundError` rather than
   * returning a row with an expiry set, and it drops out of `list()`. Worth knowing if you
   * reconcile against your own records: a share you expired and one that never existed look
   * identical afterwards.
   *
   * A key can only expire shares its own account created. A short code belonging to somebody
   * else reports as not-found, so this cannot be used to probe for shares elsewhere — and an
   * organization-scoped key cannot expire a colleague's share even though `list()` shows it.
   */
  async expire(shortCode: string): Promise<void> {
    await this.#client.request('DELETE', `/shares/${encodeURIComponent(shortCode)}`)
  }
}

function errorFor(response: Response, payload: ApiPayload, text: string): ApiError {
  let message = `HTTP ${response.status}`
  if (typeof payload.message === 'string' && payload.message) message = payload.message
  else if (text) message = text.slice(0, 200)

  const code = typeof payload.error_code === 'number' ? payload.error_code : undefined
  const requestId =
    response.headers.get('x-request-id') ?? response.headers.get('x-amzn-requestid')
  const init = { status: response.status, code, requestId }

  switch (response.status) {
    case 401:
      return new AuthenticationError(message, init)
    case 403:
      // A spent allowance is a 403 like a missing scope, but the remedies are opposite: one
      // needs a plan change, the other a different key. The numeric code separates them.
      return code === QUOTA_EXCEEDED_CODE
        ? new QuotaExceededError(message, init)
        : new PermissionError(message, init)
    case 404:
      return new NotFoundError(message, init)
    case 409:
      return code === IDEMPOTENCY_CONFLICT_CODE
        ? new IdempotencyConflictError(message, init)
        : new ApiError(message, init)
    case 429: {
      const header = response.headers.get('retry-after')
      return new RateLimitError(message, {
        ...init,
        retryAfter: header && /^\d+$/.test(header) ? Number(header) : undefined,
      })
    }
    case 503:
      return new ServiceUnavailableError(message, init)
    default:
      return new ApiError(message, init)
  }
}

function userAgent(): string {
  return 'credenshare-node/0.1.0'
}
