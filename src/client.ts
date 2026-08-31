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
  DeliveryUnknownError,
  IdempotencyConflictError,
  IdempotencyInFlightError,
  MalformedKeyError,
  NetworkError,
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

/** The identical request is still in flight. Wait and repeat it; do not change the key. */
const IDEMPOTENCY_IN_FLIGHT_CODE = 106

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

  /**
   * Wrap a payload to this credential's own custody public key.
   *
   * Done here rather than by handing the secret out, because the custody secret is the one
   * value in this class that must never leave it: it is what the server deliberately cannot
   * hold, and an accessor is all it takes for it to end up somewhere that logs.
   */
  async wrapToCustody(payload: Uint8Array): Promise<string> {
    if (this.#custodySecret === undefined) {
      throw new CredentialFormatError(
        'custody needs a three-part credential ' +
          "'crs_sk_live_<keyId>.<authSecret>.<custodySecret>'; this one has two parts, so " +
          'there is no custody key to wrap to',
      )
    }
    const keypair = await crypto.custodyKeypair(this.#custodySecret)
    return crypto.wrapToPublicKey(payload, keypair.publicKeyRaw)
  }

  /** Never render the secrets. A credential in a log line is a credential that must be rotated. */
  toJSON(): string {
    return `<Credential ${this.keyId} (${this.hasCustody ? 'with custody' : 'no custody'})>`
  }

  toString(): string {
    return this.toJSON()
  }
}

/**
 * A created share, and the only place its link exists.
 *
 * This is a class rather than a plain object so that printing it does not print the key.
 * `link` carries the content key in its fragment, so an object literal turns any incidental
 * `console.log(share)`, structured-logger call or `JSON.stringify` into a permanent
 * plaintext record of the secret in a log aggregator. The properties are still there and
 * still readable — you have to ask for them by name.
 */
export class Share {
  readonly shortCode: string
  /**
   * The full recipient link, INCLUDING the key fragment. Treat this as the secret itself:
   * anyone holding it can read the content, and CredenShare cannot.
   */
  readonly link: string
  /** The content key, if you need to build your own link or decrypt later. */
  readonly contentKey: Uint8Array
  readonly expiredAt: string | null
  readonly custody: string | null
  /**
   * The Idempotency-Key this create was sent with, generated when you did not supply one.
   *
   * Surfaced because the documented recovery from an uncertain outcome is to repeat the
   * identical request with the same key — which is impossible for a key you were never told.
   */
  readonly idempotencyKey: string

  constructor(init: {
    shortCode: string
    link: string
    contentKey: Uint8Array
    expiredAt?: string | null
    custody?: string | null
    idempotencyKey: string
  }) {
    this.shortCode = init.shortCode
    this.link = init.link
    this.contentKey = init.contentKey
    this.expiredAt = init.expiredAt ?? null
    this.custody = init.custody ?? null
    this.idempotencyKey = init.idempotencyKey
  }

  /** Redacted. The link and the key are omitted on purpose. */
  toJSON(): Record<string, unknown> {
    return {
      shortCode: this.shortCode,
      expiredAt: this.expiredAt,
      custody: this.custody,
      idempotencyKey: this.idempotencyKey,
      link: '[redacted - contains the content key]',
      contentKey: '[redacted]',
    }
  }

  toString(): string {
    return `Share(${this.shortCode}, link redacted)`
  }

  /** Node's console.log / util.inspect path, which ignores toJSON. */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString()
  }
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
  /**
   * Also wrap the content key to the custody public key derived from your credential's third
   * part, so the share is readable from the dashboard later.
   *
   * Without this an API-created share is custody `"none"`: the link is the only way back to
   * the content, and losing it loses the secret. The custody secret is used locally to derive
   * a public key and is never transmitted.
   */
  custody?: boolean
  /** A wrap you computed yourself. Mutually exclusive with `custody`. */
  itemKeyWrap?: string
  organizationId?: string
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
    let delivered = false
    for (;;) {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), this.#timeoutMs)
      let response: Response
      let text: string
      try {
        response = await this.#fetch(url.toString(), {
          method,
          headers,
          body,
          signal: controller.signal,
        })
        // Headers arrived: the request was delivered and the server may have committed.
        // That is a different answer from never reaching it, and the difference decides
        // whether a caller may safely retry.
        delivered = true
        // Read the body inside the guarded region. With the read outside it, the timeout
        // covers only the headers, so a server that responds and then stalls mid-body
        // hangs this call forever — the one failure a timeout exists to prevent.
        text = await response.text()
      } catch (error) {
        // Retry only the failures that prove nothing was received. A 5xx might have
        // committed and this client cannot tell, so it is surfaced rather than repeated.
        if (attempt >= this.#maxRetries) {
          const attempts = attempt + 1
          if (delivered) {
            throw new DeliveryUnknownError(
              `the request was delivered but no response was read after ${attempts} ` +
                `attempt(s): ${String(error)}`,
              attempts,
            )
          }
          throw new NetworkError(
            `could not reach the API after ${attempts} attempt(s): ${String(error)}`,
            attempts,
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
    // Check the key before anything is encrypted or sent. The only length check used to live
    // in encodeFragment, which runs AFTER the share exists on the server — so a wrong-length
    // key created a real share holding a real secret and then threw, losing the short code.
    // The caller could neither find it nor expire it.
    if (contentKey.length !== crypto.CONTENT_KEY_LENGTH) {
      throw new MalformedKeyError(
        `a content key is ${crypto.CONTENT_KEY_LENGTH} bytes; this one is ${contentKey.length}`,
      )
    }
    if (options.custody && options.itemKeyWrap !== undefined) {
      throw new MalformedKeyError('pass either custody or itemKeyWrap, not both')
    }

    let itemKeyWrap = options.itemKeyWrap
    if (options.custody) {
      itemKeyWrap = await this.#client.credential.wrapToCustody(contentKey)
    }

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
    if (itemKeyWrap !== undefined) body.item_key_wrap = itemKeyWrap
    if (options.organizationId !== undefined) body.organization_id = options.organizationId

    // Required by the API, not optional. A retried automation must not create a second copy
    // of a credential in the world, with its own link and audit trail, that the caller does
    // not know exists.
    const idempotencyKey = options.idempotencyKey ?? globalThis.crypto.randomUUID()
    const headers = { 'Idempotency-Key': idempotencyKey }

    const data = await this.#client.request('POST', '/shares', { body, headers })
    const shortCode = String(data.short_code)
    return new Share({
      shortCode,
      link: this.#client.linkFor(shortCode, contentKey),
      contentKey,
      expiredAt: (data.expired_at as string | null) ?? null,
      custody: (data.custody as string | null) ?? null,
      idempotencyKey,
    })
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
    // The limit the SERVER applied, not the one the caller asked for. A server free to cap
    // page size returns fewer rows than requested on a page that is nonetheless full, and
    // comparing against the request makes that look like the end of the result set.
    const resolvedLimit = pagination.limit ?? limit
    return {
      shares: rows.map((row) => ({
        shortCode: String(row.short_code),
        expiredAt: (row.expired_at as string | null) ?? null,
      })),
      page: resolvedPage,
      limit: resolvedLimit,
      total: pagination.total,
      totalPages,
      // When the server omits total_pages, fall back to a full-page heuristic rather
      // than to false. Reporting "no more" on a full page is what makes iterateAll()
      // stop after page one and silently return a fraction of the account — the exact
      // truncation this type exists to prevent.
      hasMore:
        totalPages === undefined ? rows.length >= resolvedLimit : resolvedPage < totalPages,
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
  // The server's per-field detail. Dropped until now, so a validation error never named the
  // field it rejected and the caller had to re-issue the request to find out.
  const additionalData =
    payload.additional_data && typeof payload.additional_data === 'object'
      ? (payload.additional_data as Record<string, unknown>)
      : undefined
  const init = { status: response.status, code, requestId, additionalData }

  switch (response.status) {
    case 401:
      return new AuthenticationError(message, init)
    case 403:
      // A spent allowance is a 403 like a missing scope, but the remedies are opposite: one
      // needs a plan change, the other a different key. The numeric code separates them.
      if (code === QUOTA_EXCEEDED_CODE) return new QuotaExceededError(message, init)
      // A revoked or unknown key never reaches the application: API Gateway denies it and
      // answers 403 with no error_code and no message of ours. Reporting that as
      // PermissionError sends the reader to check scopes on a key that no longer exists,
      // and made AuthenticationError unreachable in practice despite the README listing it.
      if (code === undefined && typeof payload.message !== 'string') {
        return new AuthenticationError(message, init)
      }
      return new PermissionError(message, init)
    case 404:
      return new NotFoundError(message, init)
    case 409:
      if (code === IDEMPOTENCY_CONFLICT_CODE) return new IdempotencyConflictError(message, init)
      // 106 is not a conflict: the identical request is still running. The remedy is to wait
      // and repeat the SAME request, where a conflict means the body genuinely differed.
      if (code === IDEMPOTENCY_IN_FLIGHT_CODE) return new IdempotencyInFlightError(message, init)
      return new ApiError(message, init)
    case 429: {
      // Retry-After is a delta-seconds value OR an HTTP-date (RFC 9110). Reading only the
      // digits form leaves retryAfter undefined for the date form, and the README tells the
      // caller to wait that many seconds - which is a zero-length wait straight back into
      // the limit.
      const header = response.headers.get('retry-after')
      return new RateLimitError(message, { ...init, retryAfter: retryAfterSeconds(header) })
    }
    case 503:
      return new ServiceUnavailableError(message, init)
    default:
      return new ApiError(message, init)
  }
}

/**
 * Retry-After as whole seconds, accepting both RFC 9110 forms.
 *
 * Returns undefined rather than 0 for an unreadable header: a caller who waits `undefined`
 * seconds notices, where one who waits 0 hammers the endpoint that just rate-limited them.
 */
function retryAfterSeconds(header: string | null): number | undefined {
  if (!header) return undefined
  const trimmed = header.trim()
  if (/^\d+$/.test(trimmed)) return Number(trimmed)
  const at = Date.parse(trimmed)
  if (Number.isFinite(at)) return Math.max(0, Math.ceil((at - Date.now()) / 1000))
  return undefined
}

function userAgent(): string {
  return 'credenshare-node/0.1.0'
}
