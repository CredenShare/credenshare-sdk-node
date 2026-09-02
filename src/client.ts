/**
 * The CredenShare API client.
 *
 * Everything sensitive happens before a request is built. By the time anything reaches the
 * network it is ciphertext plus metadata, and the content key exists only in the link this
 * client hands back to you.
 */

import * as crypto from './crypto.js'
import type { Field, FieldType } from './crypto.js'
import {
  ApiError,
  AuthenticationError,
  CredentialFormatError,
  CustodySecretTransmittedError,
  DeliveryUnknownError,
  IdempotencyConflictError,
  IdempotencyInFlightError,
  InvalidFieldError,
  MalformedKeyError,
  NetworkError,
  NotFoundError,
  PermissionError,
  QuotaExceededError,
  RateLimitError,
  RequestSeedTransmittedError,
  ServiceUnavailableError,
} from './errors.js'

export const DEFAULT_BASE_URL = 'https://api.credenshare.io/v1'
export const DEFAULT_LINK_ORIGIN = 'https://crs.sh'

/**
 * The package version, and the only copy of it inside the code.
 *
 * Declared here rather than in `index.ts` because `userAgent()` needs it, and two copies of a
 * version number drift: the exported constant read `0.1.0` while `0.1.3` was on npm, and the
 * User-Agent then drifted the same way on its own, still reporting `0.1.0` at 0.1.4. One
 * constant, re-exported from `index.ts`, and a test asserts it equals `package.json`.
 */
export const VERSION = '0.2.0'

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
 * The methods that get an auto-generated `Idempotency-Key`, and the reason the list is these
 * three rather than "everything that is not a GET".
 *
 * The header exists to stop a network retry from CREATING a second thing. Those are the calls
 * where repeating a request differs from making it once, and on this API they are POST, PUT
 * and PATCH — the server consults the header on creates.
 *
 * DELETE is deliberately absent, and that absence is a compatibility guarantee as much as a
 * design one. `shares.expire()` is a `DELETE /shares/{code}` that shipped at 0.1.4 with no
 * such header; adding one would change the bytes of an already-published call to buy nothing,
 * because the endpoint does not read the header and a repeated delete is idempotent by
 * construction — the row is gone either way. A key the CALLER passes on a DELETE is still
 * forwarded untouched. This list governs only what the SDK adds on its own.
 */
const IDEMPOTENT_KEYED_METHODS = new Set(['POST', 'PUT', 'PATCH'])

/**
 * Retries for network failures. Only connection and timeout errors are retried, never an
 * HTTP status: a 5xx may have committed, and this client cannot tell. A create is safe to
 * retry because the Idempotency-Key and the body are both identical on the second attempt —
 * which is the entire reason the header is mandatory.
 */
/**
 * The most pages `iterateAll()` will walk before giving up.
 *
 * The end of a result set is not always knowable: a server that omits every paging figure and
 * returns full pages forever cannot be told from a very large account. An unbounded walk
 * against one never returns. At the default page size of 100 this is ten million shares.
 */
export const MAX_PAGES = 100_000

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
 * The paging figures every list on this API attaches.
 *
 * One interface shared by the three lists rather than three copies, because they have to
 * answer "is there more" identically. A plain array would leave a caller guessing whether
 * more exists, and a caller who has to guess guesses wrong — usually by stopping at the
 * first short page.
 */
export interface PageInfo {
  /** The page the SERVER says it returned, which is not always the page that was asked for. */
  page: number
  /** The limit the SERVER applied. A server free to cap page size returns a lower one. */
  limit: number
  total?: number
  totalPages?: number
  hasMore: boolean
}

/** A page of shares, with the paging figures attached. Metadata only, and never a key. */
export interface SharePage extends PageInfo {
  shares: ShareSummary[]
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

/**
 * One prompt on a collect form.
 *
 * Unknown members are accepted without error but NOT STORED: the server unmarshals a request
 * field into `{item, type}` and silently discards the rest. Unlike a share's fields, whose
 * extras survive because they sit inside the ciphertext, a request's prompts are plaintext
 * metadata — so an extra member here reaches the API, is not refused, and is not kept. The
 * member is open so that an older field list cannot refuse a newer sender, not so that you
 * can store data in one.
 */
export interface RequestField {
  /**
   * The VISIBLE PROMPT — "Staging database password".
   *
   * `item`, not `key`. A share's field spells its label `key` and a request's spells it
   * `item`, and this one SDK carries both, so handing a share field to a request is the easy
   * mistake here. The server's own refusal names `Fields[0].Item`, which is not the member
   * anybody typed, so this client refuses it locally and says which spelling belongs where.
   */
  item: string
  /** How the field renders for the submitter. Defaults to `text` server-side when omitted. */
  type?: FieldType | string
  [extra: string]: unknown
}

export interface CreateRequestOptions {
  title: string
  /**
   * What the person filling the link is asked for. At least one, and this client checks that
   * before anything is sent: a request with no fields is created successfully, returns a 201
   * and a live short code, and renders "Unable to Load Request" for whoever it was sent to.
   */
  fields: readonly RequestField[]
  description?: string
  /**
   * A gate on the collect link, sent to the server AS GIVEN.
   *
   * Deliberately unlike a share's passcode, which travels as a one-way verifier. There is
   * nothing for a verifier to protect here: the server has to admit or refuse a submitter
   * arriving at a form whose contents it never sees, so the check has to be one it can
   * perform. This is an access gate, not part of the encryption — the seed is what keeps the
   * submissions unreadable, and it stays with you either way.
   */
  passcode?: string
  /**
   * When the collect link stops accepting submissions.
   *
   * Omitting it does NOT leave the link open forever. The server defaults to 30 days, the
   * same as the dashboard, because a request created with no expiry at all is invisible: the
   * list query is `expired_at > now`, and NULL satisfies neither that nor its negation.
   */
  expiredAt?: string
  /** How many submissions the link will accept in total. */
  maxSubmission?: number
  /** How many times the form may be OPENED, which is not the same as submitted. */
  accessCountsLeft?: number
  requiresLogin?: boolean
  requiresMfa?: boolean
  restrictedDomain?: readonly string[]
  ipWhitelist?: readonly string[]
  /**
   * Required by the API, and generated when you do not pass one.
   *
   * Unlike a share create, two calls under one key CAN legitimately be the same request: the
   * body carries no ciphertext, so passing the same `seed` with the same arguments produces a
   * byte-identical body and the API replays its first answer. Change the seed and the body
   * differs, which is refused with `IdempotencyConflictError` — that is the header working,
   * not failing.
   */
  idempotencyKey?: string
  /**
   * Create the request under a keypair you already hold, rather than a fresh random one.
   *
   * The case this exists for is a runner that wants its keypair to be REPRODUCIBLE: derive a
   * seed from the third part of your credential with `custodyKeypair(custodySecret)` and pass
   * `.seed` here, and an ephemeral container can read the submissions later with no local
   * state and nothing to store.
   *
   * The trade is compartmentalisation. A fresh seed per request means a leaked seed opens one
   * request; a seed shared across every request a credential creates means a leaked seed
   * opens all of them. Pass one when statelessness is worth more than that, and not by
   * default.
   *
   * Either way the seed is never transmitted. Only the public half goes.
   */
  seed?: Uint8Array
  organizationId?: string
}

/**
 * A created secure request, and the only place its seed exists.
 *
 * A class rather than a plain object for the reason `Share` is one: `seed` and `accessLink`
 * ARE the ability to read every submission, so an object literal turns any incidental
 * `console.log(request)`, structured-logger call or `JSON.stringify` into a permanent
 * plaintext record of them. The properties are all still here and still readable — you have
 * to ask for them by name.
 */
export class SecureRequest {
  readonly shortCode: string
  /** The public half that was registered, base64url and unpadded, as the server echoed it. */
  readonly publicKey: string
  /**
   * The keyless link you hand to a human. Safe to put in a ticket: holding it lets somebody
   * submit, never read.
   */
  readonly collectLink: string
  readonly expiredAt: string | null
  /**
   * The Idempotency-Key this create was sent with, generated when you did not supply one.
   *
   * Surfaced because the documented recovery from an uncertain outcome is to repeat the
   * identical request with the same key — impossible for a key you were never told.
   */
  readonly idempotencyKey: string

  // The two secrets are PRIVATE fields behind getters, not public own properties, and that is
  // the difference between redacting a rendering and not having one to redact.
  //
  // `toJSON`, `toString` and the inspect symbol cover the paths that ask the value how to
  // render itself. Two reflexive paths do not ask: `console.dir(request, { depth: null })`
  // passes `customInspect: false`, and `console.table([request])` builds its columns from own
  // properties — both walked straight past all three hooks and printed the seed's 32 bytes
  // and the access link in full. An own property cannot be hidden from them; a private field
  // is not there to find. `#`, not `readonly`, is what makes the guarantee hold, and the
  // spread `{ ...request }` stops carrying the seed as a side effect.
  readonly #seed: Uint8Array
  readonly #accessLink: string

  constructor(init: {
    shortCode: string
    seed: Uint8Array
    publicKey: string
    collectLink: string
    accessLink: string
    expiredAt?: string | null
    idempotencyKey: string
  }) {
    this.shortCode = init.shortCode
    this.publicKey = init.publicKey
    this.collectLink = init.collectLink
    this.expiredAt = init.expiredAt ?? null
    this.idempotencyKey = init.idempotencyKey
    this.#seed = init.seed
    this.#accessLink = init.accessLink
  }

  /**
   * The 32-byte private seed.
   *
   * **This is the only way to read the submissions, and it was never sent to CredenShare.**
   * We hold the public half and cannot open anything sealed to it. Handing this back is the
   * entire point of the method that returned it: store it, or store the access link that
   * carries it. Lose both and the submissions are unreadable by everyone, us included.
   *
   * A getter over a private field, so that reading it is something you did on purpose and
   * every ordinary path that enumerates or serializes this object finds nothing to print.
   * `scripts/seed-sweep.ts` runs the list and greps every rendering for the bytes in five
   * encodings: `JSON.stringify` (bare and nested), `{ ...request }`, `structuredClone`,
   * `console.log` (plain, `%s` and `%o`), `console.dir(request, { depth: null })`,
   * `console.table` on the object and on an array of it, `util.inspect` with
   * `customInspect: false` and with `showHidden: true`, `for..in`, `Object.keys`/`entries`,
   * `Object.getOwnPropertyDescriptors` and template interpolation. All clean.
   *
   * **One documented exception, which cannot be closed from inside this class.**
   * `util.inspect(request, { getters: true, showHidden: true, customInspect: false })` prints
   * these 32 bytes in full, and `accessLink` beside them. All three flags are needed, and
   * each one is doing exactly what it says:
   *
   * - `showHidden: true` makes a prototype accessor visible to the walk at all — this is why
   *   the two-flag `{ getters: true, customInspect: false }` is clean, since `seed` is a class
   *   accessor and inspect otherwise only walks own properties;
   * - `getters: true` then invokes it instead of printing `[Getter]`;
   * - `customInspect: false` discards the redacting hook that would have answered first.
   *
   * Together they say "ignore this object's own opinion about how to render itself and call
   * every accessor on it" — an explicit instruction to do the one thing this design asks a
   * caller not to do, and no getter can both answer it and withhold its value. It is not
   * particular to this class: that combination renders any getter-backed secret in any
   * library. The rule is to keep it away from anything whose output reaches a log.
   */
  get seed(): Uint8Array {
    return this.#seed
  }

  /**
   * Your own link, with the seed in the fragment. Treat it as the secret itself — anyone
   * holding it can read every submission, and CredenShare cannot.
   *
   * A getter for the same reason as `seed`: it is the same 32 bytes in a different alphabet,
   * so anything that hides one and prints the other hides nothing. The documented exception
   * on `seed` applies here too, for the same reason and with the same remedy.
   */
  get accessLink(): string {
    return this.#accessLink
  }

  /** Redacted. The seed and the access link are omitted on purpose; the collect link is not. */
  toJSON(): Record<string, unknown> {
    return {
      shortCode: this.shortCode,
      publicKey: this.publicKey,
      collectLink: this.collectLink,
      expiredAt: this.expiredAt,
      idempotencyKey: this.idempotencyKey,
      accessLink: '[redacted - contains the seed]',
      seed: '[redacted]',
    }
  }

  toString(): string {
    return `SecureRequest(${this.shortCode}, seed redacted)`
  }

  /**
   * Node's console.log / util.inspect path, which ignores toJSON.
   *
   * One of three hooks and not sufficient on its own: `console.dir` passes
   * `customInspect: false` and `console.table` never asks either. That is what the private
   * fields above are for.
   */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString()
  }
}

/**
 * Metadata for a secure request. Never a submission, and never a private key.
 *
 * `publicKey` is returned where a share's key material never is, which is not an
 * inconsistency: this is the PUBLIC half, you supplied it, and getting it back is how you
 * confirm what was stored. It is absent on a request whose row the server can no longer
 * read — an expired one fetched by its owner — so it is nullable rather than assumed.
 */
export interface RequestSummary {
  shortCode: string
  expiredAt?: string | null
  publicKey?: string | null
}

/** A page of secure requests, with the paging figures attached. */
export interface RequestPage extends PageInfo {
  requests: RequestSummary[]
}

/**
 * One submission, still sealed.
 *
 * `data` is content, and this is the only read on the API that carries any — which is the
 * metadata-only rule working rather than an exception to it. What comes back is sealed to the
 * request's public key, so the API hands over something it cannot open, to the one party who
 * can. Use `decryptSubmission` and the seed.
 */
export interface Submission {
  shortCode: string
  createdAt?: string | null
  /**
   * The sealed blob: STANDARD base64, padded, because it travels in a JSON body. The
   * request's `public_key` is base64url and unpadded because it was minted for a URL. Two
   * halves of one feature, two alphabets; `decryptSubmission` feeds this one the right
   * decoder for you.
   */
  data: string
  encryptionType?: string | null
}

/**
 * The submissions to one request — all of them.
 *
 * No paging figures, because this endpoint has none: the handler ignores `page` and `limit`
 * and answers `{submissions, count}` with no pagination block at all. The name keeps the
 * `…Page` suffix its two siblings have, but there is nothing to walk and no next page to ask
 * for. Attaching a paging envelope here is what made the walk re-request page one forever.
 */
export interface SubmissionPage {
  submissions: Submission[]
  /**
   * The count the API reported alongside the rows.
   *
   * Its own member rather than folded into a paging total: it is the server's count of what
   * it actually returned, which equals `submissions.length` unless the two disagree — and if
   * they ever disagree, that is worth being able to see.
   */
  count?: number
  /**
   * Submissions the server withheld because they are not end-to-end encrypted.
   *
   * A request created before E2EE collects server-encrypted submissions, and returning those
   * over a bearer-authenticated API would make this the one place in the product where a
   * credential yields readable secrets. They are withheld and COUNTED, so a caller
   * reconciling against their dashboard can see why the numbers differ instead of reading a
   * short page as the end of the list.
   */
  skippedNotEndToEndEncrypted?: number
}

/**
 * What a delete did.
 *
 * `expired` on the first call, `deleted` on a second — see `Requests.delete`. Reported rather
 * than left to be inferred, because the two are not interchangeable: one preserves the
 * submissions already received and the other destroys them.
 *
 * `null` when the server did not say. Not coerced to `expired`: an outcome the SDK invented
 * is indistinguishable from one the server sent, on the one destructive call in this surface,
 * and a TS union cannot be widened after publication without breaking every consumer.
 */
export interface RequestDeletion {
  shortCode: string
  outcome: 'expired' | 'deleted' | null
}

export interface ShareCounts {
  active: number
  expired: number
  totalViewed: number
}

export interface DailyView {
  /** `YYYY-MM-DD`. */
  date: string
  count: number
}

/**
 * The account's usage figures, or the organization's when the key acts in one.
 *
 * The per-member breakdown the dashboard shows is deliberately absent from the API and so
 * from here: a key scoped to read statistics should not become a way to enumerate colleagues.
 */
export interface Stats {
  shares: ShareCounts
  /** Oldest first, zero-filled, and always present — possibly empty. */
  dailyViews: DailyView[]
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
  readonly requests: Requests
  readonly stats: StatsClient

  constructor(credential: string, options: ClientOptions = {}) {
    this.credential = Credential.parse(credential)
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '')
    this.#linkOrigin = (options.linkOrigin ?? DEFAULT_LINK_ORIGIN).replace(/\/+$/, '')
    this.#timeoutMs = options.timeoutMs ?? 30_000
    this.#maxRetries = Math.max(0, options.maxRetries ?? DEFAULT_MAX_RETRIES)
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
    this.shares = new Shares(this)
    this.requests = new Requests(this)
    this.stats = new StatsClient(this)
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
   * The keyless collect link for a secure request — the one you hand to a human.
   *
   * Deliberately without a fragment. Holding this link lets somebody SUBMIT and never read,
   * which is what makes it safe to paste into a ticket. `accessLinkFor` is the other half.
   */
  collectLinkFor(shortCode: string): string {
    return `${this.#linkOrigin}/r/${shortCode}`
  }

  /**
   * Your own access link for a secure request: the seed in the fragment, which browsers never
   * send to a server.
   *
   * Treat the result as the secret itself — it is the ability to read every submission, on
   * any device, with nothing stored. CredenShare cannot rebuild it, because the seed was
   * never ours. Useful for turning a seed you stored at create time back into a link.
   */
  accessLinkFor(shortCode: string, seed: Uint8Array): string {
    return `${this.#linkOrigin}/r/${shortCode}#${crypto.encodeFragment(seed)}`
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

  /**
   * Issue a raw authenticated call — the escape hatch for anything this SDK does not model.
   *
   * Every typed method goes through here, so a call made this way gets the same timeout, the
   * same bounded retries, the same error mapping and the same custody assertion. What it does
   * NOT do is encrypt: a body you build here is sent exactly as you wrote it, so nothing
   * secret belongs in one.
   *
   * A POST, PUT or PATCH gets an `Idempotency-Key` when you did not supply one, because
   * those are the calls where a retry could create a second thing, and a 400 saying the
   * header was required is a poor way to find that out from an endpoint you reached past the
   * typed methods to call. A GET and a DELETE get nothing added: neither reads the header,
   * and a DELETE is idempotent by construction. A key you DID supply is sent on ANY method,
   * exactly as you wrote it, matched case-insensitively — two spellings of the same header is
   * worse than none.
   */
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

    // Assembled ONCE, before the retry loop, and that placement is the point: a key minted
    // per attempt would make the retry a new request under a new key, which is the exact
    // duplicate the header exists to prevent. A caller-supplied key is left untouched — this
    // fills a gap, it does not take the decision away.
    //
    // POST/PUT/PATCH only. See IDEMPOTENT_KEYED_METHODS: a DELETE does not get one, so the
    // bytes of `shares.expire()` are exactly those 0.1.4 published.
    if (
      IDEMPOTENT_KEYED_METHODS.has(method.toUpperCase()) &&
      !hasHeader(headers, 'Idempotency-Key')
    ) {
      headers['Idempotency-Key'] = globalThis.crypto.randomUUID()
    }

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
    return {
      shares: rows.map((row) => ({
        shortCode: String(row.short_code),
        expiredAt: (row.expired_at as string | null) ?? null,
      })),
      // Every figure, and the hasMore ladder, come from `pageEnvelope` — shared with the
      // requests and submissions lists, because three copies of that reasoning would drift
      // and the drift shows up as a walk that returns part of an account and reports success.
      ...pageEnvelope(data, page, limit, rows.length),
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
    yield* walkPages(async (page) => {
      const batch = await this.list({ limit: options.limit ?? 100, page })
      return { rows: batch.shares, page: batch.page, hasMore: batch.hasMore }
    })
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

/**
 * Secure requests: collect links a human fills in.
 *
 * The asymmetry with shares is the whole feature. A share is content you encrypt and hand
 * out; a request is a form you hand out and someone else encrypts INTO. So the keypair is
 * minted here, the public half is published for submitters to seal to, and the private seed
 * is handed back to you and never sent. One submitter cannot read another's submission
 * because each seals under its own ephemeral key, and CredenShare cannot read any of them
 * because the seed was never ours.
 */
class Requests {
  readonly #client: CredenShare

  constructor(client: CredenShare) {
    this.#client = client
  }

  /**
   * Create a secure request, and hand you back the seed that reads its submissions.
   *
   * A keypair is generated from a 32-byte seed, the PUBLIC half is registered with the API,
   * and the seed is returned to you in `SecureRequest.seed`. **The seed is never
   * transmitted.** That is not an implementation detail to be tidied away later — it is the
   * property the feature is built on, and the reason this method returns something you have
   * to store rather than a bare short code. A body assertion below enforces it rather than
   * trusting the field list, so a later edit that adds a `seed` member fails here instead of
   * in production.
   *
   * Each field is `{ item, type }`. `item` is the visible prompt — not `key`, which is what a
   * SHARE field uses; passing one of those creates a live collect link whose prompts are
   * blank. This client refuses it before anything is sent.
   */
  async create(options: CreateRequestOptions): Promise<SecureRequest> {
    // Locally, and first. A field spelled wrong or a missing field array both produce a 201
    // and a live short code, and the failure surfaces in a stranger's browser rather than
    // anywhere the creator is looking.
    validateRequestFields(options.fields)

    const seed = options.seed ?? crypto.newSeed()
    // Checked before the keypair is derived, so a wrong-length seed is a typed error rather
    // than the plain Error keypairFromSeed would raise from inside a crypto primitive.
    if (seed.length !== crypto.SEED_LENGTH) {
      throw new MalformedKeyError(
        `a request seed is ${crypto.SEED_LENGTH} bytes; this one is ${seed.length}`,
      )
    }
    const keypair = await crypto.keypairFromSeed(seed)

    const body: ApiPayload = {
      title: options.title,
      // The PUBLIC half, base64url and UNPADDED, because it was minted to travel in a URL.
      // The submission blobs that come back are standard padded base64. Two encodings on one
      // feature, and mixing them up yields a wrap that will not open.
      public_key: keypair.publicKeyB64url,
      fields: options.fields,
    }
    if (options.description !== undefined) body.description = options.description
    if (options.passcode !== undefined) body.passcode = options.passcode
    if (options.expiredAt !== undefined) body.expired_at = options.expiredAt
    if (options.maxSubmission !== undefined) body.max_submission = options.maxSubmission
    if (options.accessCountsLeft !== undefined) body.access_counts_left = options.accessCountsLeft
    if (options.requiresLogin !== undefined) body.requires_login = options.requiresLogin
    if (options.requiresMfa !== undefined) body.requires_mfa = options.requiresMfa
    if (options.restrictedDomain !== undefined) body.restricted_domain = options.restrictedDomain
    if (options.ipWhitelist !== undefined) body.ip_whitelist = options.ipWhitelist
    if (options.organizationId !== undefined) body.organization_id = options.organizationId

    // Belt and braces, at the boundary, in the manner of the custody assertion in
    // `request()`. Checked against the SERIALIZED body so a seed smuggled in through a title,
    // a description or an unknown field member is caught too — not only one added to the
    // field list above.
    //
    // The Idempotency-Key is resolved BEFORE the scan and included in what gets scanned,
    // because it is an outgoing header and the body is not the only thing that goes on the
    // wire. `seed` and `idempotencyKey` are adjacent members of the same options object, the
    // reproducible-keypair recipe pushes callers towards determinism, and a caller who wants
    // a deterministic KEY to match their deterministic SEED has the seed in hand — so
    // `idempotencyKey: b64url(seed)` carried it out through a header, past a check that only
    // ever looked at the body.
    const idempotencyKey = options.idempotencyKey ?? globalThis.crypto.randomUUID()
    const serialized =
      JSON.stringify(body) + JSON.stringify({ 'Idempotency-Key': idempotencyKey })
    for (const rendering of seedRenderings(seed)) {
      if (serialized.includes(rendering)) {
        throw new RequestSeedTransmittedError(
          'the request seed was about to be transmitted; the submissions to a request whose ' +
            'seed reached the server are not zero-knowledge, so expire it and create a new one',
        )
      }
    }

    const data = await this.#client.request('POST', '/requests', {
      body,
      // Required by the API, not optional. A retried automation must not leave two collect
      // links in the world when the caller believes it created one — and unlike a duplicate
      // share, a duplicate collect link is not inert: a human can fill it in.
      headers: { 'Idempotency-Key': idempotencyKey },
    })

    const shortCode = String(data.short_code)
    return new SecureRequest({
      shortCode,
      seed,
      publicKey: String(data.public_key ?? keypair.publicKeyB64url),
      collectLink: this.#client.collectLinkFor(shortCode),
      accessLink: this.#client.accessLinkFor(shortCode, seed),
      expiredAt: (data.expired_at as string | null) ?? null,
      idempotencyKey,
    })
  }

  /**
   * One page of the account's secure requests, newest first. Metadata only.
   *
   * Use `iterateAll()` to walk every page.
   */
  async list(options: { limit?: number; page?: number } = {}): Promise<RequestPage> {
    const limit = options.limit ?? 25
    const page = options.page ?? 1
    const data = await this.#client.request('GET', '/requests', { query: { limit, page } })
    const rows = (data.requests ?? data.data ?? []) as Array<Record<string, unknown>>
    return {
      requests: rows.map(requestSummaryOf),
      ...pageEnvelope(data, page, limit, rows.length),
    }
  }

  /**
   * Every secure request, page by page.
   *
   * Same walk as `shares.iterateAll()`, and written here for the same reason: the
   * hand-rolled version stops on the first page shorter than `limit`, which is a page the
   * server is entitled to return in the middle of a result set.
   */
  async *iterateAll(options: { limit?: number } = {}): AsyncGenerator<RequestSummary> {
    yield* walkPages(async (page) => {
      const batch = await this.list({ limit: options.limit ?? 100, page })
      return { rows: batch.requests, page: batch.page, hasMore: batch.hasMore }
    })
  }

  /**
   * One request's metadata, including the public key it was created with.
   *
   * A request belonging to another account reports exactly as one that does not exist.
   */
  async get(shortCode: string): Promise<RequestSummary> {
    const data = await this.#client.request('GET', `/requests/${encodeURIComponent(shortCode)}`)
    // The path short code as the fallback, not the override: a server that answers with a
    // different code is telling us something, and `String(null)` would otherwise report the
    // literal text "null" as a short code.
    return requestSummaryOf({ ...data, short_code: data.short_code ?? shortCode })
  }

  /**
   * Expire a request — and, on a SECOND call, delete it.
   *
   * Two steps by design, and `outcome` says which one happened. The first call expires an
   * active request, which stops new submissions while PRESERVING the ones already received.
   * Calling it again on an already-expired request removes the request outright. So a caller
   * that loops until this stops erroring destroys the submissions, which is exactly why the
   * outcome is returned rather than a bare 200.
   *
   * No Idempotency-Key is required here, unlike a create. A key can only act on requests its
   * own account created; a short code belonging to somebody else reports as not-found, so
   * this cannot be used to probe for requests elsewhere.
   */
  async delete(shortCode: string): Promise<RequestDeletion> {
    const data = await this.#client.request(
      'DELETE',
      `/requests/${encodeURIComponent(shortCode)}`,
    )
    return {
      shortCode: String(data.short_code ?? shortCode),
      // An unrecognised or absent value is `null`, NOT the less destructive of the two. The
      // server always sends one, so this is unreachable today — but reporting "expired" for
      // an answer that said nothing makes an outcome this SDK invented indistinguishable
      // from one the server sent, on the only destructive call in this surface. A caller who
      // can see `null` goes and checks; a caller told "expired" has no reason to.
      outcome:
        data.outcome === 'deleted' ? 'deleted' : data.outcome === 'expired' ? 'expired' : null,
    }
  }

  /**
   * EVERY submission to a request, STILL SEALED, in one call.
   *
   * Not paginated, and that is the endpoint rather than a shortcut taken here: the handler
   * ignores `page` and `limit` and answers `{submissions, count}` with no pagination block at
   * all, so there is no next page to ask for and this takes no page or limit. What comes back
   * is the whole set, plus the server's own `count`.
   *
   * It used to take both and route them through the shared paging ladder, whose last rung
   * infers "there is more" from a page as long as the limit. Against an endpoint that sends
   * no paging figures that inference is true forever: a request holding at least `limit`
   * submissions re-requested page one up to `MAX_PAGES` times, re-yielding every sealed
   * submission on each pass, and then threw. The fix is not a better guess — it is that there
   * is nothing here to guess.
   *
   * Sealed and not decrypted, deliberately. Decrypting on fetch would put every credential a
   * human handed over into memory — and into whatever logged the result — for a caller who
   * only wanted to count them. It is the same line the shares side draws: a list is metadata,
   * and reading content is a call you make on purpose. Pass a row to `decryptSubmission()`
   * with the seed when you want it.
   */
  async submissions(shortCode: string): Promise<SubmissionPage> {
    const data = await this.#client.request(
      'GET',
      `/requests/${encodeURIComponent(shortCode)}/submissions`,
    )
    const rows = (data.submissions ?? []) as Array<Record<string, unknown>>
    const skipped = data.skipped_not_end_to_end_encrypted
    return {
      submissions: rows.map((row) => ({
        shortCode: String(row.short_code),
        createdAt: (row.created_at as string | null) ?? null,
        data: String(row.data ?? ''),
        encryptionType: (row.encryption_type as string | null) ?? null,
      })),
      count: typeof data.count === 'number' ? data.count : undefined,
      skippedNotEndToEndEncrypted: typeof skipped === 'number' ? skipped : undefined,
    }
  }

  /**
   * Every submission to a request, still sealed, one row at a time.
   *
   * ONE HTTP call, and then it stops: there are no further pages to fetch. Kept because a
   * caller reaching for the row-at-a-time shape the other two lists have should find it, and
   * finding it absent invites a hand-rolled loop against an endpoint that answers every page
   * number identically.
   */
  async *iterateSubmissions(shortCode: string): AsyncGenerator<Submission> {
    const all = await this.submissions(shortCode)
    yield* all.submissions
  }

  /**
   * Open a submission with the seed you kept when the request was created.
   *
   * Takes a row from `submissions()` or a bare blob string, so a caller who stored only the
   * ciphertext can still read it later. Nothing here touches the network — the same function
   * is exported as `decryptSubmission` for callers holding a blob and no client.
   *
   * A wrong seed and an altered blob are indistinguishable, and surface as `WireFormatError`.
   */
  async decryptSubmission(
    submission: Submission | string,
    seed: Uint8Array,
  ): Promise<Field[]> {
    return crypto.decryptSubmission(
      typeof submission === 'string' ? submission : submission.data,
      seed,
    )
  }
}

/**
 * The account's usage figures.
 *
 * Its own namespace rather than a bare method, so it reads like the other two surfaces and
 * has somewhere to grow if `/stats` ever gains a sibling.
 */
class StatsClient {
  readonly #client: CredenShare

  constructor(client: CredenShare) {
    this.#client = client
  }

  /**
   * Counts and the daily view series.
   *
   * Scoped to the organization when the key acts in one, which is the answer a seat member's
   * automation actually wants: a member has no figures of their own worth reporting, and the
   * team's are what the question is about.
   *
   * Missing counts read as 0 and a missing series as empty, rather than as undefined. A
   * caller has to distinguish "no data" from "field absent" otherwise, and will get it wrong.
   */
  async get(): Promise<Stats> {
    const data = await this.#client.request('GET', '/stats')
    const shares = (data.shares ?? {}) as Record<string, unknown>
    const rows = Array.isArray(data.daily_views)
      ? (data.daily_views as Array<Record<string, unknown>>)
      : []
    return {
      shares: {
        active: countOf(shares.active),
        expired: countOf(shares.expired),
        totalViewed: countOf(shares.total_viewed),
      },
      dailyViews: rows.map((row) => ({
        date: String(row.date ?? ''),
        count: countOf(row.count),
      })),
    }
  }
}

/**
 * Check a collect form's prompts before a request is created.
 *
 * Both failures this catches produce a LIVE collect link and a 201. An empty field array
 * renders "Unable to Load Request" for whoever it was sent to; a field spelled `key` — the
 * member a SHARE field uses, in this same SDK — renders a prompt with no text. Neither
 * surfaces anywhere the creator looks, which is why they are refused here rather than left to
 * the server's own message about `Fields[0].Item`.
 */
function validateRequestFields(fields: readonly RequestField[]): void {
  if (!Array.isArray(fields) || fields.length === 0) {
    throw new InvalidFieldError(
      'a request needs at least one field; one with none is created successfully and then ' +
        'renders as "Unable to Load Request" for whoever you send it to',
    )
  }
  fields.forEach((field, index) => {
    if (typeof field !== 'object' || field === null || Array.isArray(field)) {
      throw new InvalidFieldError(`field ${index} is not an object`)
    }
    if (!('item' in field)) {
      for (const wrong of ['key', 'label', 'name', 'title', 'prompt']) {
        if (wrong in field) {
          throw new InvalidFieldError(
            `field ${index} uses ${JSON.stringify(wrong)} for its prompt; on a REQUEST the ` +
              "member is 'item'. A share's field uses 'key', which is the easy mistake here, " +
              'and the field would render with a blank prompt.',
          )
        }
      }
      throw new InvalidFieldError(`field ${index} has no 'item' (its visible prompt)`)
    }
    if (typeof field.item !== 'string' || field.item === '') {
      throw new InvalidFieldError(`field ${index} has an empty 'item'`)
    }
  })
}

function requestSummaryOf(row: Record<string, unknown>): RequestSummary {
  return {
    shortCode: String(row.short_code),
    expiredAt: (row.expired_at as string | null) ?? null,
    publicKey: (row.public_key as string | null) ?? null,
  }
}

/**
 * Every encoding a 32-byte seed could plausibly be rendered in, for the boundary assertion.
 *
 * Three rather than one because the point is to catch a seed that reached the wire through a
 * route nobody anticipated, and somebody hand-rolling that would reach for whichever encoder
 * was nearest.
 *
 * Both base64 spellings are UNPADDED, which is what makes three enough. 32 bytes are 43
 * base64 characters plus one `=`, so an `includes()` of the PADDED form does not match the
 * unpadded one: the list read as complete while missing the standard alphabet's 43-character
 * spelling entirely, catching it only when the seed's base64 happened to contain no `+` or
 * `/`. An unpadded string is a prefix of its padded form, so testing for it covers both.
 */
function seedRenderings(seed: Uint8Array): string[] {
  return [
    crypto.b64url(seed),
    crypto.b64(seed).replace(/=+$/, ''),
    Array.from(seed, (byte) => byte.toString(16).padStart(2, '0')).join(''),
  ]
}

function countOf(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

/**
 * The paging figures for one page, read from whatever the server actually said.
 *
 * Shared by the three lists rather than reimplemented in each, because every line of it is
 * load-bearing and a second copy would drift from this one silently — and the failure that
 * drift produces is a walk that returns a fraction of an account while reporting success.
 */
function pageEnvelope(
  payload: ApiPayload,
  requestedPage: number,
  requestedLimit: number,
  rowCount: number,
): PageInfo {
  const pagination = (payload.pagination ?? {}) as Record<string, number | undefined>
  const totalPages = pagination.total_pages
  const resolvedPage = pagination.page ?? requestedPage
  // The limit the SERVER applied, not the one the caller asked for. A server free to cap
  // page size returns fewer rows than requested on a page that is nonetheless full, and
  // comparing against the request makes that look like the end of the result set.
  // A non-positive echo is not information, so it is ignored in favour of what was asked
  // for. Believing `limit: 0` made `rows.length >= 0` true on every page, including empty
  // ones, and the walk never ended - strictly worse than the truncation the fallback fixed.
  const echoed = pagination.limit
  const resolvedLimit = echoed !== undefined && echoed > 0 ? echoed : requestedLimit
  const total = pagination.total
  // Belt and braces: if the caller also asked for 0, fall back to what arrived, and if
  // nothing arrived there is no progress to claim.
  const progress = resolvedLimit > 0 ? resolvedLimit : rowCount
  return {
    page: resolvedPage,
    limit: resolvedLimit,
    total,
    totalPages,
    // Three rungs, in descending order of how much the server told us. Reporting "no
    // more" on a full page is what makes a walk stop after page one and silently return a
    // fraction of the account; but a rung that can be true FOREVER is worse - it turns
    // that truncation into a request loop. `progress` is what prevents it: when the server
    // echoes limit: 0 and sends an empty page, no rung can claim there is more.
    hasMore:
      totalPages !== undefined
        ? resolvedPage < totalPages
        : total !== undefined
          ? progress > 0 && resolvedPage * progress < total
          : progress > 0 && rowCount >= progress,
  }
}

/**
 * Walk a paginated list to its end, one page at a time.
 *
 * The guards are the point. A walk that cannot observe progress must refuse rather than
 * loop, and a walk with no end signal must stop and say so rather than run forever — both
 * are failures a caller can act on, where a silently truncated result is not.
 */
async function* walkPages<T>(
  fetchPage: (page: number) => Promise<{ rows: readonly T[]; page: number; hasMore: boolean }>,
): AsyncGenerator<T> {
  let page = 1
  for (;;) {
    const batch = await fetchPage(page)
    yield* batch.rows
    if (!batch.hasMore) return

    // The API echoing a page number other than the one asked for makes progress
    // unobservable, so no termination condition can be trusted. Refuse rather than loop.
    if (batch.page !== page) {
      throw new ApiError(
        `asked for page ${page} and the API answered with page ${batch.page}, so paging ` +
          `cannot be trusted to terminate`,
      )
    }
    if (page >= MAX_PAGES) {
      throw new ApiError(
        `stopped after ${MAX_PAGES} pages without the API signalling the end of the result ` +
          `set. A walk that cannot terminate is worse than one that stops and says so.`,
      )
    }
    page += 1
  }
}

/**
 * Whether a header is already present, matched the way HTTP matches: case-insensitively.
 *
 * A caller who passed `idempotency-key` in lower case must not end up sending two headers
 * under two spellings, which is worse than sending none.
 */
function hasHeader(headers: Record<string, string>, name: string): boolean {
  const wanted = name.toLowerCase()
  return Object.keys(headers).some((key) => key.toLowerCase() === wanted)
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
  // typeof [] === 'object', so without the Array check a JSON array reaches the caller
  // behind a declared Record type - a lie the type system cannot catch.
  const additionalData =
    payload.additional_data &&
    typeof payload.additional_data === 'object' &&
    !Array.isArray(payload.additional_data)
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
  return `credenshare-node/${VERSION}`
}
