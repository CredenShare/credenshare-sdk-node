/**
 * Errors whose types imply remedies.
 *
 * Several of these look identical on screen and have opposite fixes — a link that arrived
 * without its key versus a link that arrived damaged; a spent plan allowance versus a rate
 * limit. Distinguishing them in the type is the difference between a caller who knows what
 * to do and one who retries forever.
 */

export class CredenShareError extends Error {
  constructor(message: string) {
    super(message)
    this.name = new.target.name
    // Without this, `instanceof` fails for subclasses when the package is compiled down to
    // ES5 by a consumer's bundler — and an error nobody can catch by type is an error whose
    // type carries no information.
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

/**
 * A link arrived with no key at all.
 *
 * Usually something stripped the fragment: a chat client that "cleaned" the URL, a redirect,
 * a copy that stopped at the `#`. The remedy is to ask for the link again — not to ask for
 * the share to be recreated.
 */
export class MissingKeyError extends CredenShareError {}

/**
 * A key is present but unusable — truncated, or from a newer format.
 *
 * Distinct from `MissingKeyError` because "your link is incomplete" and "this link is
 * damaged" send somebody to different places, and both look the same on screen.
 */
export class MalformedKeyError extends CredenShareError {}

/**
 * Content could not be read: a wrong passcode, or altered ciphertext.
 *
 * The two are indistinguishable on purpose. Telling them apart would hand an attacker an
 * oracle for guessing passcodes.
 */
export class WireFormatError extends CredenShareError {}

/** A credential is not in the `crs_sk_live_<keyId>.<authSecret>[.<custodySecret>]` shape. */
export class CredentialFormatError extends CredenShareError {}

/**
 * The custody secret was about to be transmitted.
 *
 * Raised at the boundary rather than trusted to a constructor elsewhere. If this ever fires,
 * the credential has to be rotated: the guarantee it exists to provide — that the server
 * *cannot* reconstruct the custody private key — is gone the moment it reaches the wire.
 */
export class CustodySecretTransmittedError extends CredenShareError {}

/**
 * A secure request's private seed was about to be transmitted.
 *
 * The mirror of {@link CustodySecretTransmittedError}, for the other secret this SDK holds
 * that the server must never see. A request's seed IS the ability to read its submissions:
 * the public half is published so submitters can seal to it, and the seed stays with the
 * caller, which is what makes one submitter unable to read another's and us unable to read
 * any of them. If it reaches the wire that property is gone, and the remedy is to expire the
 * request and create a new one under a new seed — not to retry.
 */
export class RequestSeedTransmittedError extends CredenShareError {}

/**
 * A field object is not shaped the way the wire format requires.
 *
 * Its own class rather than a TypeError so that a blanket `catch (e) { if (e instanceof
 * CredenShareError) ... }` — the pattern the README teaches — actually catches it.
 */
export class InvalidFieldError extends CredenShareError {}

export interface ApiErrorInit {
  status?: number
  code?: number
  requestId?: string | null
  additionalData?: Record<string, unknown>
}

/** Any refusal from the API. */
export class ApiError extends CredenShareError {
  readonly status?: number
  /** The API's numeric error code, where it sends one. */
  readonly code?: number
  /** Quote this when reporting a problem; it identifies the exact request in our logs. */
  readonly requestId?: string | null
  /**
   * The server's `additional_data`, where it sent any.
   *
   * This is where a 4xx names the field it rejected — `{ field: 'expired_at', reason: 'must
   * be in the future' }`. Dropping it meant a validation failure could not be attributed to
   * a request field without re-issuing the call and reading the raw body, which for a create
   * means encrypting and sending the secret a second time.
   */
  readonly additionalData?: Record<string, unknown>

  constructor(message: string, init: ApiErrorInit = {}) {
    const parts = [
      init.status === undefined ? null : `HTTP ${init.status}`,
      init.code === undefined ? null : `code ${init.code}`,
      init.requestId ? `request ${init.requestId}` : null,
    ].filter(Boolean)
    super(parts.length ? `${message} (${parts.join(', ')})` : message)
    this.status = init.status
    this.code = init.code
    this.requestId = init.requestId
    this.additionalData = init.additionalData
  }
}

/** The credential is unknown, revoked or expired. Mint a new one. */
export class AuthenticationError extends ApiError {}

/** The credential is valid but not allowed to do this: a missing scope, or a plan without API access. */
export class PermissionError extends ApiError {}

/**
 * No such share on this account.
 *
 * A share belonging to another account reports identically, on purpose, so a credential
 * cannot be used to discover what other accounts hold.
 */
export class NotFoundError extends ApiError {}

/** Too many requests. `retryAfter` is seconds, from the header. */
export class RateLimitError extends ApiError {
  readonly retryAfter?: number

  constructor(message: string, init: ApiErrorInit & { retryAfter?: number } = {}) {
    super(message, init)
    this.retryAfter = init.retryAfter
  }
}

/**
 * The plan's share allowance is spent.
 *
 * Distinct from `RateLimitError`: waiting does not help, and the fix is a plan change or
 * expiring old shares.
 */
export class QuotaExceededError extends ApiError {}

/**
 * An Idempotency-Key was reused with a different request body.
 *
 * Almost always this means a caller passed the same `idempotencyKey` to two separate
 * `create()` calls expecting the second to be a no-op. It cannot be, and no argument to
 * `create()` makes it one: encryption is randomised per call — a fresh salt and IV every
 * time, which AES-GCM requires — so two calls with identical arguments, and even with the
 * same `contentKey`, still produce different ciphertext. The API is right to refuse.
 *
 * What the header actually protects is a NETWORK retry, where the body is byte-identical
 * because it is the same already-encrypted request being sent again. This client performs
 * those retries itself, so the protection is already in place without a caller-supplied key.
 */
export class IdempotencyConflictError extends ApiError {}

/**
 * Entitlements could not be resolved, so nothing was created.
 *
 * Transient and safe to retry. The API returns this rather than guessing, because guessing
 * "unlimited" would let an account exceed its plan and guessing "exhausted" would break a
 * healthy one during a billing hiccup.
 */
export class ServiceUnavailableError extends ApiError {}

/**
 * The API could not be reached at all. Nothing was sent, so nothing was created.
 *
 * Distinct from {@link ServiceUnavailableError}, which is a real HTTP 503 — an answer from
 * the API rather than the absence of one.
 */
export class NetworkError extends CredenShareError {
  /** How many delivery attempts were made before giving up. */
  readonly attempts: number

  constructor(message: string, attempts: number) {
    super(message)
    this.attempts = attempts
  }
}

/**
 * The request was delivered but no response could be read, so its outcome is unknown.
 *
 * A create that throws this may have produced a share whose link this process never saw.
 * Do NOT retry with a fresh idempotency key — that is how one secret becomes two, each with
 * its own link and audit trail. Repeat the identical request so the API can recognise it,
 * or reconcile by listing before retrying.
 */
export class DeliveryUnknownError extends CredenShareError {
  /** How many delivery attempts were made before giving up. */
  readonly attempts: number

  constructor(message: string, attempts: number) {
    super(message)
    this.attempts = attempts
  }
}

/**
 * An identical request is already in flight (error code 106).
 *
 * The first call has not finished. Wait briefly and repeat the byte-identical request —
 * changing the key or the body turns this into a duplicate rather than a retry.
 */
export class IdempotencyInFlightError extends ApiError {}
