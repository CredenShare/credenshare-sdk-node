/**
 * CredenShare — end-to-end encrypted secret sharing.
 *
 * Encryption happens on your machine. The content key never reaches CredenShare, which is
 * what makes "we cannot read your data" a property of the system rather than a promise.
 */

export {
  CredenShare,
  Credential,
  DEFAULT_BASE_URL,
  DEFAULT_LINK_ORIGIN,
  DEFAULT_MAX_RETRIES,
  Share,
} from './client.js'
export type { ClientOptions, CreateOptions, SharePage, ShareSummary } from './client.js'

export {
  CONTENT_KEY_LENGTH,
  FIELD_TYPES,
  accessToken,
  custodyKeypair,
  decodeFragment,
  decryptContent,
  encodeFragment,
  encryptContent,
  keypairFromSeed,
  newContentKey,
  passcodeVerifier,
  unwrapWithSeed,
  validateFields,
  wrapToPublicKey,
} from './crypto.js'
export type { Field, FieldType, SeedKeypair } from './crypto.js'

export {
  ApiError,
  AuthenticationError,
  CredenShareError,
  CredentialFormatError,
  CustodySecretTransmittedError,
  DeliveryUnknownError,
  IdempotencyConflictError,
  IdempotencyInFlightError,
  InvalidFieldError,
  NetworkError,
  MalformedKeyError,
  MissingKeyError,
  NotFoundError,
  PermissionError,
  QuotaExceededError,
  RateLimitError,
  ServiceUnavailableError,
  WireFormatError,
} from './errors.js'

export * as webhooks from './webhooks.js'

/**
 * The package version.
 *
 * A second copy of a number that lives in package.json, so it drifts: this said '0.1.0' while
 * 0.1.3 was on npm, because the release guard compared the TAG to package.json and never to
 * this. A test now asserts the two agree, and it runs in the release verification.
 */
export const VERSION = '0.1.4'
