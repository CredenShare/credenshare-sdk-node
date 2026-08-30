/**
 * CredenShare — end-to-end encrypted secret sharing.
 *
 * Encryption happens on your machine. The content key never reaches CredenShare, which is
 * what makes "we cannot read your data" a property of the system rather than a promise.
 */

export { CredenShare, Credential, DEFAULT_BASE_URL, DEFAULT_LINK_ORIGIN } from './client.js'
export type { ClientOptions, CreateOptions, Share, SharePage, ShareSummary } from './client.js'

export {
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
  IdempotencyConflictError,
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

export const VERSION = '0.1.0'
