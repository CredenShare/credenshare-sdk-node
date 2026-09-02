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
  SecureRequest,
  Share,
} from './client.js'
export type {
  ClientOptions,
  CreateOptions,
  CreateRequestOptions,
  DailyView,
  PageInfo,
  RequestDeletion,
  RequestField,
  RequestPage,
  RequestSummary,
  ShareCounts,
  SharePage,
  ShareSummary,
  Stats,
  Submission,
  SubmissionPage,
} from './client.js'

export {
  CONTENT_KEY_LENGTH,
  FIELD_TYPES,
  SEED_LENGTH,
  accessToken,
  custodyKeypair,
  decodeFragment,
  decryptContent,
  decryptSubmission,
  encodeFragment,
  encryptContent,
  keypairFromSeed,
  newContentKey,
  newSeed,
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
  RequestSeedTransmittedError,
  ServiceUnavailableError,
  WireFormatError,
} from './errors.js'

export * as webhooks from './webhooks.js'

/**
 * The package version.
 *
 * Re-exported from `client.ts` rather than declared here, because a second copy of a version
 * number drifts: this said '0.1.0' while 0.1.3 was on npm, since the release guard compared
 * the TAG to package.json and never to this. The User-Agent then drifted the same way on its
 * own, still reporting 0.1.0 at 0.1.4. There is now one constant, the User-Agent is built
 * from it, and a test asserts it equals package.json.
 */
export { VERSION } from './client.js'
