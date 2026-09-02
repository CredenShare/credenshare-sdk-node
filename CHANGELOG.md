# Changelog

## 0.2.0 — 2026-09-02

Secure requests: a keyless collect link a human fills in, whose keypair is minted here and
whose private seed is never transmitted. Additive — nothing on the shares surface changed
shape or behaviour.

### Added

- **`crs.requests`** — `create`, `list`, `iterateAll`, `get`, `delete`, `submissions`,
  `iterateSubmissions` and `decryptSubmission`. `create()` mints a P-256 keypair from a
  32-byte seed, registers the PUBLIC half, and hands the seed back in `SecureRequest.seed`.
  The seed is never sent, which is what makes one submitter unable to read another's
  submission and CredenShare unable to read any of them.
- **`SecureRequest.collectLink` / `.accessLink`, and `crs.collectLinkFor(shortCode)` /
  `crs.accessLinkFor(shortCode, seed)`** — the keyless link you hand out, and your own link
  with the seed in the fragment. The fragment is version-prefixed (`"1" + base64url`), which
  is where hand-assembly goes wrong.
- **`crs.stats.get()`** — the account's counts and daily view series, scoped to the
  organization when the key acts in one, returning `Stats { shares, dailyViews }`.
- **`decryptSubmission(data, seed)`, `newSeed()` and `SEED_LENGTH`** at the package root, for
  a caller holding a blob and no client.
- **`RequestSeedTransmittedError`** — raised at the boundary, before any bytes leave, when the
  seed appears anywhere in what is about to be sent.
- An `Idempotency-Key` is now attached to a **POST, PUT or PATCH** made through
  `crs.request()`, generated once before the retry loop and deferring case-insensitively to a
  key you supplied. Those are the methods where a retry could create a second thing, and the
  ones the API consults the header on. A GET and a DELETE get nothing added — notably
  `shares.expire()`, whose `DELETE /shares/{code}` therefore sends exactly the bytes 0.1.4
  sent. A key the CALLER supplies is still forwarded on any method, untouched.

### Fixed

- **`iterateSubmissions()` did not terminate against the deployed endpoint.** The submissions
  handler ignores `page` and `limit` and answers `{submissions, count}` with no pagination
  block, and the shared paging ladder's last rung infers "there is more" from a page as long
  as the limit — an inference that is true forever when no paging figures ever arrive. A
  request holding at least the walk's page size re-requested page one up to `MAX_PAGES`
  times, re-yielding every sealed submission on each pass, and then threw. `submissions()`
  now takes no `page` or `limit`, returns the whole set plus the API's own `count`, and
  `iterateSubmissions()` is one HTTP call.
- **The seed assertion did not cover the Idempotency-Key header.** It scanned the serialized
  body and resolved the key afterwards, so `create({ seed, idempotencyKey: b64url(seed) })`
  put the seed on the wire in a header and raised nothing. The key is now resolved first and
  scanned with the body.
- **The seed assertion missed the unpadded standard-base64 spelling.** 32 bytes are 43 base64
  characters plus one `=`, so a search for the padded form does not match the unpadded one;
  the list read as complete at three entries while covering two spellings. Both base64
  entries are now unpadded, and an unpadded string is a prefix of its padded form.
- **`RequestDeletion.outcome` reported `'expired'` for an answer that said nothing.** It is
  `'expired' | 'deleted' | null` now, and an unrecognised or absent value is `null`. An
  outcome the SDK invented is otherwise indistinguishable from one the server sent, on the
  only destructive call in this surface.
- **`Submission.expiredAt` is gone.** The handler returns `short_code`, `created_at`, `data`
  and `encryption_type` and never an expiry; `openapi.yaml` documents one and is wrong. A
  property that is always `null` reads as a broken field rather than an absent one.
- **The User-Agent no longer reports a version this package has not been for four releases.**
  It said `credenshare-node/0.1.0` at 0.1.4. `VERSION` is now declared once, in `client.ts`,
  re-exported from `index.ts`, and the User-Agent is built from it.

### Changed

- `RequestField`'s doc no longer claims unknown members are passed through. The server
  unmarshals a request field into `{item, type}` and discards the rest — unlike a *share's*
  fields, whose extras survive inside the ciphertext. Extras are accepted without error and
  not stored, and the docs and README now say so.
- `Stats` is the name of the stats DTO (it was `AccountStats`), matching the sibling SDKs.
- **The one `util.inspect` flag combination that still renders a request's seed is now
  documented rather than left to be discovered.** `SecureRequest.seed` and `.accessLink` are
  getters over private fields, so `JSON.stringify`, spread, `structuredClone`,
  `console.log`/`dir`/`table`, `for..in`, `getOwnPropertyDescriptors` and template
  interpolation all render the short code and nothing secret. But
  `util.inspect(request, { getters: true, showHidden: true, customInspect: false })` prints
  the 32 bytes: `showHidden` exposes a prototype accessor to the walk, `getters` invokes it,
  and `customInspect: false` discards the redacting hook. No getter can obey that and
  withhold its value, and the same combination renders any getter-backed secret in any
  library, so it is stated in the getter's doc comment and in the README instead of being
  worked around. `scripts/seed-sweep.ts` (`npm run seed-sweep`) runs the whole list and
  greps each rendering for the seed in five encodings, and a test asserts both directions —
  that every other path is clean, and that this one is not.


## 0.1.4 — released 2026-08-30

The first version whose install instructions are the registry ones, because 0.1.3 is on the
registries. Also fixes a version string that had drifted.

### Fixed

- **The in-code version constant was stale.** It read `0.1.0` while `0.1.3` was published: the
  release guard compared the TAG to the manifest and never to this second copy. A test asserts `VERSION` equals `package.json`, and it runs in the release verification. `package.json` is also exported now, which tooling reads routinely.

### Documentation

- The install line is the registry command rather than a git URL.


## 0.1.3 — released 2026-08-30

No code change from 0.1.2. Cut to exercise the publish path with no stored credential: the npm
`NPM_TOKEN` bootstrap secret is deleted and publication now runs on OIDC trusted publishing, so
nothing long-lived exists in any repository that could publish this package.


## 0.1.2 — released 2026-08-30

The first version published to a package registry. No code change from 0.1.1: the conformance
fixture is byte-identical and every client still reports 24/24. Cut so that the published
version's own release workflow carries the npm OIDC version floor, which is what allows npm
publishing to move off a token immediately afterwards.


## 0.1.1 — released 2026-08-30

`v0.1.0` was tagged before the release-facing files were corrected, so the artifact resolved at
that tag told consumers to install unpinned and its changelog denied its own release. This
version contains those corrections. Nothing about the cryptography or the wire format changed
between the two; the conformance fixture is byte-identical.

### Fixed

- **`iterateAll` terminates, and walks the whole account.** 0.1.0 had two defects in one
  comparison. A server echoing `limit: 0` made `rows.length >= 0` true on every page, so the
  walk never ended — measured at 43 requests before an external abort. And the ladder had only
  two rungs, so a server capping pages to 30 while reporting `total: 120` read as the end after
  one page, losing 90 rows with the count sitting on the returned object. A non-positive limit
  echo is now ignored, all three rungs are present, and `iterateAll` refuses a constant page
  echo and stops at `MAX_PAGES`.
- **`additionalData` no longer accepts a JSON array.** `typeof [] === 'object'`, so an array
  reached callers behind a declared `Record<string, unknown>`.

### Documentation

- The README install line names the tag, and the changelog no longer describes 0.1.0 as
  unreleased.

## 0.1.0 — released 2026-08-30

First release.

### Breaking, before v0.1.0

These landed before `v0.1.0` was tagged, so no released version ever had the old shape. They
are recorded because both change what a `catch` block catches, and a caught-nothing branch is
silent — the kind of thing that should be read in a changelog rather than discovered in
production.

- **Field validation throws `InvalidFieldError`, not `TypeError`.** `validateFields` and
  `create()` used bare `TypeError`s, so the blanket `catch (e) { if (e instanceof
  CredenShareError) }` the README teaches did not catch the SDK's strictest check. Code
  narrowing on `instanceof TypeError` around a create must be updated.
- **`WebhookVerificationError` now extends `CredenShareError`, not `Error`.** Anything
  narrowing webhook failures by "not a CredenShare type" now takes the other branch.

### Fixed

- **`list()` decides `hasMore` from the limit the SERVER applied**, not the one the caller
  asked for. A server free to cap page size returns fewer rows than requested on a page that
  is nonetheless full, and comparing against the request made that look like the end of the
  result set — so `iterateAll` stopped with most of the account unvisited.
- **`ApiError` carries the server's `additional_data`** as `additionalData`. It was dropped,
  so a 4xx never named the field it rejected; for a create, finding out meant encrypting and
  sending the secret a second time.
- A wrong-length content key is refused before anything is encrypted or sent. It used to
  create the share and then throw, losing the short code.
- The request timeout covers the body read, so a server that answers and then stalls no longer
  hangs the call forever.


- End-to-end encrypted share creation, listing and expiry against the `/v1` API. Encryption
  happens locally; the content key never reaches CredenShare.
- Runs on Node 20+, Deno, Bun, Workers and browsers — WebCrypto only, no runtime dependencies.
- `create()` returns a `Share` class that redacts its link and key when printed, and carries
  the `idempotencyKey` it was sent with.
- An exhausted transport retry now raises `NetworkError` (nothing was sent) or
  `DeliveryUnknownError` (delivered, outcome unknown) instead of `ServiceUnavailableError`,
  which is now only a real HTTP 503. **If you catch `ServiceUnavailableError` for transport
  failures, catch those two instead.**
- `create()` accepts `custody`, `itemKeyWrap` and `organizationId`.
- Split API credentials (`crs_sk_live_<keyId>.<authSecret>[.<custodySecret>]`). The custody
  part never leaves the machine: the bearer header is assembled from parsed parts rather than
  by trimming the string, with a second assertion at the request boundary.
- Webhook signature verification, including the dual-signature rotation grace window and a
  symmetric replay-tolerance check.
- `npx credenshare-conformance` verifies an installed copy against the wire specification's
  vectors, which ship inside the package byte-identical to the published fixture.
- Field validation refuses `label`, `name` and `title` where the specification says `key`.
