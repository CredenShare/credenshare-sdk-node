# Changelog

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
