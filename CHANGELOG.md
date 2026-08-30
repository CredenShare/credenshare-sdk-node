# Changelog

## 0.1.0 — unreleased

First release.

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
