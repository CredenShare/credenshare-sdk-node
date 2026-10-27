# CredenShare for Node

End-to-end encrypted secret sharing. **Encryption happens on your machine** — the content key
never reaches CredenShare, which is what makes "we cannot read your data" a property of the
system rather than a promise.

```bash
npm install @credenshare/sdk
```



```ts
import { CredenShare } from '@credenshare/sdk'

const crs = new CredenShare(process.env.CREDENSHARE_KEY!)

const share = await crs.shares.create({
  title: 'Staging deploy credentials',
  fields: [
    { key: 'Username', value: 'deploy-bot', type: 'text' },
    { key: 'Password', value: 'correct horse', type: 'password' },
  ],
})

console.log(share.link)
// https://crs.sh/aB3dEf12#1xK9...
```

**That link is the secret.** The key lives in its fragment, which browsers never transmit.
Anyone holding the link can read the content; we cannot, and cannot recover it for you.

## Where it runs

Node 20+, Deno, Bun, Cloudflare Workers and browsers. The crypto goes through
`globalThis.crypto.subtle`, which is the one API all of them have (Node 18 has WebCrypto but
does not expose it globally without a flag, which is why 20 is the floor) — reaching for
`node:crypto` would make this package Node-only, and the runtimes it is most useful in (edge
functions, CI runners) are exactly the ones that do not have it.

There are **no runtime dependencies**. A client whose entire claim is that it encrypts
correctly should not ask you to trust a long tail of transitive packages.

---

## The field object

Each field is `{ key, value, type }`.

`key` is the **visible label**, not an identifier. It is not `label`, `name` or `title` — the
recipient view reads `key` and ignores the others, so a share built with the wrong member
still encrypts, posts, decrypts and renders, with every field blank and nothing erroring
anywhere. This SDK refuses those spellings rather than letting the mistake through.

`type` is one of `text`, `password`, `date`, `multiline`, `markdown`, `source_code`, `url`,
`qr`, and decides how the recipient sees it: `password` is masked behind a reveal,
`source_code` is highlighted, `markdown` is rendered.

- **`url`** is a link. Only an absolute `http://` or `https://` address becomes clickable;
  anything else (a relative path, `javascript:`, a typo) is shown as plain text.
- **`qr`** is text the recipient scans with a phone, such as a Wi-Fi network or an
  `otpauth://` URI. Their browser draws the QR code when they click to show it. Keep it to
  2,300 characters at most: the web app refuses longer, and a longer value may not draw.

This SDK checks neither. A field's type travels inside the encrypted payload, where the
server cannot read it, and the SDK only checks that a type is present.

## A passcode

```ts
await crs.shares.create({
  title: 'Production database',
  fields: [{ key: 'Password', value: 's3cr3t', type: 'password' }],
  passcode: 'hunter2',
})
```

The passcode is mixed into the key derivation and never sent. The server receives only a
one-way verifier, so it can check an attempt without gaining the ability to decrypt. Share
the link and the passcode over different channels — that is the point of having both.

## Expiry and view limits

```ts
await crs.shares.create({
  title: 'Temporary access',
  fields: [...],
  expiredAt: '2026-09-01T00:00:00Z',
  accessCountsLeft: 3,   // readable three times
  timedView: 60,         // visible for 60s once opened
})
```

## Activity emails

```ts
await crs.shares.create({ title: 'Deploy key', fields, notifyOn: ['viewed', 'denied'] })
```

`notifyOn` emails the share's creator when it is viewed, when a view is refused, when it
expires or when it is deleted: any of `viewed`, `denied`, `expired` and `deleted`
(`NOTIFY_ON_EVENTS`), each at most once, the same choice as the app's "Email me when". An
unknown or repeated event throws `InvalidArgumentError` before anything is encrypted or sent.

## Listing and expiring

```ts
const page = await crs.shares.list({ limit: 50 })
console.log(page.total, page.hasMore)

for await (const row of crs.shares.iterateAll()) {
  console.log(row.shortCode, row.expiredAt)
}

await crs.shares.expire('aB3dEf12')

// Shares that have ended, by date, views or deletion, newest expiry first.
const ended = await crs.shares.list({ status: 'expired' })
for await (const row of crs.shares.iterateAll({ status: 'expired' })) { /* ... */ }
```

`crs.requests.list` and `iterateAll` take `status` too: the expired list is the requests that
have closed, and a deleted request is in neither. Without `status`, both read the active list
and send what they always have.

`list` and `get` return **metadata only** — never content, never a key. A short code
belonging to another account reports exactly as one that does not exist, so a credential
cannot be used to discover what other accounts hold.

`expire` **removes** the share rather than flagging it: a later `get` throws `NotFoundError`
rather than returning a row with an expiry set. Worth knowing if you reconcile against your
own records — a share you expired and one that never existed look identical afterwards.

There is deliberately **no method to read a share over the API**. The recipient path is
protected by proof-of-work and captcha gates that bearer auth skips, so exposing it to a
credential would be an enumeration bypass. Open the link in a browser.

## Secure requests

A secure request is a keyless collect link a human fills in. **You generate the keypair** —
this client mints it, registers the public half, and hands you the seed:

```ts
const request = await crs.requests.create({
  title: 'Onboarding credentials for Dana',
  fields: [
    { item: 'Staging database password', type: 'password' },
    { item: 'VPN config', type: 'multiline' },
  ],
})

request.collectLink // https://crs.sh/r/aB3dEf12       — hand this to the human
request.accessLink  // https://crs.sh/r/aB3dEf12#1x…   — keep this; it carries the seed
request.seed        // the 32 bytes that link carries
```

**The seed is never transmitted, and it is the only way to read the submissions.** Store it,
or store the access link that carries it. Lose both and the submissions are unreadable by
everyone, CredenShare included — that is the point, and it is also the failure mode, so decide
where the seed goes before you create anything in production.

### Printing a request does not print its seed

`seed` and `accessLink` are getters over private fields rather than own properties, so the
ordinary ways an object ends up in a log find nothing to render. Every one of these prints the
short code and no secret:

```ts
JSON.stringify(request)                            // seed: '[redacted]'
JSON.stringify({ nested: request })                // same, at any depth
{ ...request }                                     // no seed member at all
structuredClone(request)                           // no seed member at all
console.log(request)                               // SecureRequest(aB3dEf12, seed redacted)
console.log('%o', request); console.log('%s', request)
console.dir(request, { depth: null })              // own properties only
console.table(request); console.table([request])   // columns from own properties only
util.inspect(request, { customInspect: false })
util.inspect(request, { customInspect: false, showHidden: true })   // [seed]: [Getter]
for (const k in request) { /* shortCode, publicKey, collectLink, … */ }
Object.keys(request); Object.entries(request)
Object.getOwnPropertyDescriptors(request)          // no seed descriptor
`${request}`; String(request)                      // SecureRequest(aB3dEf12, seed redacted)
```

That list is a runnable script in this SDK's repository — `scripts/seed-sweep.ts`, via
`npm run seed-sweep` on a clone. It creates a request with a known seed and greps every
rendering for those bytes in base64url, base64 (padded and unpadded), hex and as a decimal
byte run, printing each rendering with its verdict. The test suite asserts the same thing in
both directions: that every path above is clean, and that the one below is not.

**One exception, and it is the caller's explicit instruction rather than a gap here:**

```ts
util.inspect(request, { getters: true, showHidden: true, customInspect: false })
// prints the seed's 32 bytes, and the access link beside them
```

All three flags are load-bearing. `showHidden: true` is what exposes a prototype accessor to
the walk at all — which is why the two-flag `{ getters: true, customInspect: false }` is clean,
since `seed` is a class accessor and `util.inspect` otherwise walks only own properties.
`getters: true` then calls it instead of printing `[Getter]`. `customInspect: false` throws
away the redacting hook that would have answered first. Together they say "ignore this
object's own opinion about how to render itself, and call every accessor on it".

There is no way for a getter to obey that and withhold its value, so this is documented rather
than defended against. It is not particular to this SDK — that combination renders any
getter-backed secret in any library. Keep it away from anything whose output reaches a log.

A `Share` is a weaker guarantee, and knowingly so: `link` and `contentKey` are own properties
on a shape published at 0.1.x, so `toJSON`, `toString` and the inspect hook redact them but
`console.table` and `{ ...share }` still show them. Do not put a `Share` in a structured
logger either.

A field's prompt is `item`. A *share's* field labels itself `key`, this one SDK carries both
spellings, and the wrong one is refused locally: the server accepts it, answers 201 with a
live short code, and the collect form then renders with no prompts on it.

A prompt is `{ item, type }` and nothing else is stored. An extra member is accepted without
error and then discarded — the server keeps `item` and `type`. Unlike a *share's* fields, whose
extras survive because they sit inside the ciphertext, a request's prompts are plaintext
metadata, so do not put anything in one that you need to read back.

Submissions come back **sealed**:

```ts
const all = await crs.requests.submissions(request.shortCode)
for (const submission of all.submissions) {
  const fields = await crs.requests.decryptSubmission(submission, request.seed)
  // Handle these; do not print them. The plaintext a human just handed over does not belong
  // in stdout or in whatever ships your logs — which is the same reason submissions() does
  // not decrypt for you.
}
```

`submissions()` does not decrypt, on purpose. Decrypting on fetch would put every credential a
human handed over into memory — and into whatever logged the result — for a caller who only
wanted to count them.

**This endpoint is not paginated,** so `submissions()` takes no `page` or `limit` and returns
every row in one call, alongside the server's own `all.count`. `iterateSubmissions()` is the
row-at-a-time spelling of exactly that one call, not a walk.

`all.skippedNotEndToEndEncrypted` counts submissions the server withheld because they predate
E2EE and are readable server-side. Withheld rather than returned, so a bearer credential is
never a way to read plaintext; counted rather than dropped, so a shorter list than your
dashboard shows has a visible reason.

Two encodings meet on this feature and they are **not** the same alphabet. A request's
`public_key` is base64url and unpadded, because it was minted to travel in a URL; a
submission's `data` is standard base64 and padded, because it travels in a JSON body.
`decryptSubmission` feeds the blob the right decoder — if you ever decode one by hand, this is
the paragraph to reread, because getting it wrong fails as "wrong key" rather than as "wrong
decoder".

`delete` is **two steps**, and it says which one happened:

```ts
(await crs.requests.delete('aB3dEf12')).outcome // 'expired' — submissions preserved
(await crs.requests.delete('aB3dEf12')).outcome // 'deleted' — gone
```

A loop that calls it until it stops erroring destroys the submissions. That is why the outcome
is returned rather than a bare 200.

`outcome` is `null` if the server did not say. It always does today, so treat `null` as "go and
check" — it is deliberately not reported as `'expired'`, because an outcome this SDK invented
would then be indistinguishable from one the server sent, on the one destructive call here.

### Turning a stored seed back into a link

```ts
crs.collectLinkFor('aB3dEf12')        // https://crs.sh/r/aB3dEf12       — hand out
crs.accessLinkFor('aB3dEf12', seed)   // https://crs.sh/r/aB3dEf12#1x…   — keep
```

The same two links `create()` returns, for a seed you stored yourself. Hand-assembling the
access link is where this goes wrong: the fragment is version-prefixed, not bare base64url, and
a link with the prefix missing loads a page that cannot decrypt anything.

### A reproducible keypair

An ephemeral runner can derive its seed from the third part of its credential rather than
storing one:

```ts
import { custodyKeypair } from '@credenshare/sdk'

const { seed } = await custodyKeypair(custodySecret)
const request = await crs.requests.create({ title: 't', fields: [/* … */], seed })
```

Every container derives the same keypair, so there is nothing to store and nothing to sync.
The trade is compartmentalisation: one seed then opens every request created under it, where a
fresh seed per request opens exactly one. Pass a seed when statelessness is worth that, and
not by default.

## Stats

```ts
const stats = await crs.stats.get()
stats.shares.active
stats.dailyViews // [{ date: '2026-08-31', count: 0 }, …] oldest first, zero-filled
```

Scoped to the organization when the key acts in one, which is the answer a seat member's
automation is actually asking for. The per-member breakdown the dashboard shows is deliberately
absent from the API: a key scoped to read statistics should not become a way to enumerate
colleagues.

Absent figures read as `0` and an absent series as `[]`, never as `undefined` — a caller who
has to tell "no data" from "field missing" apart will get it wrong, and a new account genuinely
has no views yet.

## Who opened a share

```ts
const page = await crs.shares.accessLog('aB3dEf12', { limit: 50 })
for (const e of page.entries) {          // newest first
  console.log(e.accessedAt, e.accessedIp, e.platform, e.failedPasscode, e.signedIn)
}

for await (const e of crs.shares.iterateAccessLog('aB3dEf12', { from: new Date(Date.now() - 7 * 864e5) })) {
  /* ... */
}
```

The access log the app shows under Access History. It needs the `audit:read` scope, which
`shares:read` does not include because the log carries recipients' IP addresses. Only the
share's creator can read it, for a live share or one that has ended; any other short code is a
`NotFoundError`.

Pages are cursor-based: `iterateAccessLog` follows `nextCursor` to the end, and `accessLog`
with `cursor` reads one page further back. `from` and `to` take RFC 3339 strings or Dates. The
plan's retention applies whatever `from` says, and `retentionDays`, `effectiveFrom` and
`effectiveTo` report the window used.

Each page carries a weak `etag`. Pass it back as `ifNoneMatch` and an unchanged page returns
with `notModified: true` rather than throwing. The window's ends default to the current time,
so an unchanged page is only likely when both `from` and `to` are set.

`userAgent` is the raw user agent, `null` when none was recorded; link previews and scanners
show up there. `signedIn` says whether the viewer was signed in, not who they were.

## Capabilities

```ts
const caps = await crs.capabilities.get()
console.log(caps.plan.name, caps.key.scopes, caps.limits.remainingShares)
if (caps.features.secure_requests) { /* ... */ }
```

What this credential may do: its scopes and rate limit, its plan (the team's for a team key),
the plan's limits and features, and the lists the API accepts. No scope is needed. In
`limits`, `UNLIMITED` (-1) means the plan sets none. `sharingPolicy` is the team's sharing
policy for a team key, so it can be met before creating anything, and `null` for a personal
key. `etag` and `ifNoneMatch` work as they do for the access log.

## Links on a team's own domain

```ts
const crs = new CredenShare(teamCredential)
const share = await crs.shares.create({ title, fields }) // https://links.example.com/aB3dEf12#1...
console.log(await crs.linkOrigin())                      // the origin this client builds links on
```

A team can serve its links from its own domain. A client with no `linkOrigin` option asks the
API once, on its first create, and builds every link on the team's domain when the credential is
a team key whose team has one live for new links. A personal key's links, and those of a team
without a domain, stay on `https://crs.sh`: a team's domain serves only that team's shares and
requests.

Pass `linkOrigin` to choose the origin yourself, and nothing is asked. The answer is kept for the
life of the client, a "none" included, and a failed question leaves the client on the default
rather than failing the create. Only a bare `https://` origin is followed, since the content key
goes into the links built on it. `linkFor`, `collectLinkFor` and `accessLinkFor` use the team's
domain once the client has learned it, and `capabilities.get()` returns the same value as
`linkOrigin`.

## Generating a password, passphrase or PIN

```ts
import { generatePassword, generatePassphrase, generatePin } from '@credenshare/sdk'

const password = generatePassword()                              // 20 characters
const phrase = generatePassphrase({ words: 6, separator: 'space' })
const pin = generatePin({ length: 8 })
console.log(phrase.bits, phrase.strength)                         // 77.5… 'Strong'
```

Generated on this machine, with nothing sent anywhere: the app's three modes, with the same
character sets and the same strength figures.

- **Password:** 8 to 128 characters (default 20) from upper and lower case, numbers and the
  symbols ``!@#$%^&*()_+-=[]{}|;:,.<>?`"~/\'``, any set switched off with `uppercase`,
  `lowercase`, `numbers` or `symbols: false`, and any characters left out with `exclude`.
- **Passphrase:** 3 to 12 words (default 5) from the EFF long word list, 7,776 words, joined
  by `hyphen` (the default), `space`, `period`, `underscore` or `none`. `capitalize`
  upper-cases each word; `includeNumber` adds one digit to one word.
- **PIN:** 4 to 12 digits (default 6).

Every draw is uniform: `crypto.getRandomValues` with rejection sampling, where reducing a random
value with `%` would favour some characters. `bits` is the entropy of what the options generate:
length times log2 of the pool for a password, words times log2(7,776) for a passphrase, plus
log2(10) and log2(words) for the digit. `strength` is Weak below 40 bits, Fair below 60, Strong
below 80 and Very Strong from there, as the app labels it. Out-of-range options throw
`InvalidArgumentError` rather than being adjusted. Printing, inspecting or `JSON.stringify`-ing
a `Generated` withholds its `value`.

## Idempotency and retries

Every create carries an `Idempotency-Key`. It exists so a **network** retry cannot leave a
second copy of a credential in the world, with its own link and audit trail, that you do not
know about. This client performs those retries itself, repeating the byte-identical request.
A delete carries no such header, and deliberately: repeating one has the same effect as making
it once.

Passing your own `idempotencyKey` does **not** make a second `create()` a no-op, and no
argument makes it one: encryption is randomised per call — a fresh salt and IV every time,
which AES-GCM requires — so the body differs and the API refuses with
`IdempotencyConflictError`. That is the header working, not failing.

Only connection and timeout failures are retried. A 5xx is surfaced, because it may have
committed and this client cannot tell.

`crs.request(method, path, { body, query, headers })` is the escape hatch for anything this
SDK does not model yet. It gets the same timeout, the same bounded retries, the same error
mapping and the same custody assertion as the typed methods.

A **POST, PUT or PATCH** made through it gets an `Idempotency-Key` when you did not supply
one — attached once, before the retry loop, so a retry repeats that key rather than minting a
second. Those are the methods where a retry could create a second thing, and they are the ones
the API consults the header on.

A **GET or DELETE gets nothing added.** Neither reads the header, a DELETE is idempotent by
construction, and `shares.expire()` is a `DELETE /shares/{code}` that shipped at 0.1.4 without
one — adding a header to an already-published call to buy nothing is a wire change, not a fix.
A key you *do* supply is sent on **any** method, exactly as you wrote it, matched
case-insensitively.

What the escape hatch does not do is encrypt: a body you build there is sent as you wrote it,
so nothing secret belongs in one.

---

## Verifying webhooks

```ts
import express from 'express'
import { webhooks } from '@credenshare/sdk'

app.post('/hooks/credenshare', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    await webhooks.verify(req.body, req.get('X-CredenShare-Signature')!, process.env.WEBHOOK_SECRET!)
  } catch {
    return res.sendStatus(400)
  }
  // ...
})
```

Two things people get wrong, both of which this SDK tries to make hard:

**Verify the raw body.** `express.raw()`, not `express.json()`. Re-serialising parsed JSON
changes the bytes — key order, spacing, escapes — and the signature will not match. It is the
most common reason a correct integration appears broken.

**Pass both secrets while rotating.** For 24 hours after you rotate, deliveries carry both
signatures so you can roll your configuration without dropping anything:

```ts
await webhooks.verify(body, header, [NEW_SECRET, OLD_SECRET])
```

`verify` resolves to `true` or rejects. It never resolves to `false`, because a falsy result
is too easy to drop with `if (await verify(...))` and no `else` — which yields a receiver
that accepts everything and looks like it checks.

---

## API credentials

```
crs_sk_live_<keyId>.<authSecret>.<custodySecret>
                                  └ never transmitted
```

The third part is optional and, when present, **stays on your machine**. It is a separate
secret precisely so the server cannot reconstruct your custody private key: the auth secret
goes over the wire on every request, so deriving custody from it would mean the server
*could* decrypt. Not that it would — that it could, which is what zero-knowledge removes.

This SDK builds the `Authorization` header from the parsed parts rather than by trimming the
string, so a third part cannot survive a formatting mistake and reach the wire. There is a
test asserting exactly that, and a second assertion at the request boundary.

Any machine holding the credential derives the same custody keypair, so ephemeral runners
need no local state:

```ts
await crs.credential.custodyPublicKey()   // register this; only the public half leaves
```

---

## The wire specification

This SDK implements the CredenShare wire and crypto specification, which ships in this
repository as [`CRYPTO_WIRE_SPEC.md`](CRYPTO_WIRE_SPEC.md). **The specification is
normative — not this code**, and not any other implementation. Where they disagree, this
is the bug.

Versioning, and how a release is cut, is in [`VERSIONING.md`](VERSIONING.md). Worth reading
before the first one: this SDK is not on a registry yet, and the release path needs
per-repository settings that do not exist yet.


The application and the four SDKs share no code, deliberately: a package the production
application depended on would mean a compromised publish is a compromised application. The
cost is drift, and drift here does not produce a test failure — it produces content that can
never be decrypted.

The conformance vectors are what hold the implementations together, and they ship **inside**
the package so you can verify the exact artifact you installed:

```bash
npx credenshare-conformance
```

No test runner, no dev dependencies, and a non-zero exit on failure, so it works as a
deployment gate. The vectors include cases that **decrypt and unwrap material produced by a
different implementation** — passing them means this client can read what another one wrote,
which is interoperability rather than self-consistency.

## Errors

Types imply remedies, because several of these look identical on screen and have opposite
fixes:

| Error | Means | What helps |
| ----- | ----- | ---------- |
| `MissingKeyError` | a link arrived with no key | ask for the link again — something stripped it |
| `MalformedKeyError` | the key is present but unusable | the link is truncated; ask for it again |
| `WireFormatError` | wrong passcode, or altered content | check the passcode. The two are indistinguishable by design |
| `AuthenticationError` | credential unknown or revoked | mint a new one |
| `PermissionError` | missing scope, or a plan without API access | check scopes, or upgrade |
| `QuotaExceededError` | the plan's share allowance is spent | waiting does not help — expire old shares or change plan |
| `IdempotencyConflictError` | a key was replayed with a different body | expected on a caller-level replay; see above |
| `RateLimitError` | too many requests | wait `err.retryAfter` seconds |
| `ServiceUnavailableError` | a real HTTP 503; entitlements could not be resolved | nothing was created; retry |
| `NetworkError` | the API was never reached | nothing was sent. `err.attempts` says how many tries |
| `DeliveryUnknownError` | delivered, but no response was read | it may have committed. Repeat the identical request — a fresh key here is how one secret becomes two |
| `IdempotencyInFlightError` | the identical request is still running | wait briefly, then repeat it unchanged |
| `InvalidFieldError` | a field is not `{ key, value, type }`, or a request prompt is not `{ item }` | a share labels its field `key`; a request prompt is `item`. Not `label`, `name` or `title` |
| `InvalidArgumentError` | an argument was refused before anything was sent or generated | a `notifyOn` event, a list status, access-log options or generator options out of range |
| `RequestSeedTransmittedError` | a request seed was about to be sent | expire that request and create a new one; a seed that reached the server is no longer zero-knowledge |
| `NotFoundError` | no such share or request, or not yours | a code from another account reads exactly like one that never existed |
| `ApiError` | any other refusal | the base class — `err.status`, `err.code`, `err.requestId` carry the detail |

## Licence

Apache-2.0. Open source is a requirement here, not a preference: if the client performing the
encryption is closed, the claim that we cannot read your data is unverifiable.
