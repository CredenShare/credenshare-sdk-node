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

`type` is one of `text`, `password`, `date`, `multiline`, `markdown`, `source_code`, and
decides how the recipient sees it: `password` is masked behind a reveal, `source_code` is
highlighted, `markdown` is rendered.

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

## Listing and expiring

```ts
const page = await crs.shares.list({ limit: 50 })
console.log(page.total, page.hasMore)

for await (const row of crs.shares.iterateAll()) {
  console.log(row.shortCode, row.expiredAt)
}

await crs.shares.expire('aB3dEf12')
```

`list` and `get` return **metadata only** — never content, never a key. A short code
belonging to another account reports exactly as one that does not exist, so a credential
cannot be used to discover what other accounts hold.

`expire` **removes** the share rather than flagging it: a later `get` throws `NotFoundError`
rather than returning a row with an expiry set. Worth knowing if you reconcile against your
own records — a share you expired and one that never existed look identical afterwards.

There is deliberately **no method to read a share over the API**. The recipient path is
protected by proof-of-work and captcha gates that bearer auth skips, so exposing it to a
credential would be an enumeration bypass. Open the link in a browser.

## Idempotency and retries

Every create carries an `Idempotency-Key`. It exists so a **network** retry cannot leave a
second copy of a credential in the world, with its own link and audit trail, that you do not
know about. This client performs those retries itself, repeating the byte-identical request.

Passing your own `idempotencyKey` does **not** make a second `create()` a no-op, and no
argument makes it one: encryption is randomised per call — a fresh salt and IV every time,
which AES-GCM requires — so the body differs and the API refuses with
`IdempotencyConflictError`. That is the header working, not failing.

Only connection and timeout failures are retried. A 5xx is surfaced, because it may have
committed and this client cannot tell.

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
| `ServiceUnavailableError` | entitlements could not be resolved | nothing was created; retry |

## Licence

Apache-2.0. Open source is a requirement here, not a preference: if the client performing the
encryption is closed, the claim that we cannot read your data is unverifiable.
