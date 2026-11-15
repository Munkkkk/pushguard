# API and data handling

Contents: 1. Input validation · 2. Rate limiting and abuse · 3. File uploads · 4. Webhooks ·
5. Error and information leakage · 6. Logging and personal data · 7. GraphQL · 8. Race
conditions · 9. Business logic and payments · 10. Caching · 11. Realtime and background work

## 1. Input validation

- Every entry point validates its input on the server with a schema (Zod, Valibot, Joi,
  Pydantic, class-validator, JSON Schema) **before** using it. TypeScript types are erased at
  runtime: `const body = await req.json() as CreateUser` validates nothing.
- Validate type, length, range, format and enum membership. Unknown keys stripped or rejected
  (ties into mass assignment). Arrays and strings have maximum sizes; pagination has a cap.
- Numbers: negative quantities and prices, zero, huge values, `NaN`, floats where integers
  are expected, integer overflow in typed languages, currency as float.
- Type confusion: a query parameter that arrives as an array or object (`?id[]=1`,
  `?filter[$ne]=`) where a string was assumed.
- Validation on the canonical form: decode, normalize (Unicode, case, path) and then check,
  in the same order the consumer will.
- The same rules on every path to the data: the REST route, the server action, the bulk
  import, the admin tool and the background job.
- Request body size limits and timeouts exist (the framework default may be unlimited).

## 2. Rate limiting and abuse

Missing limits are a finding where an attacker gains from repetition:

- Login, signup, password reset, OTP and magic-link requests and verifications (brute force,
  credential stuffing, SMS and email bombing with cost to the owner).
- Anything that costs money or resources per call: LLM calls, email/SMS, image or video
  processing, exports, third-party paid APIs, expensive searches.
- Coupon, invite, gift-code and promo validation (enumeration).
- Limits keyed on something the attacker cannot rotate freely: the account or target
  identifier in addition to IP. `X-Forwarded-For` is trustworthy only behind a known proxy.
- Limits enforced in a shared store. An in-memory counter does nothing on serverless or with
  several instances.
- Unbounded work from one request: user-chosen page size, deep recursion, zip bombs, image
  dimensions, regexes, large JSON nesting.

## 3. File uploads

Go through each point; uploads combine several vulnerability classes.

- **Authorization**: who may upload, and who may read the result. Object keys and URLs
  guessable or listable? Signed upload URLs scoped to one key, one content type, a size limit
  and a short expiry.
- **Type**: an allow-list of extensions and content types, verified from the file's content
  (magic bytes), not from the client-supplied `Content-Type` or name alone.
- **Dangerous types served from the app's origin**: HTML, SVG, XML, PDF with scripts → stored
  XSS. Serve user files from a separate domain or with `Content-Disposition: attachment`,
  `X-Content-Type-Options: nosniff` and a restrictive CSP.
- **Name and path**: generate the stored name server-side; never use the original filename as
  a path (traversal, overwrite, executable extensions like `.php`, `.jsp`, `.aspx` in a web root).
- **Size and count limits**, enforced while streaming.
- **Processing**: image, video, document and archive libraries are a large attack surface
  (ImageMagick, ffmpeg, LibreOffice, unzip). Zip slip, decompression bombs, XXE in
  Office/SVG files, SSRF from documents that reference URLs. Process in isolation when possible.
- **Metadata**: EXIF GPS data in user photos shown to others.
- Malware scanning where users exchange files.

## 4. Webhooks

An incoming webhook endpoint is public; the signature is its only authentication.

- Signature verified **before any side effect**, over the **raw request body** (parsing JSON
  first and re-serializing breaks or weakens the check), with the provider's library or a
  constant-time HMAC comparison.
- Timestamp tolerance checked (replay), event ids deduplicated (idempotency): providers
  retry, and attackers replay.
- The secret from the environment, different per environment.
- Do not trust amounts, statuses or user ids in the payload more than the signature
  justifies; for payments, re-fetch the object from the provider when the decision matters.
- Verification failure returns an error and stops. A `try/catch` that logs and carries on is
  a bypass.
- Outgoing webhooks to user-supplied URLs are SSRF (see `injection.md`), and should be signed.

## 5. Error and information leakage

- Stack traces, SQL errors, file paths, framework debug pages, internal hostnames or
  dependency versions returned to clients. Production handlers return a generic message and
  log the detail server-side.
- Debug mode, verbose errors, GraphQL introspection or playgrounds, API explorers, source
  maps, directory listings enabled in production.
- Different responses that reveal whether a user, email, file or record exists.
- Internal fields in API responses: hashes, tokens, internal ids, flags, other users' data,
  soft-deleted rows. Select explicitly.
- Health, status, metrics and version endpoints that disclose configuration or environment
  variables.
- Comments in shipped HTML/JS with internal notes, endpoints or credentials.

## 6. Logging and personal data

- Not in logs, analytics, error trackers or traces: passwords, tokens, session ids, API keys,
  `Authorization` and `Cookie` headers, full request bodies of auth and payment routes, card
  numbers, government ids, health data, full personal records.
- Security events **are** logged: logins and failures, password and email changes, permission
  changes, admin actions, access denials. Without them an incident cannot be investigated.
- Personal data: collected only as needed, encrypted in transit and at rest where the
  platform offers it, not copied to third parties (analytics, LLM providers, support tools)
  without it being intended, and deletable. Flag new flows that send user data to a new
  external service.
- Payment card data should never touch the application's servers (use the provider's hosted
  fields). Any code handling raw card numbers is a finding.

## 7. GraphQL

- Authorization in **resolvers** (or a schema-level directive applied to every field), not
  only at the route: nested fields let a caller walk from an allowed object to a forbidden one
  (`me { organization { members { email, passwordHash } } }`).
- Introspection and playground off in production (defence in depth, not a control).
- Query depth, complexity and alias limits; batching limits (aliases and array batching
  multiply a login mutation past the rate limiter).
- Mutations validate input like any API; ids in arguments are checked for ownership (IDOR).
- Field suggestions and verbose errors disabled.
- Subscriptions authenticated and authorized per event, not just at connection time.

## 8. Race conditions

Check-then-act sequences without atomicity, hit by parallel requests:

- Redeeming a coupon, gift card or invite once; withdrawing or transferring a balance;
  decrementing stock; claiming a unique username; enforcing "one free trial"; voting once.
- Limits of the form "read count, compare, then write".
- Fix: a single atomic statement (`UPDATE ... SET balance = balance - $1 WHERE id = $2 AND
  balance >= $1`), a unique constraint, a transaction with the right isolation or
  `SELECT ... FOR UPDATE`, or an idempotency key.
- Time-of-check to time-of-use on files and permissions (check access, then open by path).

## 9. Business logic and payments

No pattern finds these. Ask what the code assumes the client will do, then imagine a client
that does otherwise.

- **Prices and totals computed or trusted from the client.** Amount, currency, discount,
  shipping, tax and plan must come from the server's own data.
- Steps of a flow callable out of order or skipped (confirm without paying, access step 3
  directly, reuse a completed checkout session).
- Payment success decided by the redirect back to the site instead of a verified webhook or
  a server-side fetch of the payment object.
- Entitlements granted before payment is final, never revoked on refund, chargeback or
  subscription cancellation.
- Negative quantities, zero-price items, coupon stacking, refund larger than the charge,
  currency switching, rounding exploited over many operations.
- Limits and quotas enforced only in the UI or per request rather than per account.
- Referral, reward and credit systems: self-referral, replay, automated farming.
- Ownership transfer, invitation and sharing flows: can a user escalate to owner, invite
  themselves to another organization, or keep access after removal?
- Destructive actions (delete account, organization, data): re-authentication, confirmation,
  and correct authorization.

## 10. Caching

- Personalized or authenticated responses cached by a CDN, reverse proxy, framework data
  cache or service worker and served to another user. Look at new `Cache-Control` values,
  `revalidate` / ISR settings, `unstable_cache` / `use cache` keys, and cache keys that leave
  out the user or tenant.
- Cache poisoning: responses that vary on a header the cache key ignores (`Host`,
  `X-Forwarded-Host`, `Origin`).
- Web cache deception: `/account/profile.css` served by the dynamic handler but cached as static.

## 11. Realtime and background work

- WebSocket and SSE endpoints: authentication at the handshake, authorization **per channel
  and per message**, `Origin` checked (cross-site WebSocket hijacking when auth is by cookie).
- Channel or room names derived from guessable ids without a membership check.
- Queue consumers, cron endpoints and scheduled functions reachable over HTTP: protected by a
  secret or platform signature (a public `/api/cron` is callable by anyone).
- Job payloads built from user input: validated again in the worker, which often runs with
  more privilege than the request that enqueued it.
