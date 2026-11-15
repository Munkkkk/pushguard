# Secrets and cryptography

Contents: 1. Secrets in the repository · 2. Judging a scanner hit · 3. Secrets exposed at
build or run time · 4. Password storage · 5. Randomness · 6. Encryption and hashing ·
7. Signatures and comparisons · 8. TLS and transport

## 1. Secrets in the repository

A secret in a pushed commit is compromised: forks, clones, caches and scrapers copy public
repositories within minutes, and private repositories are read by every collaborator, CI
system and integration. Deleting it later does not help; the fix is to keep it out of the
commits and rotate it if it ever left the machine.

Where they hide, beyond source files:

- `.env*` files, `config/*.json|yml`, `appsettings.json`, `application.properties`,
  `docker-compose.yml` environment blocks, Kubernetes manifests (a `Secret` is only base64),
  Terraform `.tfvars` and state files, Helm values, Ansible vars.
- CI files (inline tokens, `curl -H "Authorization: ..."`), shell scripts, Makefiles,
  `.npmrc` / `.pypirc` / `.netrc`, IDE and tool configs, MCP server configs.
- Test fixtures, seed data, recorded HTTP cassettes (VCR, Polly, HAR files), snapshots,
  Postman/Insomnia collections, Jupyter notebook outputs, database dumps, log files.
- Documentation and comments ("temporary key for testing"), commit messages.
- Mobile and desktop bundles: `google-services.json` and similar are semi-public by design,
  but any admin or server key inside an app binary is extractable.
- Private keys and certificates (`.pem`, `.key`, `.p12`, keystores), SSH keys, signing keys.

Check `.gitignore` covers `.env*` (except the example file), key files and local config, and
that an example file (`.env.example`) contains placeholders, not real values.

## 2. Judging a scanner hit

Open the file and decide. Real secret, or one of these?

- **Placeholder or example**: `your-api-key-here`, `xxx`, `changeme`, obviously fake values,
  documentation samples (AWS `AKIAIOSFODNN7EXAMPLE`). Not a finding.
- **Public by design**: Stripe publishable keys (`pk_`), Supabase anon / publishable key,
  Firebase web config, Sentry DSN, Google Maps browser key, reCAPTCHA site key, OAuth client
  id. Not secrets, **but** check the access rules that make them safe (RLS, Firebase rules,
  key restrictions by referrer or API). Mention when those rules are absent.
- **Test-mode key**: `sk_test_`, sandbox credentials. LOW to MEDIUM: still worth removing,
  some test keys reach real data or cost money.
- **Local development default**: `postgres://postgres:postgres@localhost`. Fine if it can
  only ever work locally and production does not reuse the password.
- **Supabase JWT**: decode the payload (middle segment, base64). `"role":"anon"` is public;
  `"role":"service_role"` is CRITICAL.
- **High-entropy string that is not a credential**: hashes, integrity checksums, ids, public
  keys, encrypted blobs with the key elsewhere.

For a real secret, report where it is and what it grants, with the value masked. Silence a
confirmed false positive with a `pushguard:ignore` comment on the line or a
`.pushguardignore` path, so the gate does not trip on it again.

## 3. Secrets exposed at build or run time

A secret can be absent from the repository and still leak:

- **Client-exposed prefixes**: `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`,
  `PUBLIC_` (SvelteKit/Astro), `NUXT_PUBLIC_`, `GATSBY_` are inlined into the browser bundle.
  A secret, service-role or admin key behind such a name is CRITICAL even though the code
  only says `process.env.X`.
- A server-only module (database client, admin SDK, secret env access) imported from client
  code; build-time `define` / `env` config that injects all of `process.env`.
- Secrets passed to the client in props, server-rendered JSON, error messages, debug
  endpoints, `/api/config` style routes, or HTTP response headers.
- Secrets in logs, analytics events, error-tracker breadcrumbs, crash reports, URLs.
- Docker: `ARG`/`ENV` secrets and `COPY .env` persist in image layers. Use build secrets.
- CI: secrets echoed in logs, exposed to workflows triggered by forks, or written into
  artifacts and caches. See `supply-chain-infra.md`.
- Default fallbacks: `process.env.JWT_SECRET || 'dev-secret'` means production silently runs
  on a known secret when the variable is missing. The code should fail to start instead.

## 4. Password storage

- Use argon2id (preferred), scrypt, or bcrypt with cost ≥ 10 (bcrypt truncates at 72 bytes;
  do not pre-hash in a way that introduces null bytes). PBKDF2 only with a high iteration
  count (hundreds of thousands for SHA-256).
- Never MD5, SHA-1, SHA-256 or any fast hash, salted or not; never reversible encryption;
  never plain text, including in logs, temporary tables, password-reset emails or audit trails.
- A unique random salt per password (the above algorithms do this for you).
- Comparison through the library's verify function.
- The same applies to API keys and reset tokens stored in the database: store a hash (a fast
  hash such as SHA-256 is acceptable here because the input is high-entropy).

## 5. Randomness

Anything that must be unguessable needs a CSPRNG: session ids, reset and verification tokens,
API keys, OTP codes, invite codes, CSRF tokens, nonces, IVs, filenames meant to be secret,
coupon codes.

| Not acceptable for secrets | Use instead |
|---|---|
| `Math.random()`, `Date.now()`, counters, `uuid` v1 | `crypto.randomBytes`, `crypto.randomUUID()`, `crypto.getRandomValues` |
| Python `random.*` | `secrets.token_urlsafe`, `secrets.randbelow`, `os.urandom` |
| PHP `rand`, `mt_rand`, `uniqid` | `random_bytes`, `random_int` |
| Java `java.util.Random`, `Math.random()` | `SecureRandom` |
| Go `math/rand` | `crypto/rand` |

`Math.random()` for a shuffle, a jitter or a UI id is fine. Check what the value is used for.
Short numeric codes (4 to 6 digits) are only safe with strict attempt limits and expiry.

## 6. Encryption and hashing

- Symmetric encryption: an authenticated mode (AES-256-GCM, ChaCha20-Poly1305). Flag ECB,
  CBC without a MAC, static or reused IV/nonce (catastrophic for GCM), DES/3DES/RC4/Blowfish,
  `crypto.createCipher` (deprecated, derives the key weakly; `createCipheriv` is the right call).
- Keys: from a KMS or the environment, right length, not hardcoded, not derived from a
  password with a plain hash. A passphrase goes through a KDF (argon2, scrypt, PBKDF2).
- Hashing for integrity or deduplication: SHA-256 or better. MD5/SHA-1 are acceptable only
  where no attacker benefits from a collision (cache keys, non-security checksums); say so
  rather than flagging blindly.
- RSA: ≥ 2048 bits, OAEP for encryption, PSS for signatures; no textbook RSA, no PKCS#1 v1.5
  encryption in new code. Elliptic curves: standard curves through a maintained library.
- Home-made cryptography, custom "obfuscation" (XOR, base64, ROT) presented as protection:
  flag it. Encoding is not encryption.
- Encrypted data at rest is only as protected as its key: a key stored beside the data, or in
  the same database, changes little.

## 7. Signatures and comparisons

- Secret comparisons (HMAC signatures, API keys, tokens, OTPs) in constant time:
  `crypto.timingSafeEqual` (equal-length buffers), `hmac.compare_digest`,
  `hash_equals`, `subtle.ConstantTimeCompare`. `===` / `==` leaks timing.
- HMAC with SHA-256 or better, computed over the exact raw bytes received (webhooks: the raw
  body, before JSON parsing).
- Signed data includes everything that matters and a timestamp or nonce (replay protection).
- Signed URLs and tokens have an expiry, and the signature covers the path, the parameters
  and the expiry.
- Verification errors must fail closed: an exception path that continues as "verified" is a bypass.

## 8. TLS and transport

- Certificate verification disabled: `rejectUnauthorized: false`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, Python `verify=False`, Go `InsecureSkipVerify: true`,
  cURL `CURLOPT_SSL_VERIFYPEER => false`, `sslmode=disable` or `ssl: false` for a remote
  database, a trust-all `TrustManager` / hostname verifier. HIGH when it can run in
  production (traffic interceptable); acceptable only inside a clearly dev-only branch.
- Plain `http://`, `ws://`, `ftp://` URLs for anything carrying credentials or user data;
  mixed content; HSTS absent on a production HTTPS site.
- Internal traffic to databases, caches and queues over the network without TLS or auth.
- Minimum TLS version lowered, or weak cipher suites enabled explicitly.
