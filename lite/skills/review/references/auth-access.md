# Authentication and access control

Broken access control is the most common serious flaw in real applications, and no scanner
finds it, because the bug is a check that is missing. Give this area the most attention.

Contents: 1. Authorization (the core questions) · 2. IDOR and multi-tenancy · 3. Mass
assignment · 4. Authentication flows · 5. Sessions and cookies · 6. JWT · 7. OAuth / OIDC /
SSO · 8. Database-level access (RLS, rules, grants) · 9. Admin and internal surfaces

## 1. Authorization: the questions to answer for every entry point

For each new or changed route, server action, RPC, resolver, websocket handler or job trigger:

1. **Is the caller authenticated?** Where exactly is that enforced: in the handler, in
   middleware, in a layout, in a decorator? Open that code and confirm this path goes through it.
2. **Is the caller allowed to perform this action?** Role or permission check, on the server.
3. **Is the caller allowed to act on this particular object?** Ownership or tenant check on
   the row, not just on the route.
4. **Is the check enforced server-side?** Hidden buttons, client-side route guards, disabled
   form fields and checks in a React component protect nothing.

Typical failures:

- Middleware matcher that does not cover the new path (`matcher: ['/dashboard/:path*']` while
  the new route lives under `/api/`), or path normalization tricks (`/api//admin`, trailing
  slash, case, encoded characters) that skip a prefix check.
- A check in the page or layout but none in the API route or server action that does the work.
  Server actions and route handlers are public HTTP endpoints, whatever the UI in front of them.
- Authorization on `GET` but not on `POST/PUT/PATCH/DELETE` of the same resource.
- Method confusion: a handler that accepts every method but only checks one branch.
- Role read from a place the user controls: request body, query, an unsigned cookie, a JWT
  claim the user can set (Supabase `user_metadata`, a client-set custom claim), local storage.
- "Fail open": `if (user && user.role !== 'admin') return 403` lets an anonymous caller in.
  A caught exception in the auth check that falls through to the handler does the same.
- A new GraphQL field or tRPC procedure using the public procedure builder instead of the
  protected one that its neighbours use.

## 2. IDOR and multi-tenancy

Any identifier that comes from the client (`/orders/:id`, `?userId=`, a body field, a GraphQL
argument) must be tied to the session before it is used.

```js
// Vulnerable: any logged-in user reads any invoice
const invoice = await db.invoice.findUnique({ where: { id: params.id } })

// Fixed: the ownership condition is part of the query
const invoice = await db.invoice.findFirst({ where: { id: params.id, userId: session.user.id } })
```

- Check **every** operation on the resource, including update, delete, export, download,
  "duplicate", and nested resources (`/projects/:pid/files/:fid` must verify the file belongs
  to the project and the project to the caller).
- In multi-tenant code, the tenant id comes from the session, never from the request. Look
  for any query on a tenant-scoped table without the tenant filter, including joins, counts,
  search and autocomplete endpoints, and background jobs fed by request data.
- Unguessable ids (UUIDs) are not access control: they leak through logs, referrers, shared
  links and other endpoints.
- Bulk and list endpoints: a filter parameter the client controls (`?ownerId=`), missing
  pagination limits, or a `where` clause built from the request body.
- File and storage access: signed URL generation for an object key the user supplies,
  buckets or prefixes shared between tenants.

## 3. Mass assignment

Writing the request body straight into a record lets the caller set fields the form never
showed: `role`, `isAdmin`, `emailVerified`, `ownerId`, `tenantId`, `price`, `balance`, `plan`.

```js
await db.user.update({ where: { id }, data: req.body })        // vulnerable
const { name, avatarUrl } = schema.parse(req.body)             // fixed: explicit allow-list
await db.user.update({ where: { id }, data: { name, avatarUrl } })
```

Equivalents: `Model(**request.json)`, Django `fields = '__all__'`, Rails `params.permit!`,
Laravel `$guarded = []`, a Zod schema with `.passthrough()`, spreading `...body` into an insert.
Also check the reverse direction: responses that return the whole row (password hash, reset
tokens, internal flags, other users' emails) instead of a selected set of fields.

## 4. Authentication flows

- **Passwords**: hashed with argon2id, scrypt or bcrypt (cost ≥ 10). Never MD5/SHA-x, never
  reversible encryption, never compared in plain text. See `secrets-crypto.md`.
- **Login**: rate limited or locked out per account and per IP; identical response and timing
  for "unknown user" and "wrong password" (user enumeration); no credentials in URLs or logs.
- **Registration**: email ownership verified before the account gains access to anything tied
  to that email (invitations, domain-based org auto-join, account linking).
- **Password reset and magic links**: token from a CSPRNG, at least 128 bits, single use,
  short expiry, stored hashed, bound to the account, invalidated on use and on password
  change. The reset link host must come from configuration, not from the `Host` header
  (host header poisoning). Changing email or password requires the current password or a
  fresh login, and notifies the old address.
- **OTP / 2FA**: attempts limited, codes single use and short lived, the second factor
  actually enforced on the server for the session (not just a UI step that can be skipped by
  calling the next endpoint), recovery codes hashed.
- **Account enumeration** through signup, reset and login messages or timing.

## 5. Sessions and cookies

- Session id regenerated at login and privilege change (session fixation); destroyed
  server-side at logout; expiry and idle timeout exist.
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`, narrow `Path`/`Domain`,
  `__Host-` prefix where possible. `SameSite=None` needs a reason and CSRF defences.
- Tokens in `localStorage`/`sessionStorage` are readable by any XSS. Prefer HttpOnly cookies
  for session credentials; flag new code that moves a token into web storage.
- Session data the client can modify must be signed or encrypted with a real secret (not a
  default like `secret`, `changeme`, `keyboard cat`, or a value committed to the repo).

## 6. JWT

- Signature **verified** with a pinned algorithm list. `jwt.decode()` / `jwtDecode()` only
  parse; a trust decision made on decoded-but-unverified claims is an auth bypass.
- `alg: none` rejected; no algorithm taken from the token header; no HS256/RS256 confusion
  (verifying an RS256 token with the public key as an HMAC secret).
- `exp` enforced, plus `iss` and `aud` when several services or environments share a key.
- HMAC secret long and random (≥ 32 bytes), from the environment, not in the repo.
- Key lookup from `kid` / `jku` / `x5u` headers restricted to known keys and hosts.
- A revocation story for long-lived tokens (short access token + rotating refresh token, or
  a server-side deny list). Refresh tokens rotated and reuse detected.
- No sensitive data in the payload: it is only base64.

## 7. OAuth / OIDC / SSO

- `state` parameter generated, bound to the session and checked on callback (login CSRF);
  PKCE for public clients; `nonce` checked for OIDC.
- `redirect_uri` matched exactly against an allow-list. No wildcards, no open redirect on an
  allowed host that can forward the code or token.
- ID token validated: signature, `iss`, `aud`, `exp`. Access tokens for the wrong audience rejected.
- Account linking by email only when the provider asserts `email_verified`; otherwise an
  attacker registers the victim's email at a lax provider and takes over the account.
- Client secret server-side only. Tokens not logged, not placed in URLs.
- Post-login redirect targets (`next`, `returnTo`, `callbackUrl`) restricted to same-origin
  relative paths.

## 8. Database-level access: RLS, rules, grants

When the browser talks to the database directly (Supabase, Firebase, Hasura, PostgREST,
Appwrite), these policies are the only access control. Treat every migration and rules file
as security code.

**Postgres / Supabase**

- Every table in an exposed schema has `ENABLE ROW LEVEL SECURITY`. A new `CREATE TABLE`
  without it, in a project that uses the anon key from the browser, is world readable and
  writable: CRITICAL when the table holds user data.
- Policies scoped with `auth.uid()` (or the tenant claim), for each of SELECT, INSERT, UPDATE,
  DELETE. Watch for `USING (true)`, policies granted `TO public`/`anon` on private data, an
  UPDATE policy without `WITH CHECK` (lets a user reassign `user_id` to someone else), and
  INSERT policies that do not pin `user_id = auth.uid()`.
- Authorization data must not come from `auth.jwt() -> 'user_metadata'`: users can edit it.
  Use `app_metadata` or a table the user cannot write.
- `SECURITY DEFINER` functions run as their owner and bypass RLS: they need their own checks,
  a fixed `search_path`, and `REVOKE EXECUTE ... FROM public/anon` unless meant to be public.
  Views bypass RLS of the underlying tables unless created `WITH (security_invoker = true)`.
- Storage buckets: public flag, and policies on `storage.objects` scoped by owner or path.
- The `service_role` / secret key bypasses RLS entirely. It must never reach client code or a
  `NEXT_PUBLIC_`/`VITE_` variable, and every server route using it needs its own
  authentication and authorization, since the database will not help.
- Column-level exposure: RLS filters rows, not columns. Sensitive columns in a readable table
  are readable.

**Firebase**: no `allow read, write: if true`; rules check `request.auth.uid` against the
document owner, validate the shape of writes, and do not rely on client-side queries for
filtering. Realtime Database: no `".read": true` / `".write": true` at a broad path.

**SQL in general**: least-privilege roles, no `GRANT ALL` to an application or public role,
migrations that do not drop or loosen an existing policy without replacement.

## 9. Admin and internal surfaces

- Admin routes, debug endpoints, health checks with detail, metrics, queue dashboards, API
  docs / playgrounds, seed or reset endpoints: authenticated and not left enabled by an
  environment flag that defaults to on.
- Impersonation ("log in as user") restricted, logged, and unable to target higher roles.
- Internal service-to-service endpoints not reachable from the internet without a credential;
  trust in headers like `X-Forwarded-For`, `X-User-Id`, `X-Internal` only behind a proxy that
  strips them from external traffic.
- Feature flags and "beta" checks enforced server-side.
