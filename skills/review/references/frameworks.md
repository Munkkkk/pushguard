# Framework-specific pitfalls

Read the sections for the stack in use. Each lists the mistakes that are easy to make in that
framework and hard to see in a diff. Framework behaviour changes between versions: when a
finding depends on a default, confirm it against the version in the project's manifest or the
current documentation before reporting it as confirmed.

Contents: Next.js · React (and other SPAs) · Supabase · Firebase · Node / Express / Fastify /
NestJS · tRPC · Prisma / Drizzle · Django · Flask / FastAPI · Rails · Laravel / PHP · Go ·
Java / Spring · Mobile (React Native, Expo, Flutter, native) · Serverless and edge

## Next.js

- **Server Actions are public POST endpoints.** Every `'use server'` function can be called
  directly by anyone with its id, with any arguments, regardless of which page renders the
  form. Each one needs its own authentication, authorization and input validation. Arguments
  bound or closed over on the server are sent to the client (encrypted, but do not put secrets
  in them).
- **Route handlers** (`app/**/route.ts`, `pages/api/**`) have no built-in auth or CSRF check.
- **Middleware is not a security boundary on its own.** Check the `matcher` covers the new
  paths (API routes, server actions posting to page URLs, static exclusions written too
  broadly). Authorization must also live next to the data access. Projects on old versions
  should be past the middleware-bypass advisory (CVE-2025-29927, `x-middleware-subrequest`).
- A check in a `layout.tsx` does not protect the pages below it during partial rendering, and
  never protects route handlers or actions.
- **Server/client boundary**: `NEXT_PUBLIC_*` values are inlined in the bundle. Server-only
  modules (DB client, admin SDK, secrets) should import `server-only` so that an accidental
  client import fails the build. Props passed from a server component to a client component
  are serialized into the page: pass selected fields, not whole records.
- **Caching**: `fetch` caching, `unstable_cache`, `'use cache'`, ISR and `generateStaticParams`
  on per-user data serve one user's response to another. Routes reading cookies or headers
  must be dynamic, and cache keys must include the user.
- `next.config`: `images.remotePatterns` with broad wildcards (image optimizer as an SSRF and
  bandwidth proxy), `rewrites` to internal hosts, `productionBrowserSourceMaps`, headers
  removed, `serverActions.allowedOrigins` widened, `dangerouslyAllowSVG`.
- `redirect()` / `NextResponse.redirect()` with a user-supplied target (open redirect).
- `dangerouslySetInnerHTML`, including JSON-LD script tags built with unescaped data.
- Draft / preview mode secrets, and `revalidate` API routes callable without a secret.
- Error boundaries and `error.tsx` that print `error.message` from server errors.

## React (and other SPAs)

- JSX escapes text, not attributes that take URLs: `href={userUrl}` accepts `javascript:`.
- `dangerouslySetInnerHTML`, `ref.current.innerHTML`, third-party components that render HTML
  (rich text viewers, Markdown with raw HTML enabled, chart tooltips, i18n with HTML).
- Everything in the bundle is public: API keys, feature flags, hidden admin routes, disabled
  buttons. All enforcement is the API's job.
- Tokens in `localStorage`; auth state trusted from client storage to show admin UI is fine
  only if the API re-checks.
- Vue: `v-html`, dynamic component names or templates from data. Angular:
  `bypassSecurityTrust*`, `[innerHTML]` with unsanitized values. Svelte: `{@html}`.

## Supabase

- **RLS on every table in `public`** (and any exposed schema); see `auth-access.md` section 8.
  A migration that creates a table without enabling RLS is the single most common critical
  finding in Supabase projects.
- The **service-role / secret key** bypasses RLS. Server-only, never in a `NEXT_PUBLIC_`
  variable, and each route using it must authenticate and authorize the caller itself.
- On the server, trust `supabase.auth.getUser()` (verifies with the auth server) or verified
  JWT claims. `getSession()` reads the cookie without verification and must not be used for
  authorization decisions.
- `user_metadata` is user-writable. Roles and permissions belong in `app_metadata` or a
  protected table.
- Policies: UPDATE needs both `USING` and `WITH CHECK`; INSERT must pin the owner column;
  avoid `USING (true)` on private data; policies `TO authenticated` still expose rows to
  every logged-in user unless filtered.
- `SECURITY DEFINER` functions and views bypass RLS; set `search_path`, add checks, revoke
  `EXECUTE` from `anon`/`public`. RPC functions are callable from the browser with any
  arguments.
- Storage: bucket `public` flag, policies on `storage.objects`, user-controlled paths.
- Edge Functions: `verify_jwt` disabled in config means no auth unless the code does it;
  CORS headers copied as `*`; secrets in function code.
- Realtime: broadcast and presence channels need authorization policies; Postgres changes
  respect RLS only when enabled.
- Email confirmation off, open signups on an internal tool, redirect URL allow-list with wildcards.

## Firebase

- Firestore / Storage / Realtime Database **rules** are the access control. No
  `if true`, no rules that only check `request.auth != null` on data that should be per-user,
  validation of written fields, no reliance on client-side filtering.
- Admin SDK credentials (service account JSON) only on the server.
- Callable and HTTP functions verify the ID token and authorization themselves; App Check is
  a bot deterrent, not authorization.
- Custom claims for roles are set server-side only.

## Node / Express / Fastify / NestJS

- Middleware order: auth, rate limit and body parsers registered **before** the routes they
  protect; a router mounted above the auth middleware is unprotected.
- `cors()` with defaults allows every origin; `cors({ origin: true, credentials: true })`
  reflects any origin with credentials.
- `helmet` absent or partially disabled; `app.disable('x-powered-by')`.
- `express.static` serving a directory that contains uploads, dotfiles, source or `.env`.
- Body parser limits; `qs` parsing turning `?a[b]=c` into objects (type confusion, NoSQL
  operators); `trust proxy` set correctly for rate limiting and secure cookies.
- `express-session` with the default memory store, a weak or committed secret, missing
  cookie flags.
- Unhandled promise rejections and error middleware leaking stacks.
- NestJS: guards applied per controller or globally, and `@Public()` style opt-outs on the
  right routes only; `ValidationPipe` with `whitelist: true` and `forbidNonWhitelisted`
  (otherwise DTOs do not strip unknown fields, giving mass assignment).

## tRPC

- New procedures built on `publicProcedure` where `protectedProcedure` was intended.
- Input validated with `.input(schema)`; ids checked for ownership inside the resolver.
- Middleware that adds the user to context actually runs for the router that was added.

## Prisma / Drizzle

- `$queryRawUnsafe`, `$executeRawUnsafe`, `Prisma.raw`, `sql.raw()` with interpolated input.
- `where`, `orderBy`, `select` or `include` objects taken from the request let the client
  filter on and read any field, including relations (`include: { user: true }` returning hashes).
- `data: req.body` (mass assignment); `findUnique({ where: { id } })` without the owner filter.
- Returning full models to the client; use `select`.

## Django

- `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, a committed `SECRET_KEY`, `SECURE_*` and cookie
  security settings off in production settings.
- `@csrf_exempt`; `|safe`, `mark_safe`, `format_html` misuse; `{% autoescape off %}`.
- `.raw()`, `.extra()`, `RawSQL`, `cursor.execute` with string formatting.
- Views without `@login_required` / permission classes; DRF `permission_classes = [AllowAny]`
  or missing object-level permissions (`get_queryset` not filtered by `request.user`);
  `ModelSerializer` with `fields = '__all__'`.
- `pickle`-based session or cache serializers; user-controlled `redirect()` targets
  (use `url_has_allowed_host_and_scheme`); file uploads into `MEDIA_ROOT` served as HTML.

## Flask / FastAPI

- `app.run(debug=True)` (interactive debugger = RCE), a hardcoded `SECRET_KEY`.
- `render_template_string` with user input (SSTI); `send_file` / `send_from_directory` with
  user paths; `yaml.load`, `pickle`.
- Routes missing the auth dependency/decorator that neighbours have. FastAPI: `Depends(...)`
  on the router or each route; response models that exclude sensitive fields
  (`response_model`), not returning ORM objects raw.
- `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` and regex origins.
- Pydantic models as request bodies that include privileged fields (`is_admin`, `owner_id`).
- SQLAlchemy `text()` with f-strings.

## Rails

- `params.permit!` or missing strong parameters; `skip_before_action :authenticate_user!` /
  `:verify_authenticity_token`; `html_safe`, `raw`, `<%==`; `where("... #{x}")`, `order(params[:sort])`;
  `send_file(params[:path])`; `constantize` / `send` / `public_send` on user input;
  `YAML.load`, `Marshal.load`; `redirect_to params[:url]`; secrets outside credentials.

## Laravel / PHP

- `$guarded = []` or broad `$fillable`; `DB::raw`, `whereRaw` with interpolation; Blade
  `{!! !!}`; missing `auth` / policy middleware on routes; `APP_DEBUG=true`; CSRF `$except`;
  `unserialize`, `eval`, `include`/`require` with user paths; `extract($_REQUEST)`; loose
  comparisons (`==`) on hashes and tokens; file uploads into the public directory with the
  original extension; `.env` reachable from the web root.

## Go

- `fmt.Sprintf` into SQL; `exec.Command("sh", "-c", ...)`; `html/template` vs `text/template`
  (the latter does not escape) and `template.HTML()` casts; `filepath.Join` with user input
  without a containment check; `InsecureSkipVerify`; `math/rand` for tokens; unchecked errors
  on auth and crypto calls (a discarded `err` that means "verification failed"); missing
  timeouts on `http.Server` / `http.Client`; goroutine data races on shared auth state;
  `r.ParseMultipartForm` limits; CORS middleware `AllowAllOrigins` with credentials.

## Java / Spring

- `csrf().disable()` on cookie-authenticated apps; `permitAll()` matchers broader than
  intended and matcher order; method security annotations missing on new endpoints; SpEL with
  user input; native deserialization, Jackson default typing; string-built JPQL/SQL;
  `@RequestBody` entities bound directly (mass assignment); Actuator endpoints exposed
  (`/actuator/env`, `/heapdump`); XML parsers without XXE hardening; verbose error pages.

## Mobile (React Native, Expo, Flutter, native)

- Anything in the app bundle is extractable: API secrets, admin keys, `EXPO_PUBLIC_*` values.
- Tokens in `AsyncStorage` / `SharedPreferences` / `UserDefaults` rather than Keychain /
  Keystore (`expo-secure-store`, `flutter_secure_storage`).
- Deep links and universal links: parameters are attacker-controlled input; links that
  trigger actions or carry tokens; custom URL schemes can be claimed by another app (use
  verified app links for OAuth redirects, with PKCE).
- WebViews: JavaScript bridges exposed to remote content, `allowFileAccess`, loading
  user-supplied URLs, `originWhitelist: ['*']`.
- Cleartext traffic allowed (`usesCleartextTraffic`, ATS exceptions), disabled certificate
  validation, debug builds or `android:debuggable` / `allowBackup` shipped.
- Sensitive data in logs, screenshots, clipboard, backups; exported Android components
  without permissions.
- Over-the-air update channels and signing keys; keystores and provisioning files committed.

## Serverless and edge

- Each function is its own public endpoint unless the platform config says otherwise: auth
  per function, including cron and queue triggers exposed over HTTP.
- Over-broad execution roles; environment variables holding production secrets in preview
  environments; secrets logged by default request logging.
- In-memory rate limiting and caches do not work across instances.
- Global variables persisting between invocations can leak one user's data into the next
  request (module-level caches of user-specific objects, a shared client holding a user token).
- Edge runtimes: no Node crypto defaults assumed; JWT verification libraries configured for
  the runtime; secrets not bundled into the edge script.
