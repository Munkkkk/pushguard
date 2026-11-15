# Web client: XSS, CSRF, CORS, headers, cookies

Contents: 1. XSS · 2. CSRF · 3. CORS · 4. Content Security Policy and security headers ·
5. Cookies · 6. Open redirect · 7. Clickjacking · 8. postMessage and cross-window ·
9. Client-side data exposure · 10. Third-party scripts

## 1. Cross-site scripting

XSS needs an attacker-influenced value and a sink that interprets it as markup or script.
Modern frameworks escape text by default, so look for the places that opt out.

**Sinks**

- DOM: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`,
  `Range.createContextualFragment`, jQuery `.html()` / `.append()` / `$(userString)`.
- Frameworks: React `dangerouslySetInnerHTML`, Vue `v-html`, Svelte `{@html}`, Angular
  `[innerHTML]` with `bypassSecurityTrust*`, Solid `innerHTML`, Astro `set:html`.
- Server templates with escaping off: Jinja/Django `|safe`, `mark_safe`, `{% autoescape off %}`;
  ERB `raw` / `html_safe`; EJS `<%- %>`; Handlebars `{{{ }}}`; Blade `{!! !!}`; Go
  `template.HTML()`; Twig `|raw`.
- **URL attributes**: `href`, `src`, `action`, `formaction`, `xlink:href` taking a user value
  allow `javascript:` URLs. React does not block this. Validate the scheme
  (`http:`, `https:`, `mailto:` allow-list).
- Script contexts: user data interpolated inside a `<script>` block, an inline event handler,
  a `style` attribute, or JSON embedded in HTML without escaping `<` (`</script>` breakout).
  `JSON.stringify` alone is not safe inside `<script>`.
- Rendering Markdown or rich text: the HTML output must be sanitized (DOMPurify,
  `rehype-sanitize`, bleach) after conversion. Check for `allowDangerousHtml`, `sanitize:
  false`, `rehype-raw` without a sanitizer.
- SVG and HTML file uploads served from the application's own origin execute scripts.
  See uploads in `api-data.md`.

**Sources**: URL (query, hash, path), form fields, anything stored by another user (stored
XSS: profile names, comments, filenames, support messages shown in an admin panel), HTTP
headers reflected in pages, third-party API data, `postMessage` data, error messages that
echo input.

**Judging severity**: stored XSS reaching other users or admins is HIGH. Reflected XSS is
HIGH without a strict CSP, MEDIUM with one. Self-XSS (only the author sees it) is LOW.

**Fix**: render as text; if HTML is required, sanitize with a maintained library configured
with an allow-list, at render time; validate URL schemes; keep a CSP as a second layer.

## 2. CSRF

A state-changing request that authenticates with something the browser attaches automatically
(cookies, HTTP basic auth, client certs) needs CSRF protection. APIs authenticated only by an
`Authorization` header the script adds are not exposed.

- Protection present on **every** state-changing route: token (synchronizer or signed
  double-submit), or strict `Origin` / `Sec-Fetch-Site` validation.
- `SameSite=Lax` cookies help but do not cover: top-level `GET` navigations (so state changes
  on GET are exploitable), subdomain attackers, and `SameSite=None` cookies.
- State-changing `GET` routes (`/logout`, `/delete?id=`, `/api/toggle`, unsubscribe links
  that act without confirmation) are a finding on their own.
- Framework protection switched off: Django `@csrf_exempt`, Rails
  `skip_before_action :verify_authenticity_token`, Laravel `$except`, Spring `csrf().disable()`,
  Express without any CSRF middleware on cookie-authenticated forms.
- Custom route handlers that bypass the framework's built-in check (Next.js route handlers
  have none by default, unlike server actions, which compare `Origin` and `Host`).
- JSON endpoints accepting `text/plain` or form content types can be hit by a plain HTML form.
- **Login CSRF** and OAuth callbacks without `state`.

## 3. CORS

CORS relaxes the same-origin policy; a mistake lets another website read responses with the
victim's credentials.

| Configuration | Verdict |
|---|---|
| `Access-Control-Allow-Origin: *` without credentials, on truly public data | fine |
| `*` on an API that returns user-specific data via a token in the header | review: any site can call it if it obtains or the page exposes the token; usually acceptable, note it |
| Origin **reflected** from the request (`origin: true`, `callback(null, true)`, echoing `req.headers.origin`) with `Allow-Credentials: true` | HIGH/CRITICAL: any website can read authenticated responses |
| Allow-list checked with `includes`, `endsWith`, `startsWith` or an unanchored regex | bypassable: `evil-example.com`, `example.com.evil.com`, `example.com.evil.net` |
| `null` origin allowed | exploitable from sandboxed iframes and local files |
| Wildcard subdomains (`*.example.com`) | any XSS or takeover on any subdomain becomes a full bypass |

Also check: `Vary: Origin` set when the header is dynamic (cache poisoning otherwise);
`Access-Control-Allow-Headers` / `Methods` not blanket-reflected; dev origins (`localhost`,
preview domains like `*.vercel.app` owned by anyone) not left in the production allow-list;
CORS is not treated as authentication (it does not stop non-browser clients, and does not
stop the request from being sent, only the response from being read).

Fix: exact-match allow-list from configuration, credentials only for those origins.

## 4. Content Security Policy and security headers

Missing headers alone are LOW to MEDIUM. Flag **regressions** (a header removed or loosened)
and note absences once, briefly.

- **CSP**: `script-src` with `'unsafe-inline'` (without nonce/hash + `'strict-dynamic'`),
  `'unsafe-eval'`, `*`, `data:`, `https:`, or CDNs that host arbitrary user content defeats
  the purpose. `object-src 'none'`, `base-uri 'self'` or `'none'`, `frame-ancestors` set.
  Nonces must be per-response random, not static.
- `Strict-Transport-Security` with a long `max-age` on HTTPS sites.
- `X-Content-Type-Options: nosniff`.
- `frame-ancestors` (CSP) or `X-Frame-Options` for clickjacking.
- `Referrer-Policy` (`strict-origin-when-cross-origin` or stricter), important when URLs
  carry tokens.
- `Permissions-Policy` for sensitive features; `Cross-Origin-Opener-Policy` for apps handling
  sensitive windows or OAuth popups.
- `Cache-Control: no-store` (or `private`) on authenticated and personalized responses. A CDN
  or framework cache that stores a per-user response and serves it to others is a data leak:
  check new cached routes, `revalidate`, `s-maxage`, and cache keys that omit the user.

## 5. Cookies

`HttpOnly` on anything script does not need; `Secure`; `SameSite=Lax` minimum for session
cookies; `__Host-` prefix when possible; `Domain` not set wider than needed (a parent-domain
cookie is exposed to every subdomain). Sensitive data not stored in an unsigned or merely
base64-encoded cookie. Cookie values that feed authorization must be signed and verified.

## 6. Open redirect

A redirect target taken from the request (`?next=`, `returnTo`, `callbackUrl`, `redirect_uri`,
the `Referer`) lets an attacker craft a trusted-looking link to a phishing page, and can leak
OAuth codes and tokens.

- Bypasses of naive checks: `//evil.com`, `/\evil.com`, `https:evil.com`,
  `https://example.com@evil.com`, `https://example.com.evil.com`, whitespace and control
  characters, `javascript:` in client-side redirects (which becomes XSS).
- Fix: accept only relative paths that start with a single `/` followed by a non-slash,
  non-backslash character, or map keys to known destinations. Parse with the URL API and
  compare the origin.

## 7. Clickjacking

Sensitive actions on a page that can be framed by another origin. Set
`frame-ancestors 'self'` (or `'none'`). Check that the new header configuration covers all
routes, including error pages and the ones served by a different handler or CDN rule.

## 8. postMessage and cross-window

- Receivers: `event.origin` checked against an exact allow-list **before** using `event.data`;
  the data validated and never passed to an HTML sink, `eval`, or a navigation.
- Senders: a specific target origin, not `'*'`, when the message contains anything sensitive.
- `window.opener` access: `rel="noopener"` on user-supplied links opened in a new tab (modern
  browsers default to it for `target=_blank`; explicit `window.open` does not).
- Browser extension message handlers and service workers: validate the sender.

## 9. Client-side data exposure

Everything shipped to the browser is public, whatever the UI shows.

- Secrets in the bundle: any non-public key in a `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`,
  `EXPO_PUBLIC_`, `PUBLIC_` variable; server-only modules imported into client components;
  secrets in source maps published to production.
- Over-fetching: the API or a server component passing whole records to the client (other
  users' emails, hashes, internal flags) while the UI displays two fields. Serialized props,
  hydration payloads and `__NEXT_DATA__` are readable.
- Sensitive values in URLs (tokens, emails, reset codes): they end up in logs, history,
  analytics and `Referer`.
- Sensitive data in `localStorage`, IndexedDB, or cached by a service worker on shared devices.
- Client-side-only enforcement of price, quantity, role, feature access or validation.

## 10. Third-party scripts

New external `<script>` tags, tag managers, analytics or widgets run with full access to the
page. Check the source is one the project intends, pinned with Subresource Integrity when
loaded from a public CDN, and not placed on pages handling credentials or payment data
without need.
