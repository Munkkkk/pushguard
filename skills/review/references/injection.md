# Injection

Injection happens when data is interpreted as code or structure by something downstream: a
database, a shell, a filesystem, an HTTP client, a parser, a template engine. The review
question is always the same: can an attacker-influenced value reach the interpreter without
being parameterized, validated against an allow-list, or encoded for that exact context?

Remember second-order paths: a value stored safely today and concatenated into a query,
a shell command or a template by another piece of code later is still injection.

Contents: 1. SQL · 2. NoSQL · 3. OS command · 4. Path traversal and file access · 5. SSRF ·
6. Deserialization · 7. XML (XXE) · 8. Template injection (SSTI) · 9. Code evaluation ·
10. Prototype pollution · 11. ReDoS · 12. Header, log and other injections

## 1. SQL

```js
db.query(`SELECT * FROM users WHERE email = '${email}'`)          // vulnerable
db.query('SELECT * FROM users WHERE email = $1', [email])         // fixed
```

- String concatenation, template literals, `%` / `.format()` / f-strings in any SQL text.
- ORM escape hatches: Prisma `$queryRawUnsafe` / `$executeRawUnsafe` (and `$queryRaw` called
  as a function rather than a tagged template), Sequelize `query()` and `literal()`, Knex
  `raw()` / `whereRaw()`, TypeORM `query()` and string `where`, Django `raw()` / `extra()` /
  `RawSQL`, SQLAlchemy `text()` with interpolation, ActiveRecord `where("name = '#{x}'")`,
  Laravel `DB::raw` / `whereRaw`, Supabase `rpc()` into a function that builds dynamic SQL.
- **Identifiers cannot be parameterized**: table names, column names, `ORDER BY` columns and
  direction, `LIMIT` in some drivers. They need an allow-list mapping, not escaping.
- `LIKE` patterns: parameterized but `%` and `_` unescaped can turn a search into a full scan
  or bypass a prefix restriction.
- Dynamic SQL inside stored procedures (`EXECUTE format(...)` without `%I` / `%L`).
- PostgREST / Supabase filter strings built from input (`.or(\`name.eq.${x}\`)`): the user
  can append conditions. Use the structured filter methods.

## 2. NoSQL

- MongoDB operator injection: passing `req.body.password` straight into a filter lets the
  client send `{"$ne": null}`. Cast to string or validate the type with a schema first.
- `$where`, `mapReduce`, `$function` with any user input: server-side JavaScript execution.
- Query objects built by spreading the request (`find({...req.query})`).
- Redis: commands or Lua scripts concatenated from input; key names from input without a
  prefix (cross-tenant key access). Elasticsearch: raw query DSL or scripts from the client.

## 3. OS command

```js
exec(`convert ${file} out.png`)                          // vulnerable: shell parses the string
execFile('convert', [file, 'out.png'])                   // fixed: no shell, arguments as array
```

- `child_process.exec`, `execSync`, `spawn(..., { shell: true })`, Python `os.system`,
  `subprocess.*(shell=True)`, PHP `shell_exec` / backticks, Ruby backticks / `system(string)`,
  Go `exec.Command("sh", "-c", ...)`.
- Even without a shell, **argument injection**: a value starting with `-` becomes an option
  (`git clone --upload-pack=...`, `tar --checkpoint-action`, `curl -o`, `ffmpeg -i`). Validate
  the value, and put `--` before positional arguments.
- Input reaching environment variables, a working directory, or a script file that is then run.

## 4. Path traversal and file access

- Any path built from input: `path.join(base, userValue)` does **not** stop `../`. Resolve it
  and check it stays inside the base directory:
  ```js
  const full = path.resolve(base, name)
  if (!full.startsWith(path.resolve(base) + path.sep)) throw new Error('invalid path')
  ```
- Absolute paths, encoded separators (`%2e%2e%2f`, double encoding), backslashes on Windows,
  null bytes in older runtimes.
- Archive extraction (zip slip): entry names containing `../`, and symlinks inside archives.
- Upload filenames used as storage paths; object-storage keys built from input.
- `res.sendFile` / `send_file` / static file handlers with a user-supplied name; "download"
  and "export" endpoints; template or locale names loaded from a query parameter (LFI).
- File writes: can the user choose the extension or directory (web root, `.ssh`, cron, a
  source directory)?

## 5. SSRF

The server makes a request to a URL the attacker influences: webhooks, "import from URL",
image/PDF/preview fetchers, OEmbed, proxies, link unfurling, OAuth discovery, SVG/HTML to PDF
renderers (headless browsers follow embedded URLs too).

What an attacker reaches: cloud metadata (`169.254.169.254`, `metadata.google.internal`),
localhost admin ports, internal services, private IP ranges, and `file://` / `gopher://`.

A sound defence has all of these, so flag whichever is missing when the URL is user-controlled:

- Scheme allow-list (`https` only) and, where possible, a host allow-list.
- Resolve the hostname and reject private, loopback, link-local and metadata ranges, for
  **every** resolved address, IPv4 and IPv6 (including `::ffff:127.0.0.1`, decimal/octal/hex
  IP notations).
- Protect against DNS rebinding: connect to the IP that was validated, not a second lookup.
- Redirects disabled, or each hop re-validated.
- Response not returned verbatim to the user (limits blind-to-full escalation); timeouts and
  size limits set.

Substring or regex checks on the URL string (`url.includes('mycdn.com')`,
`startsWith('https://trusted')`) are bypassable (`https://trusted.evil.com`,
`https://evil.com/?x=mycdn.com`, `https://trusted@evil.com`). Parse the URL and compare the host.

## 6. Deserialization

Formats that can instantiate arbitrary objects on untrusted data give code execution:
Python `pickle`, `yaml.load` without `SafeLoader`, `jsonpickle`, `marshal`; Java native
serialization, XStream, Jackson with default typing; .NET `BinaryFormatter`,
`TypeNameHandling != None`; PHP `unserialize`; Ruby `Marshal.load`, `YAML.load`; Node
`node-serialize`, `funcster`. Also ML model files (`torch.load`, pickle-based formats) from
untrusted sources. Fix: a data-only format (JSON) with schema validation, or signed payloads.

## 7. XML (XXE)

External entity and DTD processing must be off for untrusted XML (including SVG, DOCX/XLSX,
SAML responses, RSS, SOAP). Check parser configuration: libxml `noent: true` / `LIBXML_NOENT`,
Python `lxml` `resolve_entities=True`, Java `DocumentBuilderFactory` / `SAXParserFactory` /
`XMLInputFactory` without `disallow-doctype-decl`, .NET `XmlResolver`. Impact: local file
read, SSRF, denial of service (entity expansion). SAML: signature wrapping and unsigned
assertions deserve a close look whenever SAML code changes.

## 8. Template injection (SSTI)

User input used **as the template** rather than as data: Flask `render_template_string(user)`,
Jinja `Template(user).render()`, Handlebars/EJS/Pug/Nunjucks `compile(user)`, Twig
`createTemplate`, Freemarker/Velocity, ERB. This is code execution on the server. Also
email and notification templates that admins or tenants can edit, and i18n strings with
interpolation engines.

## 9. Code evaluation

`eval`, `new Function`, `setTimeout("string")`, `vm.runInNewContext` (not a sandbox),
Python `eval` / `exec` / `compile` / `__import__`, PHP `eval` / `assert(string)` /
`preg_replace` with `/e`, dynamic `require()` / `import()` with a user-influenced path,
expression engines (SpEL, OGNL, MVEL), spreadsheet formula evaluation, user-supplied
"filters" or "formulas" compiled into code. The only real fix is not evaluating input;
"sanitizing" before `eval` does not hold.

## 10. Prototype pollution (JavaScript)

Recursive merge, clone, `set(obj, path, value)` or query-string parsing applied to user JSON
lets `__proto__`, `constructor.prototype` or `prototype` keys modify every object. Impact
ranges from auth bypass (`isAdmin` appears on all objects) to RCE through gadget libraries.
Look for hand-written deep merges, `lodash.merge` / `defaultsDeep` / `set` on request data,
`Object.assign(target, req.body)` onto long-lived objects. Fix: schema validation that strips
unknown keys, `Object.create(null)` maps, `Map`, key deny-lists.

## 11. ReDoS

- A regex built from user input (`new RegExp(userValue)`): escape it or avoid it.
- Hand-written patterns with nested or overlapping quantifiers (`(a+)+`, `(.*)*`, `(\w+\s?)+$`)
  applied to unbounded user input in a single-threaded runtime: one request can pin the CPU.
  Fix with input length limits, a linear-time engine (RE2), or a rewritten pattern.

## 12. Header, log and other injections

- **HTTP response splitting / header injection**: user input in `Location`, `Set-Cookie`,
  `Content-Disposition` or custom headers without stripping CR/LF.
- **Host header**: links in emails and redirects built from `req.headers.host`.
- **Email header injection**: user input in `To`, `Subject`, `From`, `Reply-To` with newlines.
- **Log injection**: newlines forging log entries; more serious when logs feed a parser,
  an alerting rule or a terminal.
- **LDAP / XPath / GraphQL**: queries concatenated from input.
- **CSV / formula injection**: exported cells starting with `=`, `+`, `-`, `@` execute in
  spreadsheet software. Prefix with `'` on export.
- **HTML to PDF / image**: user HTML rendered by a headless browser can read local files and
  internal URLs (combine with section 5).
