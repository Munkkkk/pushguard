# Finding secrets in the outgoing commits

This edition has no scanner script, so the search is done with git itself. Search the
commits, not just the final diff: a key added in one commit and deleted in the next is still
published by the push.

`git log -G` lists the commits and files whose added or removed lines match a regular
expression, without printing the matching line. That keeps secret values out of the
conversation until you choose to open a file. Replace `RANGE` with the outgoing range from
the scope step (for example `@{upstream}..HEAD`).

## 1. High-confidence credential formats

Run this as one command:

```bash
git log RANGE --format='%h %s' --name-only -G'(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|-----BEGIN ([A-Z]+ )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}|glpat-[A-Za-z0-9_-]{20,}|(sk|rk)_live_[0-9a-zA-Z]{20,}|whsec_[A-Za-z0-9]{24,}|sk-ant-[A-Za-z0-9_-]{24,}|sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}|AIza[0-9A-Za-z_-]{35}|GOCSPX-[A-Za-z0-9_-]{20,}|"type"[[:space:]]*:[[:space:]]*"service_account"|AccountKey=[A-Za-z0-9+/=]{60,}|xox[baprs]-[A-Za-z0-9-]{10,}|hooks\.slack\.com/services/T[A-Za-z0-9_]+/B|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc|hf_[A-Za-z0-9]{34,}|do[por]_v1_[a-f0-9]{64}|shp(at|ca|pa|ss)_[a-fA-F0-9]{32}|sb_secret_[A-Za-z0-9_-]{20,}'
```

What the alternatives cover, in order: AWS access key ids, PEM private keys, GitHub tokens
(classic and fine-grained), GitLab tokens, Stripe live keys and webhook secrets, Anthropic
and OpenAI-style keys, Google API keys and OAuth client secrets, GCP service account files,
Azure storage keys, Slack tokens and webhooks, SendGrid, npm, PyPI, Hugging Face,
DigitalOcean, Shopify and Supabase secret keys.

Any hit here is CRITICAL until you have opened the file and shown it is a placeholder or a
documented example.

## 2. Lower-confidence patterns

These need judgement. Run them the same way:

```bash
git log RANGE --format='%h %s' --name-only -G'(postgres(ql)?|mysql|mongodb(\+srv)?|rediss?|amqps?)://[^:@/ ]+:[^@/ ]+@'
```

```bash
git log RANGE --format='%h %s' --name-only -G'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
```

```bash
git log RANGE --format='%h %s' --name-only -i -G'(api[_-]?key|secret|token|passw(or)?d|private[_-]?key|client[_-]?secret)[a-z0-9_]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9+/_=.-]{16,}["'"'"']'
```

- Database URL with a password: real unless it is a local development default that
  production cannot reuse.
- A JWT literal: decode the middle segment. A Supabase `service_role` token or a session
  token is critical; an `anon` token is public by design.
- A value assigned to a secret-looking name: often a placeholder, a test value or a
  translation key. Open the file.

## 3. Sensitive files added to history

```bash
git log RANGE --diff-filter=A --name-only --format= | sort -u
```

Look in that list for: `.env` and `.env.*` (except `.env.example`, `.env.sample`,
`.env.template`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `id_rsa`,
`id_ed25519`, `credentials.json`, `client_secret*.json`, service account files,
`.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `terraform.tfstate`, `*.tfvars`,
database files and dumps (`*.sqlite`, `*.db`, `*.dump`, `dump*.sql`), `*.har`.

## 4. Judging and reporting

`references/secrets-crypto.md` section 2 explains how to tell a real secret from a
placeholder, a public-by-design key or a test key. In the report, give the file, the line
and the commit, and mask the value. Never paste a secret into the report, a commit message
or a command.

If a real secret is in an outgoing commit, deleting it in a new commit does not help: the
old commit is still pushed. The commits are not published yet, so they can be rewritten,
but rewriting history is the user's decision. If the key ever left the machine, it must be
rotated.
