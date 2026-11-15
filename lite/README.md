# Pushguard Lite

A security review skill for the commits you are about to push.

Ask Claude to "review before I push", "is this safe to push", or run `/pushguard-lite:review`.
Claude works out which commits would be published, searches them for secrets, reviews the
change area by area, verifies each finding, and gives a verdict: BLOCK, WARN or PASS, with
the file and line, the attack scenario and the fix for every finding.

## What it checks

- Secrets in every outgoing commit, including ones deleted by a later commit
- Authentication and access control: missing checks, IDOR, multi-tenant leaks, mass
  assignment, JWT, OAuth, sessions
- Database policies: Supabase and Postgres row level security, Firebase rules
- Injection: SQL, NoSQL, command, path traversal, SSRF, deserialization, template injection
- Web client: XSS, CSRF, CORS, security headers, cookies, open redirects
- API and data: validation, rate limiting, uploads, webhooks, error leakage, race conditions,
  payment logic
- Supply chain and infrastructure: dependencies, GitHub Actions, Docker, Terraform
- AI features: prompt injection, agent tools, key exposure
- Framework pitfalls: Next.js, React, Supabase, Firebase, Express, Django, Flask, FastAPI,
  Rails, Laravel, Go, Spring, mobile, serverless

## What this edition contains, and what it does not

This edition is instructions only: one skill, its reference files and one read-only agent,
all in Markdown. It runs no hook and ships no script. During a review Claude runs read-only
`git` commands in your repository; nothing is written and nothing is sent anywhere.

Because it has no hook, **it does not block a push by itself**. The review happens when you
ask for it, or when Claude decides the skill applies.

The full edition adds an automatic gate that blocks `git push` until the review passes, a
deterministic secret scanner, and an optional native git hook. It needs hooks and shell
scripts, so it is distributed from GitHub:

```
/plugin marketplace add Munkkkk/pushguard
/plugin install pushguard@pushguard
```

Install one edition or the other, not both.

To install this lite edition from GitHub instead of the directory:

```
/plugin install pushguard-lite --marketplace Munkkkk/pushguard
```

## Limits

The review is done by a language model. It finds a lot, including missing-check bugs that
pattern scanners cannot see, but it can miss things and can be wrong. It complements code
review, tests, dependency scanning and penetration testing. It replaces none of them.

## License

MIT. Source: https://github.com/Munkkkk/pushguard
