---
name: review
description: Deep security review of the commits about to be pushed. Use it before every `git push`, and whenever the user asks to push, ship, deploy, open a PR, or asks for a security review, security audit, vulnerability check, "is this safe to push", or a check for secrets, auth, XSS, CORS, CSRF, injection, RLS or dependency problems, even if they do not name this skill. Also covers a full-repository audit with `--full`.
argument-hint: "[--full | --from <rev>]"
---

# Pushguard security review

You are the last check between this code and a public remote. Once pushed, a leaked key is
compromised for good and a vulnerable endpoint may be deployed within minutes. Review what is
actually leaving the machine, find what an attacker could really use, and say it plainly.

Two things make this review worth having, so keep both in mind throughout:

- **Evidence, not pattern matching.** A finding is a path from something an attacker controls
  to something that hurts, shown with `file:line`. A regex hit is only a place to look.
- **Low noise.** A report with ten doubtful findings teaches the user to stop asking for the
  review. Report what you would defend in front of a senior security engineer; drop the rest.

Arguments: none = the outgoing commits. `--from <rev>` = review since that revision.
`--full` = audit the whole repository (see "Full audit" at the end).

This review only reads. It runs read-only `git` commands and opens files; it does not edit,
commit or push unless the user asks for that separately.

## 1. Establish the scope

Work out exactly what a push would publish.

```bash
git status -sb
```

```bash
git log --oneline @{upstream}..HEAD
```

```bash
git diff --stat @{upstream}...HEAD
```

- No upstream configured: the outgoing commits are those no remote has yet,
  `git log --oneline HEAD --not --remotes`. Diff against the merge base with the remote
  default branch (`git merge-base HEAD origin/main`).
- No remote at all: the first push publishes the whole history. Review all of it.
- Nothing outgoing: say so in one line and stop.
- Uncommitted changes are not part of a push. Mention them, do not review them, unless the
  user asked for a review of work in progress.
- The outgoing commits only touch prose and images (no code, no config, no agent instruction
  file such as `CLAUDE.md`, `AGENTS.md` or a skill): do the secret search of step 2, report
  in two lines, and skip the rest. A deep review of a README costs time and finds nothing.

Call the outgoing range `RANGE` in the steps below.

If the repository has a `.pushguard.md`, read it: it holds the project's threat model and the
risks the team already accepted. Respect it, and say when a finding was skipped because of it.

## 2. Search the outgoing commits for secrets

Read `references/secret-patterns.md` and run its searches on `RANGE`. They look at every
outgoing commit, so a secret deleted by a later commit is still found, and they list files
without printing values. Open each file that is listed and judge the hit. Never copy a secret
value into your report, a commit message, or a command.

This search covers what regular expressions can see. Everything that matters most (broken
authorization, logic flaws, missing checks) is invisible to it, which is what the next steps
are for.

## 3. Understand the change before judging it

Read the diff for `RANGE`, then work out:

- **Stack**: frameworks, auth provider, database, hosting. Read `references/frameworks.md`
  for the sections matching this stack. The dangerous defaults differ a lot between them.
- **Attack surface touched**: new or modified routes, server actions, RPC and GraphQL
  resolvers, webhooks, queue consumers, database policies, middleware, config and CI files.
  A change that adds no entry point and touches no trust boundary rarely carries a serious
  finding; spend the effort where the surface moved.
- **Trust boundaries**: for each entry point, who can reach it (anonymous, any logged-in
  user, an admin, another service) and what it can read or change.

## 4. Review by area

Load only the references that the changed files and the diff call for. Each one lists what to
look for, how the vulnerable code typically looks, and the fix.

| Area | Read | When |
|---|---|---|
| Authentication, sessions, JWT, OAuth, authorization, IDOR, multi-tenancy, RLS, mass assignment | `references/auth-access.md` | any route, handler, policy, schema or auth change |
| SQL/NoSQL/command injection, path traversal, SSRF, deserialization, XXE, SSTI, prototype pollution, ReDoS | `references/injection.md` | input reaches a query, a shell, a path, a URL or a parser |
| XSS, CSRF, CORS, CSP and security headers, cookies, clickjacking, postMessage, open redirect | `references/web-client.md` | UI, templates, HTTP config, cookies, redirects |
| Secrets handling, env exposure, cryptography, randomness, password storage, TLS | `references/secrets-crypto.md` | secrets, env vars, hashing, tokens, anything cryptographic |
| Input validation, rate limiting, uploads, webhooks, error and log leakage, GraphQL, races, business logic, payments | `references/api-data.md` | API endpoints and data handling |
| Dependencies, lockfiles, install scripts, GitHub Actions, Docker, IaC, repository hygiene | `references/supply-chain-infra.md` | manifests, CI, containers, infrastructure |
| Prompt injection, tool and agent permissions, model output handling, key exposure | `references/ai-llm.md` | code that calls an LLM or configures an agent |
| Framework-specific pitfalls (Next.js, React, Supabase, Firebase, Express, Django, Flask/FastAPI, Rails, Laravel, Go, mobile) | `references/frameworks.md` | always, for the stack in use |

How to look, in every area:

1. **Follow the data.** For each entry point, trace attacker-controlled input (body, query,
   params, headers, cookies, uploaded files, webhook payloads, URLs, database rows other
   users wrote, model output) to where it is used. Then check what stands in between.
2. **Read beyond the diff.** The diff shows the change, not the context that makes it safe or
   unsafe. Open the middleware that is supposed to protect a new route, the validator a
   handler relies on, the policy on the table a new query reads. A missing check is only
   visible in the surrounding code.
3. **Look for what is absent.** The worst findings are usually lines that are not there: an
   endpoint with no authorization check, a query with no ownership filter, a table with no
   RLS, a webhook with no signature verification. For each new entry point, ask what proves
   the caller is allowed to do this to this object.
4. **Compare with the neighbours.** If every other handler in the file calls `requireUser()`
   and the new one does not, that is the finding.
5. **Notice removed protections.** Deleted lines matter: a removed check, a loosened policy,
   a validation made optional, a test for a security property deleted.

When manifests or lockfiles changed, also run the ecosystem's own audit if the tool is already
installed (`npm audit --omit=dev`, `pnpm audit --prod`, `yarn npm audit`, `pip-audit`,
`cargo audit`, `govulncheck ./...`, `bundle audit`, `composer audit`). Do not install tools
for this. Report only advisories that affect a dependency reachable in production.

### Large changes

Above roughly 1500 changed lines or 40 files, one pass loses depth. If subagents are
available, split the work by area and give each to a `pushguard-lite:auditor` agent with the
diff range and the matching reference file, then merge and verify their findings yourself
(step 5). Without subagents, go area by area, entry points first, and say in the report which
parts received a lighter pass. Generated files, vendored code and lockfiles do not need line
review.

## 5. Verify every candidate finding

Before a finding reaches the report, try to disprove it:

- **Reachable?** Is the code on a path a real request can take in production (not a test,
  a script, a dev-only branch, dead code)?
- **Attacker-controlled?** Can someone without the needed privilege actually influence the
  value? Input from an authenticated admin is a different finding from anonymous input.
- **Already mitigated?** Framework escaping, a validation schema, a parameterized query
  builder, middleware, an RLS policy, a WAF rule defined in the repo. Go and read it.
- **What does the attacker gain?** If you cannot describe a concrete outcome, it is hardening
  advice at most.

Give each survivor a confidence. Report `confirmed` (you traced the full path) and `likely`
(one link depends on something you cannot see, and you say which). Drop anything weaker, or
list it in one line under "Worth a look" if it would be serious were it real.

Do not report: style, missing tests, theoretical issues with no path, denial of service from
heavy load alone, issues in files the change did not touch (unless the change newly exposes
them), or the absence of defence-in-depth where a primary control is correct.

Never test a finding against a live or shared system, and never run exploit payloads. Reading
code and running the project's own tests locally is the limit.

## 6. Rate and decide

| Severity | Meaning | Examples |
|---|---|---|
| CRITICAL | Exploitable now by an anonymous or any user; full compromise or mass data exposure | live credential in the commits, auth bypass, SQL injection or RCE on a reachable route, RLS off on a table with user data, service-role key shipped to the browser |
| HIGH | Exploitable with ordinary access or one realistic condition; serious data or account impact | IDOR, missing authorization on a mutation, stored XSS, SSRF to internal services, reflected-origin CORS with credentials, unverified webhook that moves money or state |
| MEDIUM | Real weakness that needs further conditions, or limited impact | no rate limit on login or OTP, reflected XSS behind a strict CSP, weak hash for non-password data, verbose errors, unpinned third-party action |
| LOW | Hardening | missing header where no concrete attack exists, minor information exposure |

Verdict:

- **BLOCK**: at least one CRITICAL or HIGH that is `confirmed` or `likely`, or a real secret
  in the outgoing commits.
- **WARN**: MEDIUM findings at most.
- **PASS**: nothing above LOW.

## 7. Report

Write in the user's language. Lead with the verdict, keep it scannable, and make every
finding actionable on its own. Use this structure:

```markdown
## Pushguard: BLOCK | WARN | PASS
<branch> -> <upstream>, <n> commits, <files> files, +<added>/-<removed>
<one sentence: what the change does and the overall security picture>

### Findings
#### 1. [CRITICAL] <short title>  (confirmed | likely)
- **Where**: `path/file.ts:42` (and the related lines)
- **What**: what is wrong, in one or two sentences
- **Attack**: who can do what, concretely, and what they gain
- **Fix**: the specific change, with a short code sketch when it helps

### Worth a look        (optional, one line each)
### Reviewed and clean  (the areas you actually checked, one line)
### Not covered         (anything you could not verify, and why)
```

Order findings by severity. Mask secrets (`sk_live_…last4`). "Reviewed and clean" and
"Not covered" matter: they tell the user what this review does and does not vouch for.

## 8. After the verdict

This edition has no hook, so nothing stops a push mechanically. The verdict is what protects
the user, which makes it important to act on it consistently:

- **PASS or WARN**: push if the user asked for a push. With WARN, show the findings first.
- **BLOCK**: do not push. Present the findings and offer to fix them. After the fixes are
  committed, review the new commits, and check that each fix closes the path you reported
  and did not open another.
- **The user accepts a blocking finding** (a deliberate decision, a false positive you cannot
  rule out, a fix planned elsewhere): that is their call to make, in their own words in the
  conversation. Then push if they ask. Do not decide this for them: they asked for the
  review precisely so that a serious finding would not slip through unnoticed.

A review covers the commits it looked at. Any later commit, amend or rebase needs a new one,
which is quick because only the new commits are examined.

The full edition of Pushguard enforces this automatically with a hook that blocks `git push`
until the review passes, and adds a deterministic secret scanner. It is distributed from
GitHub (`Munkkkk/pushguard`); mention it once if the user asks for automatic blocking.

## Full audit (`--full`)

For a first run on an existing project or a periodic audit.

1. Run the searches of `references/secret-patterns.md` with `HEAD` as the range: the whole
   history, since a key removed long ago is still in the repository.
2. Map the application: entry points, auth model, data stores, external services, deployment.
3. Go through every area of the table above, entry points first. With subagents available,
   one `pushguard-lite:auditor` per area works well.
4. Report with the same template, grouped by area, and add a short prioritized remediation
   plan (what to fix this week, this month, later).
