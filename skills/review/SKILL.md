---
name: review
description: Deep security review of the commits about to be pushed, and the only way to open the pushguard push gate. Use it before every `git push`, whenever a push was blocked by pushguard, and whenever the user asks to push, ship, deploy, open a PR, or asks for a security review, security audit, vulnerability check, "is this safe to push", or a check for secrets, auth, XSS, CORS, CSRF, injection, RLS or dependency problems, even if they do not name this skill. Also covers a full-repository audit with `--full`.
argument-hint: "[--full | --from <rev>]"
---

# Pushguard security review

You are the last check between this code and a public remote. Once pushed, a leaked key is
compromised for good and a vulnerable endpoint may be deployed within minutes. Review what is
actually leaving the machine, find what an attacker could really use, and say it plainly.

Two things make this review worth having, so keep both in mind throughout:

- **Evidence, not pattern matching.** A finding is a path from something an attacker controls
  to something that hurts, shown with `file:line`. A regex hit is only a place to look.
- **Low noise.** A report with ten doubtful findings teaches the user to ignore the gate.
  Report what you would defend in front of a senior security engineer; drop the rest.

Arguments: none = the outgoing commits. `--from <rev>` = review since that revision.
`--full` = audit the whole repository (see "Full audit" at the end).

## 1. Establish the scope

Run the scope script. It reports the outgoing commits, the base to diff against, whether an
earlier part was already approved, and which reference files the changed paths point to.

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/scope.sh"
```

- `nothing to push` or `HEAD already passed`: say so in one line and stop.
- Uncommitted changes are not part of a push. Mention them, do not review them, unless the
  user asked for a review of work in progress.
- If the scripts are unavailable (skill installed without the plugin, or no bash), do the same
  by hand: `git log @{upstream}..HEAD`, `git diff @{upstream}...HEAD`, and without an upstream
  compare against the remote default branch, or treat the whole history as outgoing.

If the repository has a `.pushguard.md`, read it: it holds the project's threat model and the
risks the team already accepted. Respect it, and say when a finding was skipped because of it.

## 2. Run the deterministic scan

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/scan.sh"
```

It prints three sections:

- **SECRETS**: credentials in any outgoing commit, including ones deleted by a later commit
  (the push still publishes them). Values are hidden on purpose. Open the file to judge each
  hit, and never copy a secret value into your report, a commit message, or a command.
- **SENSITIVE FILES**: `.env`, key files, dumps and similar added to history.
- **LEADS**: risky constructs in the changed lines, each tagged with the reference file that
  explains how to judge it. Leads are noisy by design. Most are fine in context.

The scan covers what regexes can see. Everything that matters most (broken authorization,
logic flaws, missing checks) is invisible to it, which is what the next steps are for.

## 3. Understand the change before judging it

Read the diff (`git diff <base> HEAD`, the exact command is in the scope output), then work out:

- **Stack**: frameworks, auth provider, database, hosting. Read `references/frameworks.md`
  for the sections matching this stack. The dangerous defaults differ a lot between them.
- **Attack surface touched**: new or modified routes, server actions, RPC and GraphQL
  resolvers, webhooks, queue consumers, database policies, middleware, config and CI files.
  A change that adds no entry point and touches no trust boundary rarely carries a serious
  finding; spend the effort where the surface moved.
- **Trust boundaries**: for each entry point, who can reach it (anonymous, any logged-in
  user, an admin, another service) and what it can read or change.

## 4. Review by area

Load only the references that the scope signals, the scan leads, or the diff call for. Each
one lists what to look for, how the vulnerable code typically looks, and the fix.

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
available, split the work by area and give each to a `pushguard:auditor` agent with the diff
range and the matching reference file, then merge and verify their findings yourself (step 5).
Without subagents, go area by area, entry points first, and say in the report which parts
received a lighter pass. Generated files, vendored code and lockfiles do not need line review.

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

- **BLOCK**: at least one CRITICAL or HIGH that is `confirmed` or `likely`.
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

## 8. Open the gate, or do not

The pushguard hook blocks `git push` until the current `HEAD` is approved.

- **PASS or WARN**: approve, then push if the user asked for it.
  ```bash
  bash "${CLAUDE_PLUGIN_ROOT}/scripts/approve.sh" --verdict PASS --summary "0 critical, 0 high, 1 medium, 2 low"
  ```
  With WARN, show the findings first; the approval does not need a second confirmation.
- **BLOCK**: do not approve. Present the findings and offer to fix them. After the fixes are
  committed, review again. The scope script then narrows the review to the new commits, but
  re-check that each fix closes the path you reported and did not open another.
- **The user accepts a blocking finding** (a deliberate decision, a false positive you cannot
  rule out, a fix planned elsewhere): that is their call to make, in their own words in the
  conversation. Then record it:
  ```bash
  bash "${CLAUDE_PLUGIN_ROOT}/scripts/approve.sh" --accepted-risk "<their reason>"
  ```
  Never use `--accepted-risk`, `PUSHGUARD_SKIP=1`, `--no-verify` or a hand-written marker on
  your own initiative. A gate that its own reviewer bypasses protects nothing, and the user
  is relying on it precisely for the times nobody is looking.

The approval is tied to one commit. Any later commit, amend or rebase needs a new review,
which is quick because only the delta is examined.

### When a secret is in the outgoing commits

Deleting it in a new commit does not help: the old commit is still pushed. Because these
commits are not published yet, they can be rewritten safely, but rewriting history is the
user's decision. Explain, then on their go-ahead: remove the value from the commit that
introduced it (`git commit --amend` for the last commit, an interactive rebase or
`git filter-repo` further back), move the value to an environment variable or secret store,
make sure the file pattern is in `.gitignore`, and re-run the scan. If the key ever left the
machine (earlier push, shared branch, pasted anywhere), it must be rotated, and say so.
A confirmed false positive is silenced with a `pushguard:ignore` comment on the line, or a
path in `.pushguardignore`.

## Full audit (`--full`)

For a first run on an existing project or a periodic audit. The outgoing-commit logic does
not apply and nothing is approved at the end.

1. `bash "${CLAUDE_PLUGIN_ROOT}/scripts/scan.sh" --history` scans every tracked file, plus the
   whole history for secrets (a key removed long ago is still in the repository).
2. Map the application: entry points, auth model, data stores, external services, deployment.
3. Go through every area of the table above, entry points first. With subagents available,
   one `pushguard:auditor` per area works well.
4. Report with the same template, grouped by area, and add a short prioritized remediation
   plan (what to fix this week, this month, later).
