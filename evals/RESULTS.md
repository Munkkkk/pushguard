# Evaluation results

Run on 2026-11-15, pushguard 0.1.0, Claude Code headless (`claude -p`), one run per case.

## Setup

`python evals/build.py <dir>` builds eight small repositories, each with one outgoing commit:
six plant two known vulnerabilities, two are clean. Each was reviewed twice:

- **With pushguard**: the plugin loaded, prompt "Run the pushguard:review skill on the
  outgoing commits. Do not modify any file and do not push."
- **Without**: no plugin, prompt "Do a security review of the commits that are about to be
  pushed [...] Report each finding with a severity and file:line, and end with a verdict:
  BLOCK, WARN or PASS."

Outputs were graded by hand against the `expect` list of each case in `build.py`.

## Results

| Case | Planted | Found with | Verdict with | Findings reported with | Found without | Verdict without | Findings reported without |
|---|---|---|---|---|---|---|---|
| xss-stored | 2 | 2 | BLOCK | 2 | 2 | BLOCK | 4 |
| supabase-rls | 2 | 2 | BLOCK | 2 | 2 | BLOCK | 5 |
| cors-csrf | 2 | 2 | BLOCK | 2 | 2 | BLOCK | 3 |
| webhook-ssrf | 2 | 2 | BLOCK | 2 | 2 | BLOCK | 4 |
| jwt-massassign | 2 | 2 | BLOCK | 3 | 2 | BLOCK | 4 |
| gha-pwn-request | 2 | 2 | BLOCK | 2 | 2 | BLOCK | 5 |
| clean-feature | 0 | n/a | PASS | 0 | n/a | PASS | 1 (LOW) |
| clean-refactor | 0 | n/a | PASS | 0 | n/a | PASS | 0 |
| **Total** | **12** | **12** | 8/8 correct | **13** | **12** | 8/8 correct | **26** |

Average wall time per review: 47 s with pushguard, 37 s without.

## What this shows, and what it does not

- **Detection is the same.** On these cases, Claude asked explicitly for a security review
  finds every planted vulnerability with or without the plugin, and passes both clean
  commits either way. The cases are textbook examples, two files each: they do not separate
  the two configurations. The plugin's reference files did not buy extra detection here.
- **The plugin's reports are tighter.** 13 findings for 12 planted problems (the extra one, a
  password hash returned by an API route, is real) against 26 without. The difference is
  LOW and MEDIUM hardening remarks. Lower-confidence remarks went to a one-line "Worth a
  look" section, as the skill asks.
- **No false positive on the clean cases**, including the three deliberate traps in
  `clean-feature` (md5 for an ETag, `Math.random` for retry jitter, `execFile` with fixed
  arguments): each was examined and cleared.
- **The baseline only reviews when asked.** Without the plugin, "push my commits" pushes.
  What the plugin adds is that the review happens every time, before the push, together
  with the deterministic secret scan. That is not measured by this table.

Limits of this evaluation, stated plainly:

- One run per case: no variance estimate.
- Small, self-contained cases. Real findings usually depend on code outside the diff, across
  many files; nothing here tests that.
- The baseline ran on a machine that had other security plugins installed, which may have
  helped it.
- The "do not modify any file" wording made the reviewer skip the approval step on the two
  PASS cases (the approval marker is a file in `.git`). A prompt artifact, not a plugin fault.

Harder cases (larger diffs, a vulnerability that needs a file outside the diff to see,
realistic false-positive bait) are the useful next step.
