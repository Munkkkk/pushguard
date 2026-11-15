---
name: setup
description: Set up pushguard in the current repository - install or remove the native git pre-push hook that blocks secrets on pushes made outside Claude Code, create the .pushguardignore and .pushguard.md project files, or explain how to configure or bypass the gate. Use when the user asks to install, configure, enable, disable or uninstall pushguard, or wants pushes from their terminal or IDE protected too.
---

# Pushguard setup

Pushguard protects pushes at two levels. Explain this briefly so the user knows what they get:

| Level | Covers | What it does |
|---|---|---|
| Claude Code hook (active as soon as the plugin is enabled) | pushes made by Claude | blocks `git push` until the outgoing commits pass the `pushguard:review` skill |
| Native git hook (installed by this skill, per repository) | pushes from a terminal, an IDE, any tool | blocks the push when the outgoing commits contain a secret or a sensitive file; no AI review |

## Install the native git hook

Run from inside the repository:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/install-git-hook.sh"
```

- The scanner is copied into `.git/pushguard/bin`, so nothing is added to the working tree
  and the hook keeps working after a plugin update.
- Exit status 3 means another pre-push hook already exists. It was left untouched; show the
  user the chaining line the script printed and let them decide how to combine the two.
- When `core.hooksPath` is set (husky, lefthook), the hook is written to that directory. Tell
  the user, since that directory is usually versioned and shared with the team.
- Git hooks are local to a clone. Each contributor installs it, or the team wires
  `scripts/git-pre-push.sh` into its shared hook manager.

Remove it with `bash "${CLAUDE_PLUGIN_ROOT}/scripts/install-git-hook.sh" --remove`.

## Project files (optional, create only what the user wants)

- **`.pushguardignore`**: paths the secret scan skips, one glob per line (`fixtures/`,
  `docs/examples/*.md`, `*.snap`). For test fixtures with fake credentials. Keep it short:
  every entry is a place a real secret could hide.
- **`pushguard:ignore`**: a comment on a single line silences that line only. Prefer it to a
  path entry.
- **`.pushguard.md`**: free-form notes the reviewer reads first: what the application does,
  who the users are, what is intentionally public, which risks the team has accepted and why.
  A few lines here remove most false positives. Offer to draft it from what the repository
  shows, and have the user confirm the accepted-risk part: that part must be theirs.

## Bypass and disable

State these plainly when asked; the user owns the decision.

- Skip once, in Claude Code: the user asks to push without review, and the push is run as
  `PUSHGUARD_SKIP=1 git push ...`.
- Skip once, native hook: `git push --no-verify`.
- Disable the Claude Code gate: set the environment variable `PUSHGUARD_DISABLE=1`, or
  disable the plugin.

Do not apply any of these on your own initiative.
