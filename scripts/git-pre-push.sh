#!/usr/bin/env bash
# pushguard native git pre-push hook. Installed by install-git-hook.sh into .git/hooks/pre-push.
# Covers pushes made outside Claude Code (terminal, IDE): it cannot run the full review,
# but it stops the push when the outgoing commits contain a secret or a sensitive file.
# Bypass, on your own responsibility: git push --no-verify

BIN=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ -f "$BIN/scan.sh" ] || BIN="$(git rev-parse --git-common-dir)/pushguard/bin"
[ -f "$BIN/scan.sh" ] || { echo "pushguard: scanner missing, re-run the pushguard setup" >&2; exit 0; }

status=0
while read -r _local_ref local_sha _remote_ref remote_sha; do
  case $local_sha in *[!0]*) ;; *) continue ;; esac   # all zeros: deleting a remote ref
  case $remote_sha in
    *[!0]*) out=$(bash "$BIN/scan.sh" --secrets-only --from "$remote_sha" --to "$local_sha" 2>&1) ;;
    *)      out=$(bash "$BIN/scan.sh" --secrets-only --to "$local_sha" 2>&1) ;;
  esac
  if [ $? -eq 1 ]; then
    printf '%s\n' "$out" >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  {
    echo
    echo "pushguard: push rejected. Remove the secret from the commits themselves"
    echo "(amend / rebase: a follow-up commit does not unpublish it) and rotate the credential."
    echo "False positive? Add a 'pushguard:ignore' comment on the line or an entry in .pushguardignore."
  } >&2
fi
exit "$status"
