#!/usr/bin/env bash
# pushguard approve: record that HEAD passed the security review, which opens the push gate
# for exactly this commit. Any new commit needs a new review.
#
#   approve.sh --verdict PASS|WARN [--summary "0 critical, 0 high, 2 medium"]
#   approve.sh --accepted-risk "<the user's own reason>"   only after the user explicitly
#                                                          accepted the remaining findings
#
# As a backstop it re-runs the secret scan and refuses to approve while a CRITICAL/HIGH
# secret is present in the outgoing commits, unless --accepted-risk is given.

set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

VERDICT=""; SUMMARY=""; RISK=""
while [ $# -gt 0 ]; do
  case $1 in
    --verdict) VERDICT=${2:-}; shift ;;
    --summary) SUMMARY=${2:-}; shift ;;
    --accepted-risk) RISK=${2:-}; shift ;;
    -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "pushguard approve: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

pg_require_repo || exit 2
HEAD_SHA=$(git rev-parse -q --verify HEAD) || { echo "pushguard approve: no commits" >&2; exit 2; }

if [ -n "$RISK" ]; then
  VERDICT=ACCEPTED-RISK
else
  case $VERDICT in
    PASS|WARN) ;;
    *) echo "pushguard approve: --verdict must be PASS or WARN (a BLOCK verdict is never approved; use --accepted-risk only on the user's explicit decision)" >&2; exit 2 ;;
  esac
  if ! bash "$HERE/scan.sh" --secrets-only > /dev/null 2>&1; then
    echo "pushguard approve: REFUSED. The outgoing commits still contain a blocking secret or sensitive file:" >&2
    bash "$HERE/scan.sh" --secrets-only 2>&1 | sed -n '/^\[SECRETS\]/,$p' >&2
    echo "Remove it from the commits themselves (not with a follow-up commit) and rotate the credential." >&2
    echo "A confirmed false positive can be silenced with a 'pushguard:ignore' comment on the line or a .pushguardignore entry." >&2
    exit 1
  fi
fi

DIR=$(pg_state_dir) || exit 2
mkdir -p "$DIR" || exit 2
{
  echo "commit:   $HEAD_SHA"
  echo "verdict:  $VERDICT"
  echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [ -n "$SUMMARY" ] && echo "summary:  $SUMMARY"
  [ -n "$RISK" ] && echo "accepted: $RISK"
} > "$DIR/$HEAD_SHA.ok"

# Keep the 40 most recent markers.
ls -1t "$DIR"/*.ok 2>/dev/null | tail -n +41 | while IFS= read -r old; do rm -f "$old"; done

echo "pushguard: ${HEAD_SHA:0:8} approved ($VERDICT). The push gate is open for this commit."
