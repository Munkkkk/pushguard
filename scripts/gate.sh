#!/usr/bin/env bash
# pushguard gate: Claude Code PreToolUse hook for the Bash / PowerShell tools.
# Blocks `git push` (exit 2) until HEAD carries a pushguard approval marker.
# Everything that is not a push leaves through the fast path without spawning a process.
#
# This is a guard rail, not a sandbox: it stops pushes that were not reviewed by accident,
# and gives the reviewer a reason to run. Escape hatches, for the human to decide on:
#   PUSHGUARD_SKIP=1 git push ...   skip once
#   PUSHGUARD_DISABLE=1             environment variable, disables the gate entirely
#   PUSHGUARD_NO_FASTPATH=1         environment variable, review documentation-only pushes too

[ "${PUSHGUARD_DISABLE:-}" = 1 ] && exit 0

input=$(cat)
case $input in *push*) ;; *) exit 0 ;; esac
case $input in *git*) ;; *) exit 0 ;; esac

# Pull tool_input.command out of the hook JSON without jq/node/python.
extract_command() {
  local rest=$1 out="" c i n
  case $rest in *'"command"'*) ;; *) return 1 ;; esac
  rest=${rest#*\"command\"}
  rest=${rest#*\"}
  rest=${rest:0:20000}
  n=${#rest}
  for ((i = 0; i < n; i++)); do
    c=${rest:i:1}
    if [ "$c" = "\\" ]; then
      i=$((i + 1)); c=${rest:i:1}
      case $c in
        n|r|t) out+=" " ;;
        u) out+="?"; i=$((i + 4)) ;;
        *) out+=$c ;;
      esac
    elif [ "$c" = '"' ]; then
      break
    else
      out+=$c
    fi
  done
  printf '%s' "$out"
}

cmd=$(extract_command "$input") || exit 0
[ -n "$cmd" ] || exit 0

# Drop quoted strings so that "git push" inside a commit message or an echo is not a push.
bare=$cmd
re_dq='"[^"]*"'; re_sq="'[^']*'"
while [[ $bare =~ $re_dq ]]; do bare=${bare/"${BASH_REMATCH[0]}"/ Q }; done
while [[ $bare =~ $re_sq ]]; do bare=${bare/"${BASH_REMATCH[0]}"/ Q }; done

re_push='(^|[^[:alnum:]_./-])git(\.exe)?([[:space:]]+(-[cC][[:space:]]+[^[:space:]]+|--?[[:alnum:]-]+(=[^[:space:]]+)?))*[[:space:]]+push($|[^[:alnum:]_-])'
[[ $bare =~ $re_push ]] || exit 0

case $bare in *--dry-run*) exit 0 ;; esac
case $cmd in *PUSHGUARD_SKIP=1*) exit 0 ;; esac

deny() {
  printf 'pushguard: %s\n' "$@" >&2
  exit 2
}

# A command that creates commits and pushes them in one go cannot have been reviewed.
re_mut='(^|[^[:alnum:]_./-])git(\.exe)?[[:space:]]+([^;&|]*[[:space:]])?(commit|merge|rebase|cherry-pick|revert|pull|am)($|[[:space:]])'
if [[ $bare =~ $re_mut ]]; then
  deny "push blocked: this command changes history and pushes in one step, so the new commits cannot have been reviewed." \
       "Run the commit/merge on its own first. Then invoke the pushguard:review skill, and push once it passes."
fi

# Which repository? Honour `git -C <dir>` and a leading `cd <dir> &&`, else the hook's cwd.
dir=.
re_C="git(\.exe)?[[:space:]]+-C[[:space:]]+(\"([^\"]+)\"|'([^']+)'|([^[:space:]]+))"
re_cd="^[[:space:]]*cd[[:space:]]+(\"([^\"]+)\"|'([^']+)'|([^[:space:];&|]+))"
if [[ $cmd =~ $re_C ]]; then
  dir=${BASH_REMATCH[3]}${BASH_REMATCH[4]}${BASH_REMATCH[5]}
elif [[ $cmd =~ $re_cd ]]; then
  dir=${BASH_REMATCH[2]}${BASH_REMATCH[3]}${BASH_REMATCH[4]}
fi
git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || dir=.
git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0   # not a repo we can judge

head=$(git -C "$dir" rev-parse -q --verify HEAD 2>/dev/null) || exit 0
common=$(git -C "$dir" rev-parse --git-common-dir 2>/dev/null) || exit 0
case $common in /*|[A-Za-z]:*) ;; *) common="$dir/$common" ;; esac

[ -f "$common/pushguard/$head.ok" ] && exit 0

# Nothing new to publish (already on the upstream, e.g. pushing a tag or re-pushing).
if up=$(git -C "$dir" rev-parse -q --verify '@{upstream}^{commit}' 2>/dev/null); then
  [ "$(git -C "$dir" rev-list --count "$up..$head" 2>/dev/null)" = 0 ] && exit 0
fi

# Fast path: a push that only touches prose and images does not need a code review.
# approve.sh still runs the secret scan and refuses if it finds anything.
if [ "${PUSHGUARD_NO_FASTPATH:-}" != 1 ]; then
  HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  if (
    cd "$dir" && cd "$(git rev-parse --show-toplevel)" || exit 1
    . "$HERE/lib.sh"
    pg_range HEAD && pg_docs_only || exit 1
    bash "$HERE/approve.sh" --verdict PASS --summary "auto: documentation only, secret scan clean" >/dev/null 2>&1
  ); then
    exit 0
  fi
fi

deny "push blocked: commit ${head:0:8} has not passed a security review yet." \
     "Invoke the pushguard:review skill now (Skill tool). It reviews the outgoing commits and opens this gate when they pass." \
     "Then retry the same push command. Do not work around the gate: only the user may decide to skip it (PUSHGUARD_SKIP=1)."
