#!/usr/bin/env bash
# pushguard scan: deterministic secret detection + risky-pattern leads.
#
#   scan.sh                      what a push of HEAD would publish (default)
#   scan.sh --from A --to B      an explicit commit range
#   scan.sh --all                every tracked file in the working tree
#   scan.sh --history            working tree + secrets across the whole history of HEAD
#   scan.sh --secrets-only       skip the lead rules (used by the gate and the git hook)
#
# Secrets are searched in every outgoing COMMIT, not just the net diff: a key that was
# added and then deleted in a later commit is still published by the push.
# Secret values are never printed, only their location.
#
# Exit status: 0 = no blocking secret, 1 = CRITICAL/HIGH secret or sensitive file, 2 = usage error.

set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

MODE=push; FROM=""; TO=HEAD; SECRETS_ONLY=0; MAX=12
while [ $# -gt 0 ]; do
  case $1 in
    --all) MODE=all ;;
    --history) MODE=history ;;
    --from) FROM=${2:-}; shift ;;
    --to) TO=${2:-}; shift ;;
    --secrets-only) SECRETS_ONLY=1 ;;
    --max) MAX=${2:-12}; shift ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "pushguard scan: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

pg_require_repo || exit 2
cd "$(git rev-parse --show-toplevel)" || exit 2
git rev-parse -q --verify HEAD >/dev/null 2>&1 || { echo "pushguard scan: no commits yet"; exit 0; }
pg_excludes

WORK=$(mktemp -d 2>/dev/null || mktemp -d -t pushguard)
trap 'rm -rf "$WORK"' EXIT

# Turns `git log -p` / `git diff` output into: <commit|diff> TAB <file> TAB <line> TAB <added content>
AWK_ADDED='
/^@@commit / { c = substr($2, 1, 8); next }
/^\+\+\+ b\// { f = substr($0, 7); next }
/^\+\+\+ \/dev\/null/ { f = ""; next }
/^@@ / { s = $0; sub(/^@@ -[0-9,]+ \+/, "", s); sub(/[ ,].*$/, "", s); n = s + 0; next }
/^\+/ { if (f != "") print c "\t" f "\t" n "\t" substr($0, 2); n++; next }
'
DIFF_OPTS=(-U0 --no-color --no-ext-diff --no-textconv --src-prefix=a/ --dst-prefix=b/)

collect_log()  { git log -p "${DIFF_OPTS[@]}" --format='@@commit %H' "$@" -- . "${PG_EXCL[@]}" | awk "$AWK_ADDED"; }
collect_diff() { git diff "${DIFF_OPTS[@]}" "$1" "$2" -- . "${PG_EXCL[@]}" | awk -v c=diff "$AWK_ADDED"; }
collect_tree() { git grep -n -I -e '' -- . "${PG_EXCL[@]}" | sed -E "s/^([^:]+):([0-9]+):/tree${TAB}\1${TAB}\2${TAB}/"; }

case $MODE in
  push)
    if [ -n "$FROM" ]; then
      PG_BASE=$FROM; PG_LOG_ARGS=("$FROM..$TO")
    else
      pg_range "$TO"
    fi
    TIP=$(git rev-parse --short "$TO" 2>/dev/null)
    echo "== pushguard scan: outgoing commits (base ${PG_BASE:0:8}, tip $TIP) =="
    collect_log "${PG_LOG_ARGS[@]}" > "$WORK/secrets.in"
    [ "$SECRETS_ONLY" = 1 ] || collect_diff "$PG_BASE" "$TO" > "$WORK/code.in"
    git log --diff-filter=A --name-only --format= "${PG_LOG_ARGS[@]}" -- . "${PG_EXCL[@]}" | sort -u > "$WORK/files.in"
    ;;
  all|history)
    echo "== pushguard scan: full repository ($MODE) =="
    collect_tree > "$WORK/code.in"
    if [ "$MODE" = history ]; then
      collect_log HEAD > "$WORK/secrets.in"
      git log --diff-filter=A --name-only --format= HEAD -- . "${PG_EXCL[@]}" | sort -u > "$WORK/files.in"
    else
      cp "$WORK/code.in" "$WORK/secrets.in"
      git ls-files -- . "${PG_EXCL[@]}" > "$WORK/files.in"
    fi
    ;;
esac

# Lines carrying a pushguard:ignore comment are dropped once, here. Prose files are dropped
# from the lead input only: documentation talks about eval() and innerHTML without running them.
for f in secrets code; do
  [ -f "$WORK/$f.in" ] || continue
  LC_ALL=C grep -a -v 'pushguard:ignore' "$WORK/$f.in" > "$WORK/$f.tmp"; mv "$WORK/$f.tmp" "$WORK/$f.in"
done
if [ -f "$WORK/code.in" ]; then
  LC_ALL=C grep -a -v -i -E "^[^${TAB}]*${TAB}[^${TAB}]*\.(md|mdx|markdown|txt|rst|adoc)${TAB}" "$WORK/code.in" > "$WORK/leads.in"
fi

BLOCKING=0

# run_rules <rules file> <data file> <kind: secret|lead>
run_rules() {
  local id col2 flags re desc c f n content count loc shown
  local -a gflags
  while read -r id col2 flags re desc || [ -n "${id:-}" ]; do
    desc=${desc%$'\r'}
    case ${id:-} in ''|'#'*) continue ;; esac
    gflags=(-a -E); [ "$flags" = i ] && gflags+=(-i)
    LC_ALL=C grep "${gflags[@]}" -e "$re" "$2" > "$WORK/hits" 2>/dev/null || continue
    count=0; shown=0
    while IFS=$TAB read -r c f n content; do
      count=$((count + 1))
      [ "$count" -le "$MAX" ] || continue
      shown=$count
      loc="$f:$n"
      case $c in diff|tree) ;; *) loc="$loc @$c" ;; esac
      if [ "$3" = secret ]; then
        printf '%-8s %-22s %s  -- %s\n' "$col2" "$id" "$loc" "$desc"
      else
        content=${content:0:170}
        printf '%-20s [%s] %s | %s\n' "$id" "$col2" "$loc" "$content"
      fi
    done < "$WORK/hits"
    [ "$count" -gt "$MAX" ] && echo "         ... $((count - MAX)) more match(es) for $id"
    if [ "$3" = secret ]; then
      case $col2 in CRITICAL|HIGH) BLOCKING=$((BLOCKING + count)) ;; esac
    else
      echo "    ^ $desc"
    fi
  done < "$1"
}

echo
echo "[SECRETS] value hidden on purpose; open the file to judge it, never paste the value in a report"
run_rules "$HERE/rules/secrets.rules" "$WORK/secrets.in" secret > "$WORK/out.secrets"
# run_rules ran in the current shell (redirect only), so BLOCKING is preserved.
if [ -s "$WORK/out.secrets" ]; then cat "$WORK/out.secrets"; else echo "none"; fi

echo
echo "[SENSITIVE FILES] added to the pushed history"
SENSITIVE_RE='((^|/)\.env(\.[^/]*)?$|\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx|har)$|(^|/)id_(rsa|dsa|ecdsa|ed25519)$|(^|/)(credentials|client_secret[^/]*|service[-_]?account[^/]*|secrets?)\.(json|ya?ml|toml)$|(^|/)\.(npmrc|pypirc|netrc|htpasswd|git-credentials|dockercfg)$|(^|/)\.aws/credentials$|(^|/)\.docker/config\.json$|terraform\.tfstate|\.tfvars$|\.(sqlite3?|db|dump|bak)$|(^|/)dump[^/]*\.sql$|(^|/)wp-config\.php$)'
SAFE_RE='\.env\.(example|sample|template|dist|defaults?)$'
grep -E -i "$SENSITIVE_RE" "$WORK/files.in" 2>/dev/null | grep -E -i -v "$SAFE_RE" > "$WORK/out.files"
if [ -s "$WORK/out.files" ]; then
  while IFS= read -r f; do
    printf '%-8s %-22s %s\n' HIGH sensitive-file "$f"
    BLOCKING=$((BLOCKING + 1))
  done < "$WORK/out.files"
else
  echo "none"
fi

if [ "$SECRETS_ONLY" != 1 ]; then
  echo
  echo "[LEADS] risky constructs in the changed lines. Unverified: each needs the code read around it."
  echo "        [name] = references/<name>.md explains how to judge it."
  run_rules "$HERE/rules/leads.rules" "$WORK/leads.in" lead > "$WORK/out.leads"
  if [ -s "$WORK/out.leads" ]; then cat "$WORK/out.leads"; else echo "none"; fi
fi

echo
if [ "$BLOCKING" -gt 0 ]; then
  echo "RESULT: $BLOCKING blocking secret/sensitive-file hit(s)."
  exit 1
fi
echo "RESULT: no blocking secret."
exit 0
