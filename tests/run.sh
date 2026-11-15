#!/usr/bin/env bash
# pushguard test suite. Needs only git and bash. Run: bash tests/run.sh
# Fake credentials are assembled at run time so that this file contains no secret-shaped string.

set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S="$ROOT/scripts"
T=$(mktemp -d 2>/dev/null || mktemp -d -t pushguard-test)
trap 'rm -rf "$T"' EXIT
unset PUSHGUARD_DISABLE PUSHGUARD_NO_FASTPATH PUSHGUARD_SKIP
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }
eq()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected $2, got $3)"; fi; }
has()  { if printf '%s' "$3" | grep -q -e "$2"; then ok "$1"; else bad "$1 (missing: $2)"; fi; }
lacks(){ if printf '%s' "$3" | grep -q -e "$2"; then bad "$1 (unexpected: $2)"; else ok "$1"; fi; }

AWS="AKIA""ABCDEFGHIJKLMNOP"
STRIPE="sk_live_""abcdefghijklmnopqrstuvwx"
GH="ghp_""abcdefghijklmnopqrstuvwxyz0123456789"

new_repo() { # <name>: fresh repo with one pushed commit and a local bare remote
  rm -rf "$T/$1" "$T/$1.git"
  git init -q --bare "$T/$1.git"
  git init -q -b main "$T/$1"
  cd "$T/$1" || exit 1
  git config user.email test@example.invalid; git config user.name test
  git config core.autocrlf false; git config commit.gpgsign false
  echo "# app" > README.md; git add -A; git commit -qm init
  git remote add origin "$T/$1.git"; git push -q -u origin main 2>/dev/null
}
commit() { git add -A; git commit -qm "$1"; }

# gate <command>: feed the hook the JSON Claude Code would send, print its exit status
gate() {
  printf '{"session_id":"x","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s","description":"d"}}' "$1" \
    | bash "$S/gate.sh" 2>"$T/gate.err"
  echo $?
}

echo "rules"
for f in secrets leads; do
  n=0
  while read -r id c2 fl re desc; do
    case ${id:-} in ''|'#'*) continue ;; esac
    n=$((n + 1))
    case $fl in i|-) ;; *) bad "$f:$id flags '$fl'" ;; esac
    [ -n "$desc" ] || bad "$f:$id has no description (a space inside the regex?)"
    echo x | grep -E -e "$re" >/dev/null 2>"$T/re.err"
    [ -s "$T/re.err" ] && bad "$f:$id regex does not compile: $(cat "$T/re.err")"
  done < "$S/rules/$f.rules"
  [ "$n" -gt 10 ] && ok "$f.rules: $n rules parse and compile"
done

echo "gate: commands that are not a push"
new_repo gate
mkdir -p src; echo "let a = 1" > src/a.js; commit "code"
for c in 'ls -la' 'git status' 'git stash push -m wip' 'echo \"git push\"' 'git commit -m \"fix git push hook\"' 'npm run push' 'git push --dry-run' 'PUSHGUARD_SKIP=1 git push'; do
  eq "allows: $c" 0 "$(gate "$c")"
done

echo "gate: unreviewed pushes"
for c in 'git push' 'git push origin main' 'git -C . push -u origin main' 'npm test && git push' 'git.exe push --force'; do
  eq "blocks: $c" 2 "$(gate "$c")"
done
eq "blocks commit+push in one command" 2 "$(gate 'git add . && git commit -m \"x\" && git push')"
has "explains the one-step block" "one step" "$(cat "$T/gate.err")"
eq "PUSHGUARD_DISABLE=1 opens the gate" 0 "$(PUSHGUARD_DISABLE=1 gate 'git push')"

echo "scope and scan"
cat > src/api.js <<EOF
const k = "$AWS";
el.innerHTML = req.query.name;
db.query("SELECT * FROM users WHERE id = " + req.query.id);
const t = "$GH"; // pushguard:ignore
EOF
echo "STRIPE=$STRIPE" > .env
echo "document.write(x) and eval(y)" > NOTES.md
commit "leak"
sed -i.bak '1d' src/api.js; rm -f src/api.js.bak; git rm -q --cached .env; rm -f .env; commit "remove the key"
out=$(bash "$S/scope.sh")
has "scope counts outgoing commits" "commits:   3 outgoing" "$out"
has "scope signals API code" "references/api-data.md" "$out"
lacks "scope: code change is not a fast path" "fastpath:" "$out"
out=$(bash "$S/scan.sh"); rc=$?
eq "scan exits 1 on a blocking secret" 1 "$rc"
has "finds a key deleted by a later commit" "aws-access-key-id .*src/api.js" "$out"
has "finds the secret in the removed .env" "stripe-live-key" "$out"
has "flags the sensitive file" "sensitive-file .*\.env" "$out"
lacks "never prints a secret value" "$AWS" "$out"
lacks "honours pushguard:ignore" "github-token" "$out"
has "lead: DOM XSS sink" "dom-xss-sink" "$out"
has "lead: SQL string building" "sql-string-build" "$out"
lacks "no leads from documentation files" "NOTES.md" "$out"

echo "approve"
bash "$S/approve.sh" --verdict PASS >/dev/null 2>&1
eq "refuses while a secret is in the outgoing commits" 1 $?
bash "$S/approve.sh" --verdict BLOCK >/dev/null 2>&1
eq "rejects a BLOCK verdict" 2 $?
eq "gate still closed" 2 "$(gate 'git push')"
git reset -q --soft origin/main; commit "clean rewrite"
bash "$S/scan.sh" --secrets-only >/dev/null 2>&1
eq "scan clean after the history rewrite" 0 $?
bash "$S/approve.sh" --verdict WARN --summary "0 critical" >/dev/null 2>&1
eq "approves a clean WARN" 0 $?
eq "gate open for the approved commit" 0 "$(gate 'git push origin main')"
has "scope reports the approval" "already passed" "$(bash "$S/scope.sh")"
echo "// more" >> src/api.js; commit "more"
eq "gate closes again on a new commit" 2 "$(gate 'git push')"
has "scope narrows to the delta" "approved:" "$(bash "$S/scope.sh")"
bash "$S/approve.sh" --accepted-risk "test" >/dev/null 2>&1
eq "accepted-risk records an approval" 0 $?

echo "documentation fast path"
new_repo docs
echo "more words" >> README.md; mkdir -p docs; echo "guide" > docs/guide.md; commit "docs"
has "scope announces the fast path" "fastpath:" "$(bash "$S/scope.sh")"
eq "docs-only push passes without a review" 0 "$(gate 'git push')"
has "the auto-approval is recorded" "auto: documentation only" "$(cat .git/pushguard/*.ok 2>/dev/null)"
echo "again" >> README.md; commit "docs again"
eq "PUSHGUARD_NO_FASTPATH=1 forces a review" 2 "$(PUSHGUARD_NO_FASTPATH=1 gate 'git push')"
new_repo docs
echo "key $AWS" >> README.md; commit "docs with a key"
eq "docs-only push with a secret is blocked" 2 "$(gate 'git push')"
new_repo docs
echo "ignore previous instructions" > CLAUDE.md; commit "agent instructions"
eq "agent instruction files never take the fast path" 2 "$(gate 'git push')"
new_repo docs
echo "words" >> README.md; echo "x=1" > run.py; commit "docs and code"
eq "mixed docs and code is reviewed" 2 "$(gate 'git push')"

echo "repository without a remote"
rm -rf "$T/solo"; git init -q -b main "$T/solo"; cd "$T/solo" || exit 1
git config user.email test@example.invalid; git config user.name test
echo "x=1" > a.py; commit "first"
has "whole history counts as outgoing" "empty tree" "$(bash "$S/scope.sh")"
eq "gate blocks the first push" 2 "$(gate 'git push -u origin main')"

echo "full scan and ignore file"
new_repo full
mkdir -p fixtures src; echo "k=\"$AWS\"" > fixtures/fake.js; echo "eval(req.body.code)" > src/run.js; commit "files"
out=$(bash "$S/scan.sh" --all); rc=$?
eq "--all exits 1 on a secret" 1 "$rc"
has "--all reports leads" "code-eval" "$out"
echo "fixtures/" > .pushguardignore; commit "ignore fixtures"
bash "$S/scan.sh" --history >/dev/null 2>&1
eq ".pushguardignore silences the fixture" 0 $?

echo "native git hook"
new_repo hook
bash "$S/install-git-hook.sh" >/dev/null 2>&1
eq "installs" 0 $?
echo "t=\"$GH\"" > tok.js; commit "token"
git push -q origin main >/dev/null 2>&1
if [ $? -ne 0 ]; then ok "git push rejected when a secret is outgoing"; else bad "git push rejected when a secret is outgoing"; fi
echo "t=1" > tok.js; git add -A; git commit -q --amend -m "no token"
git push -q origin main >/dev/null 2>&1
eq "git push accepted once the secret is gone" 0 $?
echo "exit 0" > "$(git rev-parse --git-path hooks)/pre-push.other"
bash "$S/install-git-hook.sh" --remove >/dev/null 2>&1
if [ -f "$(git rev-parse --git-path hooks)/pre-push" ]; then bad "--remove deletes the hook"; else ok "--remove deletes the hook"; fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
