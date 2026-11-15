#!/usr/bin/env bash
# pushguard: install (or remove) the native git pre-push hook in the current repository.
#
#   install-git-hook.sh            install
#   install-git-hook.sh --remove   uninstall
#
# The scanner is copied into .git/pushguard/bin so the hook keeps working when the plugin
# is updated, moved or uninstalled. Nothing is added to the working tree.

set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

pg_require_repo || exit 2
STATE=$(pg_state_dir) || exit 2
HOOKS=$(git rev-parse --git-path hooks)
CUSTOM=$(git config --get core.hooksPath || true)
HOOK="$HOOKS/pre-push"
MARK="# pushguard-managed"

if [ "${1:-}" = --remove ]; then
  if [ -f "$HOOK" ] && grep -q "$MARK" "$HOOK"; then rm -f "$HOOK"; echo "pushguard: removed $HOOK"; fi
  rm -rf "$STATE/bin"
  exit 0
fi

mkdir -p "$STATE/bin/rules" "$HOOKS" || exit 2
cp "$HERE/lib.sh" "$HERE/scan.sh" "$HERE/git-pre-push.sh" "$STATE/bin/" || exit 2
cp "$HERE/rules/secrets.rules" "$HERE/rules/leads.rules" "$STATE/bin/rules/" || exit 2

if [ -f "$HOOK" ] && ! grep -q "$MARK" "$HOOK"; then
  echo "pushguard: a pre-push hook already exists and was left untouched: $HOOK"
  echo "Add this line to it to chain pushguard (it reads the same stdin, so place it first or tee stdin):"
  echo "  bash \"$STATE/bin/git-pre-push.sh\" \"\$@\" || exit 1"
  exit 3
fi

cat > "$HOOK" <<EOF
#!/usr/bin/env bash
$MARK
exec bash "$STATE/bin/git-pre-push.sh" "\$@"
EOF
chmod +x "$HOOK" 2>/dev/null || true

echo "pushguard: git pre-push hook installed at $HOOK"
[ -n "$CUSTOM" ] && echo "note: core.hooksPath is set to '$CUSTOM' (husky or similar). The hook was written there; commit it if that directory is versioned."
exit 0
