#!/usr/bin/env bash
# pushguard scope: describe exactly what the next push would publish, and which
# review areas the changed files point to.
#
#   scope.sh              outgoing commits of HEAD
#   scope.sh --from <rev> explicit base

set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

FROM=""
while [ $# -gt 0 ]; do
  case $1 in
    --from) FROM=${2:-}; shift ;;
    -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "pushguard scope: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

pg_require_repo || exit 2
cd "$(git rev-parse --show-toplevel)" || exit 2
if ! git rev-parse -q --verify HEAD >/dev/null 2>&1; then
  echo "status: no commits yet, nothing can be pushed"
  exit 0
fi

if [ -n "$FROM" ]; then
  PG_BASE=$(git rev-parse "$FROM") || exit 2
  PG_LOG_ARGS=("$FROM..HEAD"); PG_UPSTREAM=""
else
  pg_range HEAD
fi

HEAD_SHA=$(git rev-parse HEAD)
COMMITS=$(git rev-list --count "${PG_LOG_ARGS[@]}" 2>/dev/null || echo 0)
LAST=$(pg_last_approved)
EMPTY=$(pg_empty_tree)

echo "repo:      $(pwd)"
echo "branch:    $(git rev-parse --abbrev-ref HEAD)"
echo "head:      $HEAD_SHA"
echo "upstream:  ${PG_UPSTREAM:-none}"
if [ "$PG_BASE" = "$EMPTY" ]; then
  echo "base:      (empty tree: nothing is published yet, the push exposes the entire history)"
else
  echo "base:      $PG_BASE"
fi
echo "commits:   $COMMITS outgoing"

DIRTY=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
[ "$DIRTY" -gt 0 ] && echo "note:      $DIRTY uncommitted change(s) in the working tree are NOT part of the push"

if [ "$COMMITS" = 0 ]; then
  echo "status:    nothing to push"
  exit 0
fi

REVIEW_FROM=$PG_BASE
if [ "$LAST" = "$HEAD_SHA" ]; then
  echo "status:    HEAD already passed a pushguard review, the push gate is open"
elif [ -n "$LAST" ] && [ "$(git rev-list --count "$LAST..HEAD")" -lt "$COMMITS" ]; then
  REVIEW_FROM=$LAST
  echo "approved:  $LAST (earlier commits already reviewed: review only what came after)"
fi
echo "review:    git diff $REVIEW_FROM HEAD"
pg_docs_only && echo "fastpath:  only documentation and images changed: no code review needed, the secret scan is enough"

echo
echo "--- outgoing commits"
git log --format='%h %an: %s' "${PG_LOG_ARGS[@]}" | head -n 60

echo
echo "--- changed files since review base (added, removed, path)"
git diff --numstat "$REVIEW_FROM" HEAD | awk '{ printf "%6s %6s  %s\n", $1, $2, $3 }' | head -n 300
git diff --shortstat "$REVIEW_FROM" HEAD

LIST=$(mktemp 2>/dev/null || mktemp -t pushguard)
trap 'rm -f "$LIST"' EXIT
git diff --name-only "$REVIEW_FROM" HEAD > "$LIST"

signal() { # <label> <reference> <regex>
  local hits
  hits=$(grep -E -i "$3" "$LIST" | head -n 8 | tr '\n' ' ')
  [ -n "$hits" ] && printf '%-22s -> references/%s.md\n    %s\n' "$1" "$2" "$hits"
}

echo
echo "--- signals (which references to load)"
signal "auth / session"        auth-access        '(auth|login|logout|signin|signup|session|token|jwt|oauth|password|passwd|permission|role|rbac|acl|guard|middleware|policy|policies)'
signal "database / RLS"        auth-access        '(migration|schema|\.sql$|prisma|drizzle|supabase|firestore\.rules|database\.rules|models?/)'
signal "API routes / handlers" api-data           '((^|/)(api|routes?|controllers?|handlers?|endpoints?|views|actions|resolvers?|functions|rpc|trpc|webhooks?)(/|\.)|route\.(ts|js)$|server\.(ts|js)$)'
signal "UI / templates"        web-client         '\.(tsx|jsx|vue|svelte|html?|ejs|hbs|pug|erb|twig|blade\.php|astro|mdx)$'
signal "HTTP config / headers" web-client         '(next\.config|vercel\.json|netlify\.toml|nginx|caddy|helmet|cors|csp|headers|vite\.config|nuxt\.config|settings\.py|application\.(ya?ml|properties))'
signal "dependencies"          supply-chain-infra '((^|/)(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(\.lock)?|go\.(mod|sum)|Cargo\.(toml|lock)|Gemfile(\.lock)?|composer\.(json|lock)|pom\.xml|build\.gradle(\.kts)?|\.npmrc)$)'
signal "CI / CD"               supply-chain-infra '(\.github/(workflows|actions)/|\.gitlab-ci|\.circleci/|Jenkinsfile|azure-pipelines|bitbucket-pipelines)'
signal "containers / IaC"      supply-chain-infra '(Dockerfile|docker-compose|compose\.ya?ml|\.tf$|\.tfvars$|k8s|kubernetes|helm|charts?/|serverless\.ya?ml|\.bicep$|cloudformation|pulumi)'
signal "env / secrets files"   secrets-crypto     '(\.env|secret|credential|\.pem$|\.key$|keystore)'
signal "crypto"                secrets-crypto     '(crypt|hash|cipher|hmac|signature|signing|random|(^|[/_.-])t?otp([/_.-]|$))'
signal "AI / LLM"              ai-llm             '(openai|anthropic|llm|prompt|agent|mcp|langchain|embedding|chat|completion|\.claude/)'
signal "uploads / files"       api-data           '(upload|storage|attachment|download|(^|/)(files|media|imports?|exports?)/)'
echo "(always load references/frameworks.md for the stack in use)"
