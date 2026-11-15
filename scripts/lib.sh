#!/usr/bin/env bash
# pushguard shared helpers. Sourced by the other scripts; requires only git + POSIX tools.

TAB=$'\t'

pg_require_repo() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "pushguard: not inside a git repository" >&2
    return 1
  }
}

# Directory holding review markers. Lives inside .git, so it is never committed or pushed.
pg_state_dir() {
  local d
  d=$(git rev-parse --git-common-dir 2>/dev/null) || return 1
  d=$(cd "$d" 2>/dev/null && pwd) || return 1
  printf '%s/pushguard\n' "$d"
}

pg_empty_tree() {
  git hash-object -t tree /dev/null 2>/dev/null || echo 4b825dc642cb6eb9a060e54bf8d69288fbee4904
}

# pg_range [tip]
# Works out what a push of <tip> would newly publish. Sets:
#   PG_BASE      commit (or empty tree) to diff against for the net change
#   PG_LOG_ARGS  rev-list/log arguments selecting every outgoing commit
#   PG_UPSTREAM  upstream name, or ""
pg_range() {
  local tip=${1:-HEAD} up oldest
  PG_UPSTREAM=""; PG_LOG_ARGS=(); PG_BASE=""

  if [ "$tip" = HEAD ] && up=$(git rev-parse -q --verify '@{upstream}^{commit}' 2>/dev/null); then
    PG_BASE=$(git merge-base "$tip" "$up" 2>/dev/null) || PG_BASE=""
    if [ -n "$PG_BASE" ]; then
      PG_UPSTREAM=$(git rev-parse --abbrev-ref '@{upstream}' 2>/dev/null)
      PG_LOG_ARGS=("$up..$tip")
      return 0
    fi
  fi

  if [ -n "$(git for-each-ref --count=1 refs/remotes 2>/dev/null)" ]; then
    # No upstream: everything reachable from tip that no remote-tracking ref has yet.
    PG_LOG_ARGS=("$tip" --not --remotes)
    oldest=$(git rev-list "$tip" --not --remotes 2>/dev/null | tail -n 1)
    if [ -z "$oldest" ]; then
      PG_BASE=$(git rev-parse "$tip")
      return 0
    fi
    PG_BASE=$(git rev-parse -q --verify "$oldest^" 2>/dev/null) || PG_BASE=$(pg_empty_tree)
    return 0
  fi

  # No remote at all: the first push publishes the whole history.
  PG_LOG_ARGS=("$tip")
  PG_BASE=$(pg_empty_tree)
}

# Nearest ancestor of HEAD (or HEAD itself) that already passed a review. Prints sha or nothing.
pg_last_approved() {
  local d f sha head n best="" bestn=999999999
  d=$(pg_state_dir) || return 0
  [ -d "$d" ] || return 0
  head=$(git rev-parse HEAD 2>/dev/null) || return 0
  for f in "$d"/*.ok; do
    [ -e "$f" ] || continue
    sha=${f##*/}; sha=${sha%.ok}
    if [ "$sha" = "$head" ]; then echo "$sha"; return 0; fi
    git cat-file -e "$sha^{commit}" 2>/dev/null || continue
    git merge-base --is-ancestor "$sha" "$head" 2>/dev/null || continue
    n=$(git rev-list --count "$sha..$head" 2>/dev/null) || continue
    if [ "$n" -lt "$bestn" ]; then best=$sha; bestn=$n; fi
  done
  [ -n "$best" ] && echo "$best"
  return 0
}

# True when every file touched by the outgoing commits (PG_LOG_ARGS, set by pg_range) is prose
# or an image. Such a push needs the secret scan but not a code review.
# Agent instruction files are excluded on purpose: a CLAUDE.md or a skill is executable intent.
pg_docs_only() {
  local files
  files=$(git log --name-only --format= "${PG_LOG_ARGS[@]}" 2>/dev/null | sort -u | grep -v '^$')
  [ -n "$files" ] || return 1
  if printf '%s\n' "$files" | grep -E -i -v '\.(md|markdown|txt|rst|adoc|png|jpe?g|gif|webp|avif|ico|bmp)$|(^|/)(LICENSE|LICENCE|NOTICE|AUTHORS|CONTRIBUTORS|CHANGELOG)$' | grep -q .; then
    return 1
  fi
  if printf '%s\n' "$files" | grep -E -i '(^|/)(CLAUDE|AGENTS|GEMINI|SKILL|copilot-instructions)\.md$|(^|/)\.(claude|cursor|github|codex|windsurf)/|(^|/)(skills|agents|commands|rules|prompts)/' | grep -q .; then
    return 1
  fi
  return 0
}

# Pathspec excludes: generated files that only produce noise, plus the project's .pushguardignore.
pg_excludes() {
  PG_EXCL=(
    ':(exclude,glob)**/package-lock.json' ':(exclude,glob)**/yarn.lock'
    ':(exclude,glob)**/pnpm-lock.yaml'    ':(exclude,glob)**/bun.lock'
    ':(exclude,glob)**/Cargo.lock'        ':(exclude,glob)**/go.sum'
    ':(exclude,glob)**/poetry.lock'       ':(exclude,glob)**/uv.lock'
    ':(exclude,glob)**/composer.lock'     ':(exclude,glob)**/Gemfile.lock'
    ':(exclude,glob)**/*.min.js'          ':(exclude,glob)**/*.min.css'
    ':(exclude,glob)**/*.map'             ':(exclude,glob)**/*.svg'
  )
  local line dir
  [ -f .pushguardignore ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case $line in ''|'#'*) continue ;; esac
    dir=0
    case $line in */) dir=1; line=${line%/} ;; esac
    line=${line#/}
    case $line in */*) ;; *) line="**/$line" ;; esac
    [ "$dir" = 1 ] && line="$line/**"
    PG_EXCL+=(":(exclude,glob)$line")
  done < .pushguardignore
}
