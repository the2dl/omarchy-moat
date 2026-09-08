#!/usr/bin/env bash
# A day of ordinary developer work, on purpose, so moat's false positives are
# found here instead of in somebody's build.
#
#   tests/noise/dev-day.sh              one pass
#   tests/noise/dev-day.sh --loop 8h    passes until the deadline
#   tests/noise/dev-day.sh --report     what moat said, grouped, and nothing else
#
# Every false positive fixed on 2026-09-07 was found by a person being
# interrupted: a lake pipeline SIGKILLed mid-build, gcloud contained mid-command,
# pg_isready refused, `pnpm install` reported as persistence, cargo's crate cache
# reported as a git hook. Each one was ordinary work that no test performed,
# because moat's own suite exercises moat and nothing else. This performs the
# work.
#
# ## What it will and will not touch
#
# Everything happens under ONE directory, $LAB, which the script creates and
# removes. Containers are named `moatnoise-<pid>-<n>` and only those names are
# ever stopped or removed -- `docker rm -f $(docker ps -aq)` does not appear
# here and must not: this runs on a machine with real containers on it.
#
# It never writes outside $LAB, never installs a package system-wide, never
# touches ~/.ssh, ~/.aws or any real credential store, and never runs moat's own
# test suite (which floods the live daemon with its own fixtures -- the reason
# `--nocheck` exists on every build this week).
set -uo pipefail

LAB="${MOAT_NOISE_LAB:-$HOME/Projects/moat-noise-lab}"
# Private caches, inside $LAB, so every pass really fetches, unpacks and builds.
# The first validation pass finished in THREE SECONDS on warm caches and
# exercised nothing: unpacking is where the persist rules misfire (a dependency
# that ships an AGENTS.md), and a warm cache never unpacks.
export npm_config_cache="$LAB/.cache/npm"
export CARGO_HOME="$LAB/.cache/cargo"
export PIP_CACHE_DIR="$LAB/.cache/pip"
TAG="moatnoise-$$"
DEADLINE=0
REPORT_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --loop) DEADLINE=$(( $(date +%s) + $(numfmt --from=iec "${2%[hm]}${2: -1}" 2>/dev/null || echo 28800) )); shift 2 ;;
    --report) REPORT_ONLY=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n=== %s\n' "$*"; }

# Run a step, time it, and SAY WHAT HAPPENED. The first two validation runs
# reported "1 pass in 3s" and a clean bill of health while doing nothing,
# because every command ended in `>/dev/null 2>&1`. A harness that hides its own
# failures is worse than no harness: it reports success.
STEP_LOG="${TMPDIR:-/tmp}/moat-noise-step.$$"
step() {
  local name=$1; shift
  local t0=$SECONDS rc=0
  "$@" >"$STEP_LOG" 2>&1 || rc=$?
  local dt=$(( SECONDS - t0 ))
  if (( rc == 0 )); then
    printf '    %-28s ok    %2ds\n' "$name" "$dt"
  else
    printf '    %-28s FAIL  %2ds  rc=%d: %s\n' "$name" "$dt" "$rc" "$(tail -1 "$STEP_LOG" | cut -c1-90)"
  fi
}
have() { command -v "$1" >/dev/null 2>&1; }

# A step that cannot run has to SAY so. Containers are the richest source of
# false positives on this machine -- runc's seccomp, a container's own
# /etc/shadow, dpkg installing its own ca-certificates -- and the first runs of
# this script skipped them in silence because `docker info` failed. An absent
# section reads exactly like a section that passed.
skip() { printf '    %-28s SKIP        %s\n' "$1" "$2"; }

# Anything this script started, removed on the way out however it exits.
cleanup() {
  local ids
  ids=$(docker ps -aq --filter "name=^${TAG}-" 2>/dev/null)
  [[ -n "$ids" ]] && docker rm -f $ids >/dev/null 2>&1
  rm -rf "$LAB"
}
trap cleanup EXIT INT TERM

# `since` is an RFC3339 stamp: only alerts raised after the run started are
# reported. Without it this printed the machine's whole backlog and took credit
# for it -- the first validation run showed 105 rows, nearly all of them the
# user's own work from earlier in the day.
report() {
  say "what moat said about THIS run"
  moatctl status 2>/dev/null | sed -n '6,7p'
  export MOAT_SINCE="${1:-}"
  moatctl feed --json 2>/dev/null | python3 -c '
import sys, json, collections, os
rows = json.load(sys.stdin)["alerts"]
since = os.environ.get("MOAT_SINCE", "")
if since:
    rows = [a for a in rows if a.get("ts", "") >= since]
need = [a for a in rows if a.get("surface") == "alerts" and not a.get("acked") and not a.get("suppressed_by")]
print("badge rows:", len(need))
for (rule, sev), n in collections.Counter((a.get("rule"), a.get("severity")) for a in need).most_common(15):
    exes = collections.Counter((a.get("process") or {}).get("exe", "?").split("/")[-1]
                               for a in need if a.get("rule") == rule)
    print("  %-42s %-8s %4d  %s" % (rule, sev, n, dict(exes.most_common(2))))
' 2>/dev/null
}

[[ $REPORT_ONLY == 1 ]] && { report ""; trap - EXIT; exit 0; }

pass() {
  rm -rf "$LAB"; mkdir -p "$LAB"

  # --- javascript: the ecosystem that produced the most noise this week -----
  if have npm; then
    say "npm install"
    local d="$LAB/js"; mkdir -p "$d"
    ( cd "$d"
      step "npm init"    npm init -y
      # Small, real, and some of them ship files whose NAMES the persist rules
      # watch -- which is the whole point.
      step "npm install" timeout 300 npm install --no-audit --no-fund chalk debug express
      step "node require" node -e "require('chalk')" )
  fi

  # --- rust: build scripts, /tmp execs, the crate cache ---------------------
  if have cargo; then
    say "cargo build"
    local d="$LAB/rs"
    cargo new --quiet "$d" >/dev/null 2>&1
    ( cd "$d"
      step "cargo build" timeout 420 cargo build --quiet
      step "cargo test"  timeout 300 cargo test --quiet )
  fi

  # --- c: the plainest possible compile-and-run ----------------------------
  if have gcc && have make; then
    say "make"
    local d="$LAB/c"; mkdir -p "$d"
    printf '#include <stdio.h>\nint main(void){puts("hi");return 0;}\n' > "$d/main.c"
    printf 'all:\n\tgcc -O2 -o app main.c\n' > "$d/Makefile"
    ( cd "$d"; step "make" make; step "run app" ./app )
  fi

  # --- python: a venv and a wheel install ----------------------------------
  if have python3; then
    say "python venv + pip"
    local d="$LAB/py"; mkdir -p "$d"
    ( cd "$d"
      step "venv"       timeout 180 python3 -m venv .venv
      step "pip install" timeout 300 ./.venv/bin/pip install --quiet --disable-pip-version-check requests
      step "python import" ./.venv/bin/python -c "import requests" )
  fi

  # --- git: clone, hook, commit --------------------------------------------
  if have git; then
    say "git"
    local d="$LAB/git"; mkdir -p "$d"
    ( cd "$d"
      git init --quiet .
      git -c user.email=noise@lab -c user.name=noise commit --allow-empty -qm one
      # A repo that ships a hook is ordinary and reads like persistence.
      printf '#!/bin/sh\nexit 0\n' > .git/hooks/pre-commit; chmod +x .git/hooks/pre-commit
      git -c user.email=noise@lab -c user.name=noise commit --allow-empty -qm two )
  fi

  # --- containers: pull, run, stop. ONLY ours ------------------------------
  say "containers"
  if ! have docker; then
    skip "docker" "not installed"
  elif ! docker info >/dev/null 2>&1; then
    skip "docker" "$(docker info 2>&1 | tail -1 | cut -c1-70)"
  else
    local n="${TAG}-$RANDOM"
    step "docker run" timeout 300 docker run --rm --name "$n" alpine:latest \
      sh -c 'apk add --no-cache ca-certificates >/dev/null 2>&1; echo ok'
    docker rm -f "$n" >/dev/null 2>&1
  fi

  # --- a data pipeline: write, read back, delete. the lake_sidecar shape ---
  say "a pipeline cleaning up after itself"
  local d="$LAB/pipeline"; mkdir -p "$d/scratch"
  python3 - "$d/scratch" <<'PY' >/dev/null 2>&1
import os, sys, pathlib
scratch = pathlib.Path(sys.argv[1])
for i in range(40):
    p = scratch / f"bucket-{i:03}.bin"
    p.write_bytes(os.urandom(4096))   # write first: it is OUR file
    p.read_bytes()
    p.unlink()
# and the atomic-replace idiom, both spellings
for i in range(20):
    real = scratch / f"health-{i:02}.json"
    real.write_text("{}")
    tmp = scratch / f".tmp{i:06}"
    tmp.write_text("{}")
    tmp.replace(real)
PY
}

started=$(date +%s)
since=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
n=0
while :; do
  n=$((n + 1))
  say "pass $n"
  pass
  (( DEADLINE == 0 )) && break
  (( $(date +%s) >= DEADLINE )) && break
  sleep 60
done

printf '\n%d pass(es) in %ds\n' "$n" "$(( $(date +%s) - started ))"
report "$since"
