#!/usr/bin/env bash
# Every omarchy-sentinel suite, in dependency order, from the repo root.
#
#   tests/run-all.sh            run everything, stop reporting at the end
#   tests/run-all.sh -x         stop at the first failing suite
#
# Exits non-zero if any suite fails. Nothing here needs root, a running
# Tetragon, or an installed package: each component's suite fakes its own
# environment (see docs/INTEGRATION.md).
#
# Order matters only in that the cheap static gates run before the ones that
# build or spawn a daemon, so a typo is reported in seconds rather than minutes.
set -uo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/.." && pwd)
cd "$root"

fail_fast=0
[[ ${1:-} == "-x" ]] && fail_fast=1

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  BOLD=""; GREEN=""; RED=""; DIM=""; RESET=""
fi

declare -a NAMES=() RESULTS=() SECONDS_TAKEN=()
status=0

# suite NAME COMMAND...
suite() {
  local name=$1; shift
  printf '\n%s========== %s ==========%s\n' "$BOLD" "$name" "$RESET"
  local start=$SECONDS rc=0
  "$@" || rc=$?
  local took=$((SECONDS - start))
  NAMES+=("$name")
  SECONDS_TAKEN+=("$took")
  if ((rc == 0)); then
    RESULTS+=("PASS")
    printf '%s-> PASS%s (%ss)\n' "$GREEN" "$RESET" "$took"
  else
    RESULTS+=("FAIL(rc=$rc)")
    status=1
    printf '%s-> FAIL rc=%s%s (%ss)\n' "$RED" "$rc" "$RESET" "$took"
    ((fail_fast)) && summary_and_exit
  fi
  return 0
}

summary_and_exit() {
  printf '\n%s========== summary ==========%s\n' "$BOLD" "$RESET"
  local i
  for i in "${!NAMES[@]}"; do
    local mark=$GREEN result=${RESULTS[$i]}
    [[ $result == PASS ]] || mark=$RED
    printf '  %s%-8s%s  %-28s %s%ss%s\n' \
      "$mark" "$result" "$RESET" "${NAMES[$i]}" "$DIM" "${SECONDS_TAKEN[$i]}" "$RESET"
  done
  if ((status == 0)); then
    printf '\n%sall %d suites passed%s\n' "$GREEN" "${#NAMES[@]}" "$RESET"
  else
    printf '\n%sone or more suites failed%s\n' "$RED" "$RESET"
  fi
  exit $status
}

# Static gates first: they cost seconds and catch most breakage.
suite policies bash -c 'python3 policies/check.py'
suite scanner  bash -c 'python3 -m unittest discover scanner/tests'
suite shell    bash shell/tests/run-tests.sh
suite manifest bash -c 'command -v omarchy-plugin-validate >/dev/null \
  && omarchy-plugin-validate . \
  || { echo "omarchy-plugin-validate not installed, skipped"; }'

# Then the ones that build or run things.
suite sandbox  bash sandbox/tests/run.sh
suite sentineld bash -c 'cd sentineld && cargo test --release'

summary_and_exit
