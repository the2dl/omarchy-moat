#!/usr/bin/env bash
# dev-run.sh — end-to-end demo of sentineld as an unprivileged user.
#
# No root, no /etc, no /run, no Tetragon: every path is overridden on the
# command line, and the "Tetragon export" is testdata/sample.log copied into a
# scratch directory. It renders policies, starts the daemon, and walks through
# status / list / explain / ignore / allowlist before shutting down.
#
#   ./dev-run.sh              build, run, keep the scratch dir on failure
#   SKIP_BUILD=1 ./dev-run.sh use the binaries already in target/debug
#   DEV_DIR=/tmp/x ./dev-run.sh
#
# `cargo test --test dev_run` runs this script as an integration test.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

SENTINELD_BIN="${SENTINELD_BIN:-$HERE/target/debug/sentineld}"
SENTINELCTL_BIN="${SENTINELCTL_BIN:-$HERE/target/debug/sentinelctl}"

if [[ -z "${SKIP_BUILD:-}" ]]; then
  echo "==> cargo build"
  cargo build --quiet
fi

DEV_DIR="${DEV_DIR:-$(mktemp -d -t sentineld-dev-XXXXXX)}"
mkdir -p "$DEV_DIR"/{policies,state,run,allowlist.d}
SOCK="$DEV_DIR/run/control.sock"
LOG="$DEV_DIR/tetragon.log"
DAEMON_PID=""

cleanup() {
  local rc=$?
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [[ $rc -eq 0 && -z "${KEEP_DEV_DIR:-}" ]]; then
    rm -rf "$DEV_DIR"
  else
    echo "scratch dir kept at $DEV_DIR" >&2
  fi
  exit $rc
}
trap cleanup EXIT INT TERM

ctl() { "$SENTINELCTL_BIN" --socket "$SOCK" "$@"; }
hr() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
hr "render-policies (expand {{HOME}} for one fake user)"
"$SENTINELD_BIN" render-policies \
  --templates-dir "$HERE/testdata/templates" \
  --out-dir "$DEV_DIR/policies" \
  --export-allowlist "$DEV_DIR/export-allowlist" \
  --home /home/dan
echo "--- generated export-allowlist ---"
cat "$DEV_DIR/export-allowlist"

# ---------------------------------------------------------------------------
hr "start sentineld against a sample export"
cp "$HERE/testdata/sample.log" "$LOG"
"$SENTINELD_BIN" run \
  --log "$LOG" \
  --state-dir "$DEV_DIR/state" \
  --socket "$SOCK" \
  --policies-dir "$DEV_DIR/policies" \
  --allowlist-dir "$DEV_DIR/allowlist.d" \
  --sandbox-flag "$DEV_DIR/sandbox.enabled" \
  --passwd "$HERE/testdata/passwd" \
  --tetra /bin/false \
  --group "$(id -gn)" \
  --from-start &
DAEMON_PID=$!

for _ in $(seq 1 100); do
  [[ -S "$SOCK" ]] && break
  sleep 0.05
done
[[ -S "$SOCK" ]] || { echo "socket never appeared" >&2; exit 1; }
sleep 0.4   # let the tailer drain the sample log

# ---------------------------------------------------------------------------
hr "sentinelctl status"
ctl status

hr "sentinelctl list"
ctl list --limit 10

ALERT_ID="$(ctl --json list --limit 50 | grep -o '"id": "[0-9A-Z]*"' | head -1 | cut -d'"' -f4)"
[[ -n "$ALERT_ID" ]] || { echo "no alerts were produced" >&2; exit 1; }

hr "sentinelctl explain $ALERT_ID"
ctl explain "$ALERT_ID"

hr "sentinelctl ignore $ALERT_ID --scope exe"
ctl ignore "$ALERT_ID" --scope exe --comment "dev-run demo"

hr "sentinelctl allowlist"
ctl allowlist

hr "appending a live event to the log (tailer follows it)"
tail -n 1 "$HERE/testdata/sample.log" >> "$LOG"
sleep 0.5
ctl status | sed -n '/^unacked/p;/^socket/p'

hr "shutting down"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

echo
echo "state.json:"
cat "$DEV_DIR/state/state.json"
echo
echo "alerts.jsonl has $(wc -l < "$DEV_DIR/state/alerts.jsonl") line(s)"
echo "user.toml:"
cat "$DEV_DIR/allowlist.d/user.toml"
echo
echo "OK — dev run complete"
