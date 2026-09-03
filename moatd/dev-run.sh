#!/usr/bin/env bash
# dev-run.sh — end-to-end demo of moatd as an unprivileged user.
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

MOATD_BIN="${MOATD_BIN:-$HERE/target/debug/moatd}"
MOATCTL_BIN="${MOATCTL_BIN:-$HERE/target/debug/moatctl}"

if [[ -z "${SKIP_BUILD:-}" ]]; then
  echo "==> cargo build"
  cargo build --quiet
fi

DEV_DIR="${DEV_DIR:-$(mktemp -d -t moatd-dev-XXXXXX)}"
mkdir -p "$DEV_DIR"/{policies,state,run,allowlist.d,incidents}
SOCK="$DEV_DIR/run/control.sock"
LOG="$DEV_DIR/tetragon.log"
DAEMON_PID=""
VICTIM_PID=""

cleanup() {
  local rc=$?
  if [[ -n "$VICTIM_PID" ]] && kill -0 "$VICTIM_PID" 2>/dev/null; then
    kill -TERM "$VICTIM_PID" 2>/dev/null || true
    wait "$VICTIM_PID" 2>/dev/null || true
  fi
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

ctl() { "$MOATCTL_BIN" --socket "$SOCK" "$@"; }
hr() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
hr "render-policies (expand {{HOME}} for one fake user)"
"$MOATD_BIN" render-policies \
  --templates-dir "$HERE/testdata/templates" \
  --out-dir "$DEV_DIR/policies" \
  --export-allowlist "$DEV_DIR/export-allowlist" \
  --home /home/dan
echo "--- generated export-allowlist ---"
cat "$DEV_DIR/export-allowlist"

# ---------------------------------------------------------------------------
hr "start moatd against a sample export"
cp "$HERE/testdata/sample.log" "$LOG"
"$MOATD_BIN" run \
  --log "$LOG" \
  --state-dir "$DEV_DIR/state" \
  --socket "$SOCK" \
  --policies-dir "$DEV_DIR/policies" \
  --allowlist-dir "$DEV_DIR/allowlist.d" \
  --incidents-dir "$DEV_DIR/incidents" \
  --sandbox-flag "$DEV_DIR/sandbox.enabled" \
  --passwd "$HERE/testdata/passwd" \
  --pacman-local "$HERE/testdata/pacman-local" \
  --pacman "$HERE/testdata/fake-pacman" \
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
hr "moatctl status"
ctl status

hr "moatctl list"
ctl list --limit 10

ALERT_ID="$(ctl --json list --limit 50 | grep -o '"id": "[0-9A-Z]*"' | head -1 | cut -d'"' -f4)"
[[ -n "$ALERT_ID" ]] || { echo "no alerts were produced" >&2; exit 1; }

hr "moatctl explain $ALERT_ID"
ctl explain "$ALERT_ID"

hr "moatctl ignore $ALERT_ID --scope exe"
ctl ignore "$ALERT_ID" --scope exe --comment "dev-run demo"

hr "moatctl allowlist"
ctl allowlist

hr "moatctl baseline list (learning window, proposals, demotions)"
ctl baseline list

hr "moatctl baseline export (LEARNING §8 step 1)"
ctl baseline export

hr "appending a live event to the log (tailer follows it)"
tail -n 1 "$HERE/testdata/sample.log" >> "$LOG"
sleep 0.5
ctl status | sed -n '/^unacked/p;/^socket/p'

# ---------------------------------------------------------------------------
# LEARNING §3 and §4: an install receipt, and an incident snapshot taken
# against a REAL process — /proc is the only witness that matters here, so the
# script starts one and hands the daemon its true pid, exe and start time.
hr "an install with a live child: receipt (§3) + incident snapshot (§4)"
SLEEP_BIN="$(command -v sleep)"
"$SLEEP_BIN" 300 &
VICTIM_PID=$!
VICTIM_START="$(date -u -d "@$(date +%s)" +%Y-%m-%dT%H:%M:%S.000000000Z)"
NOW_TS="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
UID_NUM="$(id -u)"

# npm install -> sleep(as the postinstall script), which reads an SSH key.
cat >> "$LOG" <<JSON
{"process_exec":{"process":{"exec_id":"dev-npm","pid":$$,"uid":$UID_NUM,"cwd":"$DEV_DIR","binary":"/usr/bin/npm","arguments":"install","start_time":"$VICTIM_START"}}}
{"process_exec":{"process":{"exec_id":"dev-child","pid":$VICTIM_PID,"uid":$UID_NUM,"cwd":"$DEV_DIR","binary":"$SLEEP_BIN","arguments":"$DEV_DIR/node_modules/evil/setup.mjs","start_time":"$VICTIM_START","parent_exec_id":"dev-npm"}}}
{"process_kprobe":{"process":{"exec_id":"dev-child","pid":$VICTIM_PID,"uid":$UID_NUM,"cwd":"$DEV_DIR","binary":"$SLEEP_BIN","parent_exec_id":"dev-npm"},"function_name":"security_file_permission","policy_name":"moat-cred-ssh-private-key-read","args":[{"file_arg":{"path":"/home/dan/.ssh/id_ed25519"}},{"int_arg":4}]},"time":"$NOW_TS"}
{"process_exit":{"process":{"exec_id":"dev-npm","pid":$$,"binary":"/usr/bin/npm","arguments":"install"},"status":0}}
JSON
sleep 0.6

hr "moatctl receipts (LEARNING §3)"
ctl receipts --last 5

hr "moatctl incidents (LEARNING §4)"
ctl incidents --last 5

# The newest one is the alert from the live child above, so the snapshot below
# is of a process that really exists.
INCIDENT_ID="$(ctl --json incidents --last 5 | grep -o '"id": "[0-9A-Z]*"' | tail -1 | cut -d'"' -f4)"
[[ -n "$INCIDENT_ID" ]] || { echo "no incident was captured" >&2; exit 1; }
echo
echo "snapshot files for $INCIDENT_ID:"
ls -l "$DEV_DIR/incidents/$INCIDENT_ID" "$DEV_DIR/incidents/$INCIDENT_ID/file" 2>/dev/null || true
echo "process.json (first 20 lines, environ values masked):"
head -20 "$DEV_DIR/incidents/$INCIDENT_ID/process.json"
grep -c '<masked' "$DEV_DIR/incidents/$INCIDENT_ID/process.json" >/dev/null 2>&1 \
  && echo "  (secret-looking environment values are masked)"
echo "net.txt:"
head -5 "$DEV_DIR/incidents/$INCIDENT_ID/net.txt"

hr "moatctl bundle $INCIDENT_ID (LEARNING §2)"
BUNDLE="$(ctl bundle "$INCIDENT_ID")"
echo "$BUNDLE"
grep -q '```DATA' "$BUNDLE" || { echo "the bundle does not fence process strings" >&2; exit 1; }
grep -q '## Incident snapshot' "$BUNDLE" || { echo "the bundle does not link the snapshot" >&2; exit 1; }
echo "--- bundle.md, first 30 lines ---"
head -30 "$BUNDLE"

hr "moatctl analyze --dry-run (the daemon bundles; moatctl would launch the agent)"
MOAT_DEFAULT_AGENT=claude ctl analyze "$INCIDENT_ID" --dry-run

hr "moatctl digest (LEARNING §5)"
ctl digest
ctl set digest off >/dev/null && ctl digest | tail -1
ctl set digest on >/dev/null

hr "shutting down"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

echo
echo "state.json:"
cat "$DEV_DIR/state/state.json"
echo
echo "alerts.jsonl has $(wc -l < "$DEV_DIR/state/alerts.jsonl") line(s)"
echo "rarity.json has $(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))['counters']))" "$DEV_DIR/state/rarity.json" 2>/dev/null || echo 0) counter(s)"
echo "receipts: $(grep -c '"receipt"' "$DEV_DIR/state/alerts.jsonl" || true)"
echo "incident snapshots: $(ls "$DEV_DIR/incidents" | wc -l)"
echo "user.toml:"
cat "$DEV_DIR/allowlist.d/user.toml"
echo
echo "OK — dev run complete"
