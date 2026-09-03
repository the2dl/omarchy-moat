# Integration review

Five components were built in parallel against `docs/CONTRACT.md`. This file
records what happened when they were first run against each other: what passed,
what did not line up, what was changed, and what is still open.

Everything below was produced on this machine, unprivileged, with no Tetragon
running and nothing installed into `/usr` or `/etc`.

---

## 1. Suite results

Run everything with `tests/run-all.sh` (add `-x` to stop at the first failure).

| Suite | Command | Result |
|---|---|---|
| policies | `python3 policies/check.py` | **PASS** — 32 policies parse, render and match the verified v1.7.1 grammar (7 critical / 18 high / 6 medium / 1 low; 8 enforcing, 24 monitor-only) |
| scanner | `python3 -m unittest discover scanner/tests` | **PASS** — 39 tests |
| shell | `bash shell/tests/run-tests.sh` | **PASS** — 7 QML files parse; `tst_model` 39 tests; `tst_wire` 19 tests (new, see §3) |
| manifest | `omarchy-plugin-validate .` | **PASS** — silent, exit 0 |
| sandbox | `bash sandbox/tests/run.sh` | **PASS** — 53 tests (was 52; one added, see §4a) |
| sentineld | `cd sentineld && cargo test --release` | **PASS** — 131 unit tests (was 128; three added) + 5 integration tests |

Counts before this review: shell 39, sandbox 52, sentineld 128+5. After: shell
58, sandbox 53, sentineld 131+5.

`tests/run-all.sh` skips `omarchy-plugin-validate` with a notice rather than
failing when it is not on `$PATH`, so the suite runs on a machine without
omarchy-shell installed. Every other suite is a hard gate.

---

## 2. End-to-end transcript

`sentineld/dev-run.sh` renders `testdata/templates` (5 policies) and replays
`testdata/sample.log`. The scenario below extends it: the **real** 32 templates
from `policies/`, a fake home, and a synthetic Tetragon export that fires a
cred policy, a persist policy, a pkg policy, a kill + exit pair, and a dedupe
repeat. Every path is overridden on the command line; no root, no `/etc`, no
`/run`, no Tetragon, and `--tetra` deliberately points at a file that does not
exist.

```
$ sentineld render-policies --templates-dir policies/ --out-dir $D/policies \
      --export-allowlist $D/export-allowlist --home /home/sentineltest
rendered 32 policies into $D/policies (32 changed, export-allowlist updated)
{{HOME}} left over: 0 files      fake home present in: 11 files

$ head -1 $D/export-allowlist
{"event_set":["PROCESS_EXEC","PROCESS_EXIT"]}
{"event_set":["PROCESS_KPROBE","PROCESS_LSM","PROCESS_TRACEPOINT","PROCESS_UPROBE"],
 "policy_names":["sentinel-ai-cli-in-pkg-subtree", ... 32 names ... ]}

$ sentineld run --log $D/tetragon.log --state-dir $D/state --socket $SOCK \
      --policies-dir $D/policies --allowlist-dir $D/allowlist.d \
      --sandbox-flag $D/etc/sandbox.enabled --passwd $D/passwd \
      --tetra $D/no-such-tetra --group $(id -gn) --from-start &

$ sentinelctl status
sentineld  0.1.0   mode monitor
tetragon   running
policies   32
feeds      0 hashes, 0 domains, updated never
unacked    critical 0  high 3  medium 0  low 0
sandbox    off
socket     group dan   uptime 1s   11 events, 4 alerts

$ sentinelctl list --json | jq -r '.alerts[] | "\(.id) \(.family) \(.action_taken)"'
01M1M5XHBZTEYJ03KHCF0R5P32 cred    killed      <- Sigkill policy + process_exit SIGKILL
01M1M5XHBZ9F1G0T6E2X95SXRQ persist none
01M1M5XHBZKWBC6GWNGQK6PVTZ pkg     none
01M1M5XHBZVPVKYJAZM2KSSJ60 cred    none        <- count 2 (deduped repeat)

$ sentinelctl explain 01M1M5XHBZTEYJ03KHCF0R5P32
Private SSH key read by an unexpected program
=============================================
sentinel-cred-ssh-private-key-read (high)   2026-09-03T17:43:56.543Z   alert 01M1M5XHBZ...

WHAT HAPPENED
  node read your private SSH key (id_ed25519).
  process: /usr/bin/node (pid 5233, uid 1000)
  args:    /home/sentineltest/proj/node_modules/evil/setup.mjs
  parents: fish (5100) -> npm (5201) -> sh (5230)
  file:    /home/sentineltest/.ssh/id_ed25519
  mode:    monitor   action taken: killed

WHY IT WAS FLAGGED
  Private keys are the first thing npm and PyPI stealers read; only ssh, git ...

EVIDENCE
  - hook: file_post_open on /home/sentineltest/.ssh/id_ed25519 (read)
  - process: /usr/bin/node pid 5233 uid 1000 args .../setup.mjs
  - ancestry: fish -> npm -> sh -> node (cwd /home/sentineltest/proj)
  - policy message: Private SSH key opened for reading
  - policy action: KPROBE_ACTION_SIGKILL (mode monitor; a kill is only recorded
    once process_exit reports SIGKILL)
  - not in allowlist: none of the 0 rule(s) in .../allowlist.d matches
    exe=/usr/bin/node file=/home/sentineltest/.ssh/id_ed25519

IF THIS IS EXPECTED
  ... (recommended scope: exe)
  * sentinelctl ignore 01M1M5XHBZ... --scope exe
      [[rule]]
      name = "sentinel-cred-ssh-private-key-read"
      exe = "/usr/bin/node"
    ... exe+file, parent, rule ...

WHAT TO DO
  1. If you did not expect this: stop it now with `sentinelctl kill <id>` ...
  2. Rotate the SSH key: `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519`, then ...
  3. Check what was installed: diff the lockfile ...
  4. If this was you, run one of the ignore commands above; otherwise ...
  secrets to rotate: ssh-key

$ sentinelctl ignore 01M1M5XHBZ... --scope exe --comment "dev demo"
wrote to .../allowlist.d/user.toml and acked the alert:
# added 2026-09-03 from alert 01M1M5XHBZ...: Private SSH key read by an unexpected program — dev demo
[[rule]]
name = "sentinel-cred-ssh-private-key-read"
exe = "/usr/bin/node"

$ sentinelctl allowlist
  1  sentinel-cred-ssh-private-key-read
     # added 2026-09-03 from alert 01M1M5XHBZ...: Private SSH key read ...
     exe = /usr/bin/node
     from .../allowlist.d/user.toml

# ROUND TRIP: replay the identical cred event
alerts.jsonl lines before=7 after=7
ROUNDTRIP OK: allowlist suppressed the replay

$ sentinelctl unignore 1
removed from .../allowlist.d/user.toml: [[rule]] name = "sentinel-cred-..."

$ sentinelctl set mode monitor          # tetra does not exist
mode is now monitor (0 of 32 policies updated via .../no-such-tetra)
could not set the mode on 32 policies:
  sentinel-ai-cli-in-pkg-subtree: No such file or directory (os error 2)
  ... 31 more ...
$ echo $?
0                                        <- see mismatch M5

$ sentinelctl set sandbox on --json
{"sandbox": true, "flag": ".../etc/sandbox.enabled",
 "note": "shims apply to new login sessions; log out and back in", "ok": true}
$ sentinelctl status --json | jq .sandbox
true
```

`alerts.jsonl` after the run — four alert lines and four update lines, nothing
rewritten in place:

```
{"v":1,"id":"01M1M5XHBZTEYJ...","severity":"high","rule":"sentinel-cred-ssh-private-key-read",...}
{"v":1,"id":"01M1M5XHBZTEYJ...","update":{"action_taken":"killed"}}
{"v":1,"id":"01M1M5XHBZ9F1G...","severity":"high","rule":"sentinel-persist-shell-rc-write",...}
{"v":1,"id":"01M1M5XHBZKWBC...","severity":"high","rule":"sentinel-pkg-subtree-downloader",...}
{"v":1,"id":"01M1M5XHBZVPVK...","severity":"high","rule":"sentinel-cred-ssh-private-key-read",...}
{"v":1,"id":"01M1M5XHBZVPVK...","update":{"count":2,"ts":"2026-09-03T17:43:56.543Z"}}
{"v":1,"id":"01M1M5XHBZTEYJ...","update":{"acked":true}}
```

These exact bytes are checked in as `shell/tests/fixtures/wire/*`, with only
two substitutions: the scratch directory became the installed paths from
CONTRACT §2, and the socket group became `sentinel`.

---

## 3. The wire harness

`shell/tests/tst_wire.qml` (new, 19 tests, wired into `shell/tests/run-tests.sh`)
runs `SentinelModel.js` over the fixtures above — real daemon output, not
hand-written examples of what it ought to look like. `tst_model.qml` checks the
model's own rules; `tst_wire.qml` checks the seam: that the field names,
nesting, severity strings, `explain` structure, `if_expected.options` shape,
status fields and update-line shape the daemon emits are the ones the panel
reads. Four of the seven mismatches below were found by writing it.

Regenerate the fixtures whenever the alert record or a socket response changes
shape; the header of `tst_wire.qml` says how they were made.

---

## 4. Mismatches found

### M1 — rotate vocabulary: three different dictionaries (fixed, both sides)

`policies/*.yaml` annotate 20 distinct `sentinel.omarchy/rotate` values.
The daemon's `rotate_advice()` knew **4** of them; the plugin's
`ROTATE_GUIDANCE` knew **6**. Every other kind fell through to a generic
"rotate this credential" line — the alert told the user a specific secret had
leaked and then declined to say what to do about it. The three vocabularies
had no common definition anywhere.

| kind | shipped by | daemon before | plugin before |
|---|---|---|---|
| `ssh-key`, `github-token`, `npm-token`, `keyring` | cred-* | ✓ | ✓ |
| `git-credentials`, `browser-cookies` | cred-vcs, cred-browser | ✗ | ✓ |
| `pypi-token`, `cargo-token`, `docker-token`, `aws-key`, `gcp-token`, `azure-token`, `kubeconfig`, `gpg-key`, `browser-passwords`, `session-cookies`, `local-password`, `anthropic-token`, `openai-token`, `google-token` | 14 more | ✗ | ✗ |

CONTRACT §3 fixes the annotation *key* but not its values, so `policies/` is
the authority. Fixed on both sides:

* `sentineld/src/explain.rs` — `rotate_advice()` covers all 20, with the old
  short names (`aws`, `gh`, `gpg`, `kube`, `docker`, `claude`, …) kept as
  aliases. New test `policies_rotate_vocabulary_is_covered` **reads the real
  `policies/` directory** and fails if a future policy introduces a kind the
  table does not know.
* `shell/SentinelModel.js` — `ROTATE_GUIDANCE` covers all 20, aliases kept.
  `tst_wire.qml::test_every_policy_rotate_kind_has_specific_guidance` asserts
  none of them resolves to the generic fallback.

### M2 — `allowlist` response: three renamed fields (fixed, plugin)

The daemon's `allowlist` response and the plugin's `parseAllowlist` disagreed on
three names, so the allowlist tab silently rendered less than it had:

| daemon emits | plugin read | effect |
|---|---|---|
| `rule.path` (the rule's `file =` glob) | `rule.file` | the `file =` matcher never appeared in the rule's detail line; worse, `rule.file` in the response is the *source fragment* the rule came from, so an `exe+file` rule would have shown `/etc/sentinel/allowlist.d/user.toml` as its match target |
| `rule.toml` (the rendered block) | `rule.line` | the exact `[[rule]]` block was never available to the view |
| `user_file` (the file `unignore` edits) | `file` | fell back to a hardcoded `/etc/sentinel/allowlist.d/user.toml`, right in production, wrong under any override |

CONTRACT §5 does not fix these names, so per the review brief the cheaper side
changed. `shell/SentinelModel.js` now accepts both spellings, and
`normalizeAllowlistRule` distinguishes the rule's `path` glob from the source
`file`. Two extras fell out of the same read:

* `index` is `null` for rules merged from another `allowlist.d` fragment
  (only `user.toml` entries can be removed). The plugin substituted the array
  position, so the panel showed a wrong `#n` and a **Remove** button that would
  have called `unignore` with someone else's index. `normalizeAllowlistRule`
  now exposes `removable`, and `shell/AllowlistView.qml` hides the number and
  the button for those rules and says which file to edit instead.
* the response's `errors[]` (unparseable fragments) was dropped; it now feeds
  `parsed.error`.

### M3 — pkg-family `what` sentence described the wrong event (fixed, daemon)

All three shipped `pkg-*` policies hook `bprm_check_security`, so the file in
the event is the binary being **executed** inside the package-manager process
tree. The daemon's `pkg` template assumed the file was a secret being read and
ran it through `describe_secret()`, producing:

```
what:    "curl read /usr/bin/curl during a package install."
summary: "curl (pid 5250) touched /usr/bin/curl."
```

`sentineld/src/explain.rs` now branches on the hook: `"A package install
started curl (/usr/bin/curl)."` and `"curl (pid 5250) executed /usr/bin/curl."`.
New tests `a_pkg_exec_reads_as_an_exec_not_a_secret_read` and
`every_shipped_family_has_a_what_template` (the latter enumerates families from
the real `policies/` directory and fails if any falls through to the
"matched the rule …" fallback — all nine are covered).

### M4 — the dedupe update's `ts` was dropped (fixed, plugin)

CONTRACT §6.3's dedupe emits `{"count":N,"ts":"<latest>"}`. The daemon's own
`fold()` applies `ts`; the plugin's `UPDATABLE` whitelist did not, so a repeated
alert kept the *first* sighting's timestamp and the panel would show "8m ago"
for something still happening. `ts` added to `UPDATABLE`.

`severity` was left out on purpose even though the daemon folds it: an update
line must never be able to escalate an alert into a critical toast, and nothing
shipped emits one. The reasoning is now a comment in the file, and
`tst_wire.qml` asserts both halves.

### M5 — `set mode` reports success when it changed nothing (fixed, plugin)

With `tetra` missing, every `tetra tp set-mode` fails and the response is:

```json
{"ok": true, "mode": "enforce", "applied": 0, "policies": 32, "failed": [ ...32... ]}
```

Exit code 0. The failure is enumerated, not swallowed, and `sentinelctl`
prints all 32 to stderr, so as a CLI this is graceful. But `ok:true` is what
the plugin's action handler keys on, so the panel would have switched its
toggle to "enforce" while Tetragon stayed in monitor — the one lie this UI must
not tell.

Persisting the mode across a `tetra`-less restart is deliberate on the daemon
side (`set_mode_persists_even_when_tetra_is_missing` is a named test), and the
contract does not say which way this should go, so the plugin changed:
`shell/Service.qml` treats `policies > 0 && applied == 0` on a `mode` command as
a failure and names it — *"sentineld recorded mode enforce but could not apply
it to any of 32 policies … Tetragon is still in the previous mode."*

### M6 — `SENTINEL_SANDBOX=0` did not bypass the PKGBUILD scan (fixed, sandbox)

CONTRACT §8 ends the shim paragraph with "`SENTINEL_SANDBOX=0` bypasses."
`sentinel-scan-pkgbuild`'s own footer prints:

```
build anyway          SENTINEL_SANDBOX=0 makepkg -si   # skips the sandbox and this scan
```

…and the shim's refusal message says "set `SENTINEL_SANDBOX=0` to bypass
everything". But `run_scan` ran unconditionally, before the variable was ever
consulted. Verified against the real scanner and the real shim: with
`SENTINEL_SANDBOX=0` and a fixture PKGBUILD scoring high, the shim still
refused. Two components documented an escape hatch the third did not open.

`sandbox/shims/makepkg` now returns early from `run_scan` when
`SENTINEL_SANDBOX=0`. `SENTINEL_SANDBOX_ACTIVE=1` deliberately still scans: a
nested `makepkg` is usually a different directory with a different PKGBUILD the
outer call never saw. New sandbox test *"SENTINEL_SANDBOX=0 skips the PKGBUILD
scan as well as the sandbox"* (53 tests, was 52).

### M7 — `status` ships `socket_group`, the contract example says `group_ok` (documented, plugin)

CONTRACT §5's `status` example ends `"group_ok":true`. The daemon emits
`socket_group: "<group name>"` and no `group_ok`, arguing in a code comment that
"is the caller in the group" is unanswerable from the daemon side — a client
that could not reach the socket could not have received the response at all.
That reasoning is right, and the plugin already answers the question itself with
`id -nG`.

Left as a deliberate contract deviation rather than adding a field that would
always be `true`. The plugin's `normalizeStatus` keeps `group_ok` optional
(absent ≠ "not in the group") and now also carries `socket_group` through, so
`setupSteps()` prints `sudo usermod -aG <actual group> $USER` instead of
hardcoding `sentinel`.

**CONTRACT.md §5 should be amended**: replace `"group_ok":true` with
`"socket_group":"sentinel"` in the example response.

---

## 5. Seam checks that passed

**(a) makepkg shim ↔ scanner exit codes.** Verified with the real scanner
against the real shim (not the suite's stub): exit 0 → build; exit 1 (medium) →
`[sentinel] PKGBUILD scan: medium findings above. Continuing.` then build; exit 2
(high) non-interactive → refuse, rc 1, real makepkg never reached; any other
exit → warn and continue. Matches CONTRACT §8 and §9. Fixture exit codes:
`clean-bin`/`vcs-git`/`vendor-cdn` → 0, `skip-checksum` → 1, the other seven
→ 2. The `proceed`/allow-file half also lines up: the scanner's per-finding
`proceed` text names `~/.config/sentinel/scanner-allow.conf` and
`/etc/sentinel/scanner-allow.conf`, both exactly as CONTRACT §2 spells them,
with the `host=` / `rule=` / `pkg=` syntax the contract names. (One gap, not
fixed — see §6.)

**(b) Policy annotations ↔ the daemon's loader.** `policies/check.py` requires
all seven of `severity`, `title`, `enforce`, `actions`, `why`, `expected`,
`fp-hint` (with `rotate` optional) and all 32 policies carry all seven — no
policy relies on a daemon fallback. `fp-hint` values are all in
{`exe`, `exe+file`, `parent`, `rule`}, `actions` all in
{`kill`, `quarantine`, `ignore`}, severities all in the four. The daemon's
`PolicySet::parse` reads exactly these keys and has a usable fallback for each,
so an unannotated policy degrades rather than crashing. Family → `what`
template coverage is now enforced by a test that reads `policies/` (M3).

**(c) `rotate` table coverage.** Was broken; see M1. Now enforced by a test.

**(d) Allowlist round trip.** `ignore <id> --scope exe` wrote the block, the
daemon reloaded, and replaying the identical Tetragon event appended **nothing**
to `alerts.jsonl` (7 lines before, 7 after). The block `ignore` returned, the
block `explain`'s `if_expected` advertised, and the block `allowlist` listed are
byte-identical — they all come from one `render_block()`. `unignore 1` removed
it and returned the removed text.

**(e) Absolute paths vs CONTRACT §2.** Every hardcoded absolute path in
`shell/`, `sandbox/`, `scanner/`, `sentineld/src/config.rs` defaults,
`sentineld/etc/`, `sentineld/systemd/`, `policies/tetragon.conf.d/` and
`policies/tetragon.service` agrees with §2. Checked pairwise: the daemon's
`tetragon_log` default is `/var/log/sentinel/tetragon.log` = conf.d's
`export-filename`; `policies_dir` is `/run/sentinel/policies` = conf.d's
`tracing-policy-dir`; `templates_dir` is `/usr/lib/sentinel/policies`;
`export_allowlist` is `/etc/tetragon/tetragon.conf.d/export-allowlist`;
`tetragon_socket` is `/run/tetragon/tetragon.sock` = conf.d's `server-address`.
The plugin's `/usr/bin/sentinelctl`, `/var/lib/sentinel/alerts.jsonl` and
`/etc/sentinel/allowlist.d/user.toml` all match. Two paths appear that §2 does
not list — see §6.

**(f) `SENTINEL_SANDBOX_ACTIVE=1`.** Set by `sentinel-sandbox` via
`bwrap --setenv`. Documented in `sandbox/README.md`; the entry has been expanded
to say what the daemon can and cannot do with it.

*Decision: the daemon must NOT try to down-rank pkg-family alerts on it, and
cannot.* `policies/tetragon.conf.d/enable-process-environment-variables` is
`true` but `filter-environment-variables` is `LD_PRELOAD`, so the export carries
that one variable and nothing else — `Process::environment_variables` in the
daemon will never contain `SENTINEL_SANDBOX_ACTIVE`. Widening the filter to
`LD_PRELOAD,SENTINEL_SANDBOX_ACTIVE` would make it visible, but it should not be
done: the variable is trivially forgeable by the very code the pkg policies
watch (`env SENTINEL_SANDBOX_ACTIVE=1 curl …` inside a postinstall script would
buy an attacker a severity downgrade), and the sandbox does not stop a package
install from reading `~/.npmrc` or writing `$PWD` anyway. Sandboxed installs
should still alert. Documented, not implemented.

**(g) `tetragon.service` ExecStartPre ↔ the daemon's CLI.** The unit runs
`ExecStartPre=/usr/bin/sentineld render-policies` with no flags, and every
default the subcommand falls back to matches §2: templates
`/usr/lib/sentinel/policies`, out `/run/sentinel/policies`, export-allowlist
`/etc/tetragon/tetragon.conf.d/export-allowlist`, passwd `/etc/passwd`. The
unit's `ProtectSystem=strict` +
`ReadWritePaths=/run/sentinel … /etc/tetragon/tetragon.conf.d` covers both
directories it writes, and `ProtectHome=read-only` does not block it (it only
reads `/etc/passwd`). `cmd_render` exits 0 even on a partial render, so one bad
template cannot keep Tetragon from starting; the failures surface in
`status.policies_failed`. Verified by running the exact command form against
the real templates: 32 rendered, 0 `{{HOME}}` left, export-allowlist listing
all 32 names.

---

## 6. Open issues (not fixed)

1. **CONTRACT §5's `status` example is stale.** It shows `"group_ok":true`; the
   daemon ships `"socket_group":"sentinel"`. The daemon's reading is the better
   one (M7). Someone with authority over `CONTRACT.md` should amend the example.

2. **`set mode` still returns `ok:true` when it applied to zero policies.**
   Worked around in the plugin (M5), which is the cheap side, but `sentinelctl
   set mode` also exits 0 in that state, so a script cannot tell. The honest fix
   is daemon-side: keep persisting the mode, but answer
   `{"ok":false,"error":"...","mode":"enforce","applied":0}`. That would need
   `set_mode_persists_even_when_tetra_is_missing` rewritten, so it is left to
   the sentineld owner.

3. **`set mode` returns 32 identical error objects** when `tetra` is absent.
   `sentinelctl` prints all 32 lines. Collapsing identical errors into one entry
   with a count would make the failure readable.

4. **The makepkg shim's "continue anyway" is not recordable.** The scanner tells
   the user to add `pkg=<name> rule=<id>` or `host=<domain>` to
   `~/.config/sentinel/scanner-allow.conf`, but when they answer *y* at the
   `gum confirm` prompt the shim just continues — nothing is written, so the
   next `makepkg` in the same directory prompts identically. Offering to append
   the allow-file line after a confirmed build would close the loop. (Analogous
   to what `sentinelctl ignore` does for alerts.)

5. **Two installed paths are not in CONTRACT §2**, so the packaging agent may
   miss them: `sandbox/fish/conf.d/sentinel-shims.fish` (the fish equivalent of
   `/etc/profile.d/sentinel-shims.sh`, which needs to land in
   `/usr/share/fish/vendor_conf.d/sentinel-shims.fish`) and
   `/usr/share/doc/omarchy-sentinel/README.md`, referenced from
   `sandbox/README.md`. `pkg/` was out of scope for this review and was not
   inspected.

6. **`quarantine` was not exercised end to end.** The scenario used a fake home
   with no real files, so only the refusal path (a target outside
   `$HOME`/`/tmp`/`/var/tmp`/`/dev/shm`) is covered here; the move, the `chmod
   000` and the `meta.json` are covered by `sentineld`'s own unit tests but not
   against a live daemon.

7. **The `feeds` seam is untested against the network.** `sentinel-feeds`
   without an abuse.ch `Auth-Key` is a clean no-op (covered by
   `sentinel_feeds_without_a_key_is_a_no_op`), and `status.feeds` reads
   `{"updated": null, "hashes": 0, "domains": 0, "urls": 0}` — which the plugin
   normalizes to `feeds never`. Nothing here verifies the parse of a real
   MalwareBazaar/ThreatFox/URLhaus response.

8. **`process_uprobe` is in the export-allowlist but the daemon does not parse
   it.** `RawEvent` handles `process_exec`, `process_exit`, `process_kprobe`,
   `process_lsm` and `process_tracepoint`. CONTRACT §3 lists `process_uprobe` as
   carrying `policy_name` and the generated export-allowlist requests it, but no
   shipped policy uses a uprobe, so the events would be silently ignored if one
   ever did. Adding it to the `RawEvent` oneof is a three-line change whenever a
   uprobe policy lands.

---

## 7. Files changed by this review

| File | Change |
|---|---|
| `sentineld/src/explain.rs` | M1 rotate table (20 kinds + aliases), M3 pkg `what`/summary; 3 new tests, two of which read `policies/` |
| `shell/SentinelModel.js` | M1 rotate guidance, M2 allowlist field aliases + `removable`/`sourceFile`, M4 `ts` in `UPDATABLE`, M7 `socket_group` + `setupSteps(…, group)` |
| `shell/Service.qml` | M5 zero-applied mode change is a failure; pass `socket_group` to `setupSteps` |
| `shell/AllowlistView.qml` | M2 hide `#index` and **Remove** for non-`user.toml` rules, name the file to edit instead |
| `shell/tests/tst_wire.qml` | new — 19 wire-level tests over real daemon output |
| `shell/tests/fixtures/wire/*` | new — captured `alerts.jsonl` + six `--json` responses |
| `shell/tests/run-tests.sh` | run `tst_wire` |
| `sandbox/shims/makepkg` | M6 `SENTINEL_SANDBOX=0` skips the scan |
| `sandbox/tests/run.sh` | M6 regression test |
| `sandbox/README.md` | expanded the `SENTINEL_SANDBOX_ACTIVE` / `SENTINEL_SANDBOX=0` env table entries |
| `tests/run-all.sh` | new — every suite in order, non-zero on any failure |
| `docs/INTEGRATION.md` | this file |

`pkg/` was not touched. `policies/`, `scanner/` and `sentineld/src/` outside
`explain.rs` were read but needed no changes.
