# moatd

The userspace half of **omarchy-moat**. Tetragon (upstream, unmodified,
v1.7.1) does the kernel work and writes a JSON-lines export file; everything
here reads that file, adds the context the kernel cannot keep, and turns matches
into alerts a developer can act on without opening a second terminal.

Three binaries from one crate:

| binary           | what it does                                                        |
|------------------|---------------------------------------------------------------------|
| `moatd`      | `render-policies` (ExecStartPre), `wait-sensor` (ExecStartPost) and `run` (the daemon) |
| `moatctl`    | thin CLI over the control socket                                    |
| `moat-feeds` | hourly abuse.ch indicator fetch                                     |

```
cargo build --release && cargo test && cargo clippy
./dev-run.sh          # the whole thing, unprivileged, in a temp dir
```

---

## 1. The run loop

```
                       Tetragon (root)
                              │  JSON lines, rename-rotated at 50 MB
                              ▼
  /var/log/moat/tetragon.log
                              │
          ┌───────────────────┴──────────────────┐
          │ tail thread (200 ms poll)            │   thread 2: control socket
          │                                      │   /run/moat/control.sock
          │  1. parse (event.rs)                 │   accept → one JSON request
          │  2. process table (proctable.rs)     │   → one JSON response
          │  3. policy findings + userland rules │            │
          │  4. provenance + context + score     │            │
          │  5. rarity counters                  │            │
          │  6. allowlist → dedupe → alert       │◄───────────┘  shared Mutex<Daemon>
          │  7. append alerts.jsonl              │
          │  8. baseline: learn / propose /      │
          │     demote                           │
          │  9. high+ alert: incident snapshot   │
          │     BEFORE any kill                  │
          │ 10. pkg root exits: install receipt  │
          │ 11. every 5 s: prune, pacman check,  │
          │     state.json, arm when the sensor  │
          │     is loaded                        │
          │ 12. every 60 s: feeds, rarity.json,  │
          │     baseline.json, verify the armed  │
          │     set against the kernel           │
          └──────────────────────────────────────┘
```

Step by step:

1. **Tail** (`tail.rs`). The path is stat'ed on every poll: a changed inode means
   Tetragon rotated by rename, a shrunk size means truncation. Either way we
   reopen at offset 0 so nothing is lost. A partial trailing line waits for its
   newline.

2. **Parse** (`event.rs`). Tetragon's exporter is `protojson` with
   `UseProtoNames: true`, so every field is snake_case and the event kind is a
   top-level oneof: `process_exec`, `process_exit`, `process_kprobe`,
   `process_lsm`, `process_tracepoint`. Unknown fields are ignored on purpose —
   a Tetragon upgrade that adds a field must not stop parsing.

3. **Process table** (`proctable.rs`). Keyed by `exec_id`, parent chain followed
   through `parent_exec_id` and capped at 8 hops. Every event carries a
   `process` and a `parent` block, so the table stays populated even for
   processes that started before the daemon did. Entries live 60 s past
   `process_exit`, because a kprobe event can be written after the exit line and
   because kill confirmation arrives on the exit event.

4. **Detection.** A hook event whose `policy_name` starts with `moat-`
   becomes a finding, using the annotations of the rendered policy of the same
   name (`policy.rs`) — **after** the event is re-validated against that
   policy's own selectors (§3.3). Everything else is enrichment only. In
   parallel the eight userland rules (`rules/`) see every exec and every hook.

5. **Baselining** (`provenance.rs`, `context.rs`, `scoring.rs`, `rarity.rs`,
   `baseline.rs`). Section 9 below. Every finding is classified (who acted,
   from where), scored (provenance and context adjust the severity within
   documented limits), counted (how unusual is this exact combination on this
   machine), and offered to the learning window.

6. **Allowlist → dedupe → alert** (`allowlist.rs`, `explain.rs`, `store.rs`).
   A finding matching any `[[rule]]` in `/etc/moat/allowlist.d/*.toml` is
   **not** dropped: it is recorded with `suppressed_by` set, so the timeline can
   grey it out, and it is left out of the badge. Otherwise the same rule+exe+file
   within 60 s folds into a `count` update line, and anything else becomes a new
   alert with a ULID, appended to `alerts.jsonl`.

7. **Analysis** (`receipt.rs`, `incident.rs`, `bundle.rs`, `digest.rs`).
   Section 10 below. Every package install writes one receipt when its root
   exits; every alert at or above `[incidents] snapshot_min_severity` is
   snapshotted **before** anything is killed; `bundle.md` turns one alert into
   a document the user's own agent can read.

8. **Kill confirmation.** Monitor mode still reports
   `"action":"KPROBE_ACTION_SIGKILL"` (TETRAGON-NOTES §7), so the action field
   is *not* proof. `action_taken` only becomes `killed` when a `process_exit`
   for that same `exec_id` arrives carrying `"signal":"SIGKILL"`.

### Signals

| signal            | effect                                                     |
|-------------------|------------------------------------------------------------|
| `SIGHUP`          | re-read moat.toml, policy annotations, allowlist.d      |
| `SIGTERM`/`SIGINT`| flush rarity.json and baseline.json, write state.json, remove the socket, exit 0 |

`systemctl reload moatd` sends the HUP. The process table survives a reload.

### Starting up — do not restart by hand

Use `sudo moatd telemetry --apply`, or restart **tetragon** and let moatd follow
it (`PartOf=`). Restarting the two by hand in the wrong order leaves moatd
tailing a file nothing is writing.

More importantly, "tetragon has started" and "tetragon is ready" are not the
same event, and for a long time nothing in this project knew the difference.
tetragon.service is `Type=simple`, so systemd calls it started the instant it
forks; on 2026-09-05 it then spent **16 seconds** loading 44 policies. moatd is
`Requires=/After=/PartOf=` it, so it started, believed the sensor was up, and
pushed the armed set into the kernel at **+2 s** — where every `tetra tp
set-mode` failed against a policy name the kernel did not have yet, nothing
retried, and `status`, `moatctl` and the panel all went on saying seven rules
were armed while the kernel had them in `monitor`. All day. (NOTES §7.1.)

**`moatd wait-sensor` is what makes the order safe.** It counts the policies
pinned under `/sys/fs/bpf/tetragon` and blocks until that reaches the rendered
count, and it is wired as `ExecStartPost=-/usr/bin/moatd wait-sensor
--timeout 120` on tetragon.service. A unit with an `ExecStartPost` stays in
`activating` until the command returns, so this is what finally makes
`After=tetragon.service` mean *after it is loaded* rather than *after it
forked*. The `-` prefix keeps a slow load from failing the sensor unit and
handing it to `Restart=always`; run it without the prefix yourself
(`sudo moatd wait-sensor`) and it exits 0 loaded, 1 timed out, 2 bpffs never
appeared.

The daemon waits on its own account too (`[thresholds] arm_wait_secs`, 120 s),
and that is not redundant: the unit fix only orders a boot. A tetragon that
reloads a policy later, a policy re-added by a kernel exclusion, a sensor that
restarts without taking moatd with it — none of those are boot-order problems,
and all of them silently drop a policy back to the `monitor` its file declares.
`verify_enforcement` reads the kernel back once a minute for exactly that
reason; see §5 for what `status` publishes.

---

## 2. `moatd render-policies`

Tetragon path filters are Prefix/Postfix/Equal only — no middle wildcard — so
`/home/*/.ssh/` is inexpressible (NOTES §3, gap 2). The policies in `policies/`
are therefore templates carrying `{{HOME}}`, and this subcommand expands them:

* human users are those with uid in `[1000, 65534)`, a home under `/home` or
  `/var/home`, and a login shell that is not `nologin`/`false`;
* expansion runs on the **parsed YAML**, never on the text, so a home containing
  a quote or colon cannot produce a broken document;
* a sequence item containing `{{HOME}}` fans out into one item per home — that
  is the `values:` case templates are written for. A `{{HOME}}` in any other
  scalar is substituted with the first home and logged, since a scalar cannot
  fan out;
* writes are atomic and skipped when the content is unchanged, so running this
  on every boot does not churn mtimes;
* rendered policies with no matching template any more are removed, so Tetragon
  never loads a stale file.

It also regenerates `/etc/tetragon/tetragon.conf.d/export-allowlist`, byte for
byte identical to `policies/export-allowlist.example`:

```
{"event_set":["PROCESS_EXEC","PROCESS_EXIT"]}
{"event_set":["PROCESS_KPROBE","PROCESS_LSM","PROCESS_TRACEPOINT","PROCESS_UPROBE"],"policy_names":["moat-…", …]}
```

Line 1 keeps exec/exit (they carry no `policy_name`, and without them there is
no ancestry). Line 2 lists **exact** names, because `policy_names` has no glob
and no prefix match (gap 8). That is why it is regenerated on every render.

```
moatd render-policies \
  --templates-dir /usr/lib/moat/policies \
  --out-dir       /run/moat/policies \
  --export-allowlist /etc/tetragon/tetragon.conf.d/export-allowlist
```

`--home /home/x` (repeatable) overrides passwd discovery; `--json` prints a
machine-readable report; `--export-allowlist ''` skips the conf.d write.

---

## 3. Detections

### Policy-driven (`moat-<family>-<rule>`)

Severity, title, `why`, `expected`, `rotate` and `fp-hint` all come from the
policy's `moat.omarchy/*` annotations (CONTRACT §3). A policy with no
annotations still produces a usable alert, it just says so.

### Userland rules

These are the gaps a TracingPolicy cannot express. Each has its own tests and a
toggle in `[rules]` — except `moat-x-sensor-mismatch`, which is part of the
policy path itself and cannot be switched off without silently trusting a
sensor that has contradicted itself.

| rule                         | fires when                                                                                     | severity |
|------------------------------|------------------------------------------------------------------------------------------------|----------|
| `moat-x-ai-cli-headless` | an AI CLI (`claude`,`codex`,`gemini`,`opencode`,`q`,`amp`) has no terminal/tmux/ssh/editor **and** no interactive shell outside a package subtree in its ancestry, and no ancestor matching `ai.headless_allowed_parents` | high |
|                              | …or carries `--dangerously-skip-permissions`/`--yolo`/`--trust-all-tools`/`--full-auto` while its parent is an interpreter inside a package install | critical |
| `moat-x-pkg-egress`      | a package-manager subtree connects to an address that is neither private nor in `net.registry_cidrs` | medium (configurable) |
| `moat-x-new-exec-ioc`    | the sha256 of an executed file under `$HOME`,`/tmp`,`/var/tmp`,`/dev/shm` is in `feeds/hashes.txt` | critical |
| `moat-x-mass-read`       | one process reads more than `mass_read_files` distinct files under `$HOME` dotdirs within `mass_read_window_secs` | high |
| `moat-x-sensor-mismatch` | a policy event's reported path or binary does not satisfy that policy's own selectors (§3.3); the policy's own alert is **not** raised | low |
| `moat-pkg-subtree-interpreter-spawn` | a shell or interpreter execs inside a package-manager subtree — one alert per install, not per script | low |
| `moat-pkg-subtree-downloader` | `curl`,`wget`,`aria2c`,`base64`,`openssl`,`xxd`,`xh`,`httpie`, or `python -c/-m` / `node -e` carrying an http URL, execs inside a package subtree | high |
| `moat-pkg-subtree-netcat-exec` | `nc`,`ncat`,`netcat`,`socat`,`telnet` execs inside a package subtree. In `enforce` mode moatd SIGKILLs the process itself | critical |
| `moat-ai-cli-in-pkg-subtree` | an AI CLI execs inside a package subtree | high |
| `moat-shell-stdio-socket` | a shell (`bash`,`sh`,`dash`,`zsh`,`fish`,`busybox`,`ash`,`ksh`,`mksh`,`tcsh`,`csh`) execs with fd 0, 1 or 2 pointing at a network socket — the interpreter reverse shell, where `python`/`perl`/`node` connects, `dup2`s the socket onto stdio and execs `/bin/sh`. LAN and loopback **included**: unlike the kernel rule it does not exclude private addresses. In `enforce` mode moatd SIGKILLs the process itself, on this rung only | critical (medium for a loopback peer) |
|                              | …or the shell's stdio is a pty **and the parent's** stdio is a network socket — the `pty.spawn` / `script /dev/null` upgrade. Not "the parent holds a socket somewhere": that is every IDE on the machine | high |
| `moat-ransom-file-churn` | one actor READ a file under ~/Documents, ~/Desktop, ~/Pictures, ~/Videos, ~/Music or ~/Downloads and then deleted, renamed away or emptied that same file, across `ransom_churn_files` distinct files inside `ransom_churn_window_secs`. Fed by the `signal` kernel policy of the same name, which it owns (as `moat-net-first-contact` does), so the per-event records never become alerts. The children of a shell are folded into the shell, so an `openssl … && rm` loop is one actor. Build-tree fragments (`/node_modules/`, `/target/`, `/.git/`, …) under a document directory are cut in userland because Prefix cannot | critical |
|                              | …or renamed `ransom_churn_files` distinct files to ONE shared new extension in the window, where the sources were of several kinds or a suffix was appended to every name (`report.pdf` → `report.pdf.locked`). No list of known ransomware extensions: the loss of variety is the tell | high |
| `moat-ransom-snapshot-command` | exec of `btrfs subvolume delete` (any unambiguous prefix), `snapper delete|rm|remove`, `timeshift --delete[-all]`, `restic`/`rustic forget` with no `--keep*` option, or `borg delete|rdelete` — with no snapshot manager (timeshift, snapperd, snapper's `systemd-helper`, btrbk, yabsnap, btrfs-assistant, borgmatic, backrest, autorestic, resticprofile) in its ancestry. Argv is invisible to a kernel selector; exec is exported anyway, so this costs the sensor nothing | critical |
| `moat-x-noisy-rule`      | one (rule, exe, parent, dir) pattern raised more than `noisy_rule_per_day` alerts in a rolling 24 h; that pattern is demoted to the timeline, not switched off — and past five quiet patterns the alert says the rule itself wants retuning (§9.4) | medium |
| `moat-x-baseline-revoked`| a learned baseline entry's actor stopped being official, so the entry was disabled in place (§9.5) | low |

The four subtree rules (`moat-pkg-subtree-*` and `moat-ai-cli-in-pkg-subtree`)
keep the ids and severities of the kernel policies they replaced,
so allowlist entries, the plugin and the docs are unaffected — only the place
the subtree decision is made changed. They fire on `process_exec`, which is
exported unconditionally, so no policy has to be loaded for them to work — and
so does `moat-shell-stdio-socket`, which is why it keeps working when the
`shell` policies are not loaded at all.

Design notes worth knowing:

* a bare `sh`/`bash` in the ancestry is **not** an interactive shell when a
  package manager is above it — npm spawns one for every lifecycle script;
* `pkg-egress` is medium, not high, because CDN address space moves and the
  allowlist is necessarily coarse: there is no DNS in the kernel and no hostname
  in the export (gap 4);
* `moat-pkg-subtree-netcat-exec` and `moat-shell-stdio-socket` are the only two
  rules that act on their own. They kill
  **only** in enforce mode, only the process itself (not the tree), and only
  after `/proc/<pid>` proves the start time still matches — the same check the
  `kill` socket command uses. The outcome is recorded either way: `killed`, or an
  evidence line saying why it was not. `moat-shell-stdio-socket` asks only on
  its `critical` rung: a loopback peer (medium) and the pty rung (high) are
  where the rule is least certain, and killing there would make its weakest
  cases its most destructive ones. Both are armable **one at a time**:
  `moatctl set mode enforce --rule moat-shell-stdio-socket` arms that rule and
  leaves the daemon in monitor. They declare `enforce: "kill"` in their own
  meta, so `enforceable()` lists them (with `"by": "moatd"` rather than
  `"kernel"`), `maybe_enforce` gates on `mode_for(rule)`, and the rule itself
  asks `RuleCtx::enforcing(id)`. Nothing is pushed into the kernel for them —
  there is no policy to set a mode on — so arming applies immediately and cannot
  fail; the arming survives a restart through `enforcing_rules` in `state.json`,
  like a kernel rule. Until 2026-09-05 these two were the only rules that act on
  their own and the only ones the per-rule switch refused, so the only way to
  arm either was to arm the whole machine.

### 3.2 The package-subtree classifier (`rules/pkgtree.rs`)

One definition of "inside a package install", used by the four rules above, by
`moat-x-pkg-egress`, by the egress escalation and by the AI-CLI rules.

The kernel version of this (`matchParentBinaries` + `followChildren`) matched
processes with **no package manager in their ancestry at all** — `quickshell ->
bash`, `Xwayland -> bash`, `make` under `cmake` — which is why the four `pkg`
policies were deleted. The classifier works off the `exec_id` process table
instead, with exact ancestry and the real argv.

A process is a package-manager **root** when

* its binary basename is one of `npm`, `npx`, `pnpm`, `yarn`, `bun`, `corepack`,
  `pip`, `pip3`, `uv`, `poetry`, `pipx`, `cargo`, `makepkg`, `yay`, `paru`; **or**
* its arguments carry a marker: `npm-cli.js`, `npx-cli.js`, `pnpm`, `yarn.js`,
  `bun install|add|x`, `pip install`, `uv pip|sync|add|run|tool`,
  `cargo build|install|run|test|add|fetch|update`, `makepkg`.

The second half is what catches the shape that actually appears in the export,
where the binary is `node` and npm is a script it was handed. Markers match per
path segment, so a `pnpm-lock.yaml` on the command line is not an invocation.

Every descendant inherits the flag; `pkg_root_for(exec_id)` returns the
**outermost** root, so a mise shim and the binary it execs are one install with
one identity, and one `npm install` yields one interpreter-spawn alert no matter
how deep the tree goes.

### 3.3 Selector re-validation (`selectors.rs`)

The first live run produced an event carrying the SSH-key policy's name and the
file `/sys/devices/system/cpu/online` — a path that policy's `Equal` list of
`~/.ssh/id_*` cannot produce. An alert is a claim; that one would have been
false.

So every rendered policy's selectors are parsed at load time, and every policy
event is re-checked against them before it becomes an alert:

* `matchArgs` on the indexes the hook itself declares as a path (`file`, `path`,
  `linux_binprm`, `fd`, `dentry`): `Equal`, `Prefix`, `Postfix`, `NotEqual`,
  `NotIn`, `NotPrefix`, `NotPostfix`;
* `matchBinaries`: `In`, `NotIn`, `Prefix`, `NotPrefix`, `Postfix`, `NotPostfix`.

Everything else — `Mask`, `Family`, `DPort`, `NotDAddr`, `matchPIDs`,
`matchNamespaces`, … — is unknown, and **unknown passes**. Selectors are OR'd,
clauses inside one are AND'd, values inside a clause are OR'd, exactly as
Tetragon does it. When nothing accepts the event, the policy's alert is dropped
and `moat-x-sensor-mismatch` is raised at `low` instead, carrying the policy
name, the reported value, the selector that rejected it, and a `why` explaining
that the kernel reported something its own filter should have excluded and the
record is kept so a misbehaving sensor is visible rather than silent.

### 3.4 Egress escalation

`moat-net-suspicious-port-egress` (medium) watches unusual public ports for
every process, because the kernel cannot tell whether the connecting process is
inside an install. moatd can: when the classifier finds a package-manager root
above the connecting process, the alert is raised to **high** and gains an
evidence line naming the root and saying what it was raised from.

### 3.5 Binaries with no name

A binary executed from a file descriptor (`fexecve`, memfd) is reported as
`/proc/self/fd/<n>`. moatd resolves it from the hook's `linux_binprm` argument
when there is one, otherwise from the parent's argument 0, and always records
what it did as an evidence line under the `process:` line — including when
nothing could be recovered, because an alert naming `/proc/self/fd/9` with no
explanation is worse than useless.

---

## 4. Alerts

`alerts.jsonl`, 0640 root:moat, append only, rotated to `alerts.1.jsonl` at
20 MB. Full records and update lines are interleaved; readers fold updates by
id (see CONTRACT §4 for the field list).

```json
{"v":1,"id":"01J8ZK…","update":{"acked":true,"action_taken":"killed"}}
```

Every alert carries a complete `explain` block:

* **what** — one plain sentence, from a per-family template (`cred` names the
  secret in words: "node read your private SSH key (id_ed25519)");
* **why** / **expected** — the policy's annotations, or the userland rule's own;
* **evidence** — hook + path/args, process line, ancestry line, rule-specific
  extras, and the allowlist line saying which rules were checked and missed;
* **if_expected.options** — one entry per applicable scope (`exe`, `exe+file`,
  `parent`, `rule`), each with the ready-to-run `moatctl ignore` command and
  the **exact TOML block** that command would write. The recommended scope
  (`fp-hint`) is first. `exe+file` is omitted for alerts with no file, and
  `parent` for alerts with no recorded ancestry, because a rule that can never
  match is a footgun;
* **next** — response steps: stop it, rotate each named secret (a table covers
  `ssh-key`, `github-token`, `npm-token`, `aws`, `gh`, `claude`, `gpg`,
  `keyring`, `browser`, `docker`, `kube`), plus context lines for package
  installs, dropped files and network destinations.

Baselining adds eight fields to every record (BASELINE §8):

| field | meaning |
|---|---|
| `actor` | `{provenance, package, script}` — who acted, after the interpreter rule |
| `context` | `interactive` \| `pkg-install` \| `service` \| `unknown` |
| `severity_base` | what the rule itself decided, before any adjustment |
| `severity_reason` | `"high → medium: actor is official (package hyprland 0.52.0-1)"` |
| `surface` | `alerts` \| `timeline` (BASELINE §5) |
| `suppressed_by` | `null`, or `"user.toml#1"` / `"baseline.toml#3"` |
| `rarity` | `first_seen` \| `rare` \| `common` |
| `rarity_text` | `"first time /usr/bin/node has read /home/dan/.aws on this machine"` |

and one more from LEARNING §4, which arrives **as an update line** rather than
on the record itself, so a `/proc` walk can never delay the alert:

| field | meaning |
|---|---|
| `incident` | `{dir, files: [{name, size, sha256}]}` — the snapshot taken before any kill (§10.2) |

Receipts share the file as a third line kind, `{"v":1,"receipt":{…}}` (§10.1);
they parse as neither an alert nor an update, so every existing reader ignores
them.

A **suppressed** alert is still appended, so the timeline can show it greyed
out; it never notifies and never counts towards `unacked`. A **demoted** pattern
and a **`signal`-tier** rule are not suppressions: their alerts keep
`suppressed_by: null` and get `surface: "timeline"`, and the record carries
`tier` and `pkg_install_escalation` so a reader can tell the three apart
(BASELINE §4a, §8). Every one of these fields has a `serde` default, so a record
written by an older moatd still loads — and the default for `tier` is
`detection`, so silence is never the failure mode of a missing field.

---

## 5. Control socket

`/run/moat/control.sock`, 0660 root:moat, newline-delimited JSON, one
request → one response per connection.

**Every action names an alert id, never a raw pid or path.** That is what makes
the socket safe to hand to the user's group: a hostile process cannot use
moatd to kill or move something the sensor did not already flag.

| request | response (on success) |
|---|---|
| `{"cmd":"status"}` | version, mode, tetragon, policies, policies_failed, feeds, unacked, `ledger` (`needs_you` / `recorded` / `suppressed` / `signal`), sandbox, socket_group, and the enforcement triple below |
| `{"cmd":"list","since":"<ULID>","limit":100}` | `alerts: [...]`, updates folded |
| `{"cmd":"explain","id":"…"}` | `alert: {...}` with the full explain block |
| `{"cmd":"ack","id":"…"}` | appends `{"acked":true}` |
| `{"cmd":"kill","id":"…"}` | `killed: [pids]` — descendants first, then the pid |
| `{"cmd":"quarantine","id":"…"}` | `from`, `to` |
| `{"cmd":"ignore","id":"…","scope":"exe\|exe+file\|parent\|rule","comment":"…"}` | `block` (the exact TOML written), and the alert is acked |
| `{"cmd":"unignore","rule":2}` | `removed` — user.toml by index |
| `{"cmd":"unignore","file":"baseline.toml","index":2}` | the same, for a learned entry; shipped files are refused |
| `{"cmd":"allowlist"}` | merged rules with `file`, `index` (within that file), `source` (`user`\|`learned`\|`shipped`), `removable`, `comment` and TOML |
| `{"cmd":"baseline","action":"list"}` | window state, `proposals[]`, `learned[]`, `demoted_rules[]` |
| `{"cmd":"baseline","action":"accept","id":"…"}` | writes the proposal's TOML to `baseline.toml`, returns the block |
| `{"cmd":"baseline","action":"dismiss","id":"…"}` | drops it and stops asking |
| `{"cmd":"baseline","action":"relearn","days":N}` | restarts the learning window |
| `{"cmd":"baseline","action":"export","since":"YYYY-MM-DD"}` | every tuple, for review (LEARNING §8) |
| `{"cmd":"baseline","action":"propose","rule":"…"}` | proposals for a noisy rule's top tuples |
| `{"cmd":"baseline","action":"undemote","rule":"…"}` | clears a demotion: keep watching |
| `{"cmd":"set","key":"mode","value":"monitor\|enforce"}` | `applied`, `failed[]` |
| `{"cmd":"set","key":"sandbox","value":"on\|off"}` | `sandbox` |
| `{"cmd":"set","key":"digest","value":"on\|off"}` | the digest block; also `state.json.digest_enabled` |
| `{"cmd":"feeds","action":"refresh"}` | exit status and the new feed counts |
| `{"cmd":"receipts","last":20}` | `receipts[]` (LEARNING §9 shape) and their rendered form |
| `{"cmd":"incidents","last":20}` | the snapshots on disk, with their files and hashes |
| `{"cmd":"bundle","id":"…"}` | `path` — `<incidents dir>/<id>/bundle.md` |
| `{"cmd":"analyze","id":"…"}` | `path`, `preamble`, `agent_args` — **moatctl** does the launch |
| `{"cmd":"rarity","id":"…"}` | `rarity`, `rarity_text` |
| `{"cmd":"digest"}` / `{"cmd":"digest","action":"sent"}` | the weekly summary; `sent` records a delivery |

Failures are `{"ok":false,"error":"…"}`; `moatctl` exits 2 on those and 3
when it cannot reach the socket at all.

Two safety behaviours worth knowing:

* **kill** re-verifies the target before signalling: `/proc/<pid>` start time
  must be within 2 s of the alert's `start_ts` *and* `/proc/<pid>/exe` must
  still match. A recycled pid is refused, not killed.
* **quarantine** refuses any path outside `$HOME`, `/tmp`, `/var/tmp`,
  `/dev/shm`. It moves the file into `/var/lib/moat/quarantine/<alert id>/`,
  chmods it `000`, and writes a `meta.json` recording the original path, the
  sha256, and the command to restore it.

`set mode` runs `tetra tp set-mode <name> monitor|enforce` for every loaded
policy (immediate, no reload — NOTES §7) and persists the choice in
`state.json`, since the export cannot tell us the current mode. The daemon
answers `ok: true` (it did persist the choice), but **`moatctl set mode` exits 2
when `applied` is 0** and prints what to check: the mode was recorded while
nothing in the kernel changed, which is exactly the case a script must catch.

### Armed, and actually armed

`status` reports enforcement three ways, and the difference between them is the
whole point:

| field | meaning |
|---|---|
| `enforcing_rules` | what the **record** says is armed — the user's request, restored from `state.json`. What the panel binds to. |
| `enforcing_verified` | the subset the **kernel** confirms is in `enforce` |
| `enforcing_unverified` | the subset the kernel says is **not** — listed as armed, will kill nothing |
| `enforcement_unhealthy` | `enforcing_unverified` is non-empty. The analogue of `sensor_unhealthy`. |
| `arming_pending` | still waiting for the sensor to load before arming. Normal for a few seconds after a boot. |

The kernel's answer comes from `tetra tracingpolicy list -o json` — the `mode`
field of `TracingPolicyStatus`, a `TracingPolicyMode` (`TP_MODE_ENFORCE` 1,
`TP_MODE_MONITOR` 2). `verify_enforcement` reads it once a minute, re-arms
anything that disagrees, reads the kernel *back* rather than trusting the
`set-mode` exit status, and raises exactly one `moat-x-protection-changed` alert
for a gap that persists — deduped on the unverified set, cleared when a policy
comes back. `moatctl status` prints the unverified names on the `enforcing` line
itself:

```
enforcing  moat-cred-a, moat-net-b   *** NOT ARMED IN KERNEL: moat-net-b — see journal: journalctl -u moatd -u tetragon ***
```

Being unable to *ask* is never reported as a gap: an empty
`enforcing_verified` **and** an empty `enforcing_unverified` next to a non-empty
`enforcing_rules` means moatd could not reach the sensor, which is
`sensor_unhealthy`'s story to tell. None of the three persist across a restart —
agreement observed before a restart says nothing about the kernel after one.

---

## 6. Configuration

`/etc/moat/moat.toml` — every key is optional and an unknown key is an
error, so a typo is loud. See the shipped `etc/moat.toml` for the commented
version; the reference:

| key | default | meaning |
|---|---|---|
| `group` | `moat` | owns the socket and alerts.jsonl |
| `mode` | `monitor` | first-boot mode; `state.json` wins after that |
| `paths.tetragon_log` | `/var/log/moat/tetragon.log` | the export to tail |
| `paths.policies_dir` | `/run/moat/policies` | rendered policies |
| `paths.templates_dir` | `/usr/lib/moat/policies` | `{{HOME}}` templates |
| `paths.export_allowlist` | `/etc/tetragon/tetragon.conf.d/export-allowlist` | generated |
| `paths.state_dir` | `/var/lib/moat` | alerts, state, quarantine, feeds |
| `paths.socket` | `/run/moat/control.sock` | |
| `paths.allowlist_dir` | `/etc/moat/allowlist.d` | merged `*.toml` |
| `paths.sandbox_flag` | `/etc/moat/sandbox.enabled` | shims on/off |
| `paths.tetragon_socket` | `/run/tetragon/tetragon.sock` | liveness check |
| `paths.tetra` | `/usr/bin/tetra` | for `tp set-mode` |
| `paths.feeds_bin` | `/usr/bin/moat-feeds` | for `feeds refresh` |
| `paths.passwd` | `/etc/passwd` | human-user discovery |
| `paths.pacman_local` | `/var/lib/pacman/local` | provenance source; its mtime is the transaction signal |
| `paths.pacman` | `/usr/bin/pacman` | one `-Sl` per transaction, never per event |
| `rules.*` | all `true` | one toggle per userland rule (8 of them) |
| `ai.headless_allowed_parents` | `["/usr/share/omarchy/bin/omarchy-agent-usage-*"]` | ancestors allowed to launch an AI CLI headlessly; globs, matched against each ancestor's binary **and** its arguments |
| `thresholds.dedupe_secs` | 60 | fold window |
| `thresholds.mass_read_files` / `_window_secs` | 40 / 10 | mass-read rule |
| `thresholds.process_prune_secs` | 60 | how long exited processes linger |
| `thresholds.ancestry_max` | 8 | chain cap |
| `thresholds.alerts_max_bytes` | 20 MiB | rotation |
| `thresholds.state_interval_secs` / `feeds_poll_secs` | 5 / 60 | timers |
| `thresholds.arm_wait_secs` | 120 | how long to wait for the sensor to load before giving up on re-arming (§1, NOTES §7.1) |
| `net.registry_cidrs` | Fastly/GitHub/Cloudflare blocks | pkg-egress allowlist |
| `net.allow_private` | `true` | RFC1918 etc. never alert |
| `net.egress_severity` | `medium` | severity of a pkg-egress hit |
| `baseline.trusted_repos` | `["core","extra","multilib","omarchy"]` | repos whose signature makes a package `official` |
| `baseline.learning_days` | 7 | how long recurring official patterns auto-apply |
| `baseline.learn_min_days` | 3 | distinct days a tuple must recur on |
| `baseline.noisy_rule_per_day` | 20 | 24 h alerts from one pattern before that pattern is demoted |
| `baseline.provenance_downgrade` | `true` | section 2 of BASELINE |
| `learning.half_life_days` | 30 | rarity decay |
| `learning.rare_max_count` | 3 | under this many sightings a tuple is `rare` |
| `learning.rare_max_age_days` | 14 | nothing in this long puts it back to `rare` |
| `analysis.agent_args` | `{claude = ["--permission-mode","plan"]}` | advisory; see §10.3 |
| `analysis.bundle_dir` | `/var/lib/moat/incidents` | `<dir>/<alert id>/` holds the snapshot and `bundle.md` |
| `incidents.snapshot_min_severity` | `high` | `critical` narrows it, `never` switches capture off |
| `incidents.retain_days` / `retain_max` | 30 / 200 | retention, oldest first |
| `digest.enabled` | `true` | first-boot value; `state.json` wins after that |
| `digest.weekday` / `hour` | `monday` / 9 | local time, not UTC |

`/etc/moat/feeds.toml` holds the abuse.ch `auth_key` (0600) and the
endpoints; `/etc/moat/allowlist.d/default.toml` ships sensible defaults with
a comment explaining each, and `user.toml` is what `moatctl ignore` writes.

### Allowlist shape

```toml
# added 2026-09-03 from alert 01J8ZK…: Private SSH key read by an unexpected program
[[rule]]
name   = "moat-cred-ssh-private-key-read"   # or "moat-cred-*"
exe    = "/home/dan/.local/share/mise/installs/node/*/bin/node"
file   = "/home/dan/.ssh/id_rsa"
parent = "/usr/bin/restic"                      # ANY ancestor, up to 8 deep
```

All fields optional except `name`, globs allowed, and **every field present must
match**. A rule naming `file` never matches an alert without one. The comment
line directly above a `[[rule]]` is what `moatctl allowlist` shows.

---

## 7. Feeds

`moat-feeds` fetches, per the abuse.ch API docs:

| source | endpoint | method |
|---|---|---|
| MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | POST `query=get_recent&selector=time` |
| ThreatFox | `https://threatfox-api.abuse.ch/api/v1/` | POST `{"query":"get_iocs","days":N}` |
| URLhaus | `https://urlhaus-api.abuse.ch/v1/urls/recent/limit/N/` | GET |

All three require an `Auth-Key` header (free, https://auth.abuse.ch/). **With no
key configured it logs one line, exits 0, and leaves the existing files alone** —
the timer never fails and an offline machine never loses the cache it has.
Writes to `hashes.txt`, `domains.txt`, `urls.txt` and `meta.json` are atomic,
and a run where every source failed writes nothing rather than blanking the
cache. The daemon polls the mtime of `hashes.txt` every 60 s and reloads.

---

## 8. Dev mode

Nothing here needs root, Tetragon, `/etc` or `/run`: every path is a flag.

```bash
moatd run \
  --log          ./testdata/sample.log \
  --state-dir    /tmp/x \
  --socket       /tmp/x/sock \
  --policies-dir ./testdata/policies \
  --from-start
moatctl --socket /tmp/x/sock status
```

Also available: `--allowlist-dir`, `--incidents-dir`, `--sandbox-flag`, `--tetra`, `--passwd`,
`--pacman-local`, `--pacman`, `--group`, `--mode`, `--once` (drain the log and
exit), `--no-socket`, and `MOAT_CONFIG` / `MOAT_FEEDS_CONFIG` for the two config
files.

`testdata/pacman-local/` is a six-package fake of the local pacman database and
`testdata/fake-pacman` prints the `pacman -Sl` lines that go with it, so
provenance is exercised end to end without root, without pacman, and without
touching the machine's real database. Every test uses them.

`./dev-run.sh` walks the whole flow — render templates, start the daemon against
a copy of `testdata/sample.log`, `status`, `list`, `explain`, `ignore --scope
exe`, `allowlist`, `baseline list|export`, append a live line, then **start a
real child process**, describe it to the daemon as a postinstall script reading
an SSH key, and show the install receipt, the incident snapshot taken against
that live pid (masked environ included), `bundle`, `analyze --dry-run` and
`digest` — in a temp directory it cleans up on success. `cargo test --test
dev_run` runs exactly that script, so the demo cannot rot.

The snapshot step uses a live process on purpose: `/proc` is the only witness
that the capture works, and a fixture would prove nothing.

`testdata/` holds 12 synthetic export lines in the real protojson shapes (an
npm → sh → node install tree that reads an SSH key, reads AWS credentials,
connects to a shell-handler port and gets SIGKILLed; a headless auto-approved
`claude`; a dropped `/tmp/.x9k` that ptraces and sets a setuid bit), the five
templates they exercise, and their rendered forms.

---

## 9. Baselining

`docs/BASELINE.md` is the spec; this is what the code does. The product
requirement behind all of it: **a quiet day produces zero notifications**. 500
alerts a day means the user turns it off, so nothing here is a blanket
allowlist — every suppression is a specific (rule, actor) pair the user can see
in a TOML file and remove.

### 9.1 Provenance (`provenance.rs`)

| class | how it is decided |
|---|---|
| `official` | a package owns the path, that package is listed by `pacman -Sl <trusted_repos>`, and its `%VALIDATION%` is not `none` |
| `foreign` | a package owns it but no trusted repo ships it — AUR builds, `pacman -U`. **No trust**: the June 2026 AUR wave installed pacman-owned binaries |
| `user` | unowned, under a human `$HOME`, `/tmp`, `/var/tmp`, `/dev/shm`, `/opt`, `/usr/local` |
| `unknown` | anything else |

Nothing shells out per event. `/var/lib/pacman/local/*/{desc,files}` are plain
text and are parsed once into a path → package map (roughly 200 k paths on this
machine); repo membership is the one fact the local database does not hold, so
it comes from a **single** `pacman -Sl` at startup, repeated only when the mtime
of `/var/lib/pacman/local` moves — one spawn per pacman transaction. Per-path
results are cached by `(path, inode, mtime)`, so a replaced binary is
re-classified without a reload. The lister is a trait, so tests inject a fixture.

**Interpreters carry the provenance of their script.** `bash`, `sh`, `zsh`,
`dash`, `ksh`, `fish`, `python*`, `node`, `perl` and `ruby` take `argv[1]` (or
the first non-flag argument that looks like a path, resolved against the
process's cwd) and classify *that*, because an official `/usr/bin/bash` running
`/tmp/x.sh` is a `user` actor. A `-c` / `-e` / `-m` invocation is code, not a
file, so the interpreter keeps its own class. The script lands in
`actor.script`, and the timeline groups on it.

### 9.2 Context (`context.rs`)

One context per process, from the exact `exec_id` chain:

* **`pkg-install`** — inside a package-manager subtree (`rules/pkgtree.rs`).
  This **wins over `interactive`** even when the install was typed at a prompt:
  "I typed `npm install`" says nothing about what the package then did.
* **`interactive`** — the nearest root is a terminal, a multiplexer, an
  editor/IDE, or a login path.
* **`service`** — systemd, a compositor or desktop launcher, cron, D-Bus, a
  `.desktop` activation.
* **`unknown`** — the ancestry is lost; nothing is adjusted.

An AI agent CLI (`claude`, `codex`, `gemini`, `opencode`, `amp`, `q`) is
deliberately **transparent**: the walk continues past it, so an agent started
from a terminal is `interactive` and the same agent under a systemd unit is
`service`. That is exactly BASELINE §2b's "an AI agent CLI that itself has an
interactive root", and it needs no special case.

### 9.3 Scoring (`scoring.rs`)

Two adjustments, applied after the base alert is built and **before** the
allowlist and dedupe see it.

1. **Provenance** — `provenance_delta(family, rule, provenance)`. Only an
   `official` actor moves anything, and only one step:
   `persist`/`priv`/`exec`/`net` go down one; `cred`, `rootkit` and `shell`
   never move (an official binary reading your SSH key is still worth a look);
   the `pkg` and `moat-x-*` rules have a per-rule table, in which only
   `interpreter-spawn`, `pkg-egress` and `mass-read` move.
2. **Context** — `MATRIX`, the ten rows of BASELINE §2b **encoded as data** so
   they can be reviewed rather than read out of control flow. Each row names the
   event and its outcome per context: a severity, `timeline only` (severity
   `low` with `surface: "timeline"`), `nothing` (recorded, never surfaced), or
   no change. `cargo test the_context_matrix_is_reviewable -- --nocapture`
   prints the table. An event with no row falls back to the general rules:
   `interactive` takes two steps off exec/persist/priv/net and one off `cred`
   (never below `low` — credential reads are always at least visible),
   `service` and `pkg-install` take none.

Three guards make the whole thing safe to leave on:

* `pkg-install` is never downgraded, by provenance or by anything else.
* Nothing is ever *lowered* for a finding that matched a threat feed, for the
  `rootkit` family, or for the rules in `NEVER_LOWERED` (`new-exec-ioc`,
  `netcat-exec`, and moat's own meta-rules). Those are facts about an artefact,
  not judgements about a workload. When a matrix cell would have lowered one,
  the record says so instead of silently ignoring it.
* Nothing is ever *upgraded* by provenance alone. Upgrades come from context.

Everything lands on the record: `severity_base`, `severity`, `severity_reason`
(with the matrix row id), `actor`, `context`, `surface`.

### 9.4 Rarity, the learning window, the noise guard

**Rarity** (`rarity.rs`) keeps decayed counters for the four tuples of
LEARNING §1: `(actor, parent)`, `(actor, file dir)`, `(actor, dst /24 or
domain, port)`, `(pkg root, child)`. Counters update from every `process_exec`
**and** from every event that produces an alert, suppressed or not — learning
never stops; the window only controls whether a proposal auto-applies. A
sighting's decayed weight halves every `half_life_days`; raw totals never decay,
so "seen 41 times since Aug 12" stays honest. Persisted to
`/var/lib/moat/rarity.json`, atomically, every 60 s and on shutdown, with cold
counters pruned. Rarity **never changes a severity**; it is evidence, and it
gates proposals.

**The learning window** (`baseline.rs`). `installed_at` is stamped in
`state.json` on the first run and never moved again. For `learning_days` (7)
after it, a `(rule, actor exe, parent exe, file dir)` tuple that produces
**medium or low** alerts from an **official** actor on `learn_min_days` (3)
distinct days, with `common` rarity, is written straight to
`/etc/moat/allowlist.d/baseline.toml` with a comment recording the counts, the
dates and the word `learned`. High and critical are never learned — and one high
anywhere in a tuple's history disqualifies it for good. Foreign and user actors
are never learned. Neither are moat's own meta-rules, or a tuple an allowlist
entry already covers. After the window the same condition produces a
**proposal** in `state.json.proposals[]` carrying the exact TOML that accepting
would write.

**The rule tier.** A rule can declare itself a **building block** rather than a
detection: `moat.omarchy/tier: "signal"` on a policy, `rules::signal_meta` for a
userland rule (BASELINE §4a). A `signal` rule keeps its severity, is recorded in
full, and is a full trigger for `chain.rs` — it just never reaches the badge on
its own, takes no incident snapshot and is never queued for triage. Two things
put one on the badge anyway: the §2b matrix escalating it inside a `pkg-install`
(a `/tmp` exec inside a package install IS a detection), and a chain that
reached `high` re-stamping it. Seven rules carry it, and they are exactly the
set the old fan-out demotion kept rediscovering.

**The noise guard.** More than `noisy_rule_per_day` (20) alerts from one
**(rule, exe, parent, dir) pattern** in a rolling 24 h (hourly buckets) demotes
that pattern: it keeps writing to `alerts.jsonl`, it just stops being an
Alerts-tab item, and the daemon restamps the backlog the demotion covers. One
`moat-x-noisy-rule` alert at medium names the rule's top five tuples and offers
two `if_expected` options — `these-are-expected` (`moatctl baseline propose
--rule …`, which proposes baseline entries for exactly those tuples) and
`keep-watching` (`moatctl baseline undemote …`). The demotion clears itself
after 24 h under the threshold.

Three kinds of alert never count towards it: suppressed ones (the user already
answered), `signal`-tier ones (the rule already said it is not a conclusion),
and anything the severity table keeps off the badge anyway. And a demotion never
moves a **package-install escalation** to the timeline — the guard's arithmetic
is about how often a shape fires on this machine, which says nothing about what
a package install did.

There is **no rule-wide demotion**. The old fan-out backstop silenced a whole
rule once five of its patterns had gone quiet, including shapes nobody had ever
seen; on 2026-09-04 that hid a real `/tmp` dropper inside a package install.
Past `noisy_rule_fanout` (5) quiet patterns the `moat-x-noisy-rule` alert now
*says* the rule itself is the problem — retune it, or declare it `signal` —
and silences nothing further.

### 9.5 Revocation

Learned entries are re-checked whenever the pacman database moves. If the
actor's provenance is no longer `official`, the entry is **commented out in
place** in `baseline.toml` with a `# DISABLED <ts>: <reason>` header — deleting
it would hide the fact that moat once trusted it — and a low
`moat-x-baseline-revoked` alert says why.

### 9.6 CLI

```
moatctl baseline list                    window state, proposals, learned, demoted
moatctl baseline accept <id>             write the proposal to baseline.toml
moatctl baseline dismiss <id>            drop it and stop asking
moatctl baseline relearn [--days N]      restart the window
moatctl baseline export [--since DATE] [--json]
moatctl baseline propose --rule <r> [--top N]
moatctl baseline undemote <rule>
moatctl unignore <n> [--file baseline.toml]
```

`export` is LEARNING §8 step 1: every `(rule, actor exe, actor provenance,
parent exe, file dir, context)` tuple with its count, distinct days, first/last
seen, severity and rarity. Suppressed and demoted tuples are **included and
marked**, and each row carries the TOML it would become and an `eligible` flag
that is true only for `official` provenance — nothing else is ever shipped.

### 9.7 What `status` gains

```json
"installed_at": "2026-09-03T18:56:31.000Z",
"baseline": {"learning": true, "learning_ends": "…", "proposals": 0,
             "learned": 0, "demoted": []},
"proposals": [ {"id","rule","exe","parent","dir","count","days",
                "first_seen","last_seen","toml"} ],
"demoted_rules": [],
"alerts_suppressed": 0,
"rarity_counters": 14,
"provenance": {"packages": 6, "files": 8, "trusted_repos": [...]}
```

and, from LEARNING §5 and §9:

```json
"digest": true,                       // the switch the plugin binds to
"digest_enabled": true,               // the name LEARNING §5 gives it
"digest_summary": {"due": "…", "text": "moat: 0 incidents, 18 installs watched, …",
                   "enabled": true, "last_sent": null, "weekday": "monday", "hour": 9},
"incidents": 3,                       // snapshots on disk
"incidents_dir": "/var/lib/moat/incidents",
"receipts": 18                        // install receipts written
```

---

## 10. Analysis: receipts, snapshots, bundles, digest

`docs/LEARNING-AND-ANALYSIS.md` §2-§5 is the spec; this is what the code does.

### 10.1 Install receipts (`receipt.rs`, LEARNING §3)

Every alert is a negative. A receipt is the positive picture — the thing a
developer actually wants after `npm install`:

```
npm install in /home/dan/Projects/app (41 s, exit 0)
  postinstall scripts: 3 (esbuild, sharp, husky)
  wrote outside the project: /home/dan/.npm/_cacache, /home/dan/.cache/prisma
  network: registry.npmjs.org, github.com
  credential reads: none · persistence writes: .husky/pre-commit (alerted, low)
  binaries executed from the tree: 12 · from /tmp: 0
```

One accumulator per package-manager subtree (`rules/pkgtree.rs`), opened the
first time anything in that tree is seen and closed on the root's
`process_exit`, written as `{"v":1,"receipt":{…}}` — its own line kind in
`alerts.jsonl` (LEARNING §9). `parse_record` returns `None` for it, so **no
alert reader can mistake a receipt for an alert**: they never notify, never
count, never dedupe and have no actions.

What lands in one:

* `postinstall_scripts` — the `node_modules/<name>` a child came out of
  (`@scope/pkg` kept whole, `.bin` and the other dot-directories excluded
  because they are npm's bookkeeping, not packages), or the script path an
  interpreter was handed;
* `writes_outside_project` — directories only, deduped, from persist/cred write
  findings attributed to the subtree. Writes *inside* the worktree are what
  installs do;
* `network`, `credential_reads`, `persistence_writes` (`{path, alerted,
  severity}` — `alerted: false` means an allowlist entry covered it, and the
  write still happened);
* `execs_from_tree` / `execs_from_tmp` — counted from execs, which is where most
  of an install's behaviour is and where no alert is raised at all.

Only the **outermost** root closes a receipt, so a mise shim, the npm it execs
and a nested `npm run build` are one install with one id. Every list is capped
at 64 entries, and an install whose exit line never arrives is dropped after
six hours rather than leaking.

### 10.2 Incident snapshots (`incident.rs`, LEARNING §4)

On every alert at or above `[incidents] snapshot_min_severity` (default `high`,
`never` switches it off), **before any kill**, into `<bundle_dir>/<alert id>/`
at 0750 root:moat:

| file | contents |
|---|---|
| `process.json` | `status`, `cmdline`, `environ` (masked), `cwd`, exe target and the fd list with socket peers — for the process **and every live ancestor** |
| `tree.txt` | the chain as the daemon's own `exec_id` table saw it, with argv and cwd |
| `net.txt` | the tree's sockets, parsed out of `/proc/net/{tcp,tcp6,udp,udp6}` |
| `file/` | the executed binary (≤ 8 MB, read through `/proc/<pid>/exe` so a deleted dropper is still caught) and the alerted file (≤ 1 MB, only under `$HOME` or a temp dir) |
| `pkg.json` | in `pkg-install` context: the lockfiles in the cwd, and the `node_modules/<name>/package.json` (`name`, `version`, `_resolved`, `scripts`) that owns the acting script |
| `meta.json` | the alert, what was copied from where, the file list with sha256, and every step that failed |

Four decisions worth knowing:

* **Ordering.** The id is allocated before enforcement, the capture runs, *then*
  the kill, *then* the alert line, *then* an `{"incident":{dir,files}}` update
  line. In enforce mode the process is seconds from not existing; in monitor
  mode the environment of a postinstall script is gone the moment it exits.
* **Best effort, loudly.** Every step is individually fallible: not being root,
  a process that exited mid-capture, a file that vanished. Each failure is
  caught, logged, and written into `meta.json` — the capture never blocks or
  fails an alert, and a snapshot that is missing something says so.
* **No `ss`.** `net.txt` is parsed from `/proc/net`, so a snapshot never depends
  on a tool being installed or on `$PATH` at the moment of an incident. The
  hex-address decoding (including IPv6's four little-endian groups) has its own
  tests against a fixture.
* **Masking.** `environ` is exactly where the token the attacker wanted lives.
  A value is replaced with `<masked: N chars>` when its key contains
  token/secret/key/password/auth/credential/session/cookie, **or** when the
  value itself looks like a credential whatever the key is (`ghp_`, `sk-`,
  `AKIA`, `xox`, `eyJ`, `glpat-`, a PEM header, or a long unbroken base64-ish
  blob). Snapshots are group-readable; they must not become the second copy of
  your GitHub token.

Retention (`retain_days`, `retain_max`, oldest first — ids are ULIDs, so
lexicographic order is chronological) runs after every capture, so the cap holds
on a machine that never restarts the daemon.

### 10.3 Bundle and analyze (`bundle.rs`, `analysis.rs`, LEARNING §2)

`moatctl bundle <id>` writes `<incidents dir>/<id>/bundle.md` (0640, group
readable): the five explain blocks, the full ancestry with args and cwd,
provenance and context, the rarity sentences, the policy's `why` and `expected`,
every ignore option with its exact command and TOML, the related timeline
(alerts *and* receipts from the same process tree, ±5 min), the incident
snapshot's file list, and the current mode.

**Every process-derived string is wrapped in a ```` ```DATA ```` fence**, and the
fence grows past any backtick run inside the content, so a payload carrying
```` ``` ```` cannot close the block and escape into instruction position. This
is not decoration: the s1ngularity attack drove the victim's own AI CLIs, and an
alert about a malicious postinstall must not become an injection channel into
the agent analysing it.

`moatctl analyze <id>` bundles, reads `omarchy default agent` (and says exactly
how to set one if there is none — the bundle is written either way), and execs

```
omarchy-agent --prompt "<the fixed preamble of LEARNING §2 step 2, naming the bundle path>"
```

The prompt is the **path**, never the content: the agent opens the file itself,
and the preamble tells it that everything inside a `DATA` fence is untrusted and
that `kill`, `quarantine` and `ignore` are to be proposed, not run.

**The daemon never launches an agent.** It runs as root with no session and no
terminal; `{"cmd":"analyze"}` only bundles and hands back the preamble, and
`moatctl` — in the user's session, with no privilege at all — does the exec.

**`agent_args` cannot reach the agent, and moat says so.**
`/usr/share/omarchy/bin/omarchy-agent` parses exactly `--inline`, `--pick` and
`--prompt`, rejects anything else with "Unexpected argument", and builds each
agent's command line itself (`claude --permission-mode auto`, `codex
--approve-for-me`, …). There is no pass-through argument and no environment
variable, and forking a script the package owns is not an option. So
`[analysis] agent_args` is advisory: `moatctl analyze` prints the equivalent
direct command (`claude --permission-mode plan …`) and launches anyway, rather
than dropping a configured setting in silence. If `omarchy-agent` ever grows a
pass-through, that note is the only thing that has to change.

### 10.4 The weekly digest (`digest.rs`, LEARNING §5)

> moat: 0 incidents, 18 installs watched, 3 baseline proposals to review

The only scheduled notification moat ever sends, and its purpose is to say the
thing is on and working — which is why it counts what was *watched*, not only
what was wrong. Incidents are the week's unsuppressed high/critical alerts,
installs are the week's receipts, proposals is the current queue.

Who does what:

* the **daemon** computes it and publishes it in `state.json` as
  `digest_summary = {due, text, enabled, last_sent, …}`, plus the boolean
  `digest` that LEARNING §9 puts in `status`. It sends nothing.
* the **user timer** `systemd/user/moat-digest.timer` runs `moatctl digest
  --notify` weekly, which calls `omarchy-notification-send -u normal` and then
  reports the delivery back (`{"cmd":"digest","action":"sent"}`) so a catch-up
  run after a suspend does not send twice. It is a *user* unit because desktop
  notifications belong to the user's session bus, and because `moatctl` needs no
  privilege.
* the **plugin** can show the same block without the timer, since it is in
  `state.json` either way.

`moatctl set digest off` flips `state.json.digest_enabled`; the timer keeps
firing and `--notify` then does nothing, so switching it off needs neither root
nor `systemctl`. `due` is computed in **local** time: "Monday 9am" is a promise
about the user's morning.

### 10.5 The shipped baseline (`etc/allowlist.d/omarchy-default.toml`)

BASELINE §5's "moat's own build and tests are not incidents", and nothing wider.
Four entries: `moat-exec-untrusted-tmpfs` and `moat-pkg-subtree-netcat-exec`,
each for `/tmp/.tmp*/nc` and `/tmp/.tmp*/moat-*`, each requiring
`parent = "*/target/*/deps/moatd-*"` — the hashed binary cargo builds for the
test suite. All three fields must match, so the same binary run from a shell,
or a real dropper in `/tmp`, still alerts. The loader reports the file as
`source: shipped`, `removable: false`, and `unignore` refuses it: to override
one, write a narrower rule in `user.toml`.

### 10.6 CLI

```
moatctl receipts [--last N] [--json]      what installs actually did
moatctl incidents [--last N]              the snapshots on disk, with hashes
moatctl bundle <id> [--json]              write bundle.md, print its path
moatctl analyze <id> [--dry-run]          bundle + hand it to your agent
moatctl rarity <id>                       how unusual this tuple is here
moatctl digest [--notify] [--force]       the weekly summary; --notify is the timer
moatctl set digest on|off                 the only scheduled notification, switched
```

---

## 11. Layout

```
src/
  config.rs     moat.toml + every path override
  render.rs     render-policies: {{HOME}} expansion, export-allowlist
  policy.rs     rendered-policy annotations (severity/title/why/…)
  tail.rs       rotation- and truncation-safe line tailer
  event.rs      Tetragon protojson event structs
  proctable.rs  exec_id -> process, parent chain capped at 8
  allowlist.rs  allowlist.d parsing, glob matching, append/remove
  alert.rs      the alert record and update folding
  explain.rs    what / why / evidence / if_expected / next
  selectors.rs  re-validating a kernel match against the policy's own filter
  provenance.rs official / foreign / user / unknown, from the pacman database
  context.rs    interactive / pkg-install / service / unknown, from the ancestry
  scoring.rs    the provenance table and the context matrix (BASELINE §2, §2b)
  rarity.rs     decayed per-tuple counters -> first_seen / rare / common
  baseline.rs   the learning window, proposals, the noise guard
  rules/        ai_cli, pkg_egress, new_exec_ioc, mass_read, netmatch,
                pkgtree (package-subtree classifier), pkg_subtree (the four
                rules that replaced the deleted pkg policies)
  receipt.rs    install receipts: what a package subtree actually did
  incident.rs   the pre-kill snapshot: /proc, /proc/net, file copies, masking
  bundle.rs     bundle.md, with every process string in a ```DATA fence
  analysis.rs   the agent preamble; how moatctl launches the default agent
  digest.rs     the weekly summary and when it is next due
  store.rs      append-only alerts.jsonl with rotation
  control.rs    the socket protocol and every command
  engine.rs     shared state and the run loop
  feeds.rs      abuse.ch fetch + local feed cache
  util.rs       atomic writes, /proc, hashing, human homes
  bin/          moatd, moatctl, moat-feeds
systemd/        moatd.service, moat-feeds.{service,timer},
                user/moat-digest.{service,timer}, sysusers.d/, tmpfiles.d/
etc/            moat.toml, feeds.toml,
                allowlist.d/{default,omarchy-default}.toml
testdata/       sample.log, policies, templates, passwd, plus a fake pacman
                local database and a `pacman -Sl` stand-in for provenance
```

308 tests: unit tests beside each module, plus `tests/dev_run.rs`.
