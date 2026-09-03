# sentineld

The userspace half of **omarchy-sentinel**. Tetragon (upstream, unmodified,
v1.7.1) does the kernel work and writes a JSON-lines export file; everything
here reads that file, adds the context the kernel cannot keep, and turns matches
into alerts a developer can act on without opening a second terminal.

Three binaries from one crate:

| binary           | what it does                                                        |
|------------------|---------------------------------------------------------------------|
| `sentineld`      | `render-policies` (ExecStartPre) and `run` (the daemon)             |
| `sentinelctl`    | thin CLI over the control socket                                    |
| `sentinel-feeds` | hourly abuse.ch indicator fetch                                     |

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
  /var/log/sentinel/tetragon.log
                              │
          ┌───────────────────┴──────────────────┐
          │ tail thread (200 ms poll)            │   thread 2: control socket
          │                                      │   /run/sentinel/control.sock
          │  1. parse (event.rs)                 │   accept → one JSON request
          │  2. process table (proctable.rs)     │   → one JSON response
          │  3. policy findings + userland rules │            │
          │  4. allowlist → dedupe → alert       │            │
          │  5. append alerts.jsonl              │◄───────────┘  shared Mutex<Daemon>
          │  6. every 5 s: prune + state.json    │
          │  7. every 60 s: reload feeds if new  │
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

4. **Detection.** A hook event whose `policy_name` starts with `sentinel-`
   becomes a finding, using the annotations of the rendered policy of the same
   name (`policy.rs`). Everything else is enrichment only. In parallel the four
   userland rules (`rules/`) see every exec and every hook.

5. **Allowlist → dedupe → alert** (`allowlist.rs`, `explain.rs`, `store.rs`).
   A finding matching any `[[rule]]` in `/etc/sentinel/allowlist.d/*.toml` is
   dropped. Otherwise the same rule+exe+file within 60 s folds into a `count`
   update line, and anything else becomes a new alert with a ULID, appended to
   `alerts.jsonl`.

6. **Kill confirmation.** Monitor mode still reports
   `"action":"KPROBE_ACTION_SIGKILL"` (TETRAGON-NOTES §7), so the action field
   is *not* proof. `action_taken` only becomes `killed` when a `process_exit`
   for that same `exec_id` arrives carrying `"signal":"SIGKILL"`.

### Signals

| signal            | effect                                                     |
|-------------------|------------------------------------------------------------|
| `SIGHUP`          | re-read sentinel.toml, policy annotations, allowlist.d      |
| `SIGTERM`/`SIGINT`| write state.json, remove the socket, exit 0                 |

`systemctl reload sentineld` sends the HUP. The process table survives a reload.

---

## 2. `sentineld render-policies`

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
{"event_set":["PROCESS_KPROBE","PROCESS_LSM","PROCESS_TRACEPOINT","PROCESS_UPROBE"],"policy_names":["sentinel-…", …]}
```

Line 1 keeps exec/exit (they carry no `policy_name`, and without them there is
no ancestry). Line 2 lists **exact** names, because `policy_names` has no glob
and no prefix match (gap 8). That is why it is regenerated on every render.

```
sentineld render-policies \
  --templates-dir /usr/lib/sentinel/policies \
  --out-dir       /run/sentinel/policies \
  --export-allowlist /etc/tetragon/tetragon.conf.d/export-allowlist
```

`--home /home/x` (repeatable) overrides passwd discovery; `--json` prints a
machine-readable report; `--export-allowlist ''` skips the conf.d write.

---

## 3. Detections

### Policy-driven (`sentinel-<family>-<rule>`)

Severity, title, `why`, `expected`, `rotate` and `fp-hint` all come from the
policy's `sentinel.omarchy/*` annotations (CONTRACT §3). A policy with no
annotations still produces a usable alert, it just says so.

### Userland rules (`sentinel-x-*`)

These are the gaps a TracingPolicy cannot express. Each has a toggle in
`[rules]` and its own tests.

| rule                         | fires when                                                                                     | severity |
|------------------------------|------------------------------------------------------------------------------------------------|----------|
| `sentinel-x-ai-cli-headless` | an AI CLI (`claude`,`codex`,`gemini`,`opencode`,`q`,`amp`) has no terminal/tmux/ssh/editor **and** no interactive shell outside a package subtree in its ancestry | high |
|                              | …or carries `--dangerously-skip-permissions`/`--yolo`/`--trust-all-tools`/`--full-auto` while its parent is an interpreter inside a package install | critical |
| `sentinel-x-pkg-egress`      | a package-manager subtree connects to an address that is neither private nor in `net.registry_cidrs` | medium (configurable) |
| `sentinel-x-new-exec-ioc`    | the sha256 of an executed file under `$HOME`,`/tmp`,`/var/tmp`,`/dev/shm` is in `feeds/hashes.txt` | critical |
| `sentinel-x-mass-read`       | one process reads more than `mass_read_files` distinct files under `$HOME` dotdirs within `mass_read_window_secs` | high |

Two deliberate design notes:

* a bare `sh`/`bash` in the ancestry is **not** an interactive shell when a
  package manager is above it — npm spawns one for every lifecycle script;
* `pkg-egress` is medium, not high, because CDN address space moves and the
  allowlist is necessarily coarse: there is no DNS in the kernel and no hostname
  in the export (gap 4).

---

## 4. Alerts

`alerts.jsonl`, 0640 root:sentinel, append only, rotated to `alerts.1.jsonl` at
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
  `parent`, `rule`), each with the ready-to-run `sentinelctl ignore` command and
  the **exact TOML block** that command would write. The recommended scope
  (`fp-hint`) is first. `exe+file` is omitted for alerts with no file, and
  `parent` for alerts with no recorded ancestry, because a rule that can never
  match is a footgun;
* **next** — response steps: stop it, rotate each named secret (a table covers
  `ssh-key`, `github-token`, `npm-token`, `aws`, `gh`, `claude`, `gpg`,
  `keyring`, `browser`, `docker`, `kube`), plus context lines for package
  installs, dropped files and network destinations.

---

## 5. Control socket

`/run/sentinel/control.sock`, 0660 root:sentinel, newline-delimited JSON, one
request → one response per connection.

**Every action names an alert id, never a raw pid or path.** That is what makes
the socket safe to hand to the user's group: a hostile process cannot use
sentineld to kill or move something the sensor did not already flag.

| request | response (on success) |
|---|---|
| `{"cmd":"status"}` | version, mode, tetragon, policies, policies_failed, feeds, unacked, sandbox, socket_group |
| `{"cmd":"list","since":"<ULID>","limit":100}` | `alerts: [...]`, updates folded |
| `{"cmd":"explain","id":"…"}` | `alert: {...}` with the full explain block |
| `{"cmd":"ack","id":"…"}` | appends `{"acked":true}` |
| `{"cmd":"kill","id":"…"}` | `killed: [pids]` — descendants first, then the pid |
| `{"cmd":"quarantine","id":"…"}` | `from`, `to` |
| `{"cmd":"ignore","id":"…","scope":"exe\|exe+file\|parent\|rule","comment":"…"}` | `block` (the exact TOML written), and the alert is acked |
| `{"cmd":"unignore","rule":2}` | `removed` (the block text) |
| `{"cmd":"allowlist"}` | merged rules with index, file, comment and TOML |
| `{"cmd":"set","key":"mode","value":"monitor\|enforce"}` | `applied`, `failed[]` |
| `{"cmd":"set","key":"sandbox","value":"on\|off"}` | `sandbox` |
| `{"cmd":"feeds","action":"refresh"}` | exit status and the new feed counts |

Failures are `{"ok":false,"error":"…"}`; `sentinelctl` exits 2 on those and 3
when it cannot reach the socket at all.

Two safety behaviours worth knowing:

* **kill** re-verifies the target before signalling: `/proc/<pid>` start time
  must be within 2 s of the alert's `start_ts` *and* `/proc/<pid>/exe` must
  still match. A recycled pid is refused, not killed.
* **quarantine** refuses any path outside `$HOME`, `/tmp`, `/var/tmp`,
  `/dev/shm`. It moves the file into `/var/lib/sentinel/quarantine/<alert id>/`,
  chmods it `000`, and writes a `meta.json` recording the original path, the
  sha256, and the command to restore it.

`set mode` runs `tetra tp set-mode <name> monitor|enforce` for every loaded
policy (immediate, no reload — NOTES §7) and persists the choice in
`state.json`, since the export cannot tell us the current mode.

---

## 6. Configuration

`/etc/sentinel/sentinel.toml` — every key is optional and an unknown key is an
error, so a typo is loud. See the shipped `etc/sentinel.toml` for the commented
version; the reference:

| key | default | meaning |
|---|---|---|
| `group` | `sentinel` | owns the socket and alerts.jsonl |
| `mode` | `monitor` | first-boot mode; `state.json` wins after that |
| `paths.tetragon_log` | `/var/log/sentinel/tetragon.log` | the export to tail |
| `paths.policies_dir` | `/run/sentinel/policies` | rendered policies |
| `paths.templates_dir` | `/usr/lib/sentinel/policies` | `{{HOME}}` templates |
| `paths.export_allowlist` | `/etc/tetragon/tetragon.conf.d/export-allowlist` | generated |
| `paths.state_dir` | `/var/lib/sentinel` | alerts, state, quarantine, feeds |
| `paths.socket` | `/run/sentinel/control.sock` | |
| `paths.allowlist_dir` | `/etc/sentinel/allowlist.d` | merged `*.toml` |
| `paths.sandbox_flag` | `/etc/sentinel/sandbox.enabled` | shims on/off |
| `paths.tetragon_socket` | `/run/tetragon/tetragon.sock` | liveness check |
| `paths.tetra` | `/usr/bin/tetra` | for `tp set-mode` |
| `paths.feeds_bin` | `/usr/bin/sentinel-feeds` | for `feeds refresh` |
| `paths.passwd` | `/etc/passwd` | human-user discovery |
| `rules.*` | all `true` | one toggle per userland rule |
| `thresholds.dedupe_secs` | 60 | fold window |
| `thresholds.mass_read_files` / `_window_secs` | 40 / 10 | mass-read rule |
| `thresholds.process_prune_secs` | 60 | how long exited processes linger |
| `thresholds.ancestry_max` | 8 | chain cap |
| `thresholds.alerts_max_bytes` | 20 MiB | rotation |
| `thresholds.state_interval_secs` / `feeds_poll_secs` | 5 / 60 | timers |
| `net.registry_cidrs` | Fastly/GitHub/Cloudflare blocks | pkg-egress allowlist |
| `net.allow_private` | `true` | RFC1918 etc. never alert |
| `net.egress_severity` | `medium` | severity of a pkg-egress hit |

`/etc/sentinel/feeds.toml` holds the abuse.ch `auth_key` (0600) and the
endpoints; `/etc/sentinel/allowlist.d/default.toml` ships sensible defaults with
a comment explaining each, and `user.toml` is what `sentinelctl ignore` writes.

### Allowlist shape

```toml
# added 2026-09-03 from alert 01J8ZK…: Private SSH key read by an unexpected program
[[rule]]
name   = "sentinel-cred-ssh-private-key-read"   # or "sentinel-cred-*"
exe    = "/home/dan/.local/share/mise/installs/node/*/bin/node"
file   = "/home/dan/.ssh/id_rsa"
parent = "/usr/bin/restic"                      # ANY ancestor, up to 8 deep
```

All fields optional except `name`, globs allowed, and **every field present must
match**. A rule naming `file` never matches an alert without one. The comment
line directly above a `[[rule]]` is what `sentinelctl allowlist` shows.

---

## 7. Feeds

`sentinel-feeds` fetches, per the abuse.ch API docs:

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
sentineld run \
  --log          ./testdata/sample.log \
  --state-dir    /tmp/x \
  --socket       /tmp/x/sock \
  --policies-dir ./testdata/policies \
  --from-start
sentinelctl --socket /tmp/x/sock status
```

Also available: `--allowlist-dir`, `--sandbox-flag`, `--tetra`, `--passwd`,
`--group`, `--mode`, `--once` (drain the log and exit), `--no-socket`, and
`SENTINEL_CONFIG` / `SENTINEL_FEEDS_CONFIG` for the two config files.

`./dev-run.sh` walks the whole flow — render templates, start the daemon against
a copy of `testdata/sample.log`, `status`, `list`, `explain`, `ignore --scope
exe`, `allowlist`, append a live line, shut down — in a temp directory it
cleans up on success. `cargo test --test dev_run` runs exactly that script, so
the demo cannot rot.

`testdata/` holds 12 synthetic export lines in the real protojson shapes (an
npm → sh → node install tree that reads an SSH key, reads AWS credentials,
connects to a shell-handler port and gets SIGKILLed; a headless auto-approved
`claude`; a dropped `/tmp/.x9k` that ptraces and sets a setuid bit), the five
templates they exercise, and their rendered forms.

---

## 9. Layout

```
src/
  config.rs     sentinel.toml + every path override
  render.rs     render-policies: {{HOME}} expansion, export-allowlist
  policy.rs     rendered-policy annotations (severity/title/why/…)
  tail.rs       rotation- and truncation-safe line tailer
  event.rs      Tetragon protojson event structs
  proctable.rs  exec_id -> process, parent chain capped at 8
  allowlist.rs  allowlist.d parsing, glob matching, append/remove
  alert.rs      the alert record and update folding
  explain.rs    what / why / evidence / if_expected / next
  rules/        ai_cli, pkg_egress, new_exec_ioc, mass_read, netmatch
  store.rs      append-only alerts.jsonl with rotation
  control.rs    the socket protocol and every command
  engine.rs     shared state and the run loop
  feeds.rs      abuse.ch fetch + local feed cache
  util.rs       atomic writes, /proc, hashing, human homes
  bin/          sentineld, sentinelctl, sentinel-feeds
systemd/        sentineld.service, sentinel-feeds.{service,timer},
                sysusers.d/, tmpfiles.d/
etc/            sentinel.toml, feeds.toml, allowlist.d/default.toml
```

133 tests: unit tests beside each module, plus `tests/dev_run.rs`.
