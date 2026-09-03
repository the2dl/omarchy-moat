# omarchy-moat interface contract

Every component is built by a different agent in parallel. This file is the only
shared truth. If you need to change something here, change it here first and say
so in your final report. Do not commit to git; the coordinator commits.

## 1. Components and who owns which directory

| Dir          | Artifact                                    | Language | Runs as |
|--------------|---------------------------------------------|----------|---------|
| `pkg/`       | PKGBUILD for system package `omarchy-moat` | bash   | -       |
| `policies/`  | Tetragon TracingPolicy YAML                  | yaml     | kernel  |
| `moatd/` | `moatd`, `moatctl`, `moat-feeds` | Rust     | root / user |
| `sandbox/`   | `moat-sandbox`, PATH shims               | bash     | user    |
| `scanner/`   | `moat-scan-pkgbuild`                     | python3  | user    |
| `shell/` + `manifest.json` | omarchy-shell plugin           | QML/JS   | user (inside omarchy-shell) |

Tetragon itself is **upstream, unmodified**, v1.7.1, from
`https://github.com/cilium/tetragon/releases/download/v1.7.1/tetragon-v1.7.1-amd64.tar.gz`
(sha256 published next to it as `.sha256sum`). We never fork it.

## 2. Filesystem layout after `pacman -U omarchy-moat`

```
/usr/bin/tetragon                          upstream daemon
/usr/bin/tetra                             upstream CLI
/usr/lib/tetragon/bpf/*.o                  upstream CO-RE probes (94 files)
/usr/lib/tetragon/{bpftool,gops}           upstream helpers
/etc/tetragon/tetragon.conf.d/             one flag per file (Tetragon convention):
    bpf-lib                = /usr/lib/tetragon/bpf
    tracing-policy-dir     = /run/moat/policies
    parents-map-enabled    = true                 (needed by matchParentBinaries)
    export-filename        = /var/log/moat/tetragon.log
    export-file-max-size-mb= 50
    export-file-max-backups= 3
    export-allowlist       = (see policies agent; filter to our policies + exec/exit)
    server-address         = unix:///run/tetragon/tetragon.sock
    metrics-server         =                     (empty: disabled)
    gops-address           =                     (empty: disabled)
    log-format             = json
/usr/lib/moat/policies/*.yaml          policy TEMPLATES from policies/ ({{HOME}} placeholder)
/run/moat/policies/*.yaml              rendered policies; tracing-policy-dir points here.
                                           `moatd render-policies` (ExecStartPre of
                                           tetragon.service) expands {{HOME}} into one value
                                           per human user home (uid >= 1000 in /etc/passwd,
                                           home under /home or /var/home), writes the files,
                                           and regenerates the export-allowlist conf.d file
                                           with the exact policy names (Tetragon has no
                                           prefix match and no policy hot-reload).
/etc/moat/moat.toml                moatd config (root:root 0644)
/etc/moat/allowlist.d/*.toml           user-editable allowlists, merged
/etc/moat/feeds.toml                   feed URLs, optional abuse.ch auth key
/etc/moat/sandbox.conf                 sandbox deny/allow paths
/etc/moat/scanner-allow.conf           PKGBUILD scanner allow file (host=/rule=/pkg=),
                                           root:root 0644, commented example; the user
                                           copy is ~/.config/moat/scanner-allow.conf
/usr/bin/moatd  /usr/bin/moatctl  /usr/bin/moat-feeds
/usr/bin/moat-sandbox  /usr/bin/moat-scan-pkgbuild
/usr/lib/moat/shims/{npm,npx,pnpm,yarn,bun,pip,pip3,uv,cargo,makepkg}
/etc/profile.d/moat-shims.sh           prepends shim dir to PATH iff
                                           /etc/moat/sandbox.enabled exists
/usr/lib/systemd/system/tetragon.service   hardened, After=local-fs
/usr/lib/systemd/system/moatd.service  Requires+After tetragon
/usr/lib/systemd/system/moat-feeds.{service,timer}   hourly, RandomizedDelaySec=10min
/usr/lib/sysusers.d/moat.conf          creates group `moat`
/usr/lib/tmpfiles.d/moat.conf          /var/lib/moat 0750 root:moat
                                           /var/log/moat 0750 root:moat
                                           /run/moat     0750 root:moat
                                           /var/lib/moat/quarantine 0700 root:root
/var/lib/moat/alerts.jsonl             0640 root:moat, append-only
/var/lib/moat/state.json               0640 root:moat, daemon status
/var/lib/moat/feeds/{hashes.txt,domains.txt,urls.txt,meta.json}
/run/moat/control.sock                 0660 root:moat
```

Post-install, the user runs `sudo usermod -aG moat $USER` and re-logs in.
The plugin must detect a missing group membership and show a setup hint.
The package `.install` file prints these steps; it does not enable services.

## 3. Policy conventions (policies/ ↔ moatd)

Each file in `policies/` is one `TracingPolicy` (not the namespaced kind).

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: moat-cred-ssh-private-key-read      # moat-<family>-<rule>, kebab
  annotations:
    moat.omarchy/severity: high              # critical | high | medium | low
    moat.omarchy/title: "Private SSH key read by an unexpected program"
    moat.omarchy/rotate: "ssh-key"           # comma list of secret kinds, optional
    moat.omarchy/enforce: "kill"             # kill | none. What the policy does in
                                                 # enforce mode. Monitor mode never kills.
    moat.omarchy/actions: "kill,quarantine"  # what the UI may offer
    moat.omarchy/why: >-                     # REQUIRED. One or two sentences a
      Private keys are the first thing npm and PyPI stealers read; only ssh, git and
      a few tools ever need them.                #   developer reads to understand the flag
    moat.omarchy/expected: >-                # REQUIRED. When this fires legitimately
      Backup tools, IDE git integrations, and custom scripts that call ssh libraries.
    moat.omarchy/fp-hint: "exe"              # best ignore scope for a false positive:
                                                 #   exe | exe+file | rule | parent
spec: ...
```

Families: `cred`, `pkg` (package-manager process trees), `persist`, `shell`
(reverse shells), `rootkit`, `priv` (suid/setcap/ptrace), `ai` (AI CLI abuse),
`net` (suspicious egress), `exec` (new binaries in $HOME,/tmp,/dev/shm).

Tetragon events carry `policy_name` on `process_kprobe`, `process_lsm`,
`process_tracepoint`, `process_uprobe`. moatd reads
`/run/moat/policies/*.yaml` (the rendered set) at start (and on SIGHUP) to map policy name →
annotations. An event whose policy name does not start with `moat-` is
ignored for alerting but still available for enrichment (exec/exit).

Enforce vs monitor (verified in docs/TETRAGON-NOTES.md §7): policies carry their
`matchActions` (Sigkill / Override) and set `spec.options: [{name: policy-mode,
value: monitor}]` so the default is monitor. moatd runs `tetra tp set-mode
<name> monitor|enforce` for every `moat-*` policy at start and when
`moatctl set mode` changes it; set-mode takes effect immediately. In monitor
mode the event STILL reports `action: KPROBE_ACTION_SIGKILL`; moatd must
confirm a kill from the matching `process_exit` with `signal: SIGKILL` before
recording `action_taken: killed`.

Paths: Tetragon has Prefix/Postfix/Equal only, no middle wildcard, so policies
are templates using `{{HOME}}` (e.g. `{{HOME}}/.ssh/`) that `moatd
render-policies` expands into one value per user home. See section 2.

Everything about Tetragon's grammar, hooks, flags and JSON shape is in
docs/TETRAGON-NOTES.md. That file wins over guesses. Its "Gaps" section lists
what moatd must do in userland.

Allowlisting lives in policies where Tetragon supports it (matchBinaries,
matchArgs, matchPIDs) AND in moatd (`/etc/moat/allowlist.d`) for what
Tetragon cannot express (ancestry beyond one level, session context). Both
agents document their side.

## 4. Alert record (moatd → alerts.jsonl → plugin)

One JSON object per line, UTF-8, no pretty printing. Fields:

```json
{
  "v": 1,
  "id": "01J8ZK6B4Q3M7N9P2R5S8T1V4W",           // ULID, sortable
  "ts": "2026-09-03T16:21:07.123Z",
  "severity": "high",                          // critical|high|medium|low
  "rule": "moat-cred-ssh-private-key-read",// policy name or moatd rule id
  "family": "cred",
  "title": "Private SSH key read by an unexpected program",
  "summary": "node (pid 41233) read /home/dan/.ssh/id_rsa. Parent chain: npm -> node -> sh -> node.",
  "process": {
    "pid": 41233, "uid": 1000, "exe": "/home/dan/.local/share/mise/installs/node/26.5.0/bin/node",
    "args": "/home/dan/proj/node_modules/evil/setup.mjs", "cwd": "/home/dan/proj",
    "start_ts": "2026-09-03T16:21:06.900Z",
    "ancestry": [ {"pid": 41230, "exe": "/usr/bin/sh"}, {"pid": 41201, "exe": ".../npm"} ]
  },
  "file":  { "path": "/home/dan/.ssh/id_rsa", "sha256": null },          // optional
  "net":   { "dst_ip": "1.2.3.4", "dst_port": 443, "domain": null },      // optional
  "ioc":   { "source": "malwarebazaar", "matched": "sha256:..." },        // optional
  "rotate": ["ssh-key"],
  "explain": {
    "what": "node read your private SSH key.",
    "why": "Private keys are the first thing npm and PyPI stealers read; only ssh, git and a few tools ever need them.",
    "evidence": [
      "hook: security_file_open on /home/dan/.ssh/id_rsa (read)",
      "process: /home/dan/.local/share/mise/installs/node/26.5.0/bin/node pid 41233 uid 1000",
      "ancestry: npm -> node -> sh -> node (package install in /home/dan/proj)",
      "not in allowlist: exe not in [ssh, ssh-agent, ssh-keygen, git, scp, sftp, rsync]"
    ],
    "expected": "Backup tools, IDE git integrations, and custom scripts that call ssh libraries.",
    "if_expected": {
      "hint": "exe",
      "options": [
        {"scope": "exe",      "cmd": "moatctl ignore 01J8ZK... --scope exe",
         "line": "[[rule]]\nname = \"moat-cred-ssh-private-key-read\"\nexe = \"/home/dan/.local/share/mise/installs/node/26.5.0/bin/node\""},
        {"scope": "exe+file", "cmd": "moatctl ignore 01J8ZK... --scope exe+file", "line": "..."},
        {"scope": "parent",   "cmd": "moatctl ignore 01J8ZK... --scope parent",   "line": "..."},
        {"scope": "rule",     "cmd": "moatctl ignore 01J8ZK... --scope rule",     "line": "..."}
      ],
      "file": "/etc/moat/allowlist.d/user.toml"
    },
    "next": [
      "If you did not expect this: kill the process, then rotate the key (ssh-keygen -t ed25519, replace the public key on GitHub and servers).",
      "Check what was installed: look at the npm/pip lockfile diff and the package's postinstall script."
    ]
  },
  "action_taken": "none",                      // none|killed|quarantined
  "actions": ["kill", "quarantine", "ignore"],
  "acked": false,
  "mode": "monitor"                            // mode at time of alert
}
```

moatd rewrites nothing in place. State changes (ack, action results) are
appended as `{"v":1,"id":"<same id>","update":{"acked":true,"action_taken":"killed"}}`
lines. Readers fold updates by id. The file is rotated by moatd at 20 MB
(rename to `alerts.1.jsonl`); readers must handle truncation/rotation (re-open
on inode change).

## 5. Control socket (moatctl / plugin → moatd)

Unix stream socket `/run/moat/control.sock`, newline-delimited JSON, one
request → one response per connection.

Requests:
```
{"cmd":"status"}
{"cmd":"kill","id":"<alert id>"}          kills the process tree recorded in the alert
{"cmd":"quarantine","id":"<alert id>"}    moves alert.file.path (or alert.process.exe if
                                          under $HOME,/tmp,/var/tmp,/dev/shm) to
                                          /var/lib/moat/quarantine/<id>/ with a
                                          meta.json, chmod 000
{"cmd":"ack","id":"<alert id>"}
{"cmd":"ignore","id":"<alert id>","scope":"exe|exe+file|parent|rule","comment":"..."}
                                          appends a [[rule]] block to allowlist.d/user.toml
                                          with a `# added <date> from alert <id>: <title>`
                                          comment, and acks the alert. Returns the exact
                                          block it wrote.
{"cmd":"explain","id":"<alert id>"}       returns the alert with its full explain block
{"cmd":"unignore","rule":"<n>"}           removes the n-th [[rule]] block from user.toml
{"cmd":"allowlist"}                       lists user.toml rules with their index and comment
{"cmd":"set","key":"mode","value":"monitor|enforce"}
{"cmd":"set","key":"sandbox","value":"on|off"}          touches/removes sandbox.enabled
{"cmd":"list","since":"<ULID>","limit":100}
{"cmd":"feeds","action":"refresh"}
```
Responses: `{"ok":true,...}` or `{"ok":false,"error":"..."}`.

**Actions reference alert ids, never raw pids or paths.** That is what makes the
socket safe to expose to the user's group: a malicious user-level process cannot
use moatd to kill or move something the sensor did not already flag.

`status` response:
```json
{"ok":true,"version":"0.1.0","mode":"monitor","tetragon":"running","policies":32,
 "policies_failed":[],"feeds":{"updated":"...","hashes":123456,"domains":5432},
 "unacked":{"critical":0,"high":2,"medium":5,"low":11},"sandbox":false,
 "socket_group":"moat"}
```

Two corrections to that example, made by the integration review rather than
guessed at: `policies` is 32, the number of templates in `policies/` after the
`pkg` family was deleted and its rules moved into moatd (section 6.4); and the
field is `socket_group`, the NAME of the group that owns the socket, not
`group_ok`. "Is the caller in the group" is unanswerable from the daemon side —
a client that was not in it could not have reached the socket to ask — so the
plugin answers that one itself with `id -nG` and uses `socket_group` to print
`sudo usermod -aG <actual group> $USER` instead of hardcoding `moat`. Baselining
adds more fields to this response; they are listed in docs/BASELINE.md section 8
and docs/LEARNING-AND-ANALYSIS.md section 9.

`moatctl` is a thin CLI over this socket: `moatctl status|kill|quarantine|ack|ignore|unignore|allowlist|explain|set|list|feeds`.
`moatctl explain <id>` prints the human-readable version: WHAT HAPPENED, WHY IT WAS
FLAGGED, EVIDENCE, IF THIS IS EXPECTED (the options with the exact command and the
exact TOML that would be written), WHAT TO DO IF NOT
with `--json` for machine output. It also gains nothing from root; do not ship a
sudoers rule.

## 6. moatd responsibilities

1. Tail `/var/log/moat/tetragon.log` (JSON export; handle rotation). gRPC is
   not required in v1.
2. Maintain a process table from `process_exec` / `process_exit` for ancestry
   (Tetragon gives parent, we keep the chain, capped at 8).
3. For policy events with `moat-*` names: build an alert from annotations +
   event, apply `allowlist.d`, dedupe. Allowlist TOML shape (all fields optional except
   name; globs allowed; every field present must match):
   ```toml
   # added 2026-09-03 from alert 01J8ZK...: Private SSH key read by an unexpected program
   [[rule]]
   name   = "moat-cred-ssh-private-key-read"   # or "moat-cred-*"
   exe    = "/home/dan/.local/share/mise/installs/node/*/bin/node"
   file   = "/home/dan/.ssh/id_rsa"                # exe+file scope adds this
   parent = "/usr/bin/restic"                      # parent scope: any exe under this parent
   ```
   Every alert must carry an `explain` block (section 4): `what` is one plain sentence,
   `why` and `expected` come from the policy annotations (or the userland rule's
   table), `evidence` lists the concrete matched facts, `if_expected.options` contains
   the ready-to-run command AND the exact TOML block for each scope, and `next` gives
   the response steps including rotation. Dedupe (same rule+exe+file within 60 s → one
   alert with a `count` update), append to alerts.jsonl.
4. Userland rules Tetragon cannot express (rule ids `moat-x-*`):
   - `moat-x-ai-cli-headless`: an AI CLI (`claude`,`codex`,`gemini`,`opencode`,`q`,`amp`)
     whose ancestry has no interactive shell/terminal, or whose args contain a
     permission-skipping flag (`--dangerously-skip-permissions`, `--yolo`,
     `--trust-all-tools`, `--full-auto`) while its parent is node/python/sh spawned
     by a package manager.
   - `moat-x-pkg-egress`: a package-manager subtree opens a connection to a
     host not in the registry allowlist (npmjs.org, pypi.org, crates.io,
     github.com, archlinux.org mirrors, plus config additions).
   - `moat-x-new-exec-ioc`: sha256 of a newly executed file under $HOME,
     /tmp, /var/tmp, /dev/shm matches `feeds/hashes.txt`.
   - `moat-x-mass-read`: one process reads > N (default 40) distinct files
     under $HOME dotdirs within 10 s (TruffleHog pattern). Requires the policies
     agent to emit read events for those dirs; coordinate via the `cred` family.
   Since the first live run the four package-manager rules (`moat-pkg-subtree-interpreter-spawn`,
   `moat-pkg-subtree-downloader`, `moat-pkg-subtree-netcat-exec`, `moat-ai-cli-in-pkg-subtree`)
   are userland rules built on the daemon's exec_id ancestry and argv (rules/pkgtree.rs),
   not policies: Tetragon's follow-children parent matching misfired on unrelated
   processes. `moat-x-sensor-mismatch` (low) is raised when a kernel event contradicts
   its own policy's selectors (selectors.rs re-validation).
5. Enforcement: in `enforce` mode Tetragon kills; the one userland exception is
   `moat-pkg-subtree-netcat-exec`, where moatd itself SIGKILLs after verifying pid start
   time and exe. moatd records
   `action_taken: killed` when the event carries the action. In monitor mode
   moatd never kills unless asked over the socket.
6. Serve the control socket. Write `state.json` every 5 s.
7. `moat-feeds` (separate binary or subcommand, run by the timer): fetch
   abuse.ch MalwareBazaar recent sha256 list, ThreatFox recent IOCs (domains,
   ips, urls), URLhaus recent. abuse.ch requires an `Auth-Key` header since
   2025; read it from `feeds.toml`, and if absent, skip with a clear log line
   and leave existing files in place. Atomic write. Never fail the timer hard.

## 7. Plugin responsibilities (shell/)

Kinds: `service`, `bar-widget`, `panel`. `keepLoaded: true`.

- Service: tail alerts.jsonl (handle rotation), fold updates, hold a model,
  poll `status` over the socket every 10 s (or on demand), and send desktop
  notifications through the omarchy-shell notification daemon. Critical and high
  → urgency critical/normal. The shell's notification card supports exactly one
  click action (verified), so the toast's click opens the panel focused on that
  alert and Kill / Quarantine / Ignore live in the panel; medium → normal
  notification; low → none. Respect a `minNotifySeverity` setting.
  Check how `omarchy-action` and `notify-send` are treated in
  `/usr/share/omarchy/shell/plugins/notifications/NotificationLogic.js` and use
  whichever gives clickable actions.
- Bar widget: a shield glyph. Grey = daemon down or group missing, green = ok,
  amber = unacked medium+, red = unacked high/critical (with count). Click opens
  the panel. Must be a `WidgetButton` (see gotchas below).
- Panel: alert list newest first with severity, title, process, time; detail
  view laid out as five headed blocks in this order: WHAT HAPPENED (`explain.what`
  + process/ancestry/file/net), WHY IT WAS FLAGGED (`explain.why`), EVIDENCE
  (`explain.evidence` list), IF THIS IS EXPECTED (`explain.expected` text, then one
  button per `if_expected.options` entry labelled by scope with the TOML it would
  write shown in a collapsible monospace block, the recommended scope first), and
  WHAT TO DO (`explain.next`, rotate guidance); buttons Kill,
  Quarantine, Ack, Ignore (exe) / Ignore (rule); a status strip (mode,
  tetragon, policies, feeds age); a settings row: mode monitor/enforce, sandbox
  shims on/off, min notify severity. Setup screen when group membership or the
  package is missing, with the exact commands to run.
- Settings in `manifest.json` `barWidget.defaults` + `schema` like
  `stappmus.activity-monitor` does.

omarchy-shell gotchas (verified on this machine):
- A bar widget must be a `WidgetButton` to receive clicks; bare Items never see
  the press. Use `labelVisible:false`, `hasVisualContent:true`, `fixedWidth`.
- Edits to installed plugins hot-reload; if not, `omarchy restart shell`.
- Read `/usr/share/omarchy/shell/README.md` (manifest, IPC contract, shell.json)
  and copy conventions from `/usr/share/omarchy/shell/plugins/` (battery,
  notifications, media are good references). Reference Commons from
  `/usr/share/omarchy/shell/Commons`.
- Tests: `/usr/lib/qt6/bin/qmltestrunner` exists. Any window you open while
  testing must be small, corner-placed, and closed by a trap; never fullscreen
  over the terminal.

## 8. Sandbox and shims (sandbox/)

`moat-sandbox [--allow PATH]... -- <cmd> [args]` runs the command under
bubblewrap with:
- `--ro-bind / /` baseline, `--dev /dev`, `--proc /proc`, `--unshare-pid`,
  `--die-with-parent`, `--new-session`
- writable binds: `$PWD` (and its git toplevel if inside a repo), `$TMPDIR`/`/tmp`
  as tmpfs, package caches (`~/.npm`, `~/.cache`, `~/.local/share/pnpm`,
  `~/.cargo/registry`, `~/.cargo/git`, `~/.rustup`, `~/.local/share/mise`,
  `~/.local/share/uv`, `~/.cache/pip`, `~/.bun`, `~/.yarn`)
- denied (tmpfs or empty file over them): `~/.ssh`, `~/.aws`, `~/.config/gh`,
  `~/.claude`, `~/.codex`, `~/.gemini`, `~/.gnupg`, `~/.local/share/keyrings`,
  `~/.mozilla`, `~/.config/chromium`, `~/.config/google-chrome`,
  `~/.config/BraveSoftware`, `~/.docker/config.json`, `~/.kube`, `~/.netrc`,
  `~/.git-credentials`, `~/.config/op`, `~/.password-store`, `~/.local/share/omarchy`?
  (no: needed), `~/.npmrc` and `~/.pypirc` are **allowed read-only** because
  installs from private registries need them; document the trade-off.
- network stays on (installs need it).
- env: strip `*_TOKEN`, `*_SECRET`, `*_KEY`, `AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`
  unless `--keep-env NAME`.
- `/etc/moat/sandbox.conf` adds `deny=` / `allow=` / `keep-env=` lines.

Shims: `/usr/lib/moat/shims/<name>` finds the real binary by searching
`$PATH` with the shim dir removed (mise shims must keep working), and execs
`moat-sandbox -- <real> "$@"`. `makepkg` shim first runs
`moat-scan-pkgbuild .` and, on high findings, prompts (gum confirm if
interactive, refuse if not) before continuing. `MOAT_SANDBOX=0` bypasses.

## 9. Scanner (scanner/)

`moat-scan-pkgbuild [PATH ...]` (default `.`) scans `PKGBUILD`, `*.install`,
and any `source=()` local files. Findings have `id`, `severity`, `line`, `evidence`.
Rules at minimum: curl/wget piped to a shell; `base64 -d`/`xxd -r` feeding a
shell or eval; `eval` on a variable; `npm install`/`pip install`/`cargo install`
inside PKGBUILD or `.install` (the June 2026 AUR pattern); sources whose host
differs from the `url=` host and is not a known forge/CDN; pastebin/ngrok/onion/
discord-webhook/telegram-bot hosts; `systemctl enable`, writes to `~/.bashrc`,
`~/.zshrc`, `~/.profile`, autostart, `crontab`, `/etc/ld.so.preload`; `chmod +s`,
`setcap`; zero-width / bidi / invisible Unicode; `.install` scripts calling the
network at all; `sha256sums=('SKIP')` on remote non-VCS sources. Exit 0 no
findings, 1 medium, 2 high. `--json` output. Fixtures under `scanner/tests/`
include a synthetic reproduction of the AUR incidents.

## 10. Versioning and naming

Everything is version `0.1.0`. Plugin id `io.github.the2dl.moat`, package
`omarchy-moat`, binaries prefixed `moat`. Placeholder name; a rename is a
search-and-replace, so do not scatter the word into user-visible strings more
than necessary. Use "Moat" in UI text.

## 11. Baselining

Alert volume is a product requirement: a quiet day produces zero
notifications. docs/BASELINE.md specifies provenance classification, provenance
scoring, the learning window with proposals, the noise guard, and the surfacing
policy. Its section 8 extends the alert record; its section 7 adds config
keys; `moatctl baseline list|accept|dismiss|relearn` and the socket commands
`{"cmd":"baseline","action":"list|accept|dismiss|relearn",...}` are part of
section 5. The plugin gets an Alerts tab (high/critical), a Timeline tab
(everything else, grouped), and proposals in the Allowlist tab.
