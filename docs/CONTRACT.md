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
| `scanner/`   | `moat-scan-pkgbuild`, `moat-scan-npm`, `moat-scan-build` | python3  | user    |
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
    enable-process-cred    = true                 (REQUIRED for process.binary_properties:
                                                   without it moat-x-exec-memfd and
                                                   moat-x-exec-privileges-raised are live,
                                                   configured and permanently silent.
                                                   `moatctl status` reports them as INERT.)
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
/etc/moat/scanner-allow.conf           scanner allow file, shared by all three
                                           scanners (host=/rule=/pkg=),
                                           root:root 0644, commented example; the user
                                           copy is ~/.config/moat/scanner-allow.conf
/usr/bin/moatd  /usr/bin/moatctl  /usr/bin/moat-feeds  /usr/bin/moat-ship
/usr/bin/moat-sandbox  /usr/bin/moat-scan-pkgbuild  /usr/bin/moat-scan-npm
/usr/bin/moat-scan-build   (+ symlinks moat-scan-cargo, moat-scan-pip,
                            moat-scan-go: argv[0] picks the ecosystem)
/usr/lib/moat/check.py                     the policy validator, re-run by
                                           `moatd telemetry --apply` before it
                                           will restart the sensor
/usr/lib/moat/shims/{npm,npx,pnpm,yarn,bun,pip,pip3,uv,cargo,go,makepkg}
/etc/moat/ship.toml                    0644 (holds no secret; an inline token
                                           forces 0600). moat-ship destination,
                                           classes and redaction.
/etc/profile.d/moat-shims.sh           prepends shim dir to PATH iff
                                           /etc/moat/sandbox.enabled exists
/usr/lib/systemd/system/tetragon.service   hardened, After=local-fs
/usr/lib/systemd/system/moatd.service  Requires+After tetragon
/usr/lib/systemd/system/moat-feeds.{service,timer}   hourly, RandomizedDelaySec=10min
/usr/lib/systemd/system/moat-ship.service  User=moat-ship, group `moat`, NO
                                           capabilities; not enabled by default
/usr/lib/sysusers.d/moat.conf          creates group `moat` and user `moat-ship`
/usr/lib/tmpfiles.d/moat.conf          /var/lib/moat 0750 root:moat
                                           /var/log/moat 0750 root:moat
                                           /run/moat     0750 root:moat
                                           /var/lib/moat/quarantine 0700 root:root
/var/lib/moat/alerts.jsonl             0640 root:moat, append-only
/var/lib/moat/telemetry.jsonl          0640 root:moat, append-only; written
                                           only while a telemetry class beyond
                                           `alerts` is on (docs/SHIPPING.md)
/var/lib/moat/ship/cursor.json         0640, owned by moat-ship: how far the
                                           shipper has got, and what it dropped
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
    moat.omarchy/tier: "signal"              # signal | detection, OPTIONAL, default
                                                 #   detection (BASELINE §4a). `signal` =
                                                 #   a building block: recorded in full, a
                                                 #   full chain trigger, never on the badge
                                                 #   on its own. May not carry enforce
                                                 #   kill|deny. Carry a one-line WHY beside
                                                 #   it saying why the rule is weak alone.
spec: ...
```

Families: `cred`, `pkg` (package-manager process trees), `persist`, `shell`
(reverse shells), `rootkit`, `priv` (suid/setcap/ptrace), `ai` (AI CLI abuse),
`net` (suspicious egress), `exec` (new binaries in $HOME,/tmp,/dev/shm).

The `shell` family is three rules, because one policy cannot carry two
severities (`severity`, `enforce` and `message` are per-policy, not per-selector,
even though selectors may each carry their own `matchActions`):
`moat-shell-reverse-shell-connect` (critical, Sigkill) for a shell or netcat
connecting to a public address, `moat-shell-lan-connect` (high, report-only,
rate-limited per process) for the same thing to 10/8, 172.16/12, 192.168/16 or
`fc00::/7`, and the userland `moat-shell-stdio-socket` for the shapes where the
shell never connects at all (§6.4).

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
  "mode": "monitor",                           // mode at time of alert

  // BASELINE §4a. The RULE's declaration about itself, copied onto every alert
  // it raises. Absent means "detection", so an older record and a rule that
  // says nothing both read as a detection — silence is never the failure mode
  // of a missing field. A `signal` row is recorded in full, is a full chain
  // trigger, and carries "surface": "timeline" unless one of the two
  // exceptions below applies.
  "tier": "detection",                         // detection|signal
  // The §2b context matrix put this at high/critical BECAUSE it was inside a
  // package install. The one outcome that neither the `signal` tier nor a
  // noise-guard demotion may move to the timeline.
  "pkg_install_escalation": false,

  // Absent until auto-triage has looked at this alert, and absent forever when
  // [analysis] auto_triage = "off" (LEARNING §2c).
  "triage": {
    "agent": "claude",
    "at": "2026-09-04T12:04:11.220Z",
    "verdict": "benign",                       // benign|suspicious|malicious|unclear
    "confidence": "high",                      // low|medium|high
    "summary": "Your own AUR install of flea; makepkg is in the ancestry.",
    "reasoning": "...",
    "proposed_allowlist": "[[rule]]\nname = ...",   // or null; NEVER auto-applied
    "recommend": ["moatctl ack 01J8ZK..."],
    "outcome": "demoted"                       // annotated|demoted|withheld: <reason>
  },

  // Absent unless this alert turned out to be one step of a sequence
  // (design 2b "What led here", 3a "a chain not four alerts"). Appended as an
  // `update` line, because the event that makes a sequence visible happens
  // after its earlier steps are already on disk.
  "chain": {
    "v": 1,
    "id": "01J8ZK6B4Q3M7N9P2R5S8T1V4W",       // the first step's alert id
    "ancestor": {"pid": 41201, "exe": "/usr/bin/npm"},  // what every step is under
    "families": ["cred", "net", "priv"],       // crossed by the trigger steps
    "severity": "critical",                    // MAY be higher than any member
    "severity_base": "high",                   // the highest any member reached alone
    "severity_reason": "high -> critical: a credential was read and the same process tree then connected out",
    "first_ts": "2026-09-03T16:21:07.100Z",
    "last_ts":  "2026-09-03T16:21:08.400Z",
    "span_secs": 1,
    "steps": [                                 // time order, oldest first
      {"alert": "01J8ZK...", "ts": "2026-09-03T16:21:07.100Z", "family": "cred",
       "rule": "moat-cred-ssh-private-key-read", "severity": "high",
       "title": "Private SSH key read by an unexpected program",
       "pid": 41233, "exe": "/usr/bin/node", "role": "trigger"}   // trigger|context
    ],
    "steps_total": 7,                          // > steps.len() once truncated
    "truncated": false,
    "summary": "7 things happened in 1 second under npm (pid 41201), crossing cred, net and priv."
  },

  // Absent unless a chain reached `high` and moat then looked INSIDE the files
  // this alert implicated (`content.rs`). Appended as an `update` line. One
  // entry per file; `role` is `actor` (what ran) or `target` (what it touched).
  // Purely descriptive — nothing in here moves a severity.
  "content": [
    {
      "path": "/tmp/.fontconfig-helper",       // attacker-chosen; render as data
      "real_path": "/tmp/other",               // only when the descriptor disagreed
      "role": "actor",
      "ts": "2026-09-04T12:04:11.220Z",
      "sha256": "…",                           // absent on a refused file
      "bytes": 82344,
      "kind": "elf",                           // elf|script|archive|pe|macho|text|data|empty|unread
      "skipped": null,                         // set => nothing below was read
      "entropy": 7.81,                         // Shannon, bits/byte, whole file
      "elf": {
        "class": "elf64", "kind": "dyn", "machine": "x86-64",
        "linkage": "static", "interp": null, "stripped": true,
        "needed": [], "runpath": [], "imports": ["socket", "connect", "execve"],
        "sections": [{"name": ".text", "size": 40960, "entropy": 7.9}],
        "notes": ["UPX magic in the header: the file is packed"]
      },
      "script": null,                          // shebang/interpreter/lines when kind=script
      "urls": ["http://45.9.148.99/stage2"],
      "hosts": [{"value": "45.9.148.99", "scope": "public"}],  // public|loopback|private|
                                               // link-local|cgnat|multicast|domain|…
      "markers": [{"name": "exec:curl-pipe-shell", "sample": "curl -sL http://… | sh"}],
      "strings": ["…"],                        // sanitised to printable ASCII, capped
      "truncated": false
    }
  ]
}
```

Reader obligations for `content`:

- **Every string, URL, host, marker sample, symbol, section name and path in
  the block came out of the bytes of a file believed to be hostile.** It has no
  length limit and no syntax to respect, and it is the most attacker-controlled
  text moat produces. Render it as data — never as markup, never as a link,
  never into a shell. `bundle.md` puts all of it inside `DATA` fences.
- **The classifications did not.** `kind`, `entropy`, `linkage`, `scope` and
  the counts were computed by moatd from a closed vocabulary and are safe to
  format.
- **`skipped` is not "clean".** It means moat did not look — the file was over
  the size cap, was a credential path, was inside moat's own store, or the
  hourly budget was spent. Say which; do not present it as an absence of
  findings.
- **Nothing here changes severity.** Content analysis annotates a decision the
  chain correlator already made.

`triage` is advisory. A verdict never changes `acked`, `severity`,
`action_taken` or `suppressed_by`; the only field it may move is `surface`,
`alerts` → `timeline`, and only on `verdict: benign` + `confidence: high` in
`demote` mode.

Reader obligations:

- **Honour `outcome: "demoted"` when deciding the tab.** A reader that derives
  the surface itself from rule and severity — as the plugin does, because
  demotion also arrives from `status.demoted_rules[]` and from a
  `demoted:<rule>` marker — must add this third, per-alert source or a triage
  demotion changes nothing the user can see.
- **Render every string in the block as plain text.** They were written by a
  language model that had just read attacker-controlled input.
- **Treat an unrecognized `verdict` or `confidence` as `unclear` / `low`.**
  Degrade towards "nobody knows", never towards "benign".
- **`proposed_allowlist` is displayed, never applied.** No reader may grow a
  verb that writes an allowlist file from a daemon-supplied string; the
  existing `ignore` scopes, which name an alert id and a scope the daemon
  itself offered, stay the only way an entry gets written.
- **Show `outcome` when it starts with `withheld:`**, so a benign verdict the
  ceiling refused to act on explains itself rather than reading as the reader
  ignoring the agent.

### Chains (design 2b, 3a)

A chain is recognised when, inside one ten-minute window, two or more alerts
**share a process tree** and **cross two or more detection families** (`cred`,
`net`, `persist`, `exec`, `priv`, `rootkit`, `pkg`, `shell`, `ransom`), at least one of
them is `medium` or worse, and at least one of them is new on this machine
(`rarity` of `first_seen` or `rare`). The tree is rooted at the outermost
process below the session boundary — pid 1, a terminal, a multiplexer, an
editor, `sshd`, or a login shell a terminal started — so two commands typed into
one terminal window are two trees and one `npm install` is one tree however many
processes it forks. `ai` and `x` alerts are excluded: `x` is moat's own
housekeeping, and an AI CLI is too busy on a developer machine to be one of the
two families that create a story.

Reader obligations:

- **`chain.severity` may exceed every member's `severity`.** That is the point:
  a sequence means more than its steps. The member alerts are **not** rewritten —
  each one's own `severity`, `surface` and `suppressed_by` still describe the
  single event it is about — so a reader that shows a chain must show
  `chain.severity`, not the maximum of its members.
- **Never show a chain severity without `severity_reason`.** It is always
  present and always explains the number: `"high -> critical: <the pattern that
  raised it>"` when a sequence moved it, `"stays critical: <the pattern> —
  already at the highest severity"` when the pattern matched but a member was
  already at the ceiling, and `"stays high: cred and pkg in one process tree, no
  escalating sequence"` when nothing matched. Same shape as the alert-level
  field of the same name.
- **A `role: "context"` step is an alert the user had already allowed
  (`suppressed_by`), or one the noise guard had demoted for firing all day.**
  It is shown in the story — that is what makes 2b readable — but it did not
  create the chain and never contributed to the escalation. Render it as such;
  showing it as an accusation reverses a decision the user made.

  Those two are the *only* sources of `context`. In particular `surface:
  "timeline"` is **not** one: `surface` is a pure function of severity, so every
  `medium` and `low` alert carries it, and a rule that is weak on its own is the
  prime candidate for a sequence rather than a thing to discount. Treating it as
  silence is what made moat miss a `persist` write and a `cred` read one second
  apart in one pid on 2026-09-04 — it turned the documented "at least one member
  at medium or worse" into an undocumented "at least two members at high or
  worse".
- **Every member carries the whole chain**, so a reader that opened one alert
  can draw 2b without joining anything. When a chain grows, every member gets a
  new `update` line with the larger chain; fold by id as usual and the last one
  wins.
- **`chain.id` is a member's alert id**, so `moatctl explain <chain.id>` and
  `moatctl chain <chain.id>` both work, and chains sort newest-first by id.
- **Allowing a chain resolves its siblings.** `{"cmd":"ack","id":...,"chain":true}`
  acks every id in `steps[]`. It is opt-in: a plain `ack` still acks one alert.

moatd rewrites nothing in place. State changes (ack, action results) are
appended as `{"v":1,"id":"<same id>","update":{"acked":true,"action_taken":"killed"}}`
lines. Readers fold updates by id. `update.triage` carries the object above, or
`null` for `moatctl triage --undo`; a malformed one must be ignored rather than
allowed to blank a verdict already recorded. `update.chain` follows the same
rule: a chain only ever grows, so a malformed one must be ignored rather than
allowed to blank a sequence already recorded. The file is rotated by moatd at 20 MB
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
{"cmd":"ack","id":"<alert id>","chain":true} acks every alert in that alert's chain
                                          ("same chain, same decision", design 2b).
                                          Errors if the alert is not in one.
{"cmd":"chain","id":"<alert id>"}         the chain that alert is a step of, or
                                          {"chain":null} when it is not in one
{"cmd":"chain","limit":20}                the chains on record, newest first, plus
                                          "open" (live now) and "formed" (since start)
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

`EACCES` on the socket has four causes and they need four different answers: no
`moat` group (the package is not fully installed), not a member (`usermod`),
a member whose login session predates the `usermod` (re-login or `newgrp`, and
telling them to `usermod` again sends them round a loop that cannot terminate)
— and, since 2026-09-05, **the daemon simply not being up yet**. A member
hitting `EACCES` while `systemctl is-active moatd` reads `activating` (or the
socket is under five seconds old), or getting `ECONNREFUSED` at all, is told to
wait a few seconds. It is not told the socket's permissions are wrong and to
restart moatd: that message named the operation that was *causing* the symptom,
and the socket was 0660 root:moat seconds later.

**Actions reference alert ids, never raw pids or paths.** That is what makes the
socket safe to expose to the user's group: a malicious user-level process cannot
use moatd to kill or move something the sensor did not already flag.

`status` response:
```json
{"ok":true,"version":"0.1.0","mode":"monitor","tetragon":"running","policies":32,
 "sensors_loaded":32,"sensor_unhealthy":false,"enforcing_rules":[],
 "enforcing_verified":[],"enforcing_unverified":[],"enforcement_unhealthy":false,
 "arming_pending":false,
 "policies_failed":[],"feeds":{"updated":"...","hashes":123456,"domains":5432},
 "unacked":{"critical":0,"high":2,"medium":5,"low":11},"sandbox":false,
 "ledger":{"needs_you":2,"recorded":4812,"suppressed":1193,"signal":3904},
 "chains_open":0,"chains_formed":0,
 "telemetry":{"classes":["alerts"],"written":0,"filtered":0,"file":null},
 "socket_group":"moat"}
```

`ledger` splits `alerts.jsonl` into the three populations a person actually
distinguishes, because one word over three of them is how "unacked 1,854" came
to sit next to a badge of 13 (BASELINE §8). **`needs_you`** is the badge —
surfaced, unacked, unsuppressed — and is `unacked` summed, so the two can never
disagree. **`recorded`** is timeline rows: seen, written down, never asked
about. **`suppressed`** is rows an allowlist entry matched. **`signal`** is the
part of `recorded` that came from a `signal`-tier rule (BASELINE §4a).
`unacked` is unchanged and remains the badge per severity. `moatctl status`
prints the three words; so does the weekly digest.

`triage_pending` is exactly the badge (surfaced, unacked, unsuppressed, no
verdict yet) and is the same set `{"cmd":"triage","action":"pending"}` offers.
`{"cmd":"ack","all":true}` and `{"cmd":"ack","rule":...}` answer only badge rows
and return `skipped`, the number of recorded or suppressed rows they left alone:
those were never asked about, so there is nothing to answer.

`telemetry.classes` is which record streams moatd is keeping (section 12), and
it belongs beside `sensor_unhealthy` for the same reason: a reader that sees a
healthy sensor and `["alerts"]` knows exactly how much of this machine's
history exists. `written` counts records appended to `telemetry.jsonl` since
start; `filtered` counts file-class events dropped by the create/modify ladder
before anything was written, so the two together say what the scope is costing.
`file` is `null` when no class beyond `alerts` is on, which is the default and
means the file does not exist.

`tetragon` is one of `running`, `degraded <n>/<m>`, `down`, `stale`, `stopped`
or `unverified`, and `sensor_unhealthy` is true for every value except
`running` and `unverified`. `sensors_loaded` counts the directories Tetragon
pins under `/sys/fs/bpf/tetragon`, one per loaded TracingPolicy — what the
kernel is running, as opposed to `policies`, which is what is on disk.
`sensors_loaded` is `null` when moatd cannot read bpffs, which is "cannot
tell" and not "none"; that is the `unverified` state, and it must not be
rendered as an outage.

`enforcing_rules` is what the RECORD says is armed, restored from `state.json`;
`enforcing_verified` and `enforcing_unverified` are that same set split by what
the KERNEL says, read once a minute from `tetra tracingpolicy list -o json`
(the `mode` field of `TracingPolicyStatus` — NOTES §7). `enforcement_unhealthy`
is `enforcing_unverified` being non-empty, and is the direct analogue of
`sensor_unhealthy`: one boolean a consumer can key on. `arming_pending` is true
while moatd is still waiting for the sensor to finish loading before it arms
anything (`[thresholds] arm_wait_secs`), which is a normal state for the first
few seconds after a boot and must not be rendered as a failure.

**`enforcing_rules` stays the field the panel binds to** — it is what the user
asked for, and it is still the right thing to show in a toggle. But a consumer
that prints it without `enforcing_unverified` is repeating the 2026-09-05 bug:
seven rules listed as enforcing all day while all seven sat in `monitor` in the
kernel, because the post-start re-arm ran 2 s in and tetragon needed 16 s to
load 44 policies (NOTES §7.1). `moatctl status` prints the unverified set on the
`enforcing` line itself, in the same shape as the `*** NOT PROTECTED ***`
marker. Empty `enforcing_verified` **and** empty `enforcing_unverified` next to
a non-empty `enforcing_rules` means moatd could not ask the kernel, not that
the kernel agreed — "cannot tell" is never rendered as "confirmed", in either
direction. None of the three survive a restart: agreement observed before a
restart is not evidence about the kernel after one.

Consumers must treat `sensor_unhealthy` as outranking the alert counts. A
sensor that is not loaded raises nothing, so `unacked` all-zero next to an
unhealthy sensor is the most dangerous shape a status response can take, not
the safest. This is not hypothetical: on 2026-09-03 Tetragon crash-looped for
25 minutes with zero policies loaded while `tetragon` read `running`, because
the liveness check was the gRPC socket file's existence and the export log's
mtime — and a crash loop keeps both fresh.

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

`chains_open` is how many sequences the daemon is currently correlating; a
reader showing 3a ("a chain, not four alerts") instead of 1b keys on it.
`chains_formed` counts them since start.

`moatctl` is a thin CLI over this socket: `moatctl status|kill|quarantine|ack|ignore|unignore|allowlist|explain|set|list|feeds|chain`.
`moatctl chain <id>` prints design 2b in a terminal: the sequence with times,
which step was already allowed, and the one command that closes all of it.
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
   - `moat-shell-stdio-socket` (family `shell`): a shell (`bash sh dash zsh fish
     busybox ash ksh mksh tcsh csh`) whose fds 0/1/2 are a network socket, read
     from `/proc/<pid>/fd` at exec time and resolved through
     `/proc/net/{tcp,tcp6,udp,udp6}` — no hook carries file descriptors, so this
     cannot be a policy. Critical for an off-machine peer (LAN **included**;
     the kernel rule excludes RFC1918 in-kernel), medium for a loopback peer,
     and critical-but-not-killed when the fd is a socket whose inode no longer
     resolves. Inodes that resolve in `/proc/net/unix` never fire: systemd gives
     every service journald's stdout socket. Rung 2, same rule id, at high: the
     shell's stdio is a pty and the **parent's** stdio is a socket — the
     `pty.spawn` / `script /dev/null` upgrade. Deliberately not "the parent
     holds a socket somewhere", which is every IDE on the machine. See
     policies/README.md "Reverse shells" for the three shapes and the residual.
   Since the first live run the four package-manager rules (`moat-pkg-subtree-interpreter-spawn`,
   `moat-pkg-subtree-downloader`, `moat-pkg-subtree-netcat-exec`, `moat-ai-cli-in-pkg-subtree`)
   are userland rules built on the daemon's exec_id ancestry and argv (rules/pkgtree.rs),
   not policies: Tetragon's follow-children parent matching misfired on unrelated
   processes. `moat-x-sensor-mismatch` (low) is raised when a kernel event contradicts
   its own policy's selectors (selectors.rs re-validation).
4b. Sequence correlation (`moatd/src/chain.rs`, design 2b and 3a). Every rule
   above fires on one syscall in isolation, which is what let a simulated npm
   supply-chain attack read a credential, open a socket to a host on the LAN and
   rewrite its own installed source on 2026-09-04 without moat saying anything:
   each event was weak, ambiguous, or deliberately allowlisted. Alerts sharing a
   process tree inside a window and crossing two or more detection families are
   grouped into one chain whose verdict is written about the sequence, and whose
   severity may be higher than any member — see "Chains" in section 4 for the
   exact conditions, the record and the reader obligations. The chain is written
   back onto every member as an `update` line. The correlator holds a fixed
   amount of memory: 128 candidate alerts, 32 live chains, 12 steps each, all
   aged out at the window.
5. Enforcement: in `enforce` mode Tetragon kills; the userland exceptions are
   `moat-pkg-subtree-netcat-exec` and `moat-shell-stdio-socket` (its `critical`
   rung only — never the loopback `medium` or the pty `high`), where moatd
   itself SIGKILLs after verifying pid start time and exe. moatd records
   `action_taken: killed` when the event carries the action. In monitor mode
   moatd never kills unless asked over the socket.

   **Per-rule arming covers the userland rules too.** A userland rule that can
   kill declares `enforce: "kill"` in its own meta, appears in `enforceable()`
   with `"by": "moatd"` (a kernel policy carries `"by": "kernel"`), and is armed
   and disarmed by `moatctl set mode enforce|monitor --rule NAME` like any
   policy. `maybe_enforce` gates on `mode_for(rule)`, not on the daemon-wide
   mode, and the rule itself asks `RuleCtx::enforcing(id)`. Nothing is pushed
   into the kernel for one — there is no policy to `tetra tp set-mode`, so the
   arming applies immediately and cannot fail — and it round-trips a restart
   through `enforcing_rules` in `state.json` exactly as a kernel rule does.
   `enforcement_to_apply()` therefore stays kernel-only on purpose: calling
   `set-mode` on a name the kernel has never heard of would fail and be
   reported as enforcement that did not take.

   This mattered because the two rules that act on their own were the two the
   per-rule switch could not reach: `enforceable()` listed policies only,
   `set mode --rule` refused the name, and `maybe_enforce` read `self.mode`. The
   only way to arm either was to arm every rule on the machine — the
   all-or-nothing that per-rule enforcement exists to avoid.

   **Arming a kernel policy is a request, not a fact, until the kernel is read
   back.** `tetra tp set-mode` changes a LIVE policy and that change dies with
   the sensor, so the armed set has to be pushed into the kernel again on every
   start — and pushing it is not the same as it having taken. moatd therefore:

   - **waits.** `arm_tick` does not call `set-mode` until the sensor reports the
     policies loaded (the pin count under `[paths] tetragon_bpf_dir` against the
     rendered count, or `tetra tp list` naming the wanted policies when bpffs is
     unreadable), bounded by `[thresholds] arm_wait_secs` (120 s) and retried on
     a backoff inside that window. It runs on the periodic tick, never on the
     event path. tetragon.service also runs `moatd wait-sensor` as an
     `ExecStartPost` so `After=tetragon.service` orders against a loaded sensor;
     the daemon-side wait stays because a tetragon that reloads policies later
     is not a boot-order problem.
   - **verifies, and keeps verifying.** `verify_enforcement` reads `mode` per
     policy from `tetra tracingpolicy list -o json` once a minute, re-arms
     anything the kernel has in `monitor`, reads the kernel back rather than
     trusting the `set-mode` exit status, and publishes `enforcing_verified` /
     `enforcing_unverified` / `enforcement_unhealthy` in `status` (section 5).
   - **says so.** A gap raises exactly one `moat-x-protection-changed` alert
     (high, `NEVER_SILENCE`) naming the policies and what to run — deduped on
     the unverified set, so a failure that persists for a week is one alert and
     a policy coming back clears it. Being unable to *ask* is never reported as
     a gap.

   All of which exists because on 2026-09-05 none of it did: the post-start
   re-arm ran 2 s in, tetragon needed 16 s to load 44 policies, all seven
   `set-mode` calls failed, nothing retried or checked, and every surface went
   on saying ARMED for the rest of the day (NOTES §7.1).
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
`moat-sandbox -- <real> "$@"`. Before handing over, a shim runs the scanner
for its ecosystem -- `makepkg` runs `moat-scan-pkgbuild .`, the four JS shims
run `moat-scan-npm .`, `cargo` runs `moat-scan-cargo`, `pip`/`pip3`/`uv` run
`moat-scan-pip` and `go` runs `moat-scan-go` -- and on high findings prompts
(gum confirm if interactive, refuse if not) before continuing. A scanner that
is missing or that exits with anything other than 0/1/2 warns and continues:
it must never be able to stop a build by breaking. `MOAT_SANDBOX=0` bypasses
the shim, the scan included.

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

`moat-scan-npm [PATH ...]` scans a JavaScript package tree before its install
scripts run: lifecycle scripts in transitive dependencies, what those scripts
do (shell pipes, credential paths, bare IPs, decoded blobs reaching eval),
`bin` entries escaping the package, and lockfile entries resolved off the
configured registry or pinned without an integrity hash.

`moat-scan-build [PATH ...]` scans the three ecosystems that also execute code
before the user has run anything, and is installed under three names so each
shim calls the tool for its own -- `moat-scan-cargo`, `moat-scan-pip`,
`moat-scan-go` (argv[0] selects, `--for` overrides). cargo: `build.rs` and
`build = ` overrides, `.cargo/config.toml` registry replacement, runners,
compiler wrappers and linker overrides, path/git dependencies leaving the tree,
proc-macro crates, and `Cargo.lock` sources and checksums. python: `setup.py`,
PEP 517 `backend-path`, `*.pth` `import` lines (which run on every interpreter
start), `setup_requires`, and index overrides in requirements/pip.conf/uv.
go: `go:generate` directives, `replace` targets outside the module, and
`//go:linkname`.

All three share one finding shape, one allow file, one exit-code contract and
one detection vocabulary (`net.*`, `cred.*`, `obf.*`, `uni.*`, `lock.*` mean
the same thing in each, so `rule=obf.*` in the allow file covers all of them).
None of them ever executes, imports or subprocesses what it reads.

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

## 12. Telemetry and shipping records

Full detail in docs/SHIPPING.md, including the measured volume of each class
and why the `file` class is scoped the way it is. The contract-level shapes,
which any reader of these files must honour, are here.

**`/var/lib/moat/telemetry.jsonl`** — one JSON object per line, 0640 root:moat,
rotated by rename to `telemetry.1.jsonl` at 16 MiB. Written only while a class
beyond `alerts` is on. Every line carries `v`, `class`, `kind`, `ts`:

```json
{"v":1,"class":"process","kind":"exec","ts":"...","exec_id":"...","parent_exec_id":"...",
 "pid":41233,"uid":1000,"auid":1000,"exe":"...","args":"...","cwd":"...","start_time":"..."}
{"v":1,"class":"process","kind":"exit","ts":"...","exec_id":"...","pid":41233,"status":0,"signal":null}
{"v":1,"class":"network","kind":"connect","ts":"...","dst_ip":"1.2.3.4","dst_port":443,
 "hook":"tcp_connect","exec_id":"...","parent_exec_id":"...","pid":...,"uid":...,
 "exe":"...","args":"...","cwd":"...","pkg_root":"/usr/bin/npm"}
{"v":1,"class":"file","kind":"file_write","ts":"...","path":"...","verdict":"modify",
 "shape":"script","bytes":1234,"sha256":"...","exec_id":"...","pid":...,"pkg_root":null}
```

Reader obligations:

- **A telemetry record is not an alert.** It has no severity, no `explain`, no
  `id` and no actions. It never appears in `alerts.jsonl`, never reaches rule
  evaluation, and must never be rendered as a finding.
- **`verdict` is `create` | `modify` | `chmod_x`.** `modify` means the file
  existed before this write, which is the higher-value case; a reader that
  collapses the two loses the distinction the class exists for.
- **`pkg_root` is ancestry the kernel cannot see.** Non-null means the actor was
  inside a package-manager subtree.
- **`parent_exec_id` is a join, not a copy.** Reconstruct the tree from
  `exec_id`; the parent block is only inlined when `inline_parent = true`.

**The shipped envelope** (`moat-ship` → collector), one NDJSON line per record:

```json
{"v":1,"event_id":"01J8ZK6B4Q3M7N9P2R5S8T1V4W","host":"mars","class":"alerts",
 "kind":"alert","severity":"high","@timestamp":"2026-09-03T16:21:07.123Z",
 "moat":{ …the source line, redacted… }}
```

- `event_id` is the alert's **ULID** for a full alert and
  `<id>.<12 hex of sha256(line)>` for anything else. It is stable across
  re-sends: the contract is at-least-once with **receiver-side dedupe on
  `event_id`**.
- `kind` is `alert` | `update` | `receipt` | `heartbeat` | a telemetry `kind`.
- A `heartbeat` has `class: "moat"` and carries
  `{shipped, dropped, withheld, backlog, backlog_bytes, classes, last_ok,
  last_error}`. **Alert on its absence**: a dead shipper and a quiet machine
  look identical without it.
- Paths inside `moat` are redacted by default (`$HOME` → `~`, credential leaf →
  `<redacted>`), and staged evidence is replaced with
  `<withheld: staged evidence>` with no switch to disable it.
