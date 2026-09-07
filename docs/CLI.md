# moatctl

The complete command reference. `moatctl` is the whole interface — the panel is
a convenience over the same control socket, and anything the panel can do you
can do here.

Two rules govern the whole tool:

**Every action names an alert id, never a pid or a path.** You act on something
Moat observed and recorded, not on a process you found yourself. The id is a
ULID like `01M1S9DPBMBYHX5T7S3M0CGCXM`, printed by `list`, `chain` and `status`.

**Reading never needs root; weakening protection always does.** `status`,
`list`, `explain`, `decisions` and `baseline list` are ordinary group work —
they are the evidence you review before deciding, and evidence behind `sudo`
does not get read. `ignore`, `forget`, `set` and `baseline accept` change what
Moat will do next, and a hijacked package runs as you, not as root.

If you get a permission error:

```
sudo usermod -aG moat $USER      # then log out and back in
```

The group is what lets you read `/var/lib/moat/alerts.jsonl` and write to the
control socket. A new group only applies to a fresh login session.

---

## Global options

Accepted by every subcommand.

| Option | Meaning |
|---|---|
| `--json` | Print the raw JSON response instead of the rendered text. Every command supports it; the shapes are fixed by `docs/CONTRACT.md`. |
| `--socket <PATH>` | Control socket. Default `/run/moat/control.sock`. |
| `--config <PATH>` | `moat.toml`, used **only** to find the socket — not to override daemon behaviour. |
| `-V, --version` | Version of the CLI binary. |

---

## Looking

### `moatctl status`

The one-screen answer to "is this working, and does it want anything from me".

```
moatd  0.1.0   mode monitor
enforcing  moat-cred-etc-shadow-read, moat-cred-ssh-private-key-read, ...
tetragon   running
policies   44   (44 loaded in the kernel)
feeds      0 hashes, 0 domains, updated never
needs you  7   (recorded 1115, of which 162 signal; suppressed 3425)
unacked    critical 0  high 5  medium 0  low 2
sandbox    off
socket     group moat   uptime 9s   162 events, 0 alerts
baseline   learning until 2026-09-10T23:13:49.000Z   0 proposal(s), 30 learned
demoted    moat-exec-untrusted-home, ...   (timeline only)
```

Read it in this order:

- **`policies N (M loaded in the kernel)`** — these two must match. `N` is what
  was rendered to disk; `M` is what the kernel actually has pinned under
  `/sys/fs/bpf/tetragon`. A gap means a silent sensor outage: on 2026-09-03 a
  bad policy load cost 25 minutes of blindness while every other surface still
  read "running".
- **`enforcing`** — the rules armed to block rather than report. A
  `*** NOT ARMED IN KERNEL: ... ***` marker means Moat asked the kernel and the
  kernel disagreed; it re-arms once a minute and will say so until it clears.
- **`needs you`** — the only number that is asking for something. `recorded` is
  everything Moat saw, `signal` is the tier that never asks on its own, and
  `suppressed` is what your allowlist already answered.
- **`INERT`** — appears when a rule is enabled and *structurally cannot fire*
  (for example a detection that reads a Tetragon field the sensor is not
  configured to send). A rule that cannot fire reads as coverage, which is
  worse than one that is off, so it is named along with the fix.

### `moatctl list [--limit N] [--since ID]`

Recent alerts, **newest last**, so the interesting one is at the bottom of your
terminal. `--limit` defaults to 20. `--since` takes an alert id; ids are
monotonic, so an id comparison is a time comparison.

### `moatctl explain <ID>`

The full record for one alert: what happened, why the rule exists, what a
normal cause looks like, the process ancestry, the evidence lines, and what to
rotate if a credential was read.

This is the command to reach for when a one-line alert is not enough. It is
also what the panel shows when you open a card.

### `moatctl chain [ID] [--limit N]`

With an id: the sequence that alert belongs to — every step, in order, with
times, marked as `trigger` or `context`. With no id: the chains on record.

A chain forms when a process tree produces **two or more non-allowlisted
findings, crossing two or more families, at least one `medium` or worse, at
least one new on this machine**. It is the difference between "a program ran
from /tmp" and "a package install ran a program from /tmp and then called
home".

The headline counts triggers only; steps you have already allowed are reported
separately as "N more were already allowed on their own".

### `moatctl rarity <ID>`

How unusual this alert's tuple is on this machine, in plain words —
`first_seen`, `rare` or `common`, with the count and the dates. Rarity is
evidence, never a severity change on its own.

### `moatctl decisions [--limit N]`

Every decision the kill gate has made: `spared`, `would_have_killed` or
`killed`, with the chain, its families, the reason and the target processes.

**This is the evidence for whether `set kill kill` is safe on your machine.
Read it before arming, not after.** It is deliberately unprivileged, and it is
stored in `/var/lib/moat/decisions.jsonl` rather than the journal — journald is
sized by a percentage of the disk and evicts oldest-first, which is not a
retention guarantee you can plan a week of review around.

### `moatctl receipts [--last N]`

What package installs actually did — the executions, writes and connections in
each install subtree, as one record per install. Informational: a receipt has
no actions, no ack and no badge.

### `moatctl incidents [--last N]`

Incident snapshots on disk. An incident is captured before anything is killed
or quarantined, at `high` and above: the binary, its hash, the ancestry, the
open files and sockets.

### `moatctl contain [--release CHAIN]`

What Moat is refusing on its own judgement right now — which binaries may not
reach which destinations, and until when. `--release` drops one immediately.

Containment is narrow by construction: specific binaries, specific addresses,
ten minutes, auto-released. Its worst case is one program not reaching one host
for ten minutes.

### `moatctl exclusions [--remove <rule>:<binary>]`

Binaries a rule has been told to stop watching **in the kernel**. This is what
"allow this program" does for a rule that is armed — a userspace allowlist
entry cannot help there, because the process dies before Moat sees the event.

`--remove` puts the binary back under watch. Restoring protection needs no
root; removing it does.

### `moatctl allowlist`

Every merged allowlist rule with its index, source file and comment. The index
is what `unignore` takes.

### `moatctl quarantine [ID] [--list] [--restore]`

`--list` shows everything held, where it came from and when. With an id, moves
that alert's file into `/var/lib/moat/quarantine` at mode `000`; `--restore`
puts it back. Nothing is ever deleted, and the metadata records whether the
original was actually removed — "evidence kept, file left in place" is a
different outcome from success and is reported as one.

### `moatctl feed [--limit N]`

Machine-readable. Everything the panel needs, already folded, in one response.
Use `list`; this exists so the panel does not re-read and re-fold the alert log
on every append.

---

## Answering

### `moatctl ack [IDS]... [--all] [--rule R] [--before ID] [--chain]`

Mark alerts as seen. Several ids are answered in **one** request.

| Form | Meaning |
|---|---|
| `ack <id>` | One alert. |
| `ack <id> <id> <id>` | Several, one round trip. This is how the panel closes a card. |
| `ack <id> --chain` | Every alert in the same chain. One decision about a sequence should not leave its other four steps on the badge. |
| `ack --all` | Every unacked alert. |
| `ack --rule <rule>` | Everything from one rule — after a retune, when the old alerts are about rules that no longer exist. |
| `ack --before <id>` | Everything older than that alert. |

**Acking does not delete anything.** `alerts.jsonl` is append-only; an ack adds
a line saying the alert was answered, and the record survives. What changes is
whether you are asked again.

**Every ack records who asked**, from the socket peer, in `acked_by`. Acking is
not root-gated on purpose — it is the commonest action in the product, and a
prompt per click is how the meaningful prompt gets waved through. The defence
is attribution rather than privilege: a payload in the `moat` group can clear
the badge, and that leaves a mark. Clearing more than 64 alerts in one request
also raises a protection-change alert, whichever form was used.

### `moatctl ignore <ID> [--scope SCOPE] [--comment TEXT]`

Stop alerting on this pattern. Writes a `[[rule]]` block into
`/etc/moat/allowlist.d/user.toml` and acks the alert. **Needs root.**

| `--scope` | Matches |
|---|---|
| `exe` (default) | This rule, this binary. |
| `exe+file` | This rule, this binary, this directory. The narrowest. |
| `parent` | This rule, anything launched by this parent. |
| `rule` | This rule entirely. The widest — think before using it. |

The generated block is printed before it is written. An allowlisted finding is
still recorded and still appears in chains as **context**; it simply stops
asking you about it. That distinction matters: your allowlist is consent, and a
consented step should not be able to raise an alarm on its own.

### `moatctl allow --name RULE [--exe X] [--file F] [--parent P] [--script S] [--comment T] [--yes]`

Write an allowlist entry **directly**, without waiting for an alert to fire.
`ignore` needs an alert id and offers four canned scopes; this takes the
matchers themselves — including `script`, which no scope can express.

**It previews by default and writes nothing.** It prints the block it would
write and, more importantly, *which alerts already on record it would have
suppressed*, by rule and with a sample. `--yes` commits it, and **needs root**.
Seeing the blast radius before granting is the point, so it is the default
rather than a flag you have to remember.

| Matcher | Matches |
|---|---|
| `--name` (required) | The rule, or a glob: `moat-cred-*`. |
| `--exe` | The binary the *kernel loaded*. For a `#!` script that is the interpreter. |
| `--file` | The file touched. |
| `--parent` | Any ancestor's binary, up to the ancestry cap. |
| `--script` | What an interpreter was actually running. |

Every field is a glob and **every field present must match**.

It refuses four shapes, all of which look narrow and are not:

* a `--name` glob that reaches one of Moat's own self-health rules
  (`moat-*` would reach all five at once — `ignore` only ever sees one exact
  rule, so this is a refusal `ignore` never needed);
* a rule that is **armed in the kernel** — suppression is userspace and the
  kill is not, so the entry would hide the alert while the program went on
  dying (the 2026-09-05 record). The refusal names the way out;
* an `--exe` that is an interpreter with no `--script`. `--exe
  /usr/bin/python3.14` reads as "allow gcloud" and means "allow every python
  program on this machine";
* a glob that does not compile. One unparseable entry makes the loader drop
  **every other rule in the file**.

An entry that matches nothing is *not* refused — pre-authorising something that
has not happened yet is the reason the command exists — but the count is printed
and written into the entry's own comment, because zero is also what a typo looks
like.

### `moatctl unignore <RULE> [--file FILE]`

Remove the n-th rule from an allowlist file — the index comes from
`moatctl allowlist`. Defaults to `user.toml`; `--file baseline.toml` drops a
learned entry. **Needs root.**

### `moatctl kill <ID>`

SIGKILL the process tree the alert recorded. Manual, deliberate, and separate
from the automatic gate.

### `moatctl forget <DST>`

Make Moat forget everything it has learned about one network destination, so
the next connection there is a first contact again. For a re-provisioned host,
a changed network, or a lab. **Needs root, and is recorded.**

Note that rarity stores IPv4 destinations as a **/24**, so this clears the
whole block and says how many counters went. Forgetting is the cheapest way to
make Moat stop mentioning a host, which is why it is gated and audited.

---

## Deciding

### `moatctl set <KEY> <VALUE> [--rule RULE]`

| Key | Values | Root | Effect |
|---|---|---|---|
| `mode` | `monitor` \| `enforce` | yes | Whether armed policies block or only report. |
| `contain` | `on` \| `off` | yes | Whether Moat may cut the network for a sequence it is sure about. |
| `kill` | `off` \| `log` \| `kill` | yes | What containment does to the processes involved. |
| `sandbox` | `on` \| `off` | yes | The bubblewrap shims. Needs a new login shell. |
| `digest` | `on` \| `off` | no | The weekly summary. A preference, not a protection. |
| `threshold.<NAME>` | a number, or `default` | yes | How much evidence a detection needs before it fires. |

`--rule <RULE>` arms **one** rule and leaves the daemon-wide mode alone. This is
the safe way to start enforcing: one rule whose false-positive surface you have
already measured. `moatctl status --json` lists what can be armed under
`enforceable`.

**On `kill`:** `off` selects no processes; `log` runs the whole decision and
writes what it *would* have killed; `kill` acts. It ships as `log` and should
stay there until you have read a week of `moatctl decisions` and agree with
every line. Both directions are root-gated and both are recorded — arming
SIGKILL is as consequential as disarming it.

**On `threshold.<NAME>`:** retunes a detection without `sudoedit
/etc/moat/moat.toml` and a service restart. It takes effect from the next event
— `mass_read` and `ransom_churn` read the value per event — and it is stored in
`state.json`, not written back into `moat.toml`, so a file you (or your config
management) own is never rewritten. `default` puts it back to whatever the file
says.

| Name | Range | Shipped | Bigger means |
|---|---|---|---|
| `mass_read_files` | 2–25 | 3 | less caught |
| `mass_read_window_secs` | 5–3600 | 30 | more caught |
| `ransom_churn_files` | 3–500 | 8 | less caught |
| `ransom_churn_window_secs` | 10–3600 | 60 | more caught |
| `dedupe_secs` | 0–3600 | 60 | more folding |

The rest of `[thresholds]` — rotation sizes, poll intervals, the arm timeout —
is plumbing rather than tuning and is deliberately not reachable from the
socket. The ranges are not decoration: every one of these has a value at which
the rule stops existing while `moatctl status` goes on listing it as on, and a
silently disabled detection is the failure this product is built against.
`mass_read_files` shipped as **40** until 2026-09-04 and had never fired once.

Root in **both** directions, unlike everything else here. Whether a number is a
weakening depends on the number it replaces, which the privilege gate cannot
see — and only one of the two possible mistakes is safe. Both directions are
recorded, and `moatctl status --json` publishes `thresholds` (what is in force)
alongside `threshold_overrides` (what you changed).

### `moatctl baseline <SUBCOMMAND>`

| Subcommand | Root | Meaning |
|---|---|---|
| `list` | no | Learning state, pending proposals, learned entries, demoted rules. |
| `accept <ID>` | **yes** | Write a proposal into `allowlist.d/baseline.toml`. |
| `dismiss <ID>` | no | Drop a proposal and stop being asked. |
| `relearn [--days N]` | **yes** | Restart the learning window, after a new toolchain or job. |
| `export` | no | Dump every tuple for review. |
| `propose <RULE>` | no | Propose entries for a noisy rule's top tuples. |
| `undemote [RULE]` | no | Go back to watching a rule the noise guard quietened. |

`accept` is root because it appends the same allowlist entry `ignore` does,
reached by a different route. `list` and `dismiss` are not: reading the evidence
and refusing an offer weaken nothing.

A proposal carrying a **`NOTE:`** line is one Moat is *not* vouching for — it
means the noise guard has had to quieten that pattern repeatedly and is
offering to make the decision permanent. The block looks identical either way,
so read the note.

### `moatctl feeds [refresh]`

Refresh the IOC feeds.

---

## Explaining

### `moatctl bundle <ID>`

Write `<incidents dir>/<id>/bundle.md` and print its path — the alert, its
evidence, the ancestry and any file analysis, as one markdown document.

Every process-derived string in it sits inside a fenced `DATA` block. That is
not cosmetic: the strings come from a file believed hostile, and a string
constant in a dropper is itself an attack on whatever reads the bundle.

### `moatctl analyze <ID> [--dry-run]`

Bundle the alert and hand it to your default agent for a plain-language
verdict. `--dry-run` prints the command instead of running it.

The daemon never launches an agent — it runs as root with no session. `moatctl`
does, from your session, with your credentials.

### `moatctl triage [--run] [--limit N] [--dry-run] [--undo ID]`

The unattended pass. `--run` is what the user timer runs: bundle each pending
alert, ask the agent, record the verdict. With no flags it prints what is
waiting.

The agent may **explain**, may **propose** an allowlist block for you to
accept, and at most may **demote** an alert from the badge to the timeline on a
confident benign verdict. It can never hide, acknowledge, delete or re-severity
one. `--undo <id>` reverses a demotion.

### `moatctl digest [--notify] [--force]`

The weekly summary. `--notify` is what the user timer runs and sends only if it
is due and enabled; `--force` sends it regardless.

---

## The daemon

`moatd` is normally run by systemd. These are for setup and diagnosis.

| Command | Meaning |
|---|---|
| `moatd config` | Print the effective configuration and exit. |
| `moatd render-policies` | Expand `{{HOME}}` in the templates, write `/run/moat/policies`, regenerate the export allowlist. |
| `moatd telemetry` | Show the selectable telemetry classes and what each costs. |
| `moatd telemetry --apply` | **The correct way to restart after a policy change.** Validates, renders, re-runs the checker, restarts tetragon *then* moatd in that order, and verifies the kernel actually came back by counting what it pinned. |
| `moatd wait-sensor [--timeout N]` | Block until Tetragon has actually loaded the rendered policies. Wired as `ExecStartPost=` so `After=tetragon.service` means "after it loaded", not "after it forked". |

**Do not restart by hand after changing policies.** Tetragon reads its policies
once, at startup, and has no hot-reload; moatd is `Requires=` + `After=`
tetragon. Restarting moatd first leaves it reading a log the old Tetragon is
still writing under the old policy set, and restarting tetragon alone leaves
moatd holding annotations for policies that no longer exist.

---

## Files

| Path | What |
|---|---|
| `/etc/moat/moat.toml` | Configuration. Sections: `paths`, `rules`, `ai`, `thresholds`, `net`, `baseline`, `context`, `learning`, `analysis`, `incidents`, `content`, `digest`, `telemetry`, `contain`. |
| `/etc/moat/allowlist.d/user.toml` | Your decisions, written by `ignore`. |
| `/etc/moat/allowlist.d/baseline.toml` | What the baseline learned or you accepted. |
| `/etc/moat/allowlist.d/omarchy-default.toml` | Shipped defaults. |
| `/etc/tetragon/tetragon.conf.d/` | One flag per file. `enable-process-cred` is **required** for the fileless-execution and privilege-raised detections. |
| `/var/lib/moat/alerts.jsonl` | The alert log. Append-only; rotates to `alerts.1.jsonl`. |
| `/var/lib/moat/decisions.jsonl` | Kill-gate decisions. |
| `/var/lib/moat/quarantine/` | Held files, mode `000`, with metadata. |
| `/var/lib/moat/incidents/` | Snapshots and bundles. |
| `/var/log/moat/tetragon.log` | The sensor's export. Root-only. |
| `/run/moat/policies/` | Rendered policies; Tetragon's `tracing-policy-dir`. |
| `/run/moat/control.sock` | The control socket, `0660 root:moat`. |

## Services

```
sudo systemctl enable --now tetragon moatd moat-feeds.timer
systemctl --user enable --now moat-digest.timer moat-triage.timer
```

The user timers are yours, not root's: desktop notifications belong to your
session. `moat-ship` is optional and sends alerts to an HTTPS collector or
syslog — see `docs/SHIPPING.md`.

## Scanners

Run before an install by the sandbox shims, never by you directly:
`moat-scan-pkgbuild`, `moat-scan-npm`, `moat-scan-cargo`, `moat-scan-pip`,
`moat-scan-go`. They read; they never execute what they read.

---

## The order to turn things on

Moat installs in **monitor mode**: it alerts, it blocks nothing. That is
deliberate — a bad first day should be noisy rather than expensive.

1. **Watch for a few days.** The first day is the loudest: rarity knows nothing
   yet and the baseline has not learned. The noise guard quietens a flooding
   pattern after 20 alerts in 24 hours, and the 7-day window learns recurring
   signed-repo actors on its own.
2. **`moatctl set contain on`.** A narrow network cut for a sequence Moat is
   sure about: one binary, one address, ten minutes, auto-released, visible in
   `moatctl contain`. Nothing is killed.
3. **Arm one rule at a time** — `moatctl set mode enforce --rule <name>` for a
   rule whose false-positive surface you have measured.
4. **Only then consider `set kill kill`,** after a week of `moatctl decisions`
   in which you agree with every line.

Each step is reversible, root-gated, and recorded.
