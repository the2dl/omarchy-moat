# The tuning layers, what each costs, and how to undo it

Work down this list. Stop at the first layer that fits. Each one below is
wider, more expensive, or harder to see than the one above.

---

## 1. A userspace allowlist entry

**File:** `/etc/moat/allowlist.d/user.toml` (yours),
`baseline.toml` (learned), `default.toml` and `omarchy-default.toml`
(shipped by the package, `removable=false`).

**Shape** — every field optional except `name`, globs allowed, and **every
field present must match**:

```toml
# added 2026-09-07 from alert 01J8ZK...: Private SSH key read
[[rule]]
name   = "moat-cred-ssh-private-key-read"   # or a glob: "moat-cred-*"
exe    = "/usr/bin/restic"                  # what the KERNEL loaded
file   = "/home/dan/.ssh/id_ed25519"
parent = "/usr/bin/systemd"                 # any ancestor, up to the cap of 8
script = "/opt/google-cloud-cli/lib/gcloud.py"   # what an interpreter was running
```

**How to add one:**

```
# preview — writes nothing, needs no root, prints the blast radius
moatctl allow --name RULE --exe X --file F --parent P --script S

# commit
sudo moatctl allow --name RULE --script S --comment "why" --yes

# or, from an alert that already fired:
sudo moatctl ignore <id> --scope exe|exe+file|parent|rule
```

**Cost:** the narrowest thing moat has. A suppressed finding is still recorded
and still appears in chains **as context** — it simply stops asking. That is
deliberate: your allowlist is consent, and a consented step should not be able
to raise an alarm on its own.

**Undo:** `moatctl allowlist` for the index, then
`sudo moatctl unignore <index>` (or `--file baseline.toml` for a learned one).
Shipped files are refused; override them with an entry in `user.toml`.

**Traps:**
- An allowlist entry **cannot stop a rule that is armed in the kernel.** The
  process dies before moatd sees the event. `ignore` and `allow` both refuse
  this now and tell you what to do instead. On 2026-09-05, before they did:
  `cat` was allowed, `sudo cat /etc/shadow` was killed again, and the record
  read `suppressed_by: user.toml#2, action: killed` — still blocked, now quiet
  about it, under a card promising the opposite.
- A glob that does not compile makes the loader drop **every other rule in that
  file**. `allow` refuses bad globs; a hand edit does not.
- `exe` is what the kernel loaded. See `interpreters.md`.

---

## 2. A `[thresholds]` value

**When:** the rule is right, the count is wrong on this machine.

```
sudo moatctl set threshold.ransom_churn_files 12
sudo moatctl set threshold.ransom_churn_files default    # back to moat.toml
```

| name | range | shipped | bigger means |
|---|---|---|---|
| `mass_read_files` | 2–25 | 3 | less caught |
| `mass_read_window_secs` | 5–3600 | 30 | more caught |
| `ransom_churn_files` | 3–500 | 8 | less caught |
| `ransom_churn_window_secs` | 10–3600 | 60 | more caught |
| `dedupe_secs` | 0–3600 | 60 | more folding |

**Cost:** invisible unless you look. A threshold raised far enough turns the
rule off while `moatctl status` still lists it as on. `mass_read_files` shipped
as **40** until 2026-09-04 and the rule had never fired once — a threshold
nothing could reach is not a tuning, it is a disabled detection with good
manners. The bounds above exist to stop that; do not propose working around
them by editing `moat.toml` directly.

**Undo:** `default`. The value lives in `state.json`, not in `moat.toml`, so
the file the user owns is never rewritten and there is always a way back.

**Root in both directions.** Lowering a threshold is not purely restorative:
it is also the cheapest way to make moat noisy enough that nobody reads it.

The rest of `[thresholds]` — rotation sizes, poll intervals, the sensor arm
timeout — is plumbing, not tuning, and is deliberately unreachable from the
socket.

---

## 3. `tier: signal` vs `tier: detection`

A **policy annotation**, so it needs a template edit + re-render + reload.

- `detection` (default) — can be on the badge on its own.
- `signal` — recorded in full, a full chain trigger, **never on the badge
  alone**.

**When:** a rule is a genuinely useful ingredient in a sequence but is not, by
itself, worth interrupting anyone about. This is the right answer for "this
fires constantly but I do want it counted".

Related and cheaper: the **noise guard** demotes a rule that exceeds
`noisy_rule_per_day` to the timeline on its own, without suppressing it.
`moatctl baseline list` shows demotions; `moatctl baseline undemote <rule>`
(or `--all`) clears them after a retune.

---

## 4. A kernel `matchBinaries` exclusion

```
moatctl exclusions                          # what has a hole in it
moatctl exclusions --remove <rule>:<binary> # re-watch it — NO root needed
```

You do not add one directly. `moatctl ignore <id>` adds one **automatically**
when the rule is armed, because that is the only thing that stops a kill.

**Cost — read this before proposing it.** `matchBinaries` is the kernel's only
negative and **it has no path scope**. "Stop killing `ssh` when it reads
`~/.ssh/id_rsa`" is not expressible; the exclusion is "this rule no longer
watches `ssh` at all, for every path it guards". The rule stays armed for every
other binary.

Mechanically it re-renders every policy, deletes and re-adds the tracing policy
(a gap of milliseconds), and re-arms it — a fresh load starts in the `monitor`
its file declares, so forgetting to re-arm silently disarms the whole rule.

**Never exclude an interpreter.** moatd refuses it. See `interpreters.md`.

**Undo:** `moatctl exclusions --remove` — deliberately **not** root-gated,
because it makes moat watch more.

---

## 5. Enforcement

```
sudo moatctl set mode monitor --rule moat-cred-ssh-private-key-read
sudo moatctl set mode enforce --rule moat-cred-ssh-private-key-read
sudo moatctl set mode monitor          # daemon-wide; every policy moves
```

`--rule` arms **one** policy in the kernel and leaves the daemon-wide mode
alone. That distinction is the whole point: seven shipped policies carry
`Sigkill`, and arming them together on a desktop kills the module loader on USB
hotplug and kills `ssh` for reading your own key. Enforcement is something you
turn on one measured rule at a time. `moatctl status --json` lists what can be
armed under `enforceable`.

Two more switches, separate because they are two decisions:

- `sudo moatctl set contain on|off` — whether moatd may cut the network for a
  sequence it is sure about. Reversible in ten minutes, one address.
- `sudo moatctl set kill off|log|kill` — what containment does to the
  *processes*. Ships as `log`: it runs the whole decision and writes what it
  *would* have killed. Read a week of `moatctl decisions` and agree with every
  line before proposing `kill`. SIGKILL is the only thing here that destroys
  state nobody can get back.

**Turning a rule to monitor is the right answer for a temporary need.** It is
visible in `status`, it is recorded, and it does not leave a permanent grant
behind. Prefer it over an allowlist entry when the user says "just for this
afternoon".

---

## 6. Widening a policy's path scope

A real edit to `/usr/lib/moat/policies/<name>.yaml`, then a re-render and a
sensor restart (`sudo systemctl restart tetragon moatd`, in that order —
Tetragon has no policy hot-reload).

**Cost: event volume, and it is measured, not guessed.** On this machine,
2026-09-04:

| number | how |
|---|---|
| **42.3 file writes/s under `$HOME`** during one `npm install` (171 packages, 4359 events in 103 s) | `inotifywait -r -e close_write -e create -e moved_to` |
| **19.2/s** through a kernel filter of this shape | the same sample, scored against the shipped prefix/suffix lists |
| 0.32/s actually recorded | the same sample, after the userland stage |
| 127 KB/s export, 50 MB per 6–7 min | `stat` on the export file every 5 s for 300 s |

Reads outnumber writes in a build by a wide margin. Every one of those events
is a line in the export, a parse in moatd, and a pass through every rule's
`on_hook`.

`Prefix` also cannot say "under `$HOME` but **not** under any `node_modules`" —
`NotPrefix` is still a prefix and `node_modules` occurs at arbitrary depth — so
a widened scope means the kernel posts every build tree's churn and moatd cuts
it in userland, *after paying for it*.

**Widen one directory at a time and measure**, never to `$HOME` wholesale. The
2026-09-07 widening of `moat-ransom-file-churn` added `~/Projects`, `~/src` and
`~/code` — one step, taken because a simulated sweep confined to a source tree
was invisible and that is where a developer's irreplaceable data lives.

---

## 7. Telemetry classes

Not a detection knob — this is what gets *recorded* for export, in
`/var/lib/moat/telemetry.jsonl`.

- `alerts` (on by default), `process` (exec/exit), `network` (outbound
  connects), `file` (executable-shaped writes and chmod +x).

`moatd telemetry` prints what is on and what each class costs. Turning
`network` or `file` on changes what the **kernel** is asked to do, so it needs
new policies and a sensor restart:

```
sudoedit /etc/moat/moat.toml      # the [telemetry] block
sudo moatd telemetry --apply      # validates, renders, re-checks, restarts, VERIFIES
```

Never restart tetragon by hand for this. A bad policy load is a silent outage:
on 2026-09-03 one cost 25 minutes of blindness while every surface still read
"running".

---

## What is visible and what is not

Worth saying out loud to a user, because it drives which layer to prefer:

| change | leaves a trace |
|---|---|
| allowlist entry | `moatctl allowlist` + a `moat-x-protection-changed` alert |
| threshold change | `moatctl status`, both `thresholds` and `threshold_overrides`, + an alert |
| rule → monitor | `moatctl status`, + an alert |
| kernel exclusion | `moatctl exclusions`, + an alert |
| **tuning that silently does nothing** | **nothing at all** |

That last row is why the interpreter case matters so much, and why `moatctl
allow` previews by default. A grant you can see is safer than a grant you
cannot, even when it is wider.
