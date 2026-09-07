# Baselining: keeping moat quiet enough to stay on

Design principle: 500 alerts a day means the user turns it off. Defender stays
on because the user sees a handful of things a month and each one is worth a
look. moat has no cloud reputation service, so it gets there with four local
mechanisms that are all explainable and all reversible: provenance (§1), context
(§2b), the learning window (§3), and the rule tier plus the noise guard (§4).
None of them is a blanket allowlist: every suppression is a specific (rule,
actor) pair that the user can see and remove, and the tier is a declaration a
rule makes about itself, in its own file, that a reader can check.

Target after the first week on a developer machine: **zero notifications on a
quiet day, under five high/critical per week**, with medium/low visible in the
panel timeline but never notifying and never counted in the badge.

## 1. Provenance: who is acting

Every alert's acting process, and its parent chain, is classified once (cached
by exe path + inode + mtime, invalidated on pacman transactions):

| Class | Meaning | How decided |
|---|---|---|
| `official` | binary owned by a package from a trusted, signed repo | `pacman -Qo` gives a package; package is in a repo listed in `trusted_repos` (default `core extra multilib omarchy`); file passes `pacman -Qkk`-style mtime/size check against the package DB |
| `foreign` | owned by a package pacman did not get from a trusted repo | `pacman -Qm` lists it (AUR builds, local installs). **No trust**: the June 2026 AUR wave installed pacman-owned binaries |
| `user` | not package-owned, lives under $HOME, /tmp, /var/tmp, /dev/shm, /opt, /usr/local | path test |
| `unknown` | anything else, or lookup failed | fallback |

Interpreters carry the provenance of the script, not of themselves: `bash`,
`python`, `node`, `perl` running a script take the script's class (argument 0
after the interpreter, or the `binprm` path), because an official `/usr/bin/bash`
executing `/tmp/x.sh` is a `user` actor.

Provenance is evidence, not a verdict. It appears in every alert's `evidence`
list and in the panel ("actor: official, package coreutils 9.7-1").

## 2. Scoring: provenance adjusts severity, within limits

| Family | official actor | foreign / user / unknown actor |
|---|---|---|
| cred, rootkit, shell, ransom | **no change** (an official binary reading your SSH key is still worth a look; `/usr/bin/python` encrypting your documents is no safer for the repo that shipped python) | no change |
| persist, priv, exec, net | one step down (high→medium, medium→low) | no change |
| pkg (userland rules) | one step down for interpreter-spawn only | no change; `downloader` and `netcat` stay |
| x-* daemon rules | per rule, documented in the rule table | no change |

Downgrades are recorded in the alert (`severity_base`, `severity`,
`severity_reason`) so the panel can show "high → medium: actor is official
(package hyprland)". Nothing is ever upgraded by provenance alone; upgrades come
from context (pkg subtree, tmpfs binary) as the daemon rules already do.

The step is taken **after** §2b's matrix has decided the cell, because a matrix
cell sets the severity outright and a step taken before it would simply be
overwritten — named in `severity_reason` and worth nothing, as an official
quickshell running a plugin script was on 2026-09-05. The guards are unchanged:
no step during a `pkg-install`, none for a rule that is never lowered, and none
where the matrix already put the event on the timeline.

## 2b. Context: think like a developer

A developer machine executes binaries out of $HOME all day, spawns shells from
build tools constantly, compiles test programs in /tmp, and has tools that
legitimately read cloud credentials. Judging the action alone produces the
500-a-day problem. Judging the action in its **context** does not. Every process
gets one context from its ancestry (the daemon's exact exec_id chain), and the
context comes **first from the controlling terminal, then from names, then from
config** — in that order, with a package install winning over all three:

| Context | Meaning | Decided by |
|---|---|---|
| `pkg-install` | inside a package-manager subtree (section 1 of the daemon's pkgtree classifier) | npm/pnpm/yarn/bun/pip/uv/cargo/makepkg/yay/paru and their descendants. Checked first and wins outright, even when the install was typed in a terminal |
| `interactive` | the user is driving it | **1.** a controlling terminal (`tty_nr` ≠ 0, read from /proc at exec time) on the acting process or any ancestor in the capped chain — whatever opened the pty; **2.** failing that, a name: a terminal (alacritty, foot, kitty, ghostty, wezterm), tmux/zellij, `sshd`/`login`, `su`/`sudo`, an editor or IDE (nvim, vim, code, zed, hx, emacs, jetbrains); **3.** failing that, `[context] interactive_roots` in moat.toml. An AI agent CLI (claude, codex, gemini, opencode, amp) is transparent to the name walk, so it inherits whatever root is above it |
| `service` | started without a human at a prompt | no pty anywhere in the chain, **and** a name: systemd, Hyprland/quickshell launchers, desktop entries, cron, timers, D-Bus activation — or `[context] service_roots` |
| `unknown` | ancestry lost (pruned, or pre-dates the daemon) | |

**Why the terminal and not the names.** The name walk came first and it was a
to-do list, not a design: any terminal or session host nobody had written down
fell straight through to `systemd` and became a `service`, the one context this
section never softens, and nothing failed loudly when it did. On 2026-09-05 that
was nine of the thirteen alerts on this machine's badge — the user's Claude
sessions run as `systemd --user -> herdr -> bash(pts/5) -> claude`, and `herdr`
was on no list, so a `git clone` writing a vendored `.envrc` scored high instead
of low, a `git rebase` touching `~/.config/systemd/user/*.service` high instead
of medium, and a bundled `rg` reading `~/.config/gh/hosts.yml` high instead of
medium. `chain.rs` had already hit this on 2026-09-04 and moved to the kernel's
`sid == pid`. The kernel records `tty_nr` on the same /proc line, so the general
question costs nothing extra and is right for every terminal, multiplexer,
session host and `ssh` login that will ever exist. It also keeps the user's own
`setsid`/`nohup` launches from a terminal `interactive`, which is what the
ancestry walk gave before. The two config lists are the escape hatch for the
residue (a session host moat cannot see a tty through) and ship empty.

**A pty is not proof of a human, and this is not sold as one.** Upgrading a
reverse shell to a pty (`python -c 'import pty; pty.spawn("/bin/bash")'`) is the
first thing an attacker types after one lands, and that would read as
`interactive` here. The name walk had the identical hole — `exec -a alacritty`
is one word — so this is not a regression; it is the same limit stated honestly.
What bounds it: `interactive` never takes a `cred` alert below the timeline and
never touches the `shell` family at all; `pkg-install` is checked first and is
never downgraded by anything; and `chain.rs` ignores context entirely, so the
correlation that ties an incident together cannot be talked out of it by a pty.
In the other direction the change is *stricter*: a raw `nc -e /bin/sh` has no
controlling terminal, so it now scores `service` where the name walk could have
found an interactive ancestor above it.

Then the same event is scored by context. Examples that define the matrix:

| Event | interactive | pkg-install | service |
|---|---|---|---|
| node/python reads `~/.aws/credentials`, `~/.config/gh/hosts.yml` | medium ("your script read cloud creds; expected for CDK, boto, SDK tools") | **critical** | high |
| shell/interpreter spawned | timeline only | low (one per install root) | medium |
| exec of a binary under a project worktree, `target/`, `node_modules/.bin`, `.venv/bin`, `~/.cargo/bin`, `~/.local/bin`, `~/go/bin`, `~/.bun/bin`, `~/.local/share/mise`, `~/.local/share/pnpm` | timeline only | medium | high |
| exec of a binary under `~/.cache`, `~/Downloads`, `~/.config`, `~/.local/share/<other>`, a hidden dir, or `/tmp` when no build tool (cmake, make, ninja, cargo, gcc, clang, configure, pytest, go) is in the chain | medium | **high** | **high** |
| exec from `/tmp` with a build tool in the chain (cmake try_compile, autoconf, cargo build scripts, pytest tmp dirs) | timeline only | low | medium |
| curl/wget with non-registry destination | timeline only (developers curl things) | **high** | medium |
| write to `.git/hooks/*`, `.husky/`, `.envrc`, `.vscode/tasks.json`, `.claude/settings.json`, `CLAUDE.md` inside the current project | low (lefthook, husky, direnv allow) | **high** | high |
| write to shell rc, autostart, systemd user units, hyprland conf | medium (dotfile managers, installers) | **critical** | high |
| ptrace / `/proc/<pid>/mem` by a debugger/profiler | timeline only | high | high |
| AI CLI launched | nothing | **high** | medium unless parent is allowlisted (omarchy usage widgets) |

Rules of the matrix:
- `pkg-install` context never gets a downgrade from provenance or from anything
  else. The postinstall script is the attack surface this whole project exists
  for.
- `interactive` context downgrades by up to two steps for exec/persist/priv/net
  and one step for cred, never below "timeline only" for cred (credential reads
  are always at least visible).
- `service` context downgrades nothing; it is where persistence lives.
- The credential allowlists in the kernel policies stay as they are (ssh, git,
  gh, aws, docker...). The matrix only governs what happens to a read by
  something *not* on the allowlist. Add to the policy allowlists the devops
  tools that read cloud creds by design: terraform, tofu, pulumi, ansible,
  gcloud, az, sam, kubectl, helm, k9s, flyctl, wrangler, vercel, netlify, doctl.
  Node- and python-based ones (cdk, serverless, boto scripts) cannot be
  allowlisted by binary; they are exactly the `interactive` medium case above.

The context and the resulting downgrade are recorded in the alert
(`context`, `severity_reason`) and shown in the panel, so a user reading
"medium: interactive session, script under ~/Projects/infra" learns what moat
would have done to the same read from an install script.

## 3. Learning window and proposals

`state.json` records `installed_at`. For `learning_days` (default 7) after that,
moat is in **learning** mode. During learning:

- A (rule, actor exe, parent exe, file dir) tuple whose **rule** scores it
  **medium or low** — `severity_base`, before the §2b context matrix escalates
  it — from an **official** actor on **3 distinct days**
  is written to `/etc/moat/allowlist.d/baseline.toml` as a learned rule, with a
  comment recording the counts and dates. It suppresses further alerts for that
  tuple. High and critical are never learned. Foreign and user actors are never
  learned.

  **The gate reads `severity_base`, not the escalated severity.** §2b escalates
  by context and never downgrades inside `pkg-install`, so gating on the final
  value meant one sighting inside a package build barred a tuple from the
  baseline permanently — even one that scores medium every ordinary day. On
  2026-09-04 that blocked 628 of 1206 tuples, 295 of them from official actors,
  and was the single largest reason nothing had ever been learned. The severity
  a detection assigns is a statement about the action; the escalation is a
  statement about the circumstances, and circumstances are exactly what a
  baseline is for. A hard ceiling remains on the escalated value: a tuple that
  has ever reached `critical` is never learned, whatever its rule scored.
  `baseline export` reports both, as `max_rule_severity` and `max_severity`.
- The panel's Allowlist tab shows learned entries with a "learned" tag and a
  Remove button, same as user entries.

After learning ends, the same condition produces a **proposal** instead of an
allowlist entry: `state.json.proposals[]` holds the tuple, counts, and the exact
TOML that accepting would write. The panel shows "N recurring patterns to
review" with Accept / Dismiss per entry; `moatctl baseline list|accept|dismiss`
does the same from the CLI. Accepting writes to `baseline.toml` with a comment
saying who accepted and when.

`moatctl baseline relearn [--days N]` restarts the window, for after a big
change (new job, new toolchain) or after a rule retune. It clears each tuple's
distinct-day counter and its `max_rank`, so the three days have to be earned
again inside the new window; `count`, `first_seen` and anything already written
to `baseline.toml` are left alone.

Clearing `max_rank` is the point of the command. It is a running maximum that
never decays, so one high — scored under rules that have since been retuned, or
under a context escalation that no longer applies — otherwise keeps a tuple out
of the baseline permanently with no way back. The reset is safe because it is
self-healing: a tuple that still scores high re-poisons itself on its next
alert, so only tuples that have genuinely stopped being severe stay clean.

`moatctl baseline export` reports both, as `max_severity` and `blocked_by` —
the gate actually holding each tuple back, in the order the checks apply. A row
that has been seen hundreds of times over a week and still is not learned is
otherwise unexplainable from the row itself.

## 4. Rule tier, and the noise guard

### 4a. A building block says so

Some rules are right about what they saw and weak about what it means. A binary
executed out of `/tmp` is a fact; on a developer's machine it is also every
`cargo test`, every `configure`, every AppImage. Such a rule is not wrong and
must not be deleted — `chain.rs` exists because events that are ordinary alone
are not ordinary together, and the lab AUR attack was caught by
`moat-exec-untrusted-tmpfs` appearing in a chain. It simply must never be the
thing that interrupts you.

Rules declare that themselves:

```yaml
    moat.omarchy/tier: "signal"        # signal | detection. Absent = detection.
```

and userland rules use `rules::signal_meta` for the same declaration. Every
seeded rule carries a one-line WHY beside the annotation ("weak alone; exists to
be a chain step").

**What `signal` changes.** Exactly one thing: the alert's `surface`. It is
forced to `timeline`, so the rule never reaches the badge on its own. Three
consequences follow from that one fact — no incident snapshot, not queued for
auto-triage, not counted by the noise guard — because all three ask "is a person
being asked about this row", and the answer is no.

**What `signal` does not change, and this is the load-bearing half:**

- **Severity.** Chains need `>= medium` triggers, the baseline learns on
  `severity_base`, and rarity never sees the tier. A `signal` rule that scores
  `high` still records `high`.
- **Being a chain trigger.** `chain::Observation.silenced` reads `suppressed_by`
  and nothing else — not `surface`, not the tier. Only the *user's own*
  allowlist entry makes a step context rather than a trigger. A rule that is
  weak on its own is the prime candidate for a sequence, not a thing to
  discount.
- **Being recorded.** The row is in `alerts.jsonl` in full, with its evidence
  and its `explain` block, and the alert says which tier it is and why it is on
  the timeline.

**Two exceptions put a `signal` row on the badge**, and both are moat concluding
it is not "on its own" any more:

1. **The §2b matrix escalated it inside a `pkg-install` context** to `high` or
   `critical`. That is the product's thesis: a `/tmp` exec **is** a detection
   inside a package install. The alert records this as
   `pkg_install_escalation: true`.
2. **A chain reaching `high` re-stamped it** (`engine::note_chain`), which is
   the existing behaviour and is unchanged.

**Seeded on exactly seven rules**, which is not a coincidence: it is the set the
noise guard's own fan-out backstop had discovered empirically on this machine —
`exec-untrusted-home`, `exec-untrusted-tmpfs`, `net-first-contact`,
`pkg-subtree-interpreter-spawn`, `persist-desktop-entry-write`,
`persist-omarchy-plugin-write`, `persist-omarchy-menu-extension-write`. The
guard had been saying "these are building blocks" for months, once a day, through
a circuit breaker that forgets. Now the rules say it once.

Commercial analogue: Elastic Security's "building block" rules fire, are stored,
are hidden from the alerts table by default, and exist for other rules to
correlate on. This is the same idea as a declaration rather than a discovery.

**A `signal` rule may not enforce.** `check.py` rejects
`tier: signal` next to `enforce: kill|deny`: a rule that has declared its
evidence too weak for the badge must not be able to end a process on it.

### 4b. Noise guard: a pattern that floods gets demoted, not deleted

If one **(rule, actor, parent, file dir) tuple** raises more than
`noisy_rule_per_day` (default 20) alerts in a rolling 24 h, moat demotes **that
tuple** to the timeline: still logged, still grouped, no notification and no
badge count. It clears itself after 24 h under the threshold, and
`moatctl baseline undemote <rule>` clears the rule and every pattern under it at
once.

**Scoped to the tuple, not the rule.** Demoting a whole rule silences every
shape it can ever match, including shapes nobody has seen yet, and on 2026-09-04
that cost a real detection. `moat-exec-untrusted-tmpfs` had fired 320 times from
this machine's own builds — `bash` and `bwrap` out of cargo's temp directories,
plus moat's own test binaries — so the guard demoted the rule. When a package
`preinstall` then downloaded a binary into `/tmp` and executed it, which is the
precise thing that rule exists to catch, the alert went to the timeline instead
of the badge. The activity that made the rule noisy had nothing in common with
the activity that tripped it except the rule id.

Tuple scoping can only reduce what reaches the badge for patterns already
established, and never hides a new one: every shape that is quiet today stays
quiet, and a shape nobody has seen is heard.

**A package-install escalation is never demoted.** An alert the §2b matrix put
at `high` or `critical` *because it was inside a package install*
(`pkg_install_escalation: true`) stays on the badge whatever the noise guard
concludes, both for new alerts and for the retroactive pass
(`engine::quieten_backlog`). This is the 2026-09-04 failure closed in general
rather than for one path: the guard's arithmetic is about how often a shape
fires **on this machine**, and that is not evidence about what a package install
did. Nor is a step a `high` chain re-surfaced — the correlator put it back on the
badge knowing the rule was noisy, and the noise guard does not undo correlation.

**There is no rule-wide demotion, and the fan-out backstop is gone.** It said:
once `noisy_rule_fanout` (default 5) distinct tuples of one rule had each been
demoted on their own, the rule went quiet wholesale — every shape of it,
including shapes nobody had ever seen, for 24 h. It existed because the noise
guard was the only mechanism moat had for saying "this rule is a building block,
not a detection", and a 24 h circuit breaker that forgets is the wrong
instrument for a permanent fact about a rule. §4a is that fact, said once by the
rule.

What is left over — a *detection* rule flooding across many patterns — is a
**rule bug**, and the output for a rule bug is a report, not a silence. Past
`noisy_rule_fanout` quiet patterns the `moat-x-noisy-rule` alert says so: "N
distinct patterns of this rule are now quiet; that is the rule being wrong for
this machine rather than one noisy workload — it wants retuning, or a
`moat.omarchy/tier: signal` declaration if it is a building block." Nothing
beyond those N patterns is silenced; a shape nobody has seen still reaches the
badge.

`status.demoted_rules` lists every rule with at least one quietened pattern, so
"what has Moat stopped asking me about" has one answer, and `moatctl baseline
undemote <rule>` clears every pattern under it.

## 5. Surfacing policy

| Severity | Notify | Badge | Panel |
|---|---|---|---|
| critical | yes, urgency critical | yes | Alerts tab |
| high | yes | yes | Alerts tab |
| medium | no (unless `minNotifySeverity` lowered) | no | Timeline tab |
| low | no | no | Timeline tab |
| demoted pattern | no | no | Timeline tab, grouped |
| `signal` tier | no | no | Timeline tab, whatever the severity (§4a) — **except** when the §2b matrix escalated it inside a `pkg-install`, or a `high` chain re-stamped it, in which case it is on the badge like any other alert |

`surface` on the record is the single answer, and it is computed in one place
(`scoring::final_surface`) in this order: an allowlist suppression wins outright;
then a package-install escalation, which neither the tier nor a demotion may
quieten; then the `signal` tier and a noise-guard demotion; then the severity
table above.

**Notification cooldown and burst collapse (plugin):** at most one toast per
rule per `notifyCooldownMinutes` (default 10). Further alerts of that rule inside
the window are counted; when the window ends and the count is above zero, one
toast says "N more from <rule title>, see panel". A burst of the same rule never
produces more than two toasts per window. Critical alerts bypass the cooldown
only when their `rarity` is `first_seen`. Learned from the first live run, where
a broken rule produced 173 alerts in 15 minutes and every one became a popup.

**moat's own build and tests are not incidents:** the daemon's test suite spawns
a fake `nc` and executes helpers from temp dirs to prove its rules, and the
scanner suites build fake toolchains in `mkdtemp` directories and run the real
`sandbox/shims` against them. The shipped `omarchy-default.toml` allowlists
those, and nothing wider — but *which field* names the binary depends on the
hook, because that is what the daemon puts in the allowlist candidate (`exe` =
the acting process, `file` = the path the hook named, `parent` = any ancestor):

| Rule | Actor (`exe`) | Path (`file`) | Ancestry (`parent`) |
|---|---|---|---|
| `moat-exec-untrusted-tmpfs` (`bprm_check_security`) | the caller — the cargo test binary, or the bash a shim invoked | the executed binary: `/tmp/.tmp*/nc`, `/tmp/.tmp*/moat-*`, `/tmp/moat-{,build-}shim-test.*/*`, `/tmp/moat-sandbox-test.*/*` | `*/target/*/deps/moatd-*` or `*/sandbox/shims/*` |
| `moat-pkg-subtree-netcat-exec` (userland) | the copied binary itself: `/tmp/.tmp*/nc`, `/tmp/.tmp*/moat-*` | — | `*/target/*/deps/moatd-*` |
| `moat-priv-setuid-chmod` (`path_chmod`) | the test binary: `*/target/*/deps/moatd-*` | `/tmp/.tmp*/*` | — (the actor is not in its own ancestry here, so a `parent` glob would be dead) |

Writing an entry against the wrong field produces one that reads plausibly and
can never fire; `the_shipped_entries_match_the_candidates_the_engine_really_builds`
checks each one against a candidate copied from a real alert.

Dedupe stays at 60 s per (rule, exe, file) with `count` updates, and the
timeline groups by (rule, exe) so a thousand identical events read as one row
with a count.

## 6. What this is not

- Not a cloud lookup, not telemetry. Everything above is local and the
  provenance source is the local pacman database.
- Not a trust in "installed software". Trust is per trusted repo signature;
  AUR-built packages get none, which is the whole point after the 2026 AUR
  incidents.
- Not silent. Every suppression is a visible, removable line in a TOML file
  and every automatic decision leaves an alert or a proposal behind.

## 7. Config keys (`/etc/moat/moat.toml`)

```toml
[baseline]
trusted_repos       = ["core", "extra", "multilib", "omarchy"]
learning_days       = 7
learn_min_days      = 3          # distinct days a tuple must recur to be learned
noisy_rule_per_day  = 20
provenance_downgrade = true      # section 2
```

`noisy_rule_fanout` (5) is no longer a silencing threshold: it is the number of
quietened patterns at which `moat-x-noisy-rule` starts saying the rule itself is
the problem (§4b).

## 8. Alert record additions (extends CONTRACT §4)

```json
"actor": {"provenance": "official", "package": "coreutils 9.7-1", "script": null},
"context": "interactive",           // interactive | pkg-install | service | unknown
"severity_base": "high", "severity_reason": "actor is official (package hyprland)",
"suppressed_by": null,          // or "baseline.toml#3", "user.toml#1"; demoted rules are
                                // NOT suppressed: they keep suppressed_by null and get
                                // "surface": "timeline" so the panel groups them quietly
"surface": "alerts",            // alerts | timeline (BASELINE §5)
"tier": "detection",            // detection | signal (§4a). Absent means detection.
                                // A `signal` row is recorded in full and is a full chain
                                // trigger; it is never on the badge on its own.
"pkg_install_escalation": false // the §2b matrix put this at high/critical BECAUSE it
                                // was inside a package install. The one outcome neither
                                // the tier nor the noise guard may quieten, recorded
                                // because the guard reaches back over stored records.
```

Resolved shapes (both sides build against these):

- `status` carries `proposals[]` and `demoted_rules[]` at the top level, plus
  `baseline: {learning, learning_ends, proposals: n, learned: n, demoted: [...]}`.
- A proposal is `{id, rule, exe, parent, dir, count, days, first_seen, last_seen, toml}`;
  `id` is what `baseline accept|dismiss` take.
- The `allowlist` response lists entries from every file in allowlist.d with
  `file`, `index` (position within that file), `source: user|learned|shipped`,
  and `comment`; `unignore` takes `{file, index}` so learned entries can be
  removed the same way as user entries. Shipped entries (omarchy-default.toml)
  report `removable: false`.
- Timeline groups key on `actor.script` when present, else `process.exe`.
- `status.ledger` is `{needs_you, recorded, suppressed, signal}` — see below.

Suppressed alerts are still appended to alerts.jsonl with `suppressed_by` set
so the timeline can show them greyed out; the plugin hides them by default.

### Three populations, three words

One file holds three different kinds of record and they were all counted under
one word. On 2026-09-05 `moatctl status` printed **"unacked 1,854"** next to a
badge of **13**: 48% of those records were allowlist-suppressed — the user had
already answered them — and most of the rest were timeline rows that were never
a question. The number was true and the word was wrong, which is worse than a
wrong number, because it teaches the reader that the screen is noise.

So `status` carries, and `moatctl status` prints, three plainly named counts:

| word | means | predicate |
|---|---|---|
| **needs you** | on the badge, unacked, not suppressed — the only queue | `surface == "alerts" && !acked && !suppressed_by` |
| **recorded** | seen, written down, never asked about (with **signal** broken out, so "recorded" can be read as "how much of this is scaffolding") | `surface == "timeline" && !suppressed_by` |
| **suppressed** | an allowlist entry matched | `suppressed_by != null` |

`status.unacked` is unchanged and still means the badge, per severity; the panel
builds against it. `ledger.needs_you` is that same set as one number. The weekly
digest (LEARNING §5) uses the same three words in the past tense.

Two behaviours follow from the naming. `moatctl ack --all`/`--rule` skips rows
that were never on the badge and reports how many it skipped: they were never
asked about, so there is nothing to answer, and walking 1,854 rows to append an
`acked: true` line to each is a lot of writing to change nothing anyone can see.
And `triage_pending` is exactly the badge, so the panel never counts work the
triage runner will not be offered.

**Not a file split, yet.** The obvious next step is a second ledger file for
recorded rows, and it is the right one: `alerts.jsonl` rotates at 20 MB with one
generation kept, and a single day of quickshell plugin execs at the volume this
machine produces rotates a week of real detections out of it. That is a change
to the file format every reader is built against — the plugin's tail-and-fold,
`Tailer`, rotation detection, the bundle, `moatctl list --since` — so it is a
follow-up with its own migration, not a rider on a wording fix.
