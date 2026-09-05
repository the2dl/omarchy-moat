# Baselining: keeping moat quiet enough to stay on

Design principle: 500 alerts a day means the user turns it off. Defender stays
on because the user sees a handful of things a month and each one is worth a
look. moat has no cloud reputation service, so it gets there with three local
mechanisms that are all explainable and all reversible. None of them is a
blanket allowlist: every suppression is a specific (rule, actor) pair that the
user can see and remove.

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
| cred, rootkit, shell | **no change** (an official binary reading your SSH key is still worth a look) | no change |
| persist, priv, exec, net | one step down (high→medium, medium→low) | no change |
| pkg (userland rules) | one step down for interpreter-spawn only | no change; `downloader` and `netcat` stay |
| x-* daemon rules | per rule, documented in the rule table | no change |

Downgrades are recorded in the alert (`severity_base`, `severity`,
`severity_reason`) so the panel can show "high → medium: actor is official
(package hyprland)". Nothing is ever upgraded by provenance alone; upgrades come
from context (pkg subtree, tmpfs binary) as the daemon rules already do.

## 2b. Context: think like a developer

A developer machine executes binaries out of $HOME all day, spawns shells from
build tools constantly, compiles test programs in /tmp, and has tools that
legitimately read cloud credentials. Judging the action alone produces the
500-a-day problem. Judging the action in its **context** does not. Every process
gets one context from its ancestry (the daemon's exact exec_id chain):

| Context | Meaning | Roots |
|---|---|---|
| `interactive` | the user is driving it | a terminal (alacritty, foot, kitty, ghostty, wezterm), tmux/zellij, an editor or IDE (nvim, vim, code, zed, hx, emacs, jetbrains), or an AI agent CLI (claude, codex, gemini, opencode, amp) that itself has an interactive root |
| `pkg-install` | inside a package-manager subtree (section 1 of the daemon's pkgtree classifier) | npm/pnpm/yarn/bun/pip/uv/cargo/makepkg/yay/paru and their descendants; this wins over `interactive` even when the install was typed in a terminal |
| `service` | started without a human at a prompt | systemd, Hyprland/quickshell launchers, desktop entries, cron, timers, D-Bus activation |
| `unknown` | ancestry lost (pruned, or pre-dates the daemon) | |

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

## 4. Noise guard: a pattern that floods gets demoted, not deleted

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

**The fan-out backstop.** A rule that is noisy in *general* rather than in one
shape would never trip a per-tuple threshold — a flood spread across hundreds of
distinct tuples would leave every one of them under 20. So once
`noisy_rule_fanout` (default 5) distinct tuples of one rule have each been
demoted on their own, the rule is demoted wholesale.

`status.demoted_rules` lists every rule quietened either way, so "what has Moat
stopped asking me about" has one answer; `is_demoted` stays narrow and means the
whole rule.

## 5. Surfacing policy

| Severity | Notify | Badge | Panel |
|---|---|---|---|
| critical | yes, urgency critical | yes | Alerts tab |
| high | yes | yes | Alerts tab |
| medium | no (unless `minNotifySeverity` lowered) | no | Timeline tab |
| low | no | no | Timeline tab |
| demoted rule | no | no | Timeline tab, grouped |

**Notification cooldown and burst collapse (plugin):** at most one toast per
rule per `notifyCooldownMinutes` (default 10). Further alerts of that rule inside
the window are counted; when the window ends and the count is above zero, one
toast says "N more from <rule title>, see panel". A burst of the same rule never
produces more than two toasts per window. Critical alerts bypass the cooldown
only when their `rarity` is `first_seen`. Learned from the first live run, where
a broken rule produced 173 alerts in 15 minutes and every one became a popup.

**moat's own build and tests are not incidents:** the daemon's test suite spawns
a fake `nc` and executes helpers from temp dirs to prove its rules. The shipped
`omarchy-default.toml` allowlists `moat-exec-untrusted-tmpfs` and the netcat
rule for exe globs `/tmp/.tmp*/nc` and `/tmp/.tmp*/moat-*` when the parent is a
`cargo` test runner (`parent = "*/target/*/deps/moatd-*"`), and nothing wider.

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

## 8. Alert record additions (extends CONTRACT §4)

```json
"actor": {"provenance": "official", "package": "coreutils 9.7-1", "script": null},
"context": "interactive",           // interactive | pkg-install | service | unknown
"severity_base": "high", "severity_reason": "actor is official (package hyprland)",
"suppressed_by": null,          // or "baseline.toml#3", "user.toml#1"; demoted rules are
                                // NOT suppressed: they keep suppressed_by null and get
                                // "surface": "timeline" so the panel groups them quietly
"surface": "alerts"             // alerts | timeline (BASELINE §5)
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

Suppressed alerts are still appended to alerts.jsonl with `suppressed_by` set
so the timeline can show them greyed out; the plugin hides them by default.
