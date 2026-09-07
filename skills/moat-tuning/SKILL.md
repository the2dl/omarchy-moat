---
name: moat-tuning
description: >
  Diagnose and tune omarchy-moat, the eBPF supply-chain sensor on this machine
  (Tetragon in the kernel + the moatd daemon + moatctl). Use when a moat alert
  needs explaining, when a detection is too loud or too quiet, when something a
  user trusts is being flagged, refused, contained or killed, or when they want
  to allow a program, exclude a binary, change a threshold, or arm/disarm
  enforcement. Triggers: moat, moatctl, moatd, tetragon, moat alert, "why did
  moat flag", "moat keeps killing", "moat blocked", allowlist, allowlist.d,
  matchBinaries, kernel exclusion, tracing policy, moat-cred-*, moat-persist-*,
  moat-ransom-*, moat-x-*, ransom_churn_files, mass_read_files, enforce mode,
  contain, /etc/moat. Covers choosing the RIGHT tuning layer; getting that
  wrong is how people silently disable their own protection.
---

# Tuning moat

moat is a two-halves system and almost every bad tuning decision comes from
forgetting which half you are talking to.

| half | what it is | where it is configured | how a change lands |
|---|---|---|---|
| **kernel** | Tetragon tracing policies — the eBPF programs that see the syscall and can `Sigkill` | `/usr/lib/moat/policies/*.yaml` templates → rendered to `/run/moat/policies` | needs a re-render **and** a policy reload; there is no hot-reload |
| **userspace** | `moatd` — ancestry, provenance, rarity, chains, suppression, containment | `/etc/moat/moat.toml`, `/etc/moat/allowlist.d/*.toml` | live, over the control socket |

**The single most important fact in this skill:**

> A policy's `matchBinaries` is evaluated in the kernel against the binary the
> kernel **LOADED**. For a `#!` script that is the **INTERPRETER**.
> `/proc/<pid>/exe` of a running shell script is `/usr/bin/bash`, never the
> script.

This is not a footnote. It is the reason tuning can be recorded, reloaded,
verified — and do nothing, while the user keeps getting refused. Read
`references/interpreters.md` before proposing anything that names a binary. It
contains two real cases from 2026-09-07 on this machine.

## Always do this first

**Read the alert before proposing a rule.** `moatctl explain <id>` is the
primary source and it already contains almost everything you need:

- the **exe** (what the kernel loaded — possibly an interpreter),
- the **args**,
- the actor's **script**, when an interpreter was involved — moatd has already
  resolved this for you and prints it,
- the **selector** that matched,
- the **allowlist verdict** (`suppressed_by`, or why nothing matched),
- whether an **action was taken** (`action_taken`, `mode`).

Then, as needed:

```
moatctl status              # mode, armed rules, sensor health, thresholds
moatctl list --limit 20     # recent alerts
moatctl explain <id>        # THE diagnosis command
moatctl chain <id>          # the sequence this alert is one step of
moatctl allowlist           # every merged entry, with index and comment
moatctl exclusions          # binaries a rule has been told to stop watching
moatctl decisions           # what the kill gate spared and why
```

All of those are read-only and need no root. Run them. Do not reason from the
user's summary of an alert when the alert itself is one command away.

## Choosing the layer

Work down this list and stop at the first one that fits. Earlier entries are
narrower and cheaper to undo.

1. **A userspace allowlist entry** — `/etc/moat/allowlist.d/user.toml`, five
   matchers (`name`, `exe`, `file`, `parent`, `script`), globs allowed, every
   field present must match. This is the right answer for the large majority of
   false positives. Preview it first (see below).
2. **A `[thresholds]` value** — when the rule is right but the *count* is wrong
   on this machine. `sudo moatctl set threshold.ransom_churn_files 12`.
3. **`tier: signal`** — when a rule is a useful chain ingredient but should
   never be on the badge alone. A policy annotation; needs a re-render.
4. **A kernel `matchBinaries` exclusion** — `moatctl ignore <id>` does this
   automatically when the rule is **armed**, because an allowlist entry cannot
   stop a kill. It is a hole in that rule for that binary **everywhere**;
   `matchBinaries` is the kernel's only negative and it has no path scope.
5. **Turning the rule to monitor** — `sudo moatctl set mode monitor --rule X`.
   Visible in `status`, recorded, and the right answer when the need is
   temporary.
6. **Widening a policy's path scope** — a real edit to a template, a re-render
   and a sensor restart. Costs event volume; see `references/layers.md` for the
   measured numbers.

`references/layers.md` has the full table with what each layer costs and how to
undo it.

## Always preview before granting

```
moatctl allow --name moat-cred-cloud-credential-read \
              --script /opt/google-cloud-cli/lib/gcloud.py
```

With no `--yes` this **writes nothing**. It prints the block it would write and
which alerts already on record it would have suppressed, by rule and with a
sample. That is the blast radius, and you should show it to the user before
they commit. It needs no root, so you can run it yourself.

Committing is theirs: `sudo moatctl allow ... --yes`.

You may run the read commands and the preview. You may **not** run the
commands that write — propose them and let the user run them. If
`MOAT_AGENT_CONTEXT=1` is set, `moatctl` will refuse them anyway.

## Refusals — never propose these

- **Never propose excluding an interpreter.** `/bin/sh`, `/usr/bin/bash`,
  `/usr/bin/python*`, `/usr/bin/node`, `/usr/bin/perl`, `/usr/bin/ruby`,
  `/usr/bin/env`. Naming one as an allowlist `exe` or as a kernel exclusion is
  a grant to *every program it ever runs*. Use `--script` instead. moatd
  refuses both of these now; do not go looking for a way around it.
- **Never propose silencing a `moat-x-*` self-health rule.**
  `moat-x-protection-changed`, `moat-x-was-not-running`,
  `moat-x-nobody-is-watching`, `moat-x-sensor-throttled` and
  `moat-x-sensor-mismatch` are in `NEVER_SILENCE`.
  `moatctl ignore` and `moatctl allow` both refuse them outright, including via
  a glob like `moat-*`. An entry that silences one does not quieten a noisy
  detection — it makes every future weakening invisible, which is exactly the
  end state an attacker is working towards.
- **Prefer a narrow allowlist entry over turning a rule off.** A rule turned
  off stops protecting against everything, not just the thing that annoyed the
  user.
- **Prefer monitor-for-now over a permanent grant** when the need is temporary
  ("I'm doing a migration this afternoon"). `sudo moatctl set mode monitor
  --rule X`, then arm it again after.
- **Never widen a `--name` glob to make a rule match.** `moat-cred-*` to fix
  one `moat-cred-ssh-private-key-read` alert grants eleven rules at once.
- **Do not propose editing `/etc/moat/moat.toml` for a threshold.**
  `moatctl set threshold.<name>` exists, takes effect immediately, is recorded,
  and does not rewrite a file the user owns.

## Privilege model

Weakening protection needs root. Restoring it does not. Follow it exactly:

| needs `sudo` | does not |
|---|---|
| `moatctl allow --yes`, `ignore`, `unignore`, `baseline accept/relearn` | `moatctl allow` (preview), `status`, `list`, `explain`, `chain`, `decisions`, `allowlist`, `exclusions`, `baseline list` |
| `set mode`, `set contain`, `set kill`, `set sandbox` | `set digest` |
| `set threshold.*` (**both** directions) | `exclusions --remove` (re-watching a binary) |
| `forget <dst>` | `contain --release` |

Every weakening raises a `moat-x-protection-changed` alert naming the peer the
kernel reported. That record cannot be allowlisted away. Do not try to make it
quieter; it is the receipt.

## Reference files

- `references/interpreters.md` — the kernel/userspace boundary, why
  `matchBinaries` cannot see a script, and the two 2026-09-07 cases. **Read
  this before naming any binary.**
- `references/layers.md` — every tuning layer, what it costs, how to undo it.
- `references/commands.md` — the `moatctl` surface, read vs write, and the
  allowlist TOML shape.
