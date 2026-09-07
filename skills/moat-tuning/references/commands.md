# The `moatctl` surface

Full reference: `/usr/share/doc/omarchy-moat/CLI.md`. This file is the subset
an agent needs, split by whether it is safe for you to run.

Every action names an **alert id**, never a pid or a path. A hostile process in
the `moat` group cannot ask the daemon to kill or move anything the sensor did
not already flag.

---

## Read these freely

| command | what it gives you |
|---|---|
| `moatctl explain <id>` | **the primary source.** exe, args, the actor's script when an interpreter was involved, the selector that matched, the allowlist verdict, whether an action was taken, and a ready-made allowlist block per scope |
| `moatctl status` | mode, armed rules, sensor health, policy counts, thresholds in force + overrides, unacked count |
| `moatctl status --json` | the same, plus `enforceable` (what `set mode --rule` accepts) |
| `moatctl list --limit N` | recent alerts, newest last |
| `moatctl chain <id>` | the sequence this alert is one step of, with times |
| `moatctl rarity <id>` | how unusual this tuple is on this machine |
| `moatctl allowlist` | every merged entry: index, source file, comment, all five matchers |
| `moatctl exclusions` | binaries a rule has been told to stop watching |
| `moatctl contain` | what moatd is refusing on its own judgement right now |
| `moatctl decisions` | every kill-gate decision: what it spared and why. **Read this before ever proposing `set kill kill`** |
| `moatctl baseline list` | learning state, pending proposals, learned entries, demoted rules |
| `moatctl receipts` / `incidents` | what package installs did; incident snapshots |
| `moatctl allow --name ... ` (no `--yes`) | **the preview.** Writes nothing, needs no root |

Reading is deliberately not root-gated. Evidence behind `sudo` does not get
looked at.

---

## Propose these; do not run them

These change what moat does or hide an alert. Write them out for the user with
the `sudo` on the front and let them run it.

| command | needs root |
|---|---|
| `moatctl allow --name ... --yes` | yes |
| `moatctl ignore <id> [--scope exe\|exe+file\|parent\|rule] [--comment T]` | yes |
| `moatctl unignore <index> [--file baseline.toml]` | yes |
| `moatctl set mode monitor\|enforce [--rule R]` | yes |
| `moatctl set contain on\|off`, `set kill off\|log\|kill`, `set sandbox on\|off` | yes |
| `moatctl set threshold.<name> <n>\|default` | yes, both directions |
| `moatctl baseline accept <id>`, `baseline relearn` | yes |
| `moatctl forget <dst>` | yes |
| `moatctl kill <id>`, `moatctl quarantine <id>` | — but never propose these on your own initiative |
| `moatctl ack <ids>` | no — but acking is the user's decision, not yours |

If `MOAT_AGENT_CONTEXT=1` is in the environment, `moatctl` refuses all of these
itself. That is a second lock, not the boundary — do not treat its absence as
permission.

Restoring protection is never gated: `moatctl exclusions --remove <rule>:<bin>`
and `moatctl contain --release <chain>` need no root by design.

---

## `moatctl allow` in detail

```
moatctl allow --name RULE [--exe X] [--file F] [--parent P] [--script S]
              [--comment TEXT] [--yes]
```

Previews by default. The output leads with:

```
It matches 3 of the 412 alerts on record.
     3  moat-cred-cloud-credential-read

  01K5...  medium  Cloud credential read by an unexpected program
      script /opt/google-cloud-cli/lib/gcloud.py
```

Show the user that count. It is the blast radius and it is the thing worth
arguing about — the TOML block is not.

`already suppressed by user.toml#2` on a sample row means an existing entry
already covers it, and the new one adds nothing. That is how people end up with
six overlapping rules none of them dares to remove.

**Zero matches is not refused.** Pre-authorising something that has not
happened yet is a legitimate use. But zero is also exactly what a typo looks
like, so check the matchers against `moatctl explain <id>` before telling the
user to commit.

### What it refuses, and what to say instead

| refusal | say |
|---|---|
| `--name` reaches a `moat-x-*` self-health rule | "that pattern would silence moat's own alarm about being weakened; name the rule you actually mean" |
| the rule is armed in the kernel | "an allowlist entry can't stop a kill — the process dies before moatd sees it. Either put the rule back to monitor, or use `moatctl ignore <id>`, which takes the binary out of the kernel policy" |
| `--exe` is an interpreter with no `--script` | "that would allow every python program on your machine, not gcloud. Use `--script /opt/.../gcloud.py`" |
| the glob does not compile | "one unparseable entry makes moat drop every other rule in that file" |

---

## Diagnosing, end to end

1. `moatctl list --limit 20` — find the id.
2. `moatctl explain <id>` — read it. Note the **exe**, the **script** if there
   is one, the **selector**, the **allowlist verdict**, and `action_taken`.
3. `moatctl chain <id>` if it is part of a sequence — a containment or a kill
   is almost always a *chain* decision, not a single alert's.
4. Decide the layer (`layers.md`), preferring the narrowest that works.
5. `moatctl allow ... ` (no `--yes`) — show the blast radius.
6. Hand the user the `sudo` command.
7. `moatctl allowlist` afterwards to confirm the index, so they know how to
   undo it.

## Allowlist file locations

| file | source label | removable |
|---|---|---|
| `/etc/moat/allowlist.d/user.toml` | `user` | yes |
| `/etc/moat/allowlist.d/baseline.toml` | `learned` | yes (`--file baseline.toml`) |
| `/etc/moat/allowlist.d/default.toml` | `shipped` | no |
| `/etc/moat/allowlist.d/omarchy-default.toml` | `shipped` | no |

Files are merged in filename order and the **first matching rule wins**. Any
match suppresses, so a shipped entry cannot be *narrowed* from `user.toml` —
adding a rule only ever suppresses more. If a shipped entry is genuinely too
wide for a site, that is a package bug: say so rather than inventing a
workaround. (`unignore` will refuse it, and its error text suggests
"override it in user.toml", which is misleading — there is no negative form.)
