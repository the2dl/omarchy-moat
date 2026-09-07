# Incubating policies

Not shipped and not loaded: `moatd render-policies` and the PKGBUILD both take
`policies/*.yaml` non-recursively, so anything in here is inert. It is a place
for a rule whose *detection* is right but whose false-positive surface has not
been solved yet — kept in tree, with the evidence, rather than deleted and
re-derived later.

## cred-proc-environ-read

Reading another process's `/proc/<pid>/environ` lifts its whole environment —
`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `ANTHROPIC_API_KEY`, database URLs with
the password inline — without touching the target or the disk. Worth detecting.

Measured on this desktop, 2026-09-03: **126 high alerts in 4 idle minutes.**
Every one was a true cross-process read (the self-read filter in
`moatd/src/rules/self_proc_read.rs` works and is unit-tested; actor pid never
equalled target pid). They were all benign:

| reader | why it reads other processes' environ |
|---|---|
| `moatd` | **a feedback loop** — `incident.rs` snapshots `/proc/<pid>/environ` for the alerting process and every live ancestor, so each alert produced more alerts |
| `pgrep` (procps-ng) | process matching |
| `herdr` | session/process management |
| `quickshell` | the desktop shell |

The loop is a bug and is fixed separately. The others are the real problem: the
rule flags *process enumeration*, which on a developer desktop is ordinary. It
could be silenced with a `matchBinaries` exclusion list, but that list would have
to include `quickshell` — and a hijacked omarchy-shell plugin is exactly the
threat this product exists to catch, so excluding the shell would make the rule
lie about its own coverage. Quiet or faithful, not both.

**What it needs before it ships: target awareness.** Alerting on *who is being
read* rather than only *that a read happened*. A scanner touches many pids
indiscriminately; theft targets a process holding credentials. moatd already has
the proctable to resolve a target pid to an exe, so the rule can ask whether the
target is a browser, `ssh-agent`, `gpg-agent`, a cloud CLI or a shell — and stay
quiet for `systemd` and pid 1. That is a real piece of design, not tuning.

Until then this is a **known coverage gap**, recorded in INTEGRATION.md, and not
a regression: the previous shape (`proc_mem_open` with no mask filter) covered
environ only in the sense that it alerted on everything and was permanently
demoted to timeline-only, which is not coverage.

## ransom-file-churn (the whole-home variant)

The shipped `policies/ransom-file-churn.yaml` feeds the ransomware counter
(`moatd/src/rules/ransom_churn.rs`: one actor reads a file and then deletes,
renames away or empties that same file, across eight distinct files in a
minute; or renames eight files to one shared new extension). Its scope is six
directories -- `~/Documents`, `~/Desktop`, `~/Pictures`, `~/Videos`, `~/Music`,
`~/Downloads`. The file here is the same policy with the scope widened to
`{{HOME}}/`, which is what full coverage of a developer's project trees would
take. It is not shipped, for a reason that is a number rather than a guess.

The counter needs the **read half** -- every read-open under the scope, with no
`rateLimit`, because `rateLimit` suppresses events and never counts them. Under
the document directories that half is cheap: inotify over the same six
directories on this desktop (164 files) saw **zero** opens, deletes or renames in
120 s at rest on 2026-09-06, and the programs that do read them in bulk
(thumbnailers, indexers, backup and sync clients, `rg`) are excluded in the
kernel. Under `$HOME` it is the cost the telemetry fork was built to avoid:
**42.3 writes/s under `$HOME` during one `npm install`, 19.2/s through a kernel
filter of this shape** (docs/SHIPPING.md, measured 2026-09-04), and reads
outnumber writes in a build by a wide margin. Every one of those events is a
line in the export, a parse in moatd and a pass through every rule's `on_hook`.

The false-positive surface widens with it. `Prefix` cannot say "under `$HOME`
but not under any `node_modules`" (TETRAGON-NOTES gap 2), so the kernel would
post every build tree's churn and moatd would cut it in userland
(`BUILD_TREES` in the rule) -- after paying for it. And the read-then-destroy
shape has real lookalikes in project trees that it does not have in document
folders: `npm update` reads a package's `package.json` and removes the package,
`cargo` and `rustc` rewrite what they just read, test suites create and delete
fixtures they wrote a moment ago.

**What it needs before it ships: a measurement, not a design.** Load this
variant on a machine for a working day with the shipped counter, read
`moatctl status` for the sensor's event rate and the journal for
`moat-x-sensor-throttled`, and count how many `moat-ransom-file-churn` findings
came out of ordinary work. If the read half stays under a few events per second
across builds and the rule stays quiet, widen the shipped scope one directory at
a time (`~/Projects`, `~/src`, `~/code`) rather than to `$HOME` wholesale.

Until then the coverage boundary is stated in the shipped policy's `expected`,
in `policies/README.md` under blind spots, and in the rule's own `expected`: a
sweep that never reaches the document directories is not seen. Ransomware that
skips a victim's documents is not ransomware anyone has written.
