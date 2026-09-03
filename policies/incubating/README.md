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
