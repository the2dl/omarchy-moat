# Local privilege escalation: what is watched, what is not

An audit of moat's coverage of local privilege escalation, the surface this
class of machine actually presents, and what Tetragon already offers that moat
does not read.

Written 2026-09-09 against the machine moat is developed on: Omarchy, Arch,
kernel 7.1.9, 1,124 packages.

## The short version

moat covers the *outcomes* of an escalation well — a kernel module loading, a
BPF program attaching, `/etc/ld.so.preload` being written, a unit or a sudoers
file appearing. It covers the *act* of escalating hardly at all, and the three
Tetragon selectors built for exactly that are unused:

| selector | what it answers | used by moat |
|---|---|---|
| `matchCapabilityChanges` | this process **gained** a capability at runtime | **no** |
| `matchNamespaceChanges` | this process **entered** a new namespace | **no** |
| `matchCapabilities` | this process holds CAP_X right now | **no** |

Only `policies/check.py` mentions them, as validation. No shipped policy uses
one.

`process.cap` — the permitted/effective/inheritable sets Tetragon puts on every
event — is not parsed by `event.rs` either. This is the same shape as the win
`rules/exec_properties.rs` documents: *"Tetragon has been handing moat the
answer since the first run and nothing read it."* That rule got
`moat-x-exec-privileges-raised` for no runtime cost because `binary_properties`
was already arriving. `process.cap` is arriving too.

## What is already covered

Worth stating so the gaps below are not read as "moat does nothing here".

| rule | catches |
|---|---|
| `moat-x-exec-privileges-raised` | setuid/setgid/file-cap gained **at exec** (`binary_properties.privileges_changed`) |
| `moat-priv-setuid-chmod` | making a file setuid |
| `moat-priv-setcap-xattr` | writing a file capability |
| `moat-priv-ptrace-attach` | ptrace into another process |
| `moat-priv-proc-mem-access` | `/proc/*/mem` access |
| `moat-priv-container-socket-connect` | reaching the container runtime socket |
| `moat-rootkit-kernel-module-load` | module load — **global**, enforced inside containers too |
| `moat-rootkit-bpf-prog-load` | BPF program load — **global** |
| `moat-rootkit-ldso-preload-write` | `/etc/ld.so.preload` |
| `moat-persist-system-unit-write` | `/etc/systemd/system/`, `/etc/sudoers` (Prefix, so `sudoers.d/` too), `/etc/cron`, `/var/spool/cron/` |

That is a good spine. The escalation *act*, and several classic root-file
targets, are missing from it.

## Gaps, in order of how much they matter

### 1. Nothing watches `/proc/sys` at all

`grep -rn "/proc/sys" policies/*.yaml` returns nothing. That leaves the
best-known write-to-root primitives unmonitored:

* `/proc/sys/kernel/core_pattern` — a pipe here runs as root on the next crash.
  The standard container escape, and it works on the host too.
* `/proc/sys/kernel/modprobe` — point it at your own binary and trigger a
  module autoload. `moat-rootkit-kernel-module-load` watches `/usr/bin/modprobe`
  the **binary**; this replaces what the kernel calls instead.
* `/proc/sys/kernel/unprivileged_userns_clone` — turning the gate below back on.

### 2. Capability changes at runtime are invisible

`moat-x-exec-privileges-raised` fires when a binary gains privilege *at exec*.
It says nothing about a process that gains a capability **while running** — a
`capset` after a successful exploit, which is what most kernel LPEs end in.
`matchCapabilityChanges` is the selector for it and nothing uses it.

This is the single largest hole: it is the moment of escalation itself, and moat
currently sees only the aftermath.

### 3. Unprivileged user namespaces are enabled, and namespace changes are invisible

```
kernel.unprivileged_userns_clone = 1
/proc/sys/user/max_user_namespaces = 247260
```

An unprivileged user namespace hands an unprivileged user a full capability set
inside it, which is the precondition for a large family of kernel LPEs —
overlayfs (CVE-2023-0386), `nft`/netfilter, `io_uring`, CVE-2022-0185. moat has
no visibility into namespace creation at all.

**This one needs care, and is the reason it is not simply "add a rule".** On a
desktop, user namespaces are created constantly and legitimately: every Chrome
and Electron sandbox, `bwrap`, Flatpak, Docker, and any systemd unit with
sandboxing directives. A naive `matchNamespaceChanges` rule would be
`exec-untrusted-tmpfs` all over again — 300 alerts an afternoon, ignored within
a day, then demoted by the noise guard and effectively off.

It belongs as a **chain step**, not a detection: "a user namespace was created"
is close to meaningless alone, and close to conclusive next to a kernel module
load or a capability change seconds later. `chain.rs` is the right consumer.

### 4. Root-executed config that nothing watches

| path | why it is root-equivalent | covered |
|---|---|---|
| `/etc/polkit-1/rules.d/`, `/usr/share/polkit-1/actions/` | polkit rules are JS evaluated by a root daemon | **no** |
| `/etc/pam.d/` | a module line here runs in every authentication | **no** |
| `/etc/udev/rules.d/`, `/usr/lib/udev/rules.d/` | `RUN+=` executes as root on device events | **no** (udev appears only in binary allowlists) |
| `/etc/ld.so.conf.d/` | adds a library search path for everything | **no** (`ld.so.preload` is covered, `conf.d` is not) |
| `/sys/kernel/uevent_helper` | run as root on every uevent | **no** |
| `kexec_load` | boot a new kernel, bypassing everything | **no** |

These are cheap to add: same shape as `persist-system-unit-write`, one more
path list. They are ordinary-desktop-quiet — nothing legitimately writes
`/etc/pam.d` outside a package transaction, and moat already knows what a
package transaction looks like (`pkg-install` context).

## What this machine actually presents

Not theory — measured here.

**31 setuid/setgid binaries.** The usual suspects, plus some worth knowing
about: `/usr/bin/ksu`, `/usr/bin/op` (1Password CLI),
`/opt/1Password/1Password-BrowserSupport`, and five separate `chrome-sandbox`
copies (Chrome, Chromium, Electron 43, Signal, Slack).

**File capabilities, and one of them is effectively root:**

```
gsr-kms-server   cap_sys_admin=ep            <-- root-equivalent
dumpcap          cap_dac_override,cap_net_admin,cap_net_raw=eip
btop             cap_dac_read_search,cap_perfmon=ep
newuidmap        cap_setuid=ep
newgidmap        cap_setgid=ep
```

`CAP_SYS_ADMIN` on `gsr-kms-server` (gpu-screen-recorder) is the standout: that
capability is close to unrestricted root, and it sits on a helper most users do
not know is installed. `cap_dac_override` on `dumpcap` and
`cap_dac_read_search` on `btop` are read-anything primitives.

moat watches the *creation* of file capabilities (`moat-priv-setcap-xattr`) but
does not treat *execution* of an existing cap-holding binary as notable. A
`gsr-kms-server` exec with an unexpected parent is a much stronger signal than
most of what currently reaches the badge.

## The constraints this has to fit

Read out of `TETRAGON-NOTES.md` before designing anything, because two of them
decide the shape:

**19 policies per LSM hook, and the 20th kills the daemon.** An LSM program is
attached through a BPF trampoline holding `BPF_MAX_TRAMP_LINKS = 38`; Tetragon
attaches two per policy, so the 20th fails with `E2BIG`, Tetragon exits 255,
systemd restarts it, and it fails at the same policy for ever. `moatd` follows
it down through `PartOf=`. Each restart re-walks `/proc` and re-emits an exec
event per live process, so the crash loop *manufactures* alerts while the sensor
is dead. `policies/check.py` enforces the cap at build time.

Current budget, measured:

| LSM hook | policies | free |
|---|---:|---:|
| `file_post_open` | 8 | **11** |
| `bprm_check_security`, `path_chmod` | 2 each | 17 |
| `socket_connect`, `ptrace_access_check`, `inode_setxattr`, `path_unlink`, `path_rename`, `path_truncate`, `bpf` | 1 each | 18 |

So there is room to add enforcing file rules — the prevention half of this is
actually on the table, which it would not have been at 18/19.

**The escalation hooks exist.** `TETRAGON-NOTES.md` §6 lists LSM `capset` and
`task_fix_setuid` as present in kallsyms and BTF on this kernel, alongside
`bprm_creds_from_file` and `task_prctl`. `security_task_setuid` does **not**
exist; `task_fix_setuid` is the one. Both are unused hooks, so each starts at
1/19.

**`CapabilitiesGained` is a real operator** in the CRD enum, and `check.py`
already validates `matchCapabilityChanges` and `matchNamespaceChanges` as
selector fields. Nothing new has to be taught to the toolchain.

**A new policy needs no plumbing.** `render.rs` generates the export allowlist
from the rendered policy names, and severity/title come from the
`moat.omarchy/*` annotations, so a policy file is self-describing to the daemon.

## The build

Ordered by value per unit of noise. Each item names what it costs against the
budget above.

**All six are built as of 2026-09-09** (0.1.0-149). Every policy was proved to
ATTACH with `tetra tp add` against the live sensor before being committed,
because a policy that fails to load crash-loops Tetragon and takes moatd with it
-- and two of these hooks had never been attached on this machine. That gate
caught a real rejection (see the DAC_OVERRIDE note in TETRAGON-NOTES) that would
otherwise have shipped.

Final hook budget: `file_post_open` 10/19, `capset` 1/19, `task_fix_setuid`
1/19.

### 1. Parse `process.cap` — moatd only, no policy

`event.rs::Process` parses `uid`, `auid`, `ns.mnt` and `binary_properties` and
stops. The capability sets are on every event already.

Cost: nothing. No hook, no sensor restart, no budget. It is the same free win
`exec_properties.rs` took from `binary_properties`, and everything below reads
better for having it — "held CAP_DAC_OVERRIDE" on an existing alert is evidence
moat already had and never showed.

Do this first: items 2 and 6 are worth much less without it.

### 2. `moat-priv-capability-gained` — LSM `capset`, 1/19

`matchCapabilityChanges` with `CapabilitiesGained`. The escalation moment, which
nothing currently sees: `moat-x-exec-privileges-raised` covers privilege gained
*at exec*, and this covers a `capset` by a running process — how most kernel
LPEs actually end.

Detection only. The capability is already granted by the time the hook reports,
so `Override` here would be theatre; the honest action is `Post`.

Expected near-silent: dropping capabilities is constant on a desktop and
`CapabilitiesGained` does not fire on it. That is what earns it a loud severity.

### 3. `moat-priv-sysctl-write` — LSM `file_post_open`, 9/19

`Prefix "/proc/sys/kernel/"` with `Mask ["2"]` (write-open). Targets that matter:
`core_pattern`, `modprobe`, `unprivileged_userns_clone`, `kexec_load_disabled`,
`yama/ptrace_scope`, `kptr_restrict`.

**This is the prevention story.** Nothing legitimately writes these after boot
except `systemd-sysctl` and `sysctl`, both nameable in `matchBinaries NotIn`, so
an `Override` here is defensible in a way it is not for most rules. Ship it
monitor-first anyway, per §7 of the notes and every enforcing rule before it.

Unverified and worth checking on the first run: that Tetragon resolves procfs
paths in the `file` arg the way it resolves ordinary ones. The notes do not say,
and the project's habit is to mark that rather than assume it.

### 4. `moat-priv-root-config-write` — LSM `file_post_open`, 10/19

One `Prefix` list, the same shape as `persist-system-unit-write`. String
`Prefix` values are map-backed with no four-value cap, so one selector covers
all of it:

```
/etc/polkit-1/rules.d/        polkit rules are JS run by a root daemon
/usr/share/polkit-1/actions/  and the actions they authorise
/etc/pam.d/                   a module line runs in every authentication
/etc/udev/rules.d/            RUN+= executes as root on a device event
/usr/lib/udev/rules.d/
/etc/ld.so.conf.d/            a library search path for everything
/sys/kernel/uevent_helper     run as root on every uevent
```

Monitor first, and probably monitor for a long time: package transactions write
several of these legitimately, and the kernel selector cannot see moat's
`pkg-install` context — enforcement would have to name `pacman` and friends in
`matchBinaries NotIn`, which is a bigger promise than it looks.

### 5. `moat-priv-uid-transition` — LSM `task_fix_setuid`, 1/19

A process changing uid, with the known helpers excluded. The classic outcome
half of an escalation, and the noisiest thing here: `su`, `sudo`, `login`,
`systemd` starting user services, `dbus-daemon-launch-helper`, polkit agents and
every container runtime do this legitimately and often.

Deliberately last, and deliberately timeline-first. Measure for a week before
deciding it deserves the badge — this is exactly the shape that became
`exec-untrusted-tmpfs`, which "fires on every build: 300+ alerts came out of
moat's own test suite during one afternoon".

### 6. Cap-holding exec as a chain step — moatd only, no policy

With item 1 done, exec events carry the permitted set. A binary with a non-empty
permitted set executing under an unexpected parent is a stronger signal than
most of what reaches the badge today, and this machine has `gsr-kms-server` with
`cap_sys_admin=ep` sitting there.

Keyed off the capability set on the event, not a hardcoded list, so it tracks
the machine instead of this audit. Chain step, low on its own.

### Deferred: `matchNamespaceChanges`

Not built. See §3 above: it belongs in `chain.rs` as a step and nowhere near an
alert of its own.

### Budget after all of it

`file_post_open` 10/19, `capset` 1/19, `task_fix_setuid` 1/19. Nine slots still
free on the busiest hook.

## What prevention would mean, and why it is mostly not on offer

moat can *deny* with `Override`, and does for a handful of file reads. Denying
an escalation is a different proposition:

* A capability change has already happened by the time the hook reports it —
  `matchCapabilityChanges` is a notification, not a gate.
* Denying `/proc/sys` writes and root-config writes IS enforceable, and is the
  realistic prevention story here. It is also the one that breaks a machine if
  it is wrong, so it belongs behind the same host-namespace split and the same
  monitor-first rollout every other enforcing rule got.
* Denying namespace creation would break Chrome, and is not on the table.

So: prevention for §3 and §4, detection for the rest. Claiming more than that
would be the kind of promise this project keeps refusing to make.
