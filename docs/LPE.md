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

## Proposal

Ordered by value per unit of noise. Nothing here is implemented yet.

1. **Parse `process.cap`.** Free, like `binary_properties` was. Nothing else
   works without it, and it makes every existing alert richer.
2. **`matchCapabilityChanges` policy.** The escalation moment. Expected to be
   near-silent on a desktop, which is what makes it worth having loud.
3. **`/proc/sys` write policy** covering `core_pattern`, `modprobe`,
   `unprivileged_userns_clone`. Nothing legitimate writes these outside boot.
4. **Root-executed config policy**: polkit, PAM, udev rules, `ld.so.conf.d`,
   `uevent_helper`. One path list, same shape as `persist-system-unit-write`.
5. **Cap-holding binary execs as a chain step**, keyed off the capability set
   rather than a hardcoded list, so it tracks the machine rather than this
   audit.
6. **`matchNamespaceChanges` as a chain step only.** Never its own alert. See §3
   for why.

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
