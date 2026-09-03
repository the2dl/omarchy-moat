# policies/ — Tetragon TracingPolicy templates

32 `TracingPolicy` templates for Tetragon **v1.7.1** on Arch (kernel 7.1, BTF,
`lsm=...,bpf`). One file per rule, `policies/<family>-<rule>.yaml`, policy name
`sentinel-<family>-<rule>`. Everything here was written against
`docs/TETRAGON-NOTES.md`; where the notes say something is not expressible in a
policy it is **not faked here** — it is listed under [sentineld covers](#sentineld-covers).

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
limits, and that the `enforce` annotation agrees with the actions in the policy.

## Policy table

FP column = what actually fires on a workstation doing Rust, Node and Docker
builds. Allowlist knob = the field to edit in the template (a rebuild of the
package, or a drop-in override in `/usr/lib/sentinel/policies`), plus the
userland escape hatch `sentinelctl ignore <id> --scope exe|exe+file|parent|rule`
which needs no policy change and no reload.

| Policy | Sev | Hook (kind) | Enforce | Expected false positives | Allowlist knob |
|---|---|---|---|---|---|
| `sentinel-cred-ssh-private-key-read` | high | `file_post_open` (lsm) | **Sigkill** | restic/borg backups, ansible, terraform, IDE git plugins, any Python/Go tool using an ssh library instead of `ssh` | `matchBinaries NotPostfix` (ssh suite, git, rsync) |
| `sentinel-cred-cloud-credentials-read` | high | `file_post_open` (lsm) | Post 60s | direnv/aws-vault wrappers, boto3 and other SDKs inside your own scripts, k9s plugins | `matchBinaries NotPostfix` (aws, gcloud, az, kubectl, terraform, docker) |
| `sentinel-cred-vcs-token-read` | high | `file_post_open` (lsm) | Post 60s | `curl --netrc` in a script, custom git credential helpers, JetBrains/VS Code git integrations | `matchBinaries NotPostfix` (git, gh, glab, helpers) |
| `sentinel-cred-registry-token-read` | medium | `file_post_open` (lsm) | Post 300s | **frequent**: every `npm install`, `pip install`, `cargo publish`, `docker pull` from a private registry | `matchBinaries NotPostfix` (node, bun, pip, uv, cargo, docker) |
| `sentinel-cred-ai-credentials-read` | high | `file_post_open` (lsm) | Post 60s | any node/bun process is allowlisted, so this mostly fires on shell/python one-liners; a non-node agent build will fire | `matchBinaries NotPostfix` (node, bun, the CLIs) |
| `sentinel-cred-gnupg-keyring-read` | high | `file_post_open` (lsm) | Post 60s | whole-home backups, `pass`-based scripts, git commit signing through a non-gpg wrapper | `matchBinaries NotPostfix` (gpg suite, keyring daemons) |
| `sentinel-cred-browser-secrets-read` | high | `file_post_open` (lsm) | Post 60s | backups; and any unrelated file whose basename is `Cookies`, `Local State` or `Web Data` (Postfix match, no directory anchor) | `matchBinaries NotPostfix` (browsers, password managers) |
| `sentinel-cred-etc-shadow-read` | critical | `file_post_open` (lsm) | **Sigkill** | a screen locker, display manager or PAM helper not in the list. **In enforce mode a miss here can break authentication** — keep this rule in monitor until you have seen a week of clean logs | `matchBinaries NotIn` (shadow-utils, PAM helpers, lockers) |
| `sentinel-pkg-subtree-interpreter-spawn` | low | `bprm_check_security` (lsm) | Post 300s | **constant**: node-gyp, lifecycle scripts, `cargo` build scripts, `setup.py`. Kept as timeline context, not as an alert | `matchParentBinaries` values; drop the template to silence |
| `sentinel-pkg-subtree-downloader` | high | `bprm_check_security` (lsm) | Post 60s | node-pre-gyp, `sharp`, `esbuild`, playwright/puppeteer browser downloads, PKGBUILDs that curl a tarball | `matchParentBinaries` values, or ignore `--scope parent` |
| `sentinel-pkg-subtree-netcat-exec` | critical | `bprm_check_security` (lsm) | **Sigkill** | a Makefile that waits on a port with `nc`; otherwise none seen | `matchArgs Postfix` list |
| `sentinel-persist-shell-rc-write` | high | `file_post_open` (lsm) | Post 60s | mise, rustup, nvm, conda, starship, atuin, oh-my-zsh installers | `matchBinaries NotPostfix` (editors) |
| `sentinel-persist-autostart-write` | high | `file_post_open` (lsm) | Post 60s | installing a desktop app or user service, Flatpak, Docker Desktop, GNOME/KDE settings | `matchBinaries NotPostfix` (editors, systemctl, flatpak) |
| `sentinel-persist-desktop-config-write` | medium | `file_post_open` (lsm) | Post 60s | omarchy-shell saving settings, theme switches. `/usr/bin/omarchy-*` is suppressed in-kernel by a `NoPost` selector | selector 0 `matchBinaries Prefix`, selector 1 `NotPostfix` |
| `sentinel-persist-system-unit-write` | high | `file_post_open` (lsm) | Post 60s | `pacman -Syu` touching `/etc/systemd/system`, `sudo nvim /etc/sudoers.d/...`, `crontab -e` | `matchBinaries NotPostfix` (pacman, systemd, editors) |
| `sentinel-persist-authorized-keys-write` | critical | `file_post_open` (lsm) | **Sigkill** | `ssh-copy-id` (allowlisted), chezmoi/ansible managing your keys | `matchBinaries NotPostfix` |
| `sentinel-persist-git-hook-write` | high | `file_post_open` (lsm) | Post 60s | **frequent on Node repos**: husky, lefthook, pre-commit and direnv all write hooks during `npm install` | `matchBinaries NotPostfix`, or ignore `--scope exe+file` |
| `sentinel-persist-agent-config-write` | medium | `file_post_open` (lsm) | Post 300s | **frequent**: the agents rewrite `CLAUDE.md`, `settings.local.json` and `.mcp.json` themselves | `matchBinaries NotPostfix` (editors) |
| `sentinel-shell-reverse-shell-connect` | critical | `tcp_connect` (kprobe) | **Sigkill** | a script using `bash /dev/tcp` as a port check against a public host; `nc`/`socat` used deliberately. Private, loopback and link-local destinations never fire | `matchBinaries Postfix` list; add CIDRs to `NotDAddr` |
| `sentinel-rootkit-bpf-prog-load` | high | `bpf` (lsm) | Post 60s | **Docker**: containerd/runc load BPF on every container start; also bpftrace, bcc, `perf`, `tc` | `matchBinaries NotIn` |
| `sentinel-rootkit-kernel-module-load` | critical | `security_kernel_read_file` (kprobe) | **Sigkill** | dkms / NVIDIA / VirtualBox installs that insmod through a wrapper; matches both `READING_MODULE` (2) and `READING_MODULE_COMPRESSED` (7, Arch `.ko.zst`) | `matchBinaries NotIn` (kmod, systemd, dkms) |
| `sentinel-rootkit-ldso-preload-write` | critical | `file_post_open` (lsm) | **Sigkill** | none on a clean Arch desktop | `matchBinaries NotIn` |
| `sentinel-rootkit-bpffs-write` | medium | `file_post_open` (lsm) | Post 60s | container runtimes; note that `bpf(BPF_OBJ_PIN)` does not open a file, so real pinning shows up in the bpf-prog-load rule instead | `matchBinaries NotIn` |
| `sentinel-priv-setuid-chmod` | high | `path_chmod` (lsm) | Post 60s | `pacman` installing a setuid binary, `install -m 4755` inside a build, `sudo chmod u+s` by hand | `matchBinaries NotIn` (pacman, bsdtar, install) |
| `sentinel-priv-setcap-xattr` | high | `inode_setxattr` (lsm) | Post 60s | `sudo setcap` for a profiler or network tool (deliberately **not** allowlisted), pacman extracting capabilities | `matchBinaries NotIn` |
| `sentinel-priv-ptrace-attach` | high | `ptrace_access_check` (lsm) | Post 60s | debuggers not in the list (`bpftrace -p`, `py-spy`, `jstack`, JetBrains debug helpers), systemd-coredump | `matchBinaries NotIn` |
| `sentinel-priv-proc-mem-access` | medium | `ptrace_access_check` (lsm) | Post 300s | process viewers reading `/proc/<pid>/maps`: htop, btop, ps, lsof, py-spy, `docker stats` helpers | `matchBinaries NotIn` |
| `sentinel-ai-cli-in-pkg-subtree` | high | `bprm_check_security` (lsm) | Post 60s | monorepo tooling that shells out to an agent, `npx claude` started from another node process | `matchParentBinaries` / `matchArgs Postfix` |
| `sentinel-exec-untrusted-tmpfs` | high | `bprm_check_security` (lsm) | Post 60s | **build systems**: autoconf `conftest`, cargo/go temporary binaries, makepkg building under `/tmp`, AppImage extraction, `curl \| sh` installers | `matchArgs Prefix` values; ignore `--scope exe` |
| `sentinel-exec-untrusted-home` | medium | `bprm_check_security` (lsm) | Post 300s | **frequent**: playwright, cypress, puppeteer, bun, uv, mise and electron-builder all execute from `~/.cache` | `matchArgs Prefix` values |
| `sentinel-net-pkg-subtree-egress` | high | `tcp_connect` (kprobe) | Post 60s | git-over-SSH (port 22) inside a build, a private registry or corporate proxy on a custom port, dev servers calling a public API | `DPort` value lists, `NotDAddr` CIDRs |
| `sentinel-net-tmpfs-binary-egress` | critical | `tcp_connect` (kprobe) | **Sigkill** | an installer you unpacked into `/tmp` and ran on purpose | `matchBinaries Prefix` values |

7 critical, 18 high, 6 medium, 1 low. 8 policies carry `Sigkill`, 24 are
report-only. Hook load: 17 programs on `file_post_open`, 6 on
`bprm_check_security`, 3 on `tcp_connect`, 2 on `ptrace_access_check`, and one
each on `bpf`, `path_chmod`, `inode_setxattr`, `security_kernel_read_file`.

## Monitor and enforce (verified, notes section 7)

* Every template carries `spec.options: [{name: policy-mode, value: monitor}]`,
  so a policy is **monitor** the moment it loads, whatever its `matchActions`
  say. Nothing here can kill until someone opts in.
* Precedence is `spec.options` < `tetra tp add --mode ...` < `tetra tp set-mode
  <name> monitor|enforce`. sentineld calls `set-mode` for every `sentinel-*`
  policy at start and whenever `sentinelctl set mode` changes it. `set-mode`
  rewrites a pinned per-policy BPF array in place: it takes effect immediately,
  with no reload and no dropped events.
* Monitor mode **skips** `Sigkill`, `Signal`, `Override`, `NotifyEnforcer` and
  `Set`. `Post`, `NoPost`, `TrackSock`, `GetUrl` and `DnsLookup` still run.
* The event still reports `"action":"KPROBE_ACTION_SIGKILL"` in monitor mode —
  the action field is the configured action, not the taken one. **A kill is
  only proven by the matching `process_exit` with `"signal":"SIGKILL"` for that
  `exec_id`**, which is what sentineld must use before writing
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

`sentineld render-policies` (the `ExecStartPre` of `tetragon.service`):

1. reads `/etc/passwd`, selects users with `uid >= 1000` whose home is under
   `/home` or `/var/home`;
2. for each template in `/usr/lib/sentinel/policies/*.yaml`, expands `{{HOME}}`
   into **one value per home** inside every `values:` list — a template value
   becomes N values, the policy name and everything else stay identical;
3. writes the result to `/run/sentinel/policies/` (`tracing-policy-dir`);
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
| `tracing-policy-dir` | `/run/sentinel/policies` | rendered templates |
| `parents-map-enabled` | `true` | required by `matchParentBinaries` (pkg, net, ai) |
| `export-filename` | `/var/log/sentinel/tetragon.log` | sentineld tails this; gRPC is not used in v1 |
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

* `export-allowlist` — generated by `sentineld render-policies`; see
  `export-allowlist.example` for the exact two JSON lines it must write
  (`PROCESS_EXEC`+`PROCESS_EXIT`, then the exact `policy_names` list; Tetragon
  matches policy names exactly, there is no prefix match).
* `enable-ancestors` — sentineld builds the ancestry chain itself from
  `process_exec`/`process_exit` (contract section 6.2), which is cheaper.
* `disable-kprobe-multi` — add it only if kprobe attachment fails on a kernel
  without `kprobe_multi`.

`tetragon.service` is the upstream unit with FHS paths, `RuntimeDirectory=tetragon`,
`ExecStartPre=/usr/bin/sentineld render-policies`, and sandboxing that keeps BPF
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
  detection — selectors are ORed and the first match wins
  (`persist-desktop-config-write`).
* **Scripts resolve to their interpreter.** `matchBinaries`/`matchParentBinaries`
  see `/usr/bin/node`, not `/usr/bin/npm`; `/usr/bin/bash`, not
  `/usr/bin/makepkg`. The package-manager parent lists include both spellings,
  but the interpreter entries are the ones that actually match. See below.

## sentineld covers

Not expressible in a v1.7.1 policy. The policies emit the underlying event; the
decision is sentineld's (contract section 6.4, rule ids `sentinel-x-*`).

1. **Process arguments.** No selector can look at argv. That means
   `nc -e /bin/sh`, `socat ... EXEC:`, `bash -i >& /dev/tcp/...`,
   `curl ... | sh`, and the AI permission-skipping flags
   (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`,
   `--full-auto`) are all matched in userland against
   `process_exec.process.arguments`. The shell/reverse-shell family is written
   to detect the *behaviour* instead (a shell opening a public TCP socket), so
   it does not depend on flags.
2. **Ancestry beyond `matchParentBinaries` + `followChildren`.** That covers a
   subtree only when the root binary is at an exact absolute path.
   Version-managed interpreters (`~/.local/share/mise/installs/node/*/bin/node`,
   nvm, asdf, pyenv, uv-managed pythons) and script front-ends whose recorded
   binary is the interpreter (`makepkg` → bash, `npm` → node) are **not**
   matched in-kernel. sentineld's process table must supply "is this in a
   package-manager subtree" and "does this AI CLI have an interactive shell in
   its chain" (`sentinel-x-ai-cli-headless`).
3. **Middle-wildcard paths.** Browser profile directories
   (`~/.mozilla/firefox/<random>/`) are matched by basename `Postfix` only, so
   any file called `Cookies` matches; private SSH keys with non-standard names
   are not matched at all (only the `id_*` set is). Post-filter and extend in
   userland.
4. **Hostnames, DNS and registry allowlists.** Kernel-side there are IPs, ports
   and CIDRs only. `sentinel-x-pkg-egress` (destination not in the registry
   allowlist) is userland, resolving the IP from the event.
5. **IOC lookups** — sha256 of a newly executed file, feed domains/URLs
   (`sentinel-x-new-exec-ioc`). Policies carry no hashing; hash
   `process.binary` in userspace.
6. **`LD_PRELOAD` and any other environment variable.** No selector exists;
   read it from `process_exec.process.environment_variables`, which is why
   `enable-process-environment-variables` + `filter-environment-variables=LD_PRELOAD`
   are in `tetragon.conf.d`. The `/etc/ld.so.preload` file itself *is* covered
   by a policy.
7. **Counting and windows.** `rateLimit` suppresses, it never counts, and it
   has no notion of "40 distinct files in 10 s" (`sentinel-x-mass-read`). Note
   the rate-limit key is *thread + the first 40 bytes of the arguments*: two
   credential paths that share a 40-byte prefix collapse into one event, so a
   userland count of distinct files read is a **lower bound**. If mass-read
   proves lossy, drop `rateLimit` from the `cred` policies and dedupe entirely
   in sentineld.
8. **Whether a kill actually happened** — see the monitor/enforce section.
   Confirm with `process_exit.signal == SIGKILL`.
9. **Policy-name prefix matching in the export filter.** `policy_names` is an
   exact match; sentineld writes the explicit list
   (`export-allowlist.example`). The CEL `startsWith` form in the notes is
   untested live and is not used.
10. **Policy hot reload.** There is none: `sentineld render-policies` runs as
    `ExecStartPre` and a policy change means restarting tetragon (or
    `tetra tp add|delete`).
11. **Dedupe, severity escalation and correlation** — e.g. a
    `pkg-subtree-interpreter-spawn` (severity low) that is followed by a
    credential read and an egress event from the same subtree is one high-value
    incident, not three rows.

### Known blind spots (nothing covers these yet)

* **Rename-based writes.** A payload that writes `~/.bashrc.tmp` and renames it
  over `~/.bashrc` never opens the target for writing, so the `persist` rules
  miss it. `security_path_rename` and `path_unlink` are hookable; adding them
  would mean a second BPF program per persist rule and was left out for
  desktop cost. Same for writes through an already-open fd inherited across an
  exec.
* **Bind shells.** `tcp_connect` only sees outbound connections; a shell that
  listens is not covered (`security_socket_bind` would be the hook).
* **Reads of credentials with non-standard names**, and any credential file in
  a directory this list does not enumerate.
* **Container-internal activity** is seen as host activity; there is no
  per-container scoping on a single-user desktop.
