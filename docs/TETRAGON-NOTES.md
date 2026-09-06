# Tetragon v1.7.1 reference notes for omarchy-moat

Scope: upstream v1.7.1 as released, verified against its sources and docs at that tag, the
local tarball, and this kernel (7.1.9-arch1-2, `CONFIG_BPF_LSM=y`, `lsm=...,bpf`, BTF,
`CONFIG_BPF_KPROBE_OVERRIDE=y`). Nothing was loaded live (no root). Anything not confirmed
by source is marked **UNVERIFIED**.

Abbreviations: `SRC` = https://github.com/cilium/tetragon/blob/v1.7.1/, `DOC` =
`SRC docs/content/en/docs/`, `TARBALL` = `/tmp/claude-1000/-home-dan/0c902229-11d6-4cf5-9b16-a5c90e387486/scratchpad/tetragon-v1.7.1-amd64/`.

## 1. TracingPolicy skeleton

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy            # cluster-scoped; TracingPolicyNamespaced also parses but needs metadata.namespace
metadata:
  name: moat-cred-ssh-key-read     # DNS-1123 rules apply (lowercase, '-', '.')
  annotations:                          # free-form map, kept; keys must be qualified names
    moat.omarchy/severity: high
spec:
  options:                              # []{name,value}; known: policy-mode, disable-kprobe-multi, disable-uprobe-multi
    - name: policy-mode
      value: monitor                    # "monitor" | "enforce"
  kprobes:   []                         # KProbeSpec
  tracepoints: []                       # TracepointSpec
  lsmhooks:  []                         # LsmHookSpec  -- NOTE lowercase 'lsmhooks', not lsmHooks
  uprobes:   []                         # UProbeSpec
  usdts:     []
  fentries:  []                         # KProbeSpec attached via fentry
  loader: false                         # bool: emit process_loader events
  lists:     []                         # {name,type: syscalls|generated_syscalls|generated_ftrace,values,pattern}
  enforcers: []                         # PLURAL. [{calls: ["list:x"]}]. There is no spec.enforcer.
  selectorsMacros: {}                   # map name -> KProbeSelector
  podSelector/containerSelector/hostSelector   # k8s only
```

Field sets (json tags from types.go):

- `KProbeSpec`: `call`, `return`, `syscall`, `message` (≤256, exported), `args[]`, `data[]`,
  `returnArg`, `returnArgAction` (TrackSock|UntrackSock), `selectors[]`, `tags[]` (≤16),
  `ignore.callNotFound`.
- `KProbeArg`: `index`, `type`, `resolve`, `sizeArgIndex`, `returnCopy`, `maxData`, `label`,
  `source` (`current_task`, data only), `btfType`, `btfTypeModule`.
  Types: ints (`int int8..int64 uint8..uint64 size_t long ulong`), `string char_buf char_iovec
  fd file filename path dentry linux_binprm sock socket sockaddr sockaddr_un skb nop bpf_attr
  bpf_cmd bpf_map bpf_prog perf_event capability kernel_cap_t cap_* cred user_namespace kiocb
  iov_iter load_info module syscall64 data_loc net_device const_buf auto`.
- `LsmHookSpec`: `hook` (LSM name without `security_`, e.g. `file_open`), `message`, `args[]`,
  `selectors[]`, `tags[]`. No `return`/`returnArg`.
- `TracepointSpec`: `subsystem`, `event`, `message`, `args[]`, `selectors[]`, `tags[]`, `raw`.

File loading uses the CRD machinery (release binary is the k8s build): YAML parsed
**strictly** (unknown keys → error), **CRD defaults applied**, schema validated (enums for
operators/types/actions enforced). Consequence: `syscall` defaults to **true** (types.go
`+kubebuilder:default=true`; hooks.md says false — the doc is wrong for file loading).
Always write `syscall: false` on non-syscall kprobes.

Verified at: `SRC pkg/k8s/apis/cilium.io/v1alpha1/types.go`, `.../tracing_policy_types.go`,
`SRC pkg/tracingpolicy/k8s.go`, `SRC pkg/crdutils/crdutils.go` (ApplyDefaults/UnmarshalStrict/Validate),
`SRC examples/tracingpolicy/bpf.yaml` (annotations), `DOC concepts/tracing-policy/mode.md`, `options.md`.

## 2. Selectors

≤5 selectors per hook, ORed, first match wins; filters inside a selector ANDed. Fields:
`matchArgs`, `matchData`, `matchReturnArgs`, `matchPIDs`, `matchBinaries` (max 1 entry),
`matchParentBinaries` (max 1), `matchNamespaces`, `matchNamespaceChanges`, `matchCapabilities`,
`matchCapabilityChanges`, `matchActions`, `matchReturnActions`, `macros`. **No `matchAncestors`.**
Ancestry ≥2 levels only via `matchParentBinaries` + `followChildren: true` (transitive),
which needs daemon flag `--parents-map-enabled`.

`matchArgs` entry: `index` (function arg) or `args: [specPos]` (position in spec `args`;
wins over `index`; needed when two spec args share an `index`), `operator`, `values[]`.

Operator enum (CRD): `Equal NotEqual Prefix NotPrefix Postfix NotPostfix GreaterThan LessThan GT
LT Mask SPort NotSPort SPortPriv NotSportPriv DPort NotDPort DPortPriv NotDPortPriv SAddr
NotSAddr DAddr NotDAddr Protocol Family State InMap NotInMap CapabilitiesGained InRange
NotInRange SubString SubStringIgnCase CelExpr FileType NotFileType`.

Per type (from the parser, `pkg/selectors/kernel.go`):

| arg type | operators |
|---|---|
| ints (`int`,`uint32`,`uint16`,`size_t`,…) | Equal, NotEqual, GT, LT, Mask, InRange, NotInRange, InMap, NotInMap; ≤4 values per filter (else InMap) |
| `string`, `char_buf` | Equal, NotEqual, Prefix, Postfix, SubString, SubStringIgnCase |
| `file`, `path`, `fd`, `dentry`, `linux_binprm`, `filename` | Equal, NotEqual, Prefix, Postfix; `file`/`path` also FileType/NotFileType. **No SubString.** |
| `sock`, `socket`, `skb` | SAddr/DAddr (+Not; IP or CIDR), SPort/DPort (+Not; single or `min:max`), SPortPriv/DPortPriv, Protocol (`IPPROTO_TCP`/6), Family (`AF_INET`/2), State (`TCP_ESTABLISHED`/1) |
| `sockaddr` | SAddr, NotSAddr, SPort, NotSPort, SPortPriv, Family only (for `connect()` the sockaddr *is* the destination) |
| `sockaddr_un` | Equal, NotEqual, Prefix, NotPrefix, Family |
| `syscall64` | InMap `list:<name>` |

String Equal/Prefix/Postfix values are map-backed (no 4-value cap). Length caps: Prefix 256,
Postfix 127, SubString 100. Numbers accept `0x..`, leading-`0` octal, decimal.

Two `matchArgs` on the **same index** (Prefix + Postfix): the parser accepts it and BPF reads
`filter->index` per filter (`selector_arg_offset`), but selectors.md says "one per index".
**UNVERIFIED at runtime.**

```yaml
matchBinaries:              # In | NotIn | Prefix | NotPrefix | Postfix | NotPostfix
- operator: In              # values = absolute process.binary (interpreter for scripts)
  values: ["/usr/bin/cat"]
  followChildren: true      # In/NotIn only; ≤64 sections; pre-existing children not matched
matchPIDs:
- operator: NotIn           # In | NotIn; ≤4 values
  values: [1]
  isNamespacePID: false
  followForks: true
matchNamespaces:
- namespace: Pid            # Uts Ipc Mnt Pid PidForChildren Net Time TimeForChildren Cgroup User
  operator: In
  values: ["host_ns"]
matchCapabilities:
- type: Effective           # Effective | Inheritable | Permitted
  operator: In
  values: ["CAP_SYS_ADMIN"]
matchReturnArgs:            # Equal NotEqual Prefix Postfix; needs return: true + returnArg
- index: 0
  operator: GT
  values: ["0"]
matchActions:
- action: Post
  rateLimit: "60s"          # "N" | "Ns" | "Nm" | "Nh"; keyed on thread + first 40 B of args
  rateLimitScope: "process" # thread (default) | process | global
  kernelStackTrace: true
  userStackTrace: false
  imaHash: false            # LSM hooks only
- action: Sigkill
- action: Signal
  argSig: 9
- action: Override          # error-injectable fns only (syscalls, security_* hooks)
  argError: -1
- action: NoPost
- action: TrackSock
  argSock: 0
- action: NotifyEnforcer    # needs spec.enforcers; for kernels without kprobe_multi
  argError: -1
  argSig: 9
- action: GetUrl
  argUrl: "http://..."
- action: DnsLookup
  argFqdn: "canary.example"
```

Action enum: `Post FollowFD UnfollowFD Sigkill CopyFD Override GetUrl DnsLookup NoPost Signal
TrackSock UntrackSock NotifyEnforcer CleanupEnforcerNotification Set`. FollowFD/UnfollowFD/
CopyFD are deprecated ("unsafe"). BPF supports 2 actions per selector (generic_calls.h).

Verified at: `SRC pkg/k8s/apis/cilium.io/v1alpha1/types.go`, `SRC pkg/selectors/kernel.go`
(parseMatchArg, writeMatchValues, writePrefix/Postfix/SubString), `SRC bpf/process/types/basic.h`
(selector_arg_offset), `SRC bpf/process/generic_calls.h`, `DOC concepts/tracing-policy/selectors.md`, `argument_types.md`.

## 3. File monitoring (reads/writes of specific paths)

Hooks on this kernel (kallsyms + `bpf_lsm_*` stubs + BTF prototypes all confirmed):

| hook | prototype | when |
|---|---|---|
| LSM `file_open` | `(struct file *file)` | once per open |
| LSM `file_post_open` | `(struct file *file, int mask)` | after open; `mask` = MAY_* (kernel ≥6.8) |
| kprobe/LSM `file_permission` | `(struct file *file, int mask)` | **every read()/write()** — expensive |
| kprobe `security_mmap_file` | `(file, ulong prot, ulong flags)` | mmap |
| kprobe `fd_install` | `(unsigned int fd, struct file *file)` | fd installed (upstream examples) |
| kprobe `security_path_truncate` | `(const struct path *)` | truncate |

Masks (kernel 7.1): `MAY_EXEC=1 MAY_WRITE=2 MAY_READ=4 MAY_APPEND=8 MAY_OPEN=0x20`.
`security_file_permission` gets exactly `MAY_READ` or `MAY_WRITE`. `security_file_post_open`
gets `acc_mode` = `ACC_MODE(flags)` (O_RDONLY→4, O_WRONLY→2, O_RDWR→6) | MAY_WRITE if O_TRUNC
| MAY_APPEND if O_APPEND; 0 for O_PATH. So write-open = `Mask ["2"]`, read-open = `Mask ["4"]`.

`file_arg.flags` in JSON is **not** open flags: it is empty or `"unresolvedPathComponents"`.

### At most 19 policies per LSM hook (verified the hard way, 2026-09-03)

An LSM program is attached through a BPF trampoline, and a trampoline holds
`BPF_MAX_TRAMP_LINKS = 38` programs. Tetragon attaches **two** per policy
(`generic_lsm_event` and `generic_lsm_output`), so the **20th** policy on one
hook fails and takes the whole daemon down:

```
sensor generic_lsm from collection moat-rootkit-bpffs-write failed to load:
failed prog .../bpf_generic_lsm_output_v61.o loadInstance:
attaching 'generic_lsm_output' failed: create tracing link: argument list too long
```

`argument list too long` is `E2BIG` from `bpf_trampoline_link_prog()`. It is not a
policy error: the yaml is valid, the 19 policies before it loaded, and the count
is what breaks. Tetragon exits 255, systemd restarts it, and it fails at the same
policy forever — a crash loop, not a degraded mode. `moatd` follows it down
through `PartOf=tetragon.service`. Each restart also re-walks `/proc` and re-emits
an exec event per live process, so a crash loop *manufactures* alerts on
long-lived processes while the sensor is actually dead.

The cap is per hook, not per daemon: 21 policies on `file_post_open` plus 6 spread
across `bprm_check_security`, `ptrace_access_check`, `path_chmod`, `inode_setxattr`
and `bpf` fails, while the same 27 split across those hooks is fine.

**The way out is a kprobe.** Every LSM hook has a `security_<hook>` global symbol in
kallsyms (`T security_file_post_open`), a kprobe is not attached through a
trampoline, and the prototype is identical — so the same `args` and `selectors`
port across unchanged:

```yaml
-  lsmhooks:
-  - hook: "file_post_open"
+  kprobes:
+  - call: "security_file_post_open"
+    syscall: false
```

The event arrives as `process_kprobe` instead of `process_lsm` with the same
`policy_name`, `function_name` (now `security_file_post_open`) and args, so moatd
needs nothing but the new name wherever it matches on hook names.

What you give up is `Override`: blocking in-kernel needs the LSM boundary, because
a kprobe can only override a function on the `ALLOW_ERROR_INJECTION` list and
`security_file_post_open` is not on it. `Sigkill` still works from a kprobe. So
keep the rules that may want to *block* on the LSM hook and move the rest.

`policies/check.py` enforces the 19 limit at build time.

Recommended (once per open, in-kernel; `Override` can block at this boundary):

```yaml
spec:
  lsmhooks:
  - hook: "file_post_open"
    message: "SSH private key opened"
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    selectors:
    - matchBinaries:
      - operator: NotIn
        values: ["/usr/bin/ssh", "/usr/bin/ssh-add", "/usr/bin/ssh-keygen"]
      matchArgs:
      - index: 0
        operator: "Prefix"
        values: ["/home/"]
      - index: 0
        operator: "Postfix"      # same index twice: see UNVERIFIED note in section 2
        values: ["/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_ecdsa"]
      - index: 1
        operator: "Mask"
        values: ["4"]            # MAY_READ
      matchActions:
      - action: Post
        rateLimit: "10s"
        rateLimitScope: "process"
```

Middle wildcard `/home/*/.ssh/` is **not expressible**: no glob/regex, and `SubString` is
refused for `file`/`path`. Options: (a) Prefix `/home/` + Postfix list as above (same-index
UNVERIFIED); (b) render the real `$HOME` into the policy; (c) Prefix `/home/` only and
suffix-filter in moatd. `resolve: "f_path.dentry.d_parent.d_name.name"` as `string`
Equal `.ssh` is plausible but **UNVERIFIED**.

Upstream write-detection shape (`file_arg` + `int_arg` + `return`):

```yaml
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"          # 4 = MAY_READ, 2 = MAY_WRITE
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values: ["/etc/ld.so.preload"]
      - index: 1
        operator: "Equal"
        values: ["2"]
```

`FileType`/`NotFileType` (`reg dir lnk sock chr blk fifo`) on `file`/`path` skips sockets/pipes cheaply.

Verified at: `SRC examples/tracingpolicy/{filename_monitoring,filename_monitoring_filtered,lsm_file_open}.yaml`,
`DOC use-cases/filename-access.md`, `SRC pkg/reader/path/path.go`, `SRC pkg/grpc/tracing/tracing.go`,
kernel v7.1 `fs/namei.c:4701`, `fs/read_write.c` (rw_verify_area), `fs/open.c` (build_open_flags),
`include/linux/fs.h`; local kallsyms + BTF.

## 4. Process exec details

`process_exec` = `{process, parent, ancestors[]}`. `ancestors` (beyond parent) needs
`--enable-ancestors base` (`base` is required; add `kprobe,lsm,tracepoint` for those events).
Otherwise only `parent` + `process.parent_exec_id`.

`process.binary_properties` (exec only): `setuid`, `setgid`, `privileges_changed[]`
(`PRIVILEGES_RAISED_EXEC_FILE_CAP|_SETUID|_SETGID`), `file{inode{number,links},path}` (memfd/
shm/deleted binaries only). **No** file-age or interpreter field; for scripts `binary` is the
interpreter and the script is in `arguments`.

**REQUIRES `--enable-process-cred`. The whole message, `file` included.** Without it
`binary_properties` is never attached and the field simply does not appear -- silently, and
identically to "this exec was ordinary". `pkg/grpc/exec/exec.go:317` passes
`option.Config.EnableProcessCred` into `UpdateExecOutsideCache`, and
`pkg/process/process.go:190` guards the whole struct on it (`if cred && pi.apiBinaryProp !=
nil`), despite the doc comment eight lines above claiming the flag covers only the credential
fields. Upstream `main` gates it the same way, so this is not fixed by a newer version. The
kernel side is unconditional -- `tg_kp_bprm_committing_creds` is in the base sensor and fills
`tg_execve_joined_info_map` regardless -- so the values are computed and then discarded.

Also: `file.path` is never populated in v1.7.1 (`process.go` sets only `inode`). The name of a
memfd/fexecve binary has to come from `process.binary`, which is the tracepoint filename:
`/proc/self/fd/N`, `/proc/<pid>/fd/N`, or `/dev/fd/N` for `execveat(AT_EMPTY_PATH)`.

Cost of the flag: no new BPF program. Every `process`/`parent` object gains `cap` and
`process_credentials` -- empty for ordinary users, ~41 capability names per list for root. If
the export grows uncomfortably, a `field-filters` fragment
`{"fields":"process.cap,parent.cap","action":"EXCLUDE"}` drops the bulk without touching
`binary_properties`.

`process.flags` is space-separated from: `execve procFS errorEnvs truncArgs miss
errorFilename errorArgs nocwd rootcwd errorCWD clone errorCgroupName errorCgroupID
errorCgroupSubsysCgrp errorCgroupSubsys errorCgroups errorPathResolutionCwd dataFilename
dataArgs inInitTree`. Debug only per proto. `procFS` = seen at daemon start; `clone` = fork+exec.

Other fields: `exec_id` (base64 `node:ktime:pid`), `pid`, `tid`, `uid` (euid), `cwd`,
`binary`, `arguments`, `start_time`, `auid` (4294967295 if unset), `parent_exec_id`, `refcnt`,
`cap`, `ns` (`--enable-process-ns`), `process_credentials` (`--enable-process-cred`),
`environment_variables` (`--enable-process-environment-variables` +
`--filter-environment-variables LD_PRELOAD`; keys `Key`/`Value`, capitalised), `in_init_tree`.

Verified at: `SRC api/v1/tetragon/tetragon.proto`, `capabilities.proto`
(ProcessPrivilegesChanged), `SRC pkg/reader/exec/exec.go` (FlagStrings), `TARBALL
usr/local/bin/tetragon --help` (`--enable-ancestors`, env flags).

**Session id and controlling terminal are NOT in the process record**, and both
are things moatd has to ask about constantly: `chain.rs` needs "is this a
session leader" to find the root of a story, and `context.rs` needs "is a person
at the other end of this" to score an alert. The list above is the whole record
and neither field is on it. `auid` is the login uid and is identical across
every pane of one login; the systemd cgroup is identical too (every pane shares
one `app-*.scope`). So `proctable::read_session` reads `/proc/<pid>/stat` once at
exec time and takes fields 6 and 7 — `session` and `tty_nr` — off the same line;
the second one is free, and `ProcInfo` carries both as `sid` and `tty`. `None`
means /proc was already gone (the process had exited before we looked), which is
deliberately distinct from `Some(0)`, "the kernel says there is no controlling
terminal". Measured on this machine 2026-09-05: `claude` 11536 tty_nr 34821
(pts/5), `herdr` 0, `quickshell` 0. The comm field can contain spaces and
parentheses, so the fields after it are found from the LAST `)` rather than by
splitting the line.

## 5. Network

```yaml
  kprobes:
  - call: "tcp_connect"          # int tcp_connect(struct sock *sk); runs in caller context
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"     # in-kernel RFC1918/loopback exclusion, verified upstream example
        values: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
      - index: 0
        operator: "DPort"        # single ports or ranges "min:max"
        values: ["1:1023", "4444", "8080:8090"]
      - index: 0
        operator: "Family"
        values: ["AF_INET", "AF_INET6"]
```

Address values are map-backed, so >4 CIDRs are fine; add `::1/128`, `fc00::/7`, `fe80::/10` for v6. `sock_arg` JSON: `family type protocol mark
priority saddr daddr sport dport cookie state`.

For **blocking**, use LSM `socket_connect` (error-injectable; `tcp_connect` is not):

```yaml
  lsmhooks:
  - hook: "socket_connect"       # (struct socket *sock, struct sockaddr *address, int addrlen)
    args:
    - index: 0
      type: "socket"
    - index: 1
      type: "sockaddr"           # the destination; matched with SAddr/SPort (no DAddr on sockaddr)
    selectors:
    - matchArgs:
      - index: 1
        operator: "Family"
        values: ["AF_INET", "AF_INET6"]
      - index: 1
        operator: "NotSAddr"
        values: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
      matchBinaries:
      - operator: "In"
        values: ["/usr/bin/curl"]
      matchActions:
      - action: Override
        argError: -1             # -EPERM
```

No DNS/hostname matching in-kernel (see Gaps).

Verified at: `SRC examples/tracingpolicy/tcp-connect-only-private-addrs.yaml`,
`tcp-connect-with-selectors.yaml`, `security-socket-connect-block-others.yaml`,
`SRC pkg/selectors/kernel.go` (sockaddr restrictions, writeMatchAddrsInMap), `DOC
concepts/tracing-policy/selectors.md` (port ranges), `argument_types.md`, local BTF.

## 6. Env / LD_PRELOAD, bpf, modules, ptrace, /proc/*/mem, setuid, setcap

- **Env vars: no policy selector exists** (KProbeSelector has no env filter). Detect
  `LD_PRELOAD` in moatd from `process_exec.process.environment_variables` with
  `--enable-process-environment-variables` + `--filter-environment-variables LD_PRELOAD`.
  Also watch writes to `/etc/ld.so.preload` (section 3).
- **bpf()**: LSM `bpf` = `(int cmd, union bpf_attr *attr, unsigned int size, bool kernel)`;
  arg0 `int` Equal `5`=BPF_PROG_LOAD, `0`=BPF_MAP_CREATE (or type `bpf_cmd`). Or LSM
  `bpf_prog_load(struct bpf_prog *, union bpf_attr *, struct bpf_token *, bool)` with arg0
  `bpf_prog` → `bpf_prog_arg{ProgType,InsnCnt,ProgName}`. Exclude `/usr/bin/tetragon`,
  `/usr/lib/tetragon/bpftool`, `/usr/lib/systemd/systemd` via `matchBinaries NotIn`.
- **Modules** (upstream policy): kprobe `security_kernel_read_file(file, int id, bool)` with id
  Equal `2` (READING_MODULE) **and `7`** (READING_MODULE_COMPRESSED — Arch ships `.ko.zst`),
  `security_kernel_module_request(char *)` arg0 `string`, `security_kernel_load_data(int id,
  bool)` Equal `2`. LSM forms `kernel_read_file`, `kernel_module_request`, `kernel_load_data` exist.
- **ptrace**: LSM `ptrace_access_check(struct task_struct *child, unsigned int mode)`; arg1
  `uint32` Mask `2` (PTRACE_MODE_ATTACH; `1` = PTRACE_MODE_READ, also hit by `/proc/<pid>/mem`,
  `maps`). Or kprobe `sys_ptrace` (`syscall: true`) arg0 `int` Equal `16` (ATTACH), `16902`
  (SEIZE 0x4206), `0` (TRACEME).
- **/proc/*/mem**: `mem_open`/`mem_rw` are static (`t`); kprobe attach **UNVERIFIED** (ftrace
  list is root-only). Portable: LSM `file_open` Prefix `/proc/` + Postfix `/mem` (same-index
  caveat) or `ptrace_access_check` Mask `1`.
- **chmod +s**: LSM `path_chmod(const struct path *path, umode_t mode)`; arg0 `path`, arg1
  `uint16` Mask `["2048","1024"]` (S_ISUID 04000, S_ISGID 02000). `chmod_common` calls it
  (`fs/open.c:632`), covering chmod/fchmod/fchmodat.
- **setcap**: LSM `inode_setxattr(struct mnt_idmap *, struct dentry *dentry, const char *name,
  const void *value, size_t size, int flags)`; arg1 `dentry` (path within one mount), arg2
  `string` Equal `security.capability`. Same-mount limitation of `dentry` type applies.
- Also present: LSM `bprm_check_security` (`linux_binprm` → path; Override blocks exec),
  `bprm_creds_from_file`, `capset`, `task_fix_setuid`, `file_mprotect`, `mmap_file`,
  `path_unlink/rename/truncate`, `inode_setattr`, `task_prctl`.

All symbols and `bpf_lsm_<hook>` stubs above exist in `/proc/kallsyms`;
`security_task_setuid` and `proc_pid_mem_read` do NOT.

Verified at: local `/proc/kallsyms`, local BTF via `TARBALL usr/local/lib/tetragon/bpftool btf dump file
/sys/kernel/btf/vmlinux`, kernel v7.1 `include/linux/ptrace.h`, `include/linux/kernel_read_file.h`,
`/usr/include/linux/{stat.h,ptrace.h}`, `SRC examples/tracingpolicy/{modules-nohost,bpf,sys_ptrace,lsm_bprm_check}.yaml`,
`SRC pkg/k8s/apis/cilium.io/v1alpha1/types.go` (no env selector).

## 7. Enforcement modes

- Modes: `enforce` (0), `monitor` (1). Precedence low→high: `spec.options policy-mode` <
  `tetra tp add --mode monitor|enforce <file>` < `tetra tp set-mode <name> monitor|enforce`.
- One pinned BPF array `policy_conf` per policy; `set-mode` updates it in place — immediate,
  no reload.
- Monitor mode **skips** `Sigkill`, `Signal`, `Override`, `NotifyEnforcer`, `Set`; `Post`,
  `NoPost`, `TrackSock`, `GetUrl`, `DnsLookup` still run, the event is still emitted, and
  **`action` still reports the configured action** (`e->action = action` regardless of
  `enforce_mode`). `"action":"KPROBE_ACTION_SIGKILL"` therefore does NOT prove a kill:
  moatd keeps its own mode state and confirms via the next `process_exit` with
  `"signal":"SIGKILL"` for that `exec_id`.
- `tetra tp list [-o json]` shows `MODE`; `tetra` needs the root-only gRPC socket.
  `-o json` returns `ListTracingPoliciesResponse`, whose `policies[]` are
  `TracingPolicyStatus { id, name, namespace, info, sensors, enabled(deprecated),
  filter_id, error, state, kernel_memory_bytes, mode, stats }`. **`mode` (field 11) is the
  one moatd reads**, a `TracingPolicyMode`: `TP_MODE_UNKNOWN` 0, `TP_MODE_ENFORCE` 1,
  `TP_MODE_MONITOR` 2, `TP_MODE_MONITOR_ONLY` 3. Field numbers and JSON names read out of
  the FileDescriptorProto embedded in `/usr/bin/tetra` (v1.7.1), not from the docs — see
  `Daemon::kernel_policy_modes`. The text table is
  `ID NAME STATE FILTERID NAMESPACE SENSORS KERNELMEMORY MODE NPOST NENFORCE NMONITOR`;
  `NAMESPACE` is empty for every moat policy and tabwriter pads it with spaces, so the
  text parser finds the `TP_MODE_*` token by shape rather than counting columns.
- `disable-kprobe-multi` forces classic kprobes (only if attach fails); `enable-policy-filter`
  is k8s-only, leave off.

### 7.1 The arming race (2026-09-05)

`set-mode` only works on a policy the kernel **already has**, and nothing in the unit
ordering guaranteed that.

tetragon.service is `Type=simple`, so systemd calls it started the instant
`/usr/bin/tetragon` forks. moatd is `Requires=/After=/PartOf=tetragon.service`, so it
started, believed the sensor was up, and ran `reapply_enforcement` — `tetra tp set-mode
<name> enforce` for each armed policy — about **2 seconds** in.

The numbers from that day's journal: tetragon started at 21:08:45, the "Added TracingPolicy
with success" lines ran until 21:09:01, and "Listening for events…" landed at 21:09:01.
**16 seconds to load 44 policies. The re-arm ran at +2 s.** The first call failed with
`dial tcp [::1]:54321: address family not supported` (the gRPC server was not listening
yet); the six after it failed with `tracing policy {moat-…} does not exist`. moatd logged
`ERROR re-arming after start: 7 of 7 policies did NOT take` and then did nothing about it —
no retry, no verification.

Meanwhile `status.enforcing_rules`, `moatctl status`'s `enforcing` line, and the panel all
went on listing the seven as armed, because that list is restored from `state.json` and had
never been checked against the kernel. Every policy renders as `policy-mode: monitor`
(`Set option policy-mode = monitor` in the tetragon journal), so all seven sat in monitor
for the rest of the day. It happened **seven times** that day: every boot, every
`sudo moatd telemetry --apply`, every tetragon restart. The six moatd-only restarts
succeeded, because tetragon was already loaded — which is why it was invisible.

The fix has three parts, and each one covers a case the others do not:

1. **`ExecStartPost=-/usr/bin/moatd wait-sensor --timeout 120`** on tetragon.service. A unit
   with an `ExecStartPost` stays in `activating` until it returns, so this is what makes
   `After=tetragon.service` order against a *loaded* sensor instead of a *forked* one.
   `wait-sensor` counts the policies pinned under `/sys/fs/bpf/tetragon`. The `-` prefix is
   deliberate: a slow load must not fail the sensor unit and hand it to `Restart=always`.
   `TimeoutStartSec=180` covers the wait.
2. **`[thresholds] arm_wait_secs` (120 s) in the daemon.** `Daemon::arm_tick` polls the pin
   count against the rendered policy count — falling back to `tetra tp list` naming the
   wanted policies when bpffs is unreadable — and does not call `set-mode` at all until the
   sensor is ready, retrying failures on a backoff inside the window. It runs on the
   periodic tick, never on the event path, so the wait cannot stall the tail. The unit fix
   does nothing for a tetragon that reloads policies *later*; this does.
3. **`Daemon::verify_enforcement`, once a minute, for ever.** Reads `mode` per policy from
   `tetra tp list -o json` and compares it with `enforcing_rules`. A disagreement is
   re-armed, the kernel is read *back* (a `set-mode` exit status is a claim, and claims were
   the problem), and whatever survives is published as `enforcing_verified` /
   `enforcing_unverified` — with one deduped `moat-x-protection-changed` alert, not one per
   tick. Being unable to *ask* is never reported as a gap: that is `sensor_unhealthy`'s
   story, and inventing a second one from the same silence double-counts it.

Verified at: `SRC bpf/lib/policy_conf.h`, `SRC bpf/process/generic_calls.h` (do_action/do_actions),
`SRC pkg/policyconf/policyconf.go`, `DOC concepts/tracing-policy/mode.md`, `TARBALL tetra tp set-mode --help`,
`tetra tp add --help`.

## 8. Daemon config

Precedence: `/usr/lib/tetragon/tetragon.conf.d/*` < `/usr/local/lib/tetragon/tetragon.conf.d/*`
< `/etc/tetragon/tetragon.yaml` < `/etc/tetragon/tetragon.conf.d/*` < `--config-dir`. One
file per flag, content `TrimSpace`d (inner newlines kept, so the allowlist can be several
JSON lines). Empty file = disabled for `metrics-server`, `gops-address`,
`health-server-address`, `server-address`. Tarball ships `bpf-lib`, `export-file-compress=true`,
`export-filename`, `log-format=text`, `log-level=info`, `server-address=unix:///var/run/tetragon/tetragon.sock`,
empty `metrics-server`/`gops-address`; its unit is `ExecStart=/usr/local/bin/tetragon`, `Restart=on-failure`, unhardened.

Relevant flags (defaults from `--help`):

| flag | default | note |
|---|---|---|
| `--bpf-lib` | `/var/lib/tetragon/` | BTF + `*.o` |
| `--tracing-policy-dir` | `/etc/tetragon/tetragon.tp.d` | read **once at startup**, one subdir level; **no hot-reload** — `tetra tp add/delete <file>` or restart |
| `--tracing-policy` | | single file |
| `--export-filename` | disabled | JSON lines |
| `--export-file-max-size-mb` / `-max-backups` / `-rotation-interval` / `-compress` / `-perm` | 10 / 5 / 0s / false / 600 | rename-rotation; readers reopen on inode change |
| `--export-allowlist` / `--export-denylist` | | JSON lines (below); JSON export only, gRPC unaffected |
| `--export-rate-limit` | -1 | events/minute over whole export |
| `--field-filters` / `--redaction-filters` | | shrink/redact export |
| `--enable-process-cred`, `--enable-process-ns` | false | add `process_credentials` / `ns` |
| `--enable-process-environment-variables`, `--filter-environment-variables` | false | env on exec events |
| `--enable-ancestors` | empty | `base,kprobe,lsm,tracepoint` for our use |
| `--parents-map-enabled` | false | needed by `matchParentBinaries` |
| `--event-queue-size` / `--process-cache-size` | 10000 / 65536 | userspace queue / process table |
| `--rb-size` / `--rb-size-total` / `--rb-queue-size` | 0(=64k/cpu) / 0 / 65535 | ring buffer |
| `--cgroup-rate` | off | `"1000,1s"` per-cgroup base-event throttle (emits `process_throttle`) |
| `--server-address` | `localhost:54321` | `unix:///run/tetragon/tetragon.sock` |
| `--metrics-server`, `--gops-address`, `--pprof-address` | disabled | |
| `--health-server-address` | `:6789` | **set to empty to disable** (listens by default) |
| `--log-format` / `--log-level` | text / info | |
| `--keep-sensors-on-exit` | false | enforcement persists across daemon restart |

Export filter object = `tetragon.Filter` JSON (snake_case): `event_set`, `binary_regex`,
`parent_binary_regex`, `ancestor_binary_regex`, `arguments_regex`, `parent_arguments_regex`,
`pid`, `policy_names` (**exact match**, no globs), `cel_expression`, `capabilities`,
`container_id`, `in_init_tree`, k8s ones. Lines ORed, fields within a line ANDed.
Allowlist for "exec/exit + `moat-*` policy events" (`/etc/tetragon/tetragon.conf.d/export-allowlist`):

```
{"event_set":["PROCESS_EXEC","PROCESS_EXIT"]}
{"event_set":["PROCESS_KPROBE"],"cel_expression":["process_kprobe.policy_name.startsWith('moat-')"]}
{"event_set":["PROCESS_LSM"],"cel_expression":["process_lsm.policy_name.startsWith('moat-')"]}
{"event_set":["PROCESS_TRACEPOINT"],"cel_expression":["process_tracepoint.policy_name.startsWith('moat-')"]}
```

CEL variables are the event names (`process_exec`, `process_kprobe`, `process_lsm`, …)
typed as the proto messages; a CEL line is evaluated only for events it references.
`startsWith` is standard CEL but **UNVERIFIED** live; fallback is an explicit
`{"policy_names":["moat-a","moat-b"]}` line generated from the policy directory.

Verified at: `TARBALL usr/local/bin/tetragon --help`, `TARBALL usr/local/lib/tetragon/tetragon.conf.d/*`,
`TARBALL usr/lib/systemd/system/tetragon.service`, `SRC cmd/tetragon/main.go` (loadTpFromDir,
no fsnotify), `SRC pkg/option/config.go` (ReadDirConfig), `SRC pkg/filters/{filters,policies,cel_expression}.go`,
`SRC api/v1/tetragon/events.proto`, `DOC concepts/events.md`, `DOC reference/daemon-configuration.md`.

## 9. JSON export format

Encoder: `protojson` with `UseProtoNames: true` → **snake_case**, one object per line,
zero scalars omitted, wrapper ints (`pid`,`uid`,`tid`,`auid`) kept even at 0, 64-bit ints
(`cookie`, `size_arg`) as strings, enums as names, RFC3339 UTC nanosecond timestamps.
Top-level: the event oneof (`process_exec|process_exit|process_kprobe|process_tracepoint|
process_lsm|process_uprobe|process_loader|process_throttle|process_usdt`), `node_name`, `time`.

Samples (shape from proto + docs; values synthetic; one line each in the file):

```json
{"process_exec":{"process":{"exec_id":"bWFyczoxMjM0NTY3ODkwMTIzOjQxMjMz","pid":41233,"uid":1000,"cwd":"/home/dan/proj","binary":"/home/dan/.local/share/mise/installs/node/26.5.0/bin/node","arguments":"/home/dan/proj/node_modules/evil/setup.mjs","flags":"execve clone","start_time":"2026-09-03T16:21:06.900123456Z","auid":1000,"parent_exec_id":"bWFyczoxMjM0NTY3MDAwMDAwOjQxMjMw","tid":41233},"parent":{"exec_id":"bWFyczoxMjM0NTY3MDAwMDAwOjQxMjMw","pid":41230,"uid":1000,"cwd":"/home/dan/proj","binary":"/usr/bin/sh","arguments":"-c \"node setup.mjs\"","flags":"execve clone","start_time":"2026-09-03T16:21:06.800000000Z","auid":1000,"parent_exec_id":"bWFyczoxMjM0NTY2OTAwMDAwOjQxMjAx","tid":41230},"ancestors":[{"exec_id":"bWFyczoxMjM0NTY2OTAwMDAwOjQxMjAx","pid":41201,"uid":1000,"binary":"/usr/bin/npm","arguments":"install","start_time":"2026-09-03T16:21:01.000000000Z","tid":41201}]},"node_name":"mars","time":"2026-09-03T16:21:06.900200000Z"}
```
```json
{"process_exit":{"process":{"exec_id":"bWFyczoxMjM0NTY3ODkwMTIzOjQxMjMz","pid":41233,"uid":1000,"cwd":"/home/dan/proj","binary":"/usr/bin/node","arguments":"setup.mjs","flags":"execve clone","start_time":"2026-09-03T16:21:06.900123456Z","auid":1000,"parent_exec_id":"bWFyczoxMjM0NTY3MDAwMDAwOjQxMjMw","tid":41233},"parent":{"...":"..."},"signal":"SIGKILL","time":"2026-09-03T16:21:07.123456789Z"},"node_name":"mars","time":"2026-09-03T16:21:07.123456789Z"}
```
(`status` only when non-zero; `signal` only on signal death.)
```json
{"process_kprobe":{"process":{"...":"..."},"parent":{"...":"..."},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/home/dan/.ssh/id_rsa","permission":"-rw-------"}},{"int_arg":4}],"return":{"int_arg":0},"action":"KPROBE_ACTION_POST","policy_name":"moat-cred-ssh-private-key-read","return_action":"KPROBE_ACTION_POST","message":"SSH private key read","tags":["observability.filesystem"]},"node_name":"mars","time":"2026-09-03T16:21:07.001000000Z"}
```
```json
{"process_kprobe":{"process":{"...":"..."},"parent":{"...":"..."},"function_name":"tcp_connect","args":[{"sock_arg":{"family":"AF_INET","type":"SOCK_STREAM","protocol":"IPPROTO_TCP","saddr":"192.168.1.20","daddr":"1.2.3.4","sport":51234,"dport":4444,"cookie":"1234567","state":"TCP_SYN_SENT"}}],"action":"KPROBE_ACTION_SIGKILL","policy_name":"moat-shell-reverse-shell-connect","kernel_stack_trace":[{"address":"18446744072119856613","offset":"5","symbol":"tcp_connect"}]},"node_name":"mars","time":"2026-09-03T16:22:00.000000000Z"}
```
(Stack traces only with `kernelStackTrace: true`; addresses 0 unless `--expose-stack-addresses`.
Other oneofs: `int_arg` (int32), `uint_arg`, `size_arg`, `long_arg`, `string_arg`,
`path_arg{mount,path,flags,permission}`, `linux_binprm_arg{path,flags,permission}`,
`sockaddr_arg{family,addr,port}`, `bpf_prog_arg`, `syscall_id{id,abi}`, `module_arg`,
`capability_arg{value,name}`; `label` sits beside the oneof.)
```json
{"process_lsm":{"process":{"...":"..."},"parent":{"...":"..."},"function_name":"file_post_open","policy_name":"moat-cred-ssh-private-key-read","message":"SSH private key opened","args":[{"file_arg":{"path":"/home/dan/.ssh/id_ed25519","permission":"-rw-------"}},{"int_arg":4}],"action":"KPROBE_ACTION_POST","tags":["cred"]},"node_name":"mars","time":"2026-09-03T16:21:07.001000000Z"}
```
(`ima_hash` only with `imaHash: true`; LSM events have no `return`/`return_action`.)
```json
{"process_tracepoint":{"process":{"...":"..."},"parent":{"...":"..."},"subsys":"raw_syscalls","event":"sys_enter","args":[{"syscall_id":{"id":101,"abi":"x64"}}],"policy_name":"moat-priv-ptrace","action":"KPROBE_ACTION_POST"},"node_name":"mars","time":"2026-09-03T16:23:00.000000000Z"}
```

`policy_name` exists on `process_kprobe|lsm|tracepoint|uprobe|usdt`, never on exec/exit.
`ancestors[]` appears wherever `--enable-ancestors` includes that type.

Verified at: `SRC pkg/encoder/encoder.go` (ProtojsonEncoder), `SRC api/v1/tetragon/tetragon.proto`,
`events.proto`, `DOC use-cases/filename-access.md` and `process-lifecycle/process-execution.md`
(real exec/exit/kprobe samples), `DOC concepts/tracing-policy/selectors.md` (process_lsm sample,
stack trace sample).

## 10. Performance knobs for a Rust/Node desktop

- Avoid `security_file_permission`/`vfs_read`/`vfs_write` without a tight path filter: they
  fire per read/write and resolve `d_path` each time. Prefer LSM `file_open`/`file_post_open`
  (once per open) with a few Prefix values + `FileType reg`.
- Avoid `raw_syscalls/sys_enter` without `InMap` on `syscall64` + `matchBinaries`, and
  unfiltered `fd_install`.
- Filter in-kernel: every posted event costs the encoder and the log. Put a
  `matchBinaries In [...] → NoPost` selector first, use `rateLimit` + `rateLimitScope:
  process` on noisy hooks, no `kernelStackTrace` on hot hooks.
- exec/exit cannot be filtered in-kernel; builds spawn thousands. Mitigate with
  `--export-allowlist`/`--field-filters`, `--cgroup-rate "N,1s"`, larger `--rb-size` /
  `--event-queue-size`; env capture only when filtered to `LD_PRELOAD`.
- Limits: 5 selectors per hook, 5 `matchArgs` each, 4 numeric values per filter (`InMap`
  beyond); string/path values are map-backed.
- `followChildren` on `matchBinaries` is the cheap way to scope "spawned by npm/cargo";
  `matchParentBinaries` needs the extra `parents_map`.

Verified at: `DOC concepts/tracing-policy/selectors.md` (limits, NoPost pattern),
`DOC concepts/tracing-policy/hooks.md`, `SRC pkg/selectors/kernel.go`, `tetragon --help`
(`--cgroup-rate`, ring-buffer flags).

## Gaps: what a policy cannot express (moatd must)

1. Ancestry beyond parent (except `matchParentBinaries followChildren` + parents map):
   "AI CLI with no terminal in its chain", "pkg-manager subtree" → daemon process table.
2. Middle-wildcard globs, regexes, basename matching on `file` args — Prefix/Postfix/Equal
   only. Render `$HOME` into policies or post-filter.
3. Environment variables (LD_PRELOAD) — exec-event field only, no selector.
4. Hostnames/DNS, registry allowlists, IOC hash/domain lookups — IPs and ports only.
5. Counting/windows ("N files in 10 s", dedupe) — `rateLimit` suppresses, never counts.
6. File age / sha256 of the executed file — only `binary_properties`; hash `process.binary`
   in userspace.
7. Whether a kill happened — `action` is reported in both modes; use `process_exit.signal`.
8. `moat-*` prefix in `policy_names` — exact names or CEL only.
9. Policy hot-reload — none; `tetra tp add|delete` or restart.
10. Scripts: `matchBinaries` sees the interpreter; the script path is in `arguments`.
