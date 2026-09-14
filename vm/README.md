# Project VM prototype

An opt-in development VM for trying ordinary coding agents, skills and local
MCP servers without exposing the desktop. This is an experimental command-line
prototype, not a production protection mode or a GUI feature. It does not replace
normal agent commands, change Moat policy, install an autostart service, or alter
the package-install sandbox.

The first backend is **QEMU/KVM**, not Firecracker. Both provide a separate guest
kernel; QEMU lets this prototype use a normal Ubuntu cloud image and unprivileged
networking. Backend selection is secondary to the project, credential and network
boundaries. No Firecracker support is claimed.

## Try it

Host prerequisites on Omarchy (one-time, about 110 MiB installed on the test host):

```sh
sudo pacman -S --needed qemu-system-x86 qemu-img cdrtools
```

Bubblewrap, OpenSSH, Git, Python 3.11+, a user systemd manager, and working
`/dev/kvm` access are also required. Only x86_64 has been implemented. Run from
the repository root:

```sh
./vm/moat-vm doctor
./vm/moat-vm up /absolute/path/to/a/disposable-project
```

The first launch downloads a SHA-256-pinned Ubuntu 24.04 minimal image and installs
guest Git, Python and build tools, plus a SHA-256-pinned Node 22.23.2 distribution
with npm. Later launches reuse the image;
resuming a VM reuses its installed tools and project. Setup failures stop the VM
and retain its state for inspection. An incomplete VM should be discarded and
created again. Creating a new VM has no effect on existing projects or sessions.

Use the session name printed by `up`:

```sh
./vm/moat-vm agent dev-XXXXXXXX claude  # install if needed, then open normally
./vm/moat-vm agent dev-XXXXXXXX codex  # another agent, same VM boundary
./vm/moat-vm shell dev-XXXXXXXX        # ordinary guest terminal
./vm/moat-vm list
./vm/moat-vm export dev-XXXXXXXX       # separate review copy; never auto-applies
./vm/moat-vm stop dev-XXXXXXXX         # stops all VM/proxy processes, keeps disk
./vm/moat-vm resume dev-XXXXXXXX
./vm/moat-vm discard dev-XXXXXXXX      # deletes a stopped VM, including reviews
```

Log in to agents **inside the VM**. Host account files, API-key environment
variables, SSH-agent sockets and global agent settings are not forwarded. The
prototype has no credential broker or OAuth callback forwarding. Login flows
requiring a browser callback into the guest may need a device-code or manual-code
flow; authentication UX is still an open prototype task. No authenticated agent
run is claimed by a successful `--version` check.

Agents run with their ordinary built-in tools and can discover project skills
and MCP configuration. Install/configure global skills and local MCP servers in
the guest. Host-global integrations are not automatically copied, and references
to host-specific absolute paths need adjustment. MCP servers needing private
network services, desktop IPC, browser control or SSH will not work unchanged.

Inside the guest the project is `/home/dev/project`. Exiting the terminal leaves
the VM running; `stop` releases its resources. VMs never start automatically at
login. Defaults are 2 CPUs, 4 GiB guest RAM and a sparse 16 GiB disk. The temporary
user service also limits total CPU, memory and process count, including proxy
helpers. `up --memory 2048 --cpus 1` lowers the budget; `up --offline` removes
public web access and skips development-package installation.

## Boundaries

* **Separate project copy.** Git projects include tracked and untracked files
  respecting `.gitignore`, without `.git` metadata. Non-Git projects skip common
  dependency/cache directories. Symlinks and special files are not imported.
  Snapshot reads use no-follow directory descriptors. Limits: 20,000 files and
  512 MiB. This is a working-tree snapshot, not a clone preserving history.
* **Common secret names omitted.** `.env`, `.netrc`, common private-key files and
  credential directories are excluded; `.env.example` and `.env.sample` remain.
  See each session's `omitted.json`. This is not a content scanner: credentials
  embedded in source, MCP configuration or differently named files can be copied.
* **No host mounts in the guest.** Neither the original project nor home is a
  shared folder. The VMM itself has a Bubblewrap filesystem containing runtime
  files, the pinned base image and its own disk/seed. Client SSH keys and host
  project files are outside it. No new privileges and zero capabilities apply;
  QEMU additionally uses seccomp. Its privilege-syscall group must allow `setsid`
  for libslirp helpers; the outer sandbox provides the escalation restriction.
* **Public web proxy only.** QEMU `restrict=on` prevents direct guest routing.
  The only outbound forwarding rule goes to our HTTP proxy. It allows public
  IPv4 TCP 80/443, validates all DNS answers, connects to a checked numeric IP,
  and rejects private, loopback, link-local, metadata and host-interface addresses.
  Host-interface addresses are captured at launch; restart after network changes.
  The host-to-guest SSH listener binds only loopback and uses a pinned guest key,
  an isolated client key, no SSH config, and no agent/X11 forwarding.
* **Network access is still authority.** The proxy does not inspect TLS, prevent
  uploads, identify malicious instructions, or constrain remote MCP tool actions.
  A public service can forward requests elsewhere. Credentials you add inside the
  VM and copied project contents are accessible to compromised code there.
  Non-proxy-aware tools, raw TCP, UDP and SSH remotes fail; HTTPS Git works.
* **Host-controlled lifecycle and bounded logging.** A transient user systemd
  unit owns the VMM and helpers. Stop kills the entire group. Guest console output
  stays in a 1 MiB memory ring; service logs use journald rate limits rather than
  an unbounded guest-controlled file. No system-level VM daemon is installed.
* **Review before bringing changes back.** Export reads an untrusted tar stream
  with size/time limits. Only regular files with safe relative paths are written,
  into a new private review folder, without executable bits. Links, devices,
  duplicate paths and Git metadata are refused. A JSON report lists additions,
  modifications and deletions. Original files are never overwritten. Review the
  code before running it on the host; a VM does not make generated code safe.

State is under `${XDG_STATE_HOME:-~/.local/state}/moat/vms/`, mode 0700. Guest disks
may contain credentials after login. `discard` removes the session and its review
copies; export anything you want to retain first. It is ordinary deletion, not
secure erasure of snapshots/backups. The shared base image remains cached.

Host Tetragon sees the VMM and proxy, **not guest process trees**. This prototype
does not yet install guest Moat/Tetragon. It tests containment and workflow, not
guest detection coverage. A compromised guest kernel, VMM vulnerability,
same-user host attacker or malicious approved remote action is not solved by
these tests. This is not yet a hardened replacement for a production VM platform.

## Validation

```sh
python3 -m unittest discover -s vm/tests -v
# Only against the disposable sample project containing hello.py and a fake .env:
python3 vm/tests/live_smoke.py dev-XXXXXXXX
```

The live smoke uses a real host-side TCP listener as a positive control, verifies
it is unreachable from the guest, checks proxy rejection of private destinations,
and successfully fetches public HTTPS. It exercises a minimal local MCP JSON-RPC
tool server and a skill's Python script. It does not claim that an authenticated
agent discovered/invoked them or resisted prompt injection.

Lifecycle check: stop, confirm the transient unit and its cgroup are gone, resume,
then verify guest files persist. Export should produce a separate review folder
while the host sample project remains unchanged. Test ordinary host activities
alongside the VM before considering default-on use.

Diagnostics:

```sh
journalctl --user -u moat-vm-dev-XXXXXXXX.service -n 30
cat ~/.local/state/moat/vms/dev-XXXXXXXX/setup.log
```

## Before a user-facing release

The GUI should offer **Open isolated project**, a visible running indicator,
resource use, Stop, and Review changes. A saved VM should be resumable with one
click. It must say which features need extra access, and distinguish a stopped
VM from an agent merely closing its terminal. Do not reuse the existing package
sandbox switch for this feature.

Remaining work includes login/callback UX, guest updates and agent version
pinning, guest telemetry, safe dev-server previews, narrowly authorized service
credentials, project import preview, change review/application, editor integration,
and broader testing with real skills/MCP servers. The current proxy is a small
prototype component needing security review; common downloads passing is not a
complete protocol/escape audit.

References: [QEMU networking and restrictions](https://www.qemu.org/docs/master/system/qemu-manpage.html),
[pinned Ubuntu image and checksums](https://cloud-images.ubuntu.com/minimal/releases/noble/release-20260905/),
[pinned Node checksums](https://nodejs.org/dist/v22.23.2/SHASUMS256.txt),
[cloud-init SSH configuration](https://cloudinit.readthedocs.io/en/stable/reference/yaml_examples/ssh.html).
