# Moat: Current Features & Coverage Matrix

**Moat** is an open-source, workstation-focused supply-chain and runtime security sensor engineered specifically for Omarchy Linux.

Unlike server EDRs and anti-malware tools that focus on rootkit exploitation and post-compromise privilege escalation, Moat specializes in **unprivileged, invited threats**—such as malicious `npm` postinstall scripts, PyPI build wheels, poisoned AUR `PKGBUILD`s, malicious editor extensions, or compromised developer toolchains running with your normal user permissions.

---

## 1. Architecture Overview

Moat consists of five integrated layers operating between the Linux kernel and the Omarchy desktop shell:

```
┌──────────────────────────────────────────────────────────────┐
│                    Omarchy Desktop Shell                     │
│  - Bar Widget (3-state shield: quiet / needs you / gap)      │
│  - Interactive Panel (Now View, History, Settings, Allowlist)│
│  - Desktop Notifications via omarchy-notification-send       │
└───────────────────────────────┬──────────────────────────────┘
                                │ JSON via /run/moat/control.sock
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                  moatd Daemon & Correlation                  │
│  - Event stream parsing & process tree tracking (8 deep)     │
│  - Cross-family sequence correlation (Chaining)              │
│  - Provenance checking against pacman database               │
│  - DNS attribution via systemd-resolved                      │
│  - ThreatFox (Abuse.ch) & Malicious Package feed integration │
│  - Noise guard & 7-day automated baseline learning           │
│  - Containment gate & Process kill gate                      │
└───────────────────────────────┬──────────────────────────────┘
                                │ Protobuf / JSON over UNIX socket
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                In-Kernel Sensors (Tetragon)                  │
│  - 52 TracingPolicy rules loaded via eBPF                    │
│  - Hooks: kprobes, tracepoints, and BPF LSM security hooks   │
│  - Dual modes: monitor (audit) and enforce (kernel-level deny)│
└──────────────────────────────────────────────────────────────┘
                                │
   ┌────────────────────────────┴───────────────────────────┐
   ▼                                                        ▼
┌──────────────────────────────────────┐  ┌───────────────────────────────────┐
│        sandbox/ (Bubblewrap)         │  │             scanner/              │
│  - PATH shims for npm, pip, cargo,   │  │  - Pre-execution AST scanners for │
│    go, makepkg, bun, uv              │  │    PKGBUILD, .install, npm, cargo │
│  - Isolated filesystem & net limits  │  │  - Install receipts generator     │
└──────────────────────────────────────┘  └───────────────────────────────────┘
```

---

## 2. Areas of Coverage (The 10 Policy Families)

Moat monitors the system using **52 eBPF tracing policies** coupled with userland correlation rules across 10 security families:

### 1. `cred` — Credentials & Secrets
Detects unauthorized reads or exfiltration of sensitive developer credentials, secrets, and private keys located under `$HOME` or system paths.
* **Cloud Provider Keys:** AWS (`~/.aws/credentials`, `~/.aws/config`), Google Cloud (`~/.config/gcloud`), Azure (`~/.azure`).
* **SSH Secrets:** Private keys (`~/.ssh/id_*`), SSH agent socket (`$SSH_AUTH_SOCK`), reconnaissance of `~/.ssh/config` and `known_hosts`.
* **Version Control & Forge Tokens:** GitHub CLI (`~/.config/gh/hosts.yml`), `.netrc`, git credential helpers.
* **Project-Local Secrets:** `.env`, `.env.*`, worktree `.git/config`, project-local `.npmrc`.
* **Package Registry Tokens:** `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials.toml`, `~/.docker/config.json`.
* **Browser Secrets & Vaults:** Chromium and Firefox SQLite credential stores, cookie jars, session tokens.
* **GPG Keyrings:** `~/.gnupg/private-keys-v1.d`.
* **AI Agent Credentials:** `~/.claude/.credentials.json`, `.gemini`, and editor agent tokens.
* **System Secrets:** `/etc/shadow` access by non-authentication binaries.

### 2. `persist` — Persistence Mechanisms
Watches for unauthorized writes to files and locations that automatically execute on login, reboot, shell launch, or developer events.
* **Shell Startup Configurations:** `~/.bashrc`, `~/.zshrc`, `~/.config/fish/config.fish`, `~/.profile`.
* **Desktop Compositor & Autostart:** Hyprland config (`~/.config/hypr/hyprland.conf`), `~/.config/autostart/*.desktop`, `~/.local/share/applications/*.desktop`.
* **Systemd Service Units:** User service units (`~/.config/systemd/user/*`) and system units (`/etc/systemd/system/*`).
* **Git Persistence:** Local/global `.gitconfig`, git hooks (`.git/hooks/*`).
* **Omarchy Shell Plugins & Hooks:** `~/.config/omarchy/plugins/*`, `~/.config/omarchy/extensions/*`, `~/.config/omarchy/hooks/*`.
* **SSH Authorized Keys:** Modifications to `~/.ssh/authorized_keys`.
* **AI Agent Task & Rule Configurations:** `.cursor/rules`, `.claude/`, `.gemini/` task definitions.

### 3. `exec` — Untrusted Code Execution
Monitors binary executions initiated from untrusted, temporary, or cache directories where untrusted payloads are commonly dropped.
* **Scratch & Temp Filesystems:** Executions originating from `/tmp`, `/var/tmp`, or `/dev/shm`.
* **User Cache & Downloads:** Executions originating from `~/.cache/` or `~/Downloads/`.

### 4. `net` — Network & Exfiltration
Monitors anomalous outbound connections and associates raw IP packets with hostnames.
* **First Contact Tracking:** Alerts on first-ever outbound connections from an application to a previously unseen IP address or domain.
* **Egress from Scratch Filesystems:** Outbound internet sockets initiated by binaries running from `/tmp` or memory (`memfd`).
* **Suspicious Port Egress:** Network connections to unusual, non-standard, or known exfiltration ports.
* **DNS Query Attribution:** Correlates outbound IP connections with the exact DNS name queried through `systemd-resolved`.

### 5. `pkg` — Package Manager Subtrees
Watches child processes spawned under package managers and build tools (`npm`, `pip`, `cargo`, `go`, `makepkg`, `yay`).
* **Downloader Execution:** Spawning tools like `curl`, `wget`, or `aria2` during build or postinstall phases.
* **Shell/Interpreter Spawning:** Compilers or package managers spawning arbitrary interactive shells or interpreters.
* **Network Tooling:** Package managers spawning network utilities like `nc`, `netcat`, or `socat`.
* **Unauthorized Registry Egress:** Installs connecting to endpoints outside verified package registries (e.g. outside registry.npmjs.org, crates.io).

### 6. `priv` — Privilege Escalation & Process Boundaries
Monitors attempts to elevate privileges, inspect other processes, or escape sandboxes.
* **Linux Capabilities Gained:** Dynamic acquisition of root-equivalent capabilities (e.g., `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`).
* **Container Daemon Access:** Connecting to `/var/run/docker.sock` or `podman.sock`.
* **Process Memory Access:** Direct reads from `/proc/<pid>/mem`.
* **Process Debugging & Injection:** Attaching to processes via `ptrace`.
* **Kernel Parameter Writes:** Modifying runtime sysctl parameters under `/proc/sys/`.
* **Privilege Transition:** Setting file capabilities (`setcap`), setuid permissions (`chmod +s`), or transitioning user IDs (`setuid`/`setgid`).

### 7. `rootkit` — System & Sensor Integrity
Protects the operating system and Moat's own monitoring infrastructure from tampering.
* **eBPF Program Loading:** Detection of unauthorized eBPF bytecode loaded into the kernel.
* **Kernel Module Insertion:** Unauthorized loading of kernel modules (`init_module` / `finit_module`).
* **Dynamic Linker Hijacking:** Unauthorized writes to `/etc/ld.so.preload`.
* **Trust Store Manipulation:** Unauthorized addition of custom certificates to system CA trust stores.
* **Sensor & Log Tampering:** Modifications to Tetragon sockets, system journal logs, or shell histories.

### 8. `ransom` — Ransomware & Destructive Behavior
Identifies patterns indicative of data wiper or ransomware activity.
* **Mass File Churn:** Detection of rapid, consecutive file read operations followed by overwrites or unlinks.
* **Snapshot & Restore Point Deletion:** Destruction of Btrfs, Snapper, or Timeshift system restore snapshots.

### 9. `shell` — Interactive & Reverse Shells
Watches for interactive shells connected to suspicious pipes or networks.
* **Reverse Shell Connections:** Interactive shells (`sh`, `bash`, `zsh`) launched with standard input/output bound directly to a network socket.
* **Local LAN Scanning:** Interactive shells probing local subnet addresses.

### 10. `canary` & `x` — Decoy Canaries & Meta Watchdogs
Provides zero-false-positive detection tripwires and supervisory health checks.
* **Decoy Canaries:** Plants synthetic decoy credential files across the filesystem (e.g. fake AWS tokens, fake SSH keys). Any read operation triggers an immediate high-confidence alert without needing an allowlist.
* **Watchdog Protection (`moat-x-nobody-is-watching`):** Alerts when desktop panels or notification services fail to query the daemon for >30 minutes while unacknowledged alerts are waiting.
* **Mass File Read Detection:** Alerts when an unauthorized binary attempts to recursively scan and read files across developer projects.
* **Protection Audit Logging:** Records every weakening or modification of allowlists and security parameters.

---

## 3. Core Features & Capabilities

### A. Kernel eBPF Sensors & Dual Operating Modes
* **Zero-Fork Upstream Tetragon:** Built on unmodified upstream Tetragon 1.7.1, ensuring kernel stability and zero maintenance forks.
* **Dual Operating Modes:**
  * **`monitor` (Default):** Observes, correlates, logs, and alerts without interrupting developer workflows.
  * **`enforce`:** Uses in-kernel BPF LSM hooks to block prohibited actions immediately at syscall entry when enabled on supported kernels.

### B. Cross-Family Sequence Correlation (Chaining)
* Rather than inundating the user with isolated primitives (e.g., "a binary executed from `/tmp`"), Moat tracks full process ancestry trees (up to 8 levels deep).
* **Attack Chaining:** If a process sequence touches multiple distinct families within a sliding time window (e.g. reading a `.git/config` token + opening a network connection + executing an unpacked binary from `~/.cache`), Moat synthesizes them into a single **Chain** and raises the overall severity to **High** or **Critical**.
* **One-Action Resolution:** A complete multi-step attack chain can be acknowledged or acted upon with a single command (`moatctl ack <id> --chain`).

### C. Active Protection: Containment & Kill Gate
* **The Containment Gate (`moatctl set contain on`):** When enabled, Moat can automatically sever outbound network traffic for a specific offending binary and destination address for 10 minutes without killing the process tree, giving the developer time to inspect the alert.
* **The Kill Gate (`moatctl set kill kill`):** Provides automated process termination for high-confidence threats. Features a dry-run review mode (`moatctl decisions`) that records exactly what would have been killed or spared.

### D. Threat Intelligence & Network Attribution
* **DNS Query Attribution:** Listens to `systemd-resolved`'s Varlink/D-Bus interface to correlate raw IP socket events back to the specific domain names resolved on the machine.
* **ThreatFox Integration:** Ingests and maintains Abuse.ch ThreatFox indicators (~48,000+ malicious domains and IPs) to detect outbound command-and-control communication.
* **Malicious Package Feeds:** Ingests open-source vulnerability databases (OSV, GitHub Advisory) to cross-reference package installs against known malicious registries.

### E. Baselining, Noise Guard, & Auto-Demotion
* **7-Day Learning Window:** Allows new developer workstations to baseline recurring development workloads.
* **Noise Guard:** Automatically demotes noisy, benign single-primitive rules to the background timeline if they repeat without accompanying attack signals, preventing alert fatigue while keeping them active inside correlated chains.
* **Allowlist Proposal Engine (`moatctl baseline`):** Automatically generates structured allowlist proposals for signed, recurring system packages.

### F. Build Sandboxing & Pre-Execution Scanners
* **Bubblewrap PATH Shims (`sandbox/`):** Transparent shims for `npm`, `npx`, `pnpm`, `yarn`, `bun`, `pip`, `pip3`, `uv`, `cargo`, `go`, and `makepkg` that run builds inside restricted filesystem and network namespaces.
* **Static Pre-Install Scanners (`scanner/`):** Python-based AST scanners that analyze `PKGBUILD`, `.install`, `package.json`, and Cargo manifests for dangerous patterns prior to execution.
* **Install Receipts (`moatctl receipts`):** Writes an append-only audit ledger recording every network connection, file touch, and child process spawned during each package installation.

### G. Omarchy Desktop & Shell Integration
* **Desktop Bar Widget (`BarWidget.qml`):** Minimalist 3-state shield indicator embedded in the Omarchy top bar:
  * `quiet`: Dim shield (normal operation, no action needed).
  * `needs you`: Red alarm shield with count of unreviewed decisions.
  * `sensor gap`: Amber accent shield indicating sensor or policy issues.
* **Desktop Panel (`Panel.qml`):**
  * **Now View:** Summarizes open incidents, recent actions taken, and unreviewed decisions.
  * **History View:** Browsable timeline of all historical alerts, filtered bursts, and receipts.
  * **Settings View:** Interactive toggles for modes, containment, canaries, and allowlist rules.
* **Desktop Notifications:** Dispatched via `omarchy-notification-send` with native action deep links to summon the panel directly to the flagged alert.
* **AI Agent Triage Integration (`moatctl analyze`):** Built-in bridge to package incidents into markdown bundles and hand them off directly to coding agents (Antigravity, Claude, etc.) for automated triage and reasoning.
* **Weekly Posture Digest:** Automated systemd user timer producing a weekly summary of watched installs, suppressed events, and active protections.

---

## 4. CLI Control Surface (`moatctl`) Quick Reference

| Command | Purpose |
| :--- | :--- |
| `moatctl status` | Overview of daemon, Tetragon, policy count, feed updates, and unacked alerts |
| `moatctl list` | Displays recent unacknowledged alerts |
| `moatctl explain <id>` | Full human-readable breakdown and evidence forensic report for an alert |
| `moatctl chain [id]` | Displays correlated attack chains connecting related events across process trees |
| `moatctl ack <id> [--chain]` | Marks alerts or entire multi-step chains as reviewed |
| `moatctl ignore <id> [--scope]` | Generates a scoped allowlist entry (`exe`, `exe+file`, `parent`, `rule`) |
| `moatctl allowlist` | Displays merged active allowlist rules and indexes |
| `moatctl set <key> <val>` | Root-gated control toggles (`mode`, `contain`, `kill`, `sandbox`, `threshold.*`) |
| `moatctl canary <plant\|remove>` | Deploys or clears decoy honeypot credential files |
| `moatctl receipts` | Lists forensic records of what package managers did during installs |
| `moatctl decisions` | Audits what the kill gate spared or would have killed |
| `moatctl bundle <id>` | Generates a standalone forensic markdown bundle of an incident |
| `moatctl analyze <id>` | Bundles an incident and hands it off to your default AI coding agent |
