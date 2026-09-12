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
└───────────────┬───────────────────────────────┬──────────────┘
                │ alerts.jsonl / telemetry.jsonl│ Protobuf / JSON over UNIX socket
                ▼                               ▼
┌───────────────────────────────────────────┐ ┌──────────────────────────────────┐
│          moat-ship (SIEM Export)          │ │   In-Kernel Sensors (Tetragon)   │
│  - Privilege-free shipper (User=moat-ship)│ │ - 52 TracingPolicy rules in eBPF │
│  - HTTPS: Splunk HEC, Elastic, Loki, DD   │ │ - Hooks: kprobes, LSM, traces    │
│  - Syslog: RFC5424 / RFC6587 (TCP, /dev)  │ │ - Dual modes: monitor & enforce  │
└───────────────────────────────────────────┘ └─────────────────┬────────────────┘
                                                                │
   ┌────────────────────────────────────────────────────────────┘
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

### D. Threat Intelligence Feeds (Packages & Domains)
Moat maintains two independent, offline-accessible threat feeds updated on a 15-minute jittered timer via the `moat-feeds.timer` background service:
* **Malicious Package Feed (`packages.txt`):**
  * Aggregates ~242,000+ malicious package entries across **npm, PyPI, crates.io, and Go** sourced from OSSF Malicious Packages and the DataDog Malicious Software Dataset.
  * Published as immutable, content-addressed, ed25519-signed artifacts with monotonic sequence numbers. Verified before installation into `/var/lib/moat/feeds/packages.txt`.
  * Scanned completely offline via binary-search mmap lookups—zero network queries at install time, zero latency, and zero leakage of what you are installing.
* **ThreatFox Malicious Domain Feed (`domains-feed.txt`):**
  * Synchronizes ~48,000+ active command-and-control (C2) domains and IPs from Abuse.ch ThreatFox bulk feeds.
  * Applies intelligent Public Suffix List (PSL) base gating to eliminate false positives on shared hosting (e.g. `workers.dev`, `compute-1.amazonaws.com`) while preserving active single-tenant tunnels.
  * Matched at runtime against outbound connections using `moat-x-net-domain-ioc`.
* **DNS Query Attribution:** Listens to `systemd-resolved`'s Varlink/D-Bus interface to map kernel-level IP socket events back to the specific domain name queried by the process.

### E. Baselining, Noise Guard, & Auto-Demotion
* **7-Day Learning Window:** Allows new developer workstations to baseline recurring development workloads.
* **Noise Guard:** Automatically demotes noisy, benign single-primitive rules to the background timeline if they repeat without accompanying attack signals, preventing alert fatigue while keeping them active inside correlated chains.
* **Allowlist Proposal Engine (`moatctl baseline`):** Automatically generates structured allowlist proposals for signed, recurring system packages.

### F. Build Sandboxing, Pre-Execution Scanners, & Blocking
Moat prevents malicious packages from executing or persisting before, during, and after installation:
* **Automatic Pre-Execution Blocking (PATH Shims):**
  * Transparent wrappers and PATH shims intercept package manager commands before lifecycle scripts run: `npm`, `npx`, `pnpm`, `yarn`, `bun`, `pip`, `pip3`, `uv`, `cargo`, `go`, and `makepkg`.
  * Shims automatically run the corresponding offline scanner (`moat-scan-npm`, `moat-scan-pip`, `moat-scan-cargo`, `moat-scan-go`, `moat-scan-pkgbuild`) against the local malicious package feed (`packages.txt`) and AST rules.
  * **When a bad package is found in the feed:**
    * The scanner flags it as `feed.malicious-package` with **HIGH severity** (exit code `2`).
    * **Non-interactive sessions (CI, background jobs, automated scripts):** The shim **refuses and blocks the install immediately** (`exit 1`), aborting execution before any postinstall code can run.
    * **Interactive terminals:** The install is **halted** and prompts the user with an explicit confirmation (`HIGH findings. Continue anyway? [y/N]`), defaulting to **aborting** (`N`).
* **Bubblewrap Sandbox Isolation (`sandbox/`):** Restricts package builds to isolated network and filesystem namespaces, preventing postinstall scripts from wandering into `$HOME` or external networks unless permitted.
* **Static Pre-Install Scanners (`scanner/`):** Python-based AST scanners inspect `PKGBUILD`, `.install`, `package.json`, `setup.py`, and Cargo manifests for obfuscated commands, reverse shells, or suspicious network tools prior to execution.
* **Runtime Containment & Termination:**
  * If a running package attempts an outbound connection to a ThreatFox domain or performs an attack sequence, Moat's **Containment Gate** (`moatctl set contain on`) severs its network access for 10 minutes.
  * If armed (`moatctl set kill kill`), the **Kill Gate** terminates the offending process tree with `SIGKILL`.
* **Install Receipts (`moatctl receipts`):** Writes an append-only audit ledger recording every file touch, network connection, and child process spawned during each package installation.

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

### H. Log Shipping & SIEM Export (`moat-ship`)
Moat includes a dedicated log shipper binary (`/usr/bin/moat-ship`, documented in [`docs/SHIPPING.md`](docs/SHIPPING.md)) to export alerts and telemetry off the workstation to central SIEMs and log aggregators:
* **Privilege-Free Architecture:** `moatd` (running as root) does no external outbound network I/O to avoid blocking or remote attack surfaces. Instead, `moat-ship` runs as an unprivileged service (`User=moat-ship`, supplementary group `moat`) with **zero capabilities**, reading `/var/lib/moat/alerts.jsonl` and `/var/lib/moat/telemetry.jsonl`.
* **Supported Transports & SIEM Destinations:**
  * **HTTPS (NDJSON):** Ships full, structured alert records and evidence blocks in batches to **Splunk HEC**, **Elasticsearch**, **Grafana Loki**, **Datadog**, or custom ingestion endpoints. Configured in `/etc/moat/ship.toml` with safe token substitution (`/etc/moat/ship.token`, permissions `0600`).
  * **Syslog (RFC5424 / RFC6587):** Ships compact, single-line alert summaries over `/dev/log` (UNIX datagram/stream) or remote TCP (`tcp://host:port`) with truncation markers and alert IDs for quick lookup.
* **Configurable Telemetry Classes (`[telemetry]` in `/etc/moat/moat.toml`):**
  * `alerts` (Default ON): High-value alert stream, state update events, and package install receipts.
  * `process` (Optional): Compact projection of all exec/exit events on the machine (~0.99 GB/day using `parent_exec_id`).
  * `network` (Optional): All outbound connections to public internet addresses (~6.8 MB/day).
  * `file` (Optional): Two-stage kernel/userspace filter capturing creates and modifications of executable-shaped files (~9.7 MB/day).
* **SIEM Query Faceting (`moat_tier`):** Every exported record carries an indexed `moat_tier` facet for simplified querying in SIEM dashboards:
  * `gator`: Highest-value events where Moat actively defended the machine (blocked, contained, killed, quarantined).
  * `alert`: Active incidents waiting for human review.
  * `duck`: Events matching allowlist/baseline suppressions.
  * `ripple`: Signal-tier building blocks forming parts of attack chains.
  * `silt`: Quiet timeline items and receipts.
  * `current`: Raw background telemetry.
* **Delivery Guarantees & Privacy:**
  * At-least-once delivery with persistent cursor tracking (`/var/lib/moat/ship/cursor.json`).
  * Bounded backpressure buffer with drop-oldest protection if the SIEM collector goes offline.
  * Automatic redaction of sensitive credentials, tokens, and home directory prefixes before logs leave the machine.

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
