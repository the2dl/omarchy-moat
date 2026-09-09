//! Configuration. Every path in the daemon comes from here, and every path can
//! be overridden on the command line, which is what makes dev mode (no root, no
//! `/etc`, no `/run`) work: see `dev-run.sh`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

fn d(s: &str) -> PathBuf {
    PathBuf::from(s)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Paths {
    /// Tetragon's JSON-lines export (`export-filename`).
    pub tetragon_log: PathBuf,
    /// Rendered policies; also Tetragon's `tracing-policy-dir`.
    pub policies_dir: PathBuf,
    /// Policy templates carrying `{{HOME}}`.
    pub templates_dir: PathBuf,
    /// Generated Tetragon `export-allowlist` conf.d fragment.
    pub export_allowlist: PathBuf,
    /// State directory: alerts.jsonl, state.json, quarantine/, feeds/.
    pub state_dir: PathBuf,
    /// Runtime directory holding the control socket.
    pub runtime_dir: PathBuf,
    /// Control socket path.
    pub socket: PathBuf,
    /// Merged allowlist fragments.
    pub allowlist_dir: PathBuf,
    /// Presence of this file turns the PATH shims on.
    pub sandbox_flag: PathBuf,
    /// Tetragon's gRPC unix socket. Its presence is NOT a liveness check: the
    /// file outlives the process, so it reads "up" throughout a crash loop.
    pub tetragon_socket: PathBuf,
    /// Where Tetragon pins one directory per loaded TracingPolicy. Counting
    /// them is the only honest answer to "is the sensor actually loaded",
    /// because it asks the kernel instead of asking systemd or a stat().
    pub tetragon_bpf_dir: PathBuf,
    /// `tetra` CLI, used only for `tp set-mode`.
    pub tetra: PathBuf,
    /// `moat-feeds` binary, spawned by `feeds refresh`.
    pub feeds_bin: PathBuf,
    /// `policies/check.py`, re-run by `moatd telemetry apply` before any
    /// profile switch. On 2026-09-03 a bad policy load left the sensor dead for
    /// 25 minutes while every surface still read "running"; a profile switch is
    /// the same operation, so it validates first and verifies afterwards.
    pub policy_check: PathBuf,
    /// `python3`, the only interpreter `check.py` needs.
    pub python: PathBuf,
    /// Where human users are discovered for `{{HOME}}` expansion.
    pub passwd: PathBuf,
    /// The local pacman database, parsed for provenance (BASELINE §1). Its
    /// mtime is the "a pacman transaction happened" signal.
    pub pacman_local: PathBuf,
    /// Used exactly once per pacman transaction, for `pacman -Sl <repos>`.
    pub pacman: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            tetragon_log: d("/var/log/moat/tetragon.log"),
            policies_dir: d("/run/moat/policies"),
            templates_dir: d("/usr/lib/moat/policies"),
            export_allowlist: d("/etc/tetragon/tetragon.conf.d/export-allowlist"),
            state_dir: d("/var/lib/moat"),
            runtime_dir: d("/run/moat"),
            socket: d("/run/moat/control.sock"),
            allowlist_dir: d("/etc/moat/allowlist.d"),
            sandbox_flag: d("/etc/moat/sandbox.enabled"),
            tetragon_socket: d("/run/tetragon/tetragon.sock"),
            tetragon_bpf_dir: d("/sys/fs/bpf/tetragon"),
            tetra: d("/usr/bin/tetra"),
            feeds_bin: d("/usr/bin/moat-feeds"),
            policy_check: d("/usr/lib/moat/check.py"),
            python: d("/usr/bin/python3"),
            passwd: d("/etc/passwd"),
            pacman_local: d("/var/lib/pacman/local"),
            pacman: d("/usr/bin/pacman"),
        }
    }
}

impl Paths {
    pub fn alerts(&self) -> PathBuf {
        self.state_dir.join("alerts.jsonl")
    }
    pub fn alerts_rotated(&self) -> PathBuf {
        self.state_dir.join("alerts.1.jsonl")
    }
    pub fn state_file(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }
    pub fn quarantine(&self) -> PathBuf {
        self.state_dir.join("quarantine")
    }
    pub fn feeds(&self) -> PathBuf {
        self.state_dir.join("feeds")
    }
    pub fn user_allowlist(&self) -> PathBuf {
        self.allowlist_dir.join("user.toml")
    }
    /// Where the learning window and accepted proposals write (BASELINE §3).
    pub fn baseline_allowlist(&self) -> PathBuf {
        self.allowlist_dir.join("baseline.toml")
    }
    pub fn rarity_file(&self) -> PathBuf {
        self.state_dir.join("rarity.json")
    }
    /// The telemetry stream. Deliberately not `alerts.jsonl`: telemetry is high
    /// volume and disposable, alerts are small and permanent, and one file
    /// would push a week of alerts out of the store in an afternoon.
    pub fn telemetry(&self) -> PathBuf {
        self.state_dir.join("telemetry.jsonl")
    }
    pub fn telemetry_rotated(&self) -> PathBuf {
        self.state_dir.join("telemetry.1.jsonl")
    }
}

/// Severity names in the order the incident threshold compares them.
pub fn severity_at_least(sev: &str, min: &str) -> bool {
    // `never` is the off switch: nothing is ever at least "never".
    if min == "never" {
        return false;
    }
    crate::alert::severity_rank(sev) >= crate::alert::severity_rank(min)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleToggles {
    pub ai_cli_headless: bool,
    pub pkg_egress: bool,
    /// `moat-net-first-contact`: an outbound connection to a destination this
    /// machine has never talked to. Low, timeline-only, and meaningful mainly
    /// as a chain step beside a credential read.
    pub net_first_contact: bool,
    pub new_exec_ioc: bool,
    pub mass_read: bool,
    pub exec_memfd: bool,
    pub exec_privileges_raised: bool,
    /// The four rules that replaced the deleted `pkg` kernel policies.
    pub pkg_subtree_interpreter_spawn: bool,
    pub pkg_subtree_downloader: bool,
    pub pkg_subtree_netcat_exec: bool,
    pub ai_cli_in_pkg_subtree: bool,
    /// `moat-shell-stdio-socket`: a shell whose fds 0/1/2 are a network socket
    /// (the interpreter reverse shell), or whose parent's are (the pty
    /// upgrade). Reads `/proc/<pid>/fd` at exec time; no kernel hook carries
    /// file descriptors, so this cannot be a policy.
    pub shell_stdio_socket: bool,
    /// `moat-ransom-file-churn`: one actor reading a file and then deleting,
    /// renaming away or emptying that same file, across many distinct files in
    /// a window -- or renaming many files to one new extension. The kernel
    /// policy of the same name feeds it and is `signal`; the rule is the
    /// detection.
    pub ransom_file_churn: bool,
    /// `moat-ransom-snapshot-command`: `btrfs subvolume delete`, `snapper
    /// delete`, `timeshift --delete`, `restic forget` without a `--keep`,
    /// `borg delete`. Argv is not visible to a kernel selector, so this is
    /// matched on the exec event, which is exported unconditionally.
    pub ransom_snapshot_command: bool,
}

impl Default for RuleToggles {
    fn default() -> Self {
        Self {
            ai_cli_headless: true,
            pkg_egress: true,
            net_first_contact: true,
            new_exec_ioc: true,
            mass_read: true,
            exec_memfd: true,
            exec_privileges_raised: true,
            pkg_subtree_interpreter_spawn: true,
            pkg_subtree_downloader: true,
            pkg_subtree_netcat_exec: true,
            ai_cli_in_pkg_subtree: true,
            shell_stdio_socket: true,
            ransom_file_churn: true,
            ransom_snapshot_command: true,
        }
    }
}

/// AI-CLI specific tuning. Separate from `[rules]` because it is not a toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    /// Globs matched against every ancestor's binary **and** each of its
    /// arguments. A match means "this launch is one of yours" and
    /// `moat-x-ai-cli-headless` stays quiet.
    ///
    /// Omarchy's own usage reporters run `codex` and `claude` headlessly by
    /// design, which is exactly what the rule looks for, so they ship allowed.
    pub headless_allowed_parents: Vec<String>,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            headless_allowed_parents: vec![
                "/usr/share/omarchy/bin/omarchy-agent-usage-*".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    /// Same rule+exe+file inside this window folds into a `count` update.
    pub dedupe_secs: u64,
    /// How often the integrity sweep re-checks every package-owned executable
    /// against the checksum its package recorded. `0` switches it off.
    ///
    /// The sweep is what finds a replaced binary that never runs, so switching
    /// it off gives up the only check that does not need the file to act
    /// first. It costs one package per tick and, on a machine with 8,761
    /// package-owned executables, 6.8 GiB of reading spread across a day.
    pub sweep_secs: u64,
    /// `moat-x-mass-read`: distinct files that trip the rule.
    pub mass_read_files: usize,
    /// `moat-x-mass-read`: sliding window.
    pub mass_read_window_secs: u64,
    /// `moat-ransom-file-churn`: distinct files one actor must read-then-destroy
    /// (or rename to one shared new extension) inside the window to fire. The
    /// Nth file is the trigger, as for `mass_read_files`.
    pub ransom_churn_files: usize,
    /// `moat-ransom-file-churn`: sliding window, and how long a read counts as
    /// "just before" the destruction of the same path.
    pub ransom_churn_window_secs: u64,
    /// How long an exited process stays in the table (for late kprobe events).
    pub process_prune_secs: u64,
    /// Ancestry chain cap (CONTRACT §6.2).
    pub ancestry_max: usize,
    /// alerts.jsonl rotation size.
    pub alerts_max_bytes: u64,
    /// Carry-forward byte cap for rotation (`store::rotate`). At rotation the
    /// protected rows are carried into the fresh generation; when they exceed
    /// this many bytes they are evicted in importance order. Well under
    /// `alerts_max_bytes` so a rotation cannot loop.
    pub alerts_carry_max_bytes: u64,
    /// Carry-forward row cap for rotation, the count companion to
    /// `alerts_carry_max_bytes`.
    pub alerts_carry_max: usize,
    /// state.json write interval.
    pub state_interval_secs: u64,
    /// Feed file mtime poll interval.
    pub feeds_poll_secs: u64,
    /// How long the daemon will wait for the sensor to finish loading its
    /// policies before it gives up on re-arming them (`Daemon::arm_tick`).
    ///
    /// 2026-09-05: moatd is `Requires=/After=/PartOf=tetragon.service`, and
    /// tetragon is `Type=simple` — so systemd calls it "started" the moment it
    /// forks, while it is still loading. Loading 44 policies took **16
    /// seconds** on this machine (21:08:45 start, last "Added TracingPolicy
    /// with success" at 21:09:01); `reapply_enforcement` ran at **+2 s** and
    /// every `tetra tp set-mode` failed with `tracing policy {moat-…} does not
    /// exist`. Nothing retried, so all seven armed policies sat in `monitor` in
    /// the kernel while `status.enforcing_rules` and the panel said ARMED.
    ///
    /// 120 s is roughly eight times the observed load time: generous enough for
    /// a cold boot on a slow disk, bounded so a sensor that is never coming
    /// back becomes a reported failure instead of an indefinite "arming".
    pub arm_wait_secs: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            dedupe_secs: 60,
            sweep_secs: 24 * 3_600,
            // 3 distinct credential files in 30 seconds, not 40 in 10.
            //
            // 40 was a threshold nothing could ever reach: a real stealer
            // reads a dozen, and this rule had never fired on this machine.
            // Nothing legitimate reads four different credential KINDS -- an
            // npm token, an AWS key, a kube config -- inside half a minute.
            // Backup and indexing tools do, and they are a small, nameable
            // set: allowlist them once, which is a thing the user can see and
            // undo, rather than a threshold that silently disables the rule.
            mass_read_files: 3,
            mass_read_window_secs: 30,
            // 8 distinct files in 60 seconds.
            //
            // Higher than mass_read on purpose. A credential file is rare by
            // nature, so three of them is already odd; a document is not, and
            // the shapes this counts -- read a file, then delete or rename
            // that same file -- have legitimate lookalikes at small N: a
            // script tidying a handful of photos, `mv` of a few files across
            // filesystems. None of them does it to eight distinct documents
            // inside a minute, and ransomware does it to hundreds in that
            // time, so the threshold sits between the two with room on both
            // sides. A payload throttled below one file per eight seconds
            // would slip under it -- and would also need three hours for a
            // thousand files, which is the trade.
            ransom_churn_files: 8,
            ransom_churn_window_secs: 60,
            process_prune_secs: 60,
            ancestry_max: 8,
            // 20 MiB. The panel no longer reads this file (it asks moatd
            // for the folded feed), so its size is a retention question again
            // rather than a UI latency budget. See moat.toml.
            alerts_max_bytes: 20 * 1024 * 1024,
            alerts_carry_max_bytes: 5 * 1024 * 1024,
            alerts_carry_max: 1000,
            state_interval_secs: 5,
            feeds_poll_secs: 60,
            arm_wait_secs: 120,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Destinations a package-manager subtree may talk to without an alert.
    /// DNS is not available to us (CONTRACT/NOTES gap 4), so this is CIDRs only.
    pub registry_cidrs: Vec<String>,
    /// Allow RFC1918 egress from inside a package install without alerting.
    ///
    /// Stays **true**, and should: an internal Artifactory, Nexus, Verdaccio or
    /// PyPI mirror is how a great many real installs work, and alerting on all
    /// LAN traffic would make moat useless in exactly the environments that
    /// most need it.
    ///
    /// It is not a blanket pass, though. A LAN address this machine has *never
    /// talked to before* is not the registry you use every day, so a
    /// `first_seen` destination is still reported once (see `pkg_egress`). Your
    /// registry becomes ordinary within a few installs and goes quiet; a
    /// beacon to a host that has never been seen does not.
    pub allow_private: bool,
    /// Severity for an egress hit.
    pub egress_severity: String,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            registry_cidrs: vec![
                // Fastly (npm registry + crates.io) — coarse but stable blocks.
                "151.101.0.0/16".into(),
                "199.232.0.0/16".into(),
                // GitHub.
                "140.82.112.0/20".into(),
                "143.55.64.0/20".into(),
                "192.30.252.0/22".into(),
                "185.199.108.0/22".into(),
                // PyPI / Cloudflare fronted.
                "104.16.0.0/12".into(),
                "172.64.0.0/13".into(),
            ],
            allow_private: true,
            egress_severity: "medium".into(),
        }
    }
}

/// BASELINE §7. Turning the whole section off is a matter of
/// `provenance_downgrade = false` plus `learning_days = 0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaselineConfig {
    /// Repos whose signature we trust. AUR builds are in none of them, by
    /// design: that is the whole point after the 2026 AUR incidents.
    pub trusted_repos: Vec<String>,
    /// Days after `installed_at` during which learned entries auto-apply.
    pub learning_days: u64,
    /// Distinct days a tuple must recur on before it can be learned/proposed.
    pub learn_min_days: usize,
    /// Alerts from one rule in a rolling 24 h before it is demoted.
    pub noisy_rule_per_day: u64,
    /// Section 2: let an official actor take one step off a severity.
    pub provenance_downgrade: bool,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            trusted_repos: vec![
                "core".into(),
                "extra".into(),
                "multilib".into(),
                "omarchy".into(),
            ],
            learning_days: 7,
            learn_min_days: 3,
            noisy_rule_per_day: 20,
            provenance_downgrade: true,
        }
    }
}

/// BASELINE §2b: the escape hatch for the context walk, and nothing more.
///
/// Context is decided first from the controlling terminal, which needs no
/// configuration and covers every terminal and session host that allocates a
/// pty. These two lists exist for the residue: something that hands a process
/// to a person WITHOUT a pty (moat cannot see through it), or something that
/// runs unattended under a name that looks interactive. Empty by default,
/// because a config key that most people must set is a design that did not
/// finish.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextConfig {
    /// Extra process names that mean a person is driving.
    pub interactive_roots: Vec<String>,
    /// Extra process names that mean nobody is.
    pub service_roots: Vec<String>,
}

/// LEARNING §6: the rarity counters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LearningConfig {
    /// A sighting's weight halves this often.
    pub half_life_days: f64,
    /// Under this many total sightings a tuple is `rare`.
    pub rare_max_count: u64,
    /// Nothing in this many days puts a tuple back to `rare`.
    pub rare_max_age_days: u64,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            half_life_days: 30.0,
            rare_max_count: 3,
            rare_max_age_days: 14,
        }
    }
}

/// LEARNING §6 `[analysis]`: where bundles live and how the user's agent is
/// launched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    /// Per-agent extra flags, e.g. `{ claude = ["--permission-mode", "plan"] }`.
    ///
    /// **Advisory only on this Omarchy.** `omarchy-agent` accepts exactly
    /// `--inline`, `--pick` and `--prompt` and hard-codes each agent's own
    /// flags, so there is no pass-through and no environment variable to use;
    /// `moatctl analyze` prints the equivalent direct command instead of
    /// silently dropping them. See README §10.3.
    pub agent_args: BTreeMap<String, Vec<String>>,
    /// Bundles and incident snapshots: `<bundle_dir>/<alert id>/`.
    pub bundle_dir: PathBuf,

    // --- auto-triage -------------------------------------------------------
    /// `off` | `annotate` | `demote` (default `demote`).
    ///
    /// What an unattended agent run may do with an alert. The ceiling is
    /// enforced in `triage::decide`, not here: `annotate` attaches the verdict
    /// and nothing else; `demote` additionally lets a **benign** verdict at
    /// **high** confidence move an alert from the notification badge to the
    /// panel timeline. Neither can hide, ack, delete, re-severity or allowlist
    /// anything — the alert stays in the store and stays visible either way.
    ///
    /// The tradeoff to know about: the alerts worth triaging are the ones most
    /// likely to contain attacker-controlled text, so `demote` is the one mode
    /// where a successful prompt injection buys something — a move off the
    /// badge. It buys nothing more than that, it is recorded on the alert as
    /// `triage.outcome`, and `moatctl triage --undo <id>` puts it back.
    pub auto_triage: crate::triage::TriageMode,
    /// The highest severity a triage demotion may touch. Default `high`, which
    /// leaves `critical` on the badge no matter what the agent concludes.
    pub triage_demote_max_severity: String,
    /// Alerts triaged per run, so a burst cannot turn into an unbounded queue
    /// of agent calls.
    pub triage_max_per_run: usize,
    /// How long an alert must have existed before it is offered to an agent.
    ///
    /// The buffer half of "buffer, dedupe, then react". A package install
    /// fires several alerts in a couple of seconds; reading the first one
    /// while the rest are still arriving spends a call on a partial picture.
    /// Waiting a few seconds lets the burst settle so one read covers it.
    pub triage_settle_secs: u64,
    /// Wall-clock ceiling for one agent call.
    ///
    /// Measured, not guessed: on this machine an agent in plan mode reading one
    /// bundle plus its staged evidence takes about three minutes, and the first
    /// live run landed at 172s. A ceiling near that turns a normal answer into a
    /// killed child and a wasted call, so the default stays clear of it.
    ///
    /// Lowered from 600 to 300 on 2026-09-04. A pass reads up to
    /// `triage_max_per_run` alerts and the service is `Type=oneshot`, so the
    /// old ceiling let one pass hold the queue for thirty minutes while no
    /// other alert -- including a live attack -- could be looked at. 300 is
    /// still well over the measured normal; the queue is what it protects.
    pub triage_timeout_secs: u64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        let mut agent_args = BTreeMap::new();
        agent_args.insert(
            "claude".to_string(),
            vec!["--permission-mode".to_string(), "plan".to_string()],
        );
        Self {
            agent_args,
            bundle_dir: d("/var/lib/moat/incidents"),
            auto_triage: crate::triage::TriageMode::Demote,
            triage_demote_max_severity: "high".into(),
            triage_settle_secs: 20,
            triage_max_per_run: 3,
            triage_timeout_secs: 300,
        }
    }
}

/// LEARNING §4 `[incidents]`: the snapshot taken before anything is killed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IncidentsConfig {
    /// Alerts at or above this severity are captured. `critical` narrows it;
    /// `never` switches capture off entirely.
    pub snapshot_min_severity: String,
    pub retain_days: u64,
    pub retain_max: usize,
}

impl Default for IncidentsConfig {
    fn default() -> Self {
        Self {
            snapshot_min_severity: "high".into(),
            retain_days: 30,
            retain_max: 200,
        }
    }
}

/// `[content]` — analysing what is *inside* a file a chain implicated.
///
/// The limits are the feature. moat is not an anti-virus: nothing here scans on
/// write, on exec, or on a timer, and the only trigger is a chain that already
/// reached `high` (`content.rs`). These two numbers are what stop a bounded
/// after-the-fact look from turning into an ambient scanner that a hostile
/// package can aim at the machine's own disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContentConfig {
    /// Off switch. On by default: the analysis is the difference between "a
    /// binary in /tmp phoned home" and "a binary in /tmp containing this C2
    /// string phoned home".
    pub enabled: bool,
    /// Files larger than this are listed as skipped, with the reason, and never
    /// read. 16 MiB covers every dropper anyone has shipped and refuses the
    /// 8 GB video file an attacker would love moat to hash on its event thread.
    pub max_bytes: u64,
    /// Analyses per rolling hour, counted from first use and persisted through
    /// `state.json`. A high chain is a rare event by design; if this cap is
    /// ever reached, something is wrong and the right answer is to stop
    /// reading files, not to keep up.
    pub per_hour: u32,
}

impl Default for ContentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_bytes: crate::content::DEFAULT_MAX_BYTES,
            per_hour: crate::content::DEFAULT_PER_HOUR,
        }
    }
}

/// LEARNING §5 `[digest]`: the one scheduled notification moat ever sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DigestConfig {
    /// First-boot value; `moatctl set digest on|off` persists over it.
    pub enabled: bool,
    /// `monday` … `sunday`.
    pub weekday: String,
    /// Local hour, 0-23.
    pub hour: u32,
}

impl Default for DigestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            weekday: "monday".into(),
            hour: 9,
        }
    }
}

/// `[telemetry]` — which classes of record moatd keeps, and how the expensive
/// one is scoped. See `telemetry.rs` for what each class contains and
/// docs/SHIPPING.md for the measured volume of each.
///
/// Every class except `alerts` is **off by default**. This is a developer
/// workstation, not a fleet endpoint: the numbers below are real, they were
/// measured on this machine, and a user who turns one on should have seen them
/// first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// `alerts.jsonl` as it is today. Low volume, high value; on.
    pub alerts: bool,
    /// exec/exit with parent mapping. **Already exported** — Tetragon cannot
    /// filter exec in-kernel (NOTES §10) — so this is a shipping decision, not
    /// a sensor one. Measured here: 42 events/s, ~3.1 KB each, 127 KB/s.
    pub process: bool,
    /// Outbound connects. Measured here at 0.26/s against exec's 42/s, which
    /// is what makes a deliberately broad policy affordable.
    pub network: bool,
    /// Executable-shaped file writes and `chmod +x`. Scoped by `file_scope`
    /// and `file_suffixes`; see `telemetry.rs` for why it is keyed on the file
    /// rather than on the operation.
    pub file: bool,

    /// `process`: repeat the whole parent block on every child, as the raw
    /// export does. Off, because `parent_exec_id` plus a join at the collector
    /// is the same graph for roughly half the bytes.
    pub inline_parent: bool,

    /// `file`: locations where *anything* written is worth a record,
    /// regardless of what it is. Rendered into the kernel policy as a `Prefix`
    /// list, so the filtering happens before a byte is written to disk.
    /// `{{HOME}}` fans out over every human home.
    pub file_scope: Vec<String>,
    /// `file`: suffixes that make a file executable-shaped anywhere on the
    /// system. Rendered as a `Postfix` list. Magic-byte ELF detection is not
    /// expressible in a selector, so it happens in userspace on the paths
    /// these already caught.
    pub file_suffixes: Vec<String>,
    /// `file`: path fragments under which a **create** is not recorded. Build
    /// and cache trees are almost all of the volume and almost none of the
    /// value. Never applied to a modify — a rewrite of an installed script is
    /// the case the class exists for.
    pub quiet_creates_under: Vec<String>,
    /// `file`: a file born within this many seconds counts as a create.
    pub create_window_secs: u64,
    /// `file`: attach the body of a small script to its record.
    ///
    /// Off. This is the one switch that puts file *contents* on the wire, and
    /// it is worth having — the body of a freshly written dropper is the
    /// evidence — but it inherits `evidence::is_secret_path` wholesale: a path
    /// that looks like key material is never read, whatever this says.
    pub capture_body: bool,
    /// Ceiling for `capture_body`. A model cannot usefully read more, and a
    /// collector should not have to store more.
    pub capture_body_max_bytes: u64,

    /// `telemetry.jsonl` rotation size (16 MiB).
    pub max_bytes: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            alerts: true,
            process: false,
            network: false,
            file: false,
            inline_parent: false,
            file_scope: vec![
                "/usr/bin/".into(),
                "/usr/local/bin/".into(),
                "/usr/lib/systemd/system/".into(),
                "/etc/systemd/system/".into(),
                "/etc/cron.d/".into(),
                "/etc/profile.d/".into(),
                "{{HOME}}/.local/bin/".into(),
                "{{HOME}}/.config/systemd/user/".into(),
                "{{HOME}}/.config/autostart/".into(),
                "{{HOME}}/.local/share/applications/".into(),
            ],
            file_suffixes: vec![
                ".sh".into(),
                ".bash".into(),
                ".zsh".into(),
                ".py".into(),
                ".pl".into(),
                ".rb".into(),
                ".js".into(),
                ".mjs".into(),
                ".cjs".into(),
                ".ts".into(),
                ".php".into(),
                ".lua".into(),
            ],
            quiet_creates_under: vec![
                "/node_modules/".into(),
                "/.cache/".into(),
                "/.npm/".into(),
                "/target/".into(),
                "/.git/".into(),
                "/__pycache__/".into(),
                "/.venv/".into(),
                "/site-packages/".into(),
                "/.local/share/mise/".into(),
                "/.cargo/registry/".into(),
            ],
            create_window_secs: 5,
            capture_body: false,
            capture_body_max_bytes: 65536,
            max_bytes: 16 * 1024 * 1024,
        }
    }
}

impl TelemetryConfig {
    /// Is this class on?
    pub fn enabled(&self, class: &str) -> bool {
        match class {
            "alerts" => self.alerts,
            "process" => self.process,
            "network" => self.network,
            "file" => self.file,
            _ => false,
        }
    }

    /// Class names that are on, in `CLASSES` order.
    pub fn classes(&self) -> Vec<&'static str> {
        crate::telemetry::CLASSES
            .iter()
            .copied()
            .filter(|c| self.enabled(c))
            .collect()
    }

    /// Reasons this configuration cannot be applied.
    ///
    /// The one that matters: `file = true` with no scope at all would render a
    /// policy that matches every write on the machine. That is the volume trap
    /// the class exists to avoid, so it is refused rather than rendered.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.file && self.file_scope.is_empty() && self.file_suffixes.is_empty() {
            out.push(
                "telemetry.file is on but file_scope and file_suffixes are both empty: that \
                 would watch every write on the machine (measured here: 24.5/s under $HOME, \
                 2769 events from one npm install). Give it a scope or turn it off."
                    .into(),
            );
        }
        for s in &self.file_suffixes {
            if !s.starts_with('.') {
                out.push(format!(
                    "telemetry.file_suffixes entry {:?} does not start with a dot",
                    s
                ));
            }
            // Tetragon's Postfix values are capped at 127 bytes (NOTES §2).
            if s.len() > 127 {
                out.push(format!("telemetry.file_suffixes entry {:?} exceeds 127 bytes", s));
            }
        }
        for p in &self.file_scope {
            if !p.starts_with('/') && !p.starts_with("{{HOME}}") {
                out.push(format!(
                    "telemetry.file_scope entry {:?} is neither absolute nor {{{{HOME}}}}-relative",
                    p
                ));
            }
            if !p.ends_with('/') {
                out.push(format!(
                    "telemetry.file_scope entry {:?} does not end in '/': a Prefix without a \
                     trailing slash also matches sibling paths that merely start with it",
                    p
                ));
            }
            if p.len() > 256 {
                out.push(format!("telemetry.file_scope entry {:?} exceeds the 256-byte Prefix cap", p));
            }
        }
        if self.capture_body && self.capture_body_max_bytes > 1024 * 1024 {
            out.push(
                "telemetry.capture_body_max_bytes above 1 MiB: evidence.rs stages at most 1 MiB \
                 for the same reason, and this body may leave the machine"
                    .into(),
            );
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Group that owns the socket and the alert log.
    pub group: String,
    /// Starting policy mode; `moatctl set mode` persists over it.
    pub mode: String,
    pub paths: Paths,
    pub rules: RuleToggles,
    pub thresholds: Thresholds,
    pub net: NetConfig,
    pub ai: AiConfig,
    pub baseline: BaselineConfig,
    pub context: ContextConfig,
    pub learning: LearningConfig,
    pub analysis: AnalysisConfig,
    pub incidents: IncidentsConfig,
    pub content: ContentConfig,
    pub digest: DigestConfig,
    pub telemetry: TelemetryConfig,
    pub contain: ContainConfig,
}

/// Correlation-driven containment (`contain.rs`). Off by default: it is the one
/// thing moat does that acts on its own judgement rather than on a single rule
/// the user armed, so it is opt-in even when rules are armed.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContainConfig {
    pub enabled: bool,
    /// `log` | `block`. What containment does about a PRIVATE destination.
    ///
    /// **`log` by default, for the same reason `kill` is.** A containment is a
    /// refusal moatd writes on its own judgement, and refusing a LAN address is
    /// where that judgement costs the most: on 2026-09-07 a machine migration
    /// -- rsync over ssh to the old box, which by its nature reads every
    /// credential in $HOME and sends it to one host -- was contained
    /// mid-transfer, and the user saw `ssh: connect to host 192.168.44.105:
    /// Operation not permitted` with no explanation in the tool that failed.
    ///
    /// That is the failure mode that makes people turn protection off and never
    /// turn it back on. A wrong alert costs attention; a wrong block costs the
    /// product. The static deny policy beside this one already made the same
    /// call -- `moat-net-tmpfs-binary-egress` excludes RFC1918 in the kernel
    /// "because a workstation talks to its LAN all day" -- and the dynamic,
    /// heuristic mechanism should not be the braver of the two.
    ///
    /// `log` still ALERTS: the chain forms, the card is raised, and the journal
    /// records what would have been refused. Only the refusal is withheld.
    pub private: String,
    /// `off` | `log` | `kill`. Ending processes a chain implicates.
    ///
    /// **`log` by default, and that is the point.** A design review on
    /// 2026-09-05 ran the first version of the rules against this machine's own
    /// records and found they would have SIGKILLed the developer's build four
    /// times that day, thirteen processes at a time -- while failing to kill
    /// the lab payload they were written for. Rules for a destructive action
    /// have to be judged against real traffic before they are allowed to act,
    /// which is how the industry ships this too: detect first, promote to
    /// prevent after a tuning period.
    ///
    /// `log` runs the whole decision and writes what it WOULD have killed.
    /// A week of that with nothing wrong in it is the argument for `kill`.
    pub kill: String,
    /// How long a containment lasts before moatd deletes it. Minutes, not
    /// hours: long enough to stop an exfil in progress, short enough that a
    /// wrong call costs one failed connection and fixes itself.
    pub ttl_secs: u64,
    /// How many may be live at once. These share the `socket_connect` LSM hook
    /// with the detection policies and the kernel caps that hook, so this is a
    /// coverage guard, not a preference.
    pub max: usize,
}

impl Default for ContainConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kill: "log".into(),
            private: "log".into(),
            ttl_secs: 600,
            max: 4,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            group: "moat".into(),
            mode: "monitor".into(),
            paths: Paths::default(),
            rules: RuleToggles::default(),
            thresholds: Thresholds::default(),
            net: NetConfig::default(),
            ai: AiConfig::default(),
            baseline: BaselineConfig::default(),
            context: ContextConfig::default(),
            learning: LearningConfig::default(),
            analysis: AnalysisConfig::default(),
            incidents: IncidentsConfig::default(),
            content: ContentConfig::default(),
            digest: DigestConfig::default(),
            telemetry: TelemetryConfig::default(),
            contain: ContainConfig::default(),
        }
    }
}

impl Config {
    /// Load `moat.toml`. A missing file is not an error (defaults win); a
    /// malformed one is, because silently running with defaults would hide a
    /// typo'd threshold.
    pub fn load(path: &Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {}", path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {}", path.display(), e)),
        }
    }

    /// Default config file location, overridable with `MOAT_CONFIG`.
    pub fn default_path() -> PathBuf {
        std::env::var_os("MOAT_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| d("/etc/moat/moat.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_is_defaults() {
        let c = Config::load(Path::new("/nonexistent/moat.toml")).unwrap();
        assert_eq!(c.group, "moat");
        assert_eq!(c.thresholds.mass_read_files, 3);
    }

    #[test]
    fn partial_config_merges_over_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(
            &p,
            "mode = \"enforce\"\n[thresholds]\nmass_read_files = 7\n[rules]\npkg_egress = false\n",
        )
        .unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.mode, "enforce");
        assert_eq!(c.thresholds.mass_read_files, 7);
        assert_eq!(c.thresholds.dedupe_secs, 60);
        assert!(!c.rules.pkg_egress);
        assert!(c.rules.mass_read);
    }

    #[test]
    fn unknown_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(&p, "[thresholds]\nmass_red_files = 7\n").unwrap();
        assert!(Config::load(&p).is_err());
    }

    #[test]
    fn shipped_config_parses() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/moat.toml");
        let c = Config::load(&p).expect("etc/moat.toml must parse");
        assert_eq!(c.group, "moat");
    }

    /// The shipped file is the documentation. A rule with no toggle in it, or a
    /// toggle whose shipped value disagrees with the built-in default, is a
    /// user reading one thing and getting another.
    #[test]
    fn the_shipped_config_documents_every_key_and_agrees_with_the_defaults() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/moat.toml");
        let text = std::fs::read_to_string(&p).unwrap();
        let shipped: toml::Value = toml::from_str(&text).unwrap();
        let defaults = toml::Value::try_from(Config::default()).unwrap();

        for section in [
            "rules", "ai", "thresholds", "net", "baseline", "context", "learning", "analysis",
            "incidents", "content", "digest", "telemetry",
        ] {
            let want = defaults.get(section).unwrap().as_table().unwrap();
            let got = shipped
                .get(section)
                .unwrap_or_else(|| panic!("etc/moat.toml has no [{}] section", section))
                .as_table()
                .unwrap();
            for key in want.keys() {
                assert!(
                    got.contains_key(key),
                    "etc/moat.toml does not document {}.{}",
                    section,
                    key
                );
            }
        }
        // And the values that are meant to be defaults really are.
        let c = Config::load(&p).unwrap();
        assert_eq!(c.rules, RuleToggles::default(), "a shipped toggle disagrees with its default");
        assert_eq!(
            c.ai.headless_allowed_parents,
            AiConfig::default().headless_allowed_parents
        );
        assert_eq!(
            c.ai.headless_allowed_parents,
            vec!["/usr/share/omarchy/bin/omarchy-agent-usage-*"]
        );
        assert_eq!(c.baseline, BaselineConfig::default(), "a shipped baseline key drifted");
        assert_eq!(c.context, ContextConfig::default(), "a shipped context key drifted");
        assert!(
            c.context.interactive_roots.is_empty() && c.context.service_roots.is_empty(),
            "the context lists ship empty: the tty is the mechanism, these are the escape hatch"
        );
        assert_eq!(c.learning, LearningConfig::default(), "a shipped learning key drifted");
        assert_eq!(c.analysis, AnalysisConfig::default(), "a shipped analysis key drifted");
        assert_eq!(c.incidents, IncidentsConfig::default(), "a shipped incidents key drifted");
        assert_eq!(c.content, ContentConfig::default(), "a shipped content key drifted");
        assert_eq!(c.digest, DigestConfig::default(), "a shipped digest key drifted");
        assert_eq!(
            c.telemetry,
            TelemetryConfig::default(),
            "a shipped telemetry key drifted"
        );
    }

    /// LEARNING §6 publishes these values; the plugin and the docs quote them.
    #[test]
    fn the_analysis_incident_and_digest_defaults_are_the_ones_the_doc_publishes() {
        let a = AnalysisConfig::default();
        assert_eq!(a.bundle_dir, PathBuf::from("/var/lib/moat/incidents"));
        assert_eq!(
            a.agent_args.get("claude").map(|v| v.as_slice()),
            Some(["--permission-mode".to_string(), "plan".to_string()].as_slice())
        );
        let i = IncidentsConfig::default();
        assert_eq!(i.snapshot_min_severity, "high");
        assert_eq!(i.retain_days, 30);
        assert_eq!(i.retain_max, 200);
        let g = DigestConfig::default();
        assert!(g.enabled);
        assert_eq!(g.weekday, "monday");
        assert_eq!(g.hour, 9);
    }

    #[test]
    fn the_snapshot_threshold_compares_by_rank_and_never_switches_it_off() {
        assert!(severity_at_least("critical", "high"));
        assert!(severity_at_least("high", "high"));
        assert!(!severity_at_least("medium", "high"));
        assert!(severity_at_least("medium", "low"));
        assert!(!severity_at_least("critical", "never"));
    }

    #[test]
    fn the_baseline_defaults_are_the_ones_the_doc_publishes() {
        let b = BaselineConfig::default();
        assert_eq!(b.trusted_repos, ["core", "extra", "multilib", "omarchy"]);
        assert_eq!(b.learning_days, 7);
        assert_eq!(b.learn_min_days, 3);
        assert_eq!(b.noisy_rule_per_day, 20);
        assert!(b.provenance_downgrade);
        let l = LearningConfig::default();
        assert_eq!(l.half_life_days, 30.0);
        assert_eq!(l.rare_max_count, 3);
        assert_eq!(l.rare_max_age_days, 14);
    }
}
