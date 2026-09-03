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
    pub new_exec_ioc: bool,
    pub mass_read: bool,
    /// The four rules that replaced the deleted `pkg` kernel policies.
    pub pkg_subtree_interpreter_spawn: bool,
    pub pkg_subtree_downloader: bool,
    pub pkg_subtree_netcat_exec: bool,
    pub ai_cli_in_pkg_subtree: bool,
}

impl Default for RuleToggles {
    fn default() -> Self {
        Self {
            ai_cli_headless: true,
            pkg_egress: true,
            new_exec_ioc: true,
            mass_read: true,
            pkg_subtree_interpreter_spawn: true,
            pkg_subtree_downloader: true,
            pkg_subtree_netcat_exec: true,
            ai_cli_in_pkg_subtree: true,
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
    /// `moat-x-mass-read`: distinct files that trip the rule.
    pub mass_read_files: usize,
    /// `moat-x-mass-read`: sliding window.
    pub mass_read_window_secs: u64,
    /// How long an exited process stays in the table (for late kprobe events).
    pub process_prune_secs: u64,
    /// Ancestry chain cap (CONTRACT §6.2).
    pub ancestry_max: usize,
    /// alerts.jsonl rotation size.
    pub alerts_max_bytes: u64,
    /// state.json write interval.
    pub state_interval_secs: u64,
    /// Feed file mtime poll interval.
    pub feeds_poll_secs: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            dedupe_secs: 60,
            mass_read_files: 40,
            mass_read_window_secs: 10,
            process_prune_secs: 60,
            ancestry_max: 8,
            alerts_max_bytes: 20 * 1024 * 1024,
            state_interval_secs: 5,
            feeds_poll_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Destinations a package-manager subtree may talk to without an alert.
    /// DNS is not available to us (CONTRACT/NOTES gap 4), so this is CIDRs only.
    pub registry_cidrs: Vec<String>,
    /// Everything private is allowed implicitly; set false to alert on LAN too.
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
    pub learning: LearningConfig,
    pub analysis: AnalysisConfig,
    pub incidents: IncidentsConfig,
    pub digest: DigestConfig,
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
            learning: LearningConfig::default(),
            analysis: AnalysisConfig::default(),
            incidents: IncidentsConfig::default(),
            digest: DigestConfig::default(),
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
        assert_eq!(c.thresholds.mass_read_files, 40);
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
            "rules", "ai", "thresholds", "net", "baseline", "learning", "analysis", "incidents",
            "digest",
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
        assert_eq!(c.learning, LearningConfig::default(), "a shipped learning key drifted");
        assert_eq!(c.analysis, AnalysisConfig::default(), "a shipped analysis key drifted");
        assert_eq!(c.incidents, IncidentsConfig::default(), "a shipped incidents key drifted");
        assert_eq!(c.digest, DigestConfig::default(), "a shipped digest key drifted");
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
