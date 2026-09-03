//! Configuration. Every path in the daemon comes from here, and every path can
//! be overridden on the command line, which is what makes dev mode (no root, no
//! `/etc`, no `/run`) work: see `dev-run.sh`.

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
    /// Tetragon's gRPC unix socket; its presence is the liveness check.
    pub tetragon_socket: PathBuf,
    /// `tetra` CLI, used only for `tp set-mode`.
    pub tetra: PathBuf,
    /// `sentinel-feeds` binary, spawned by `feeds refresh`.
    pub feeds_bin: PathBuf,
    /// Where human users are discovered for `{{HOME}}` expansion.
    pub passwd: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            tetragon_log: d("/var/log/sentinel/tetragon.log"),
            policies_dir: d("/run/sentinel/policies"),
            templates_dir: d("/usr/lib/sentinel/policies"),
            export_allowlist: d("/etc/tetragon/tetragon.conf.d/export-allowlist"),
            state_dir: d("/var/lib/sentinel"),
            runtime_dir: d("/run/sentinel"),
            socket: d("/run/sentinel/control.sock"),
            allowlist_dir: d("/etc/sentinel/allowlist.d"),
            sandbox_flag: d("/etc/sentinel/sandbox.enabled"),
            tetragon_socket: d("/run/tetragon/tetragon.sock"),
            tetra: d("/usr/bin/tetra"),
            feeds_bin: d("/usr/bin/sentinel-feeds"),
            passwd: d("/etc/passwd"),
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleToggles {
    pub ai_cli_headless: bool,
    pub pkg_egress: bool,
    pub new_exec_ioc: bool,
    pub mass_read: bool,
}

impl Default for RuleToggles {
    fn default() -> Self {
        Self {
            ai_cli_headless: true,
            pkg_egress: true,
            new_exec_ioc: true,
            mass_read: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    /// Same rule+exe+file inside this window folds into a `count` update.
    pub dedupe_secs: u64,
    /// `sentinel-x-mass-read`: distinct files that trip the rule.
    pub mass_read_files: usize,
    /// `sentinel-x-mass-read`: sliding window.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Group that owns the socket and the alert log.
    pub group: String,
    /// Starting policy mode; `sentinelctl set mode` persists over it.
    pub mode: String,
    pub paths: Paths,
    pub rules: RuleToggles,
    pub thresholds: Thresholds,
    pub net: NetConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            group: "sentinel".into(),
            mode: "monitor".into(),
            paths: Paths::default(),
            rules: RuleToggles::default(),
            thresholds: Thresholds::default(),
            net: NetConfig::default(),
        }
    }
}

impl Config {
    /// Load `sentinel.toml`. A missing file is not an error (defaults win); a
    /// malformed one is, because silently running with defaults would hide a
    /// typo'd threshold.
    pub fn load(path: &Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {}", path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {}", path.display(), e)),
        }
    }

    /// Default config file location, overridable with `SENTINEL_CONFIG`.
    pub fn default_path() -> PathBuf {
        std::env::var_os("SENTINEL_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| d("/etc/sentinel/sentinel.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_is_defaults() {
        let c = Config::load(Path::new("/nonexistent/sentinel.toml")).unwrap();
        assert_eq!(c.group, "sentinel");
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
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/sentinel.toml");
        let c = Config::load(&p).expect("etc/sentinel.toml must parse");
        assert_eq!(c.group, "sentinel");
    }
}
