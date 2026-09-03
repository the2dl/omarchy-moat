//! Userland rules — the detections Tetragon cannot express (NOTES "Gaps").
//!
//! Each rule is a struct implementing [`UserRule`], carries its own metadata
//! (the same shape a policy's annotations produce, so the alert builder does not
//! care where a finding came from), and has a config toggle in
//! `[rules]` of `moat.toml`.
//!
//! | rule id                             | gap it fills                                  |
//! |-------------------------------------|-----------------------------------------------|
//! | `moat-x-ai-cli-headless`            | ancestry beyond one level (gap 1)             |
//! | `moat-x-pkg-egress`                 | registry allowlists, no DNS in kernel (gap 4) |
//! | `moat-x-new-exec-ioc`               | sha256 of the executed file (gap 6)           |
//! | `moat-x-mass-read`                  | counting inside a window (gap 5)              |
//! | `moat-pkg-subtree-interpreter-spawn`| exact package-subtree membership              |
//! | `moat-pkg-subtree-downloader`       | exact package-subtree membership              |
//! | `moat-pkg-subtree-netcat-exec`      | exact package-subtree membership              |
//! | `moat-ai-cli-in-pkg-subtree`        | exact package-subtree membership              |
//!
//! The last four keep the ids and severities of the kernel policies they
//! replace, because docs, the allowlist and the shell plugin all name them.
//! Tetragon's `matchParentBinaries … followChildren` could not express "inside
//! a package install" without matching half the desktop (see `pkgtree`), so the
//! subtree test moved to userland while the rule ids stayed put.

pub mod ai_cli;
pub mod mass_read;
pub mod netmatch;
pub mod new_exec_ioc;
pub mod pkg_egress;
pub mod pkg_subtree;
pub mod pkgtree;
pub mod self_proc_read;

use crate::config::Config;
use crate::event::{ExecEvent, HookHit};
use crate::explain::Finding;
use crate::feeds::Feeds;
use crate::policy::PolicyMeta;
use crate::proctable::{ProcInfo, ProcTable};

/// Shells a person actually types into. Only interactive *outside* a package
/// subtree: npm spawns `sh` for every lifecycle script.
pub const LOGIN_SHELLS: &[&str] = &["bash", "zsh", "fish", "sh", "dash", "ksh", "nu", "elvish"];

/// Interpreters a package script typically runs through.
pub const INTERPRETERS: &[&str] = &["node", "python", "python3", "sh", "bash", "zsh", "fish", "perl", "ruby"];

/// Anything that means a human is sitting in front of this process.
pub const INTERACTIVE: &[&str] = &[
    "alacritty", "foot", "kitty", "ghostty", "wezterm", "wezterm-gui", "gnome-terminal-server",
    "konsole", "xterm", "urxvt", "st", "tmux", "tmux: server", "screen", "sshd", "login",
    "systemd-logind", "code", "code-oss", "codium", "zed", "nvim", "vim", "emacs",
];

/// The AI CLIs CONTRACT §6.4 names.
pub const AI_CLIS: &[&str] = &["claude", "codex", "gemini", "opencode", "q", "amp"];

/// Flags that hand an agent the keys.
pub const SKIP_PERMISSION_FLAGS: &[&str] = &[
    "--dangerously-skip-permissions",
    "--yolo",
    "--trust-all-tools",
    "--full-auto",
    "--auto-approve",
];

pub struct RuleCtx<'a> {
    pub cfg: &'a Config,
    pub table: &'a ProcTable,
    pub feeds: &'a Feeds,
    /// Human homes, for "$HOME dotdir" tests.
    pub homes: &'a [String],
    pub now: u64,
    pub mode: &'a str,
}

impl RuleCtx<'_> {
    /// Build a finding with the process, ancestry and mode already filled in.
    pub fn finding(&self, rule: &str, meta: PolicyMeta, exec_id: &str) -> Option<Finding> {
        let proc = self.table.get(exec_id)?.clone();
        let mut f = Finding::new(rule, meta, proc);
        f.ancestry = self.table.ancestry(exec_id).into_iter().cloned().collect();
        f.ancestry_line = self.table.ancestry_line(exec_id);
        f.mode = self.mode.to_string();
        Some(f)
    }

    /// Is `path` inside a dotdir of one of the human homes?
    pub fn in_home_dotdir(&self, path: &str) -> bool {
        self.homes.iter().any(|h| {
            path.strip_prefix(h.as_str())
                .and_then(|rest| rest.strip_prefix('/'))
                .map(|rest| rest.starts_with('.'))
                .unwrap_or(false)
        })
    }
}

pub trait UserRule: Send {
    fn id(&self) -> &'static str;
    fn enabled(&self, cfg: &Config) -> bool;
    /// Annotations equivalent: the rule is its own policy.
    fn meta(&self) -> PolicyMeta;
    fn on_exec(&mut self, _ev: &ExecEvent, _exec_id: &str, _ctx: &RuleCtx) -> Vec<Finding> {
        Vec::new()
    }
    fn on_hook(&mut self, _h: &HookHit, _exec_id: &str, _ctx: &RuleCtx) -> Vec<Finding> {
        Vec::new()
    }
}

/// Every rule, in a fixed order. The engine filters by `enabled`.
pub fn all() -> Vec<Box<dyn UserRule>> {
    vec![
        Box::new(ai_cli::AiCliHeadless),
        Box::new(pkg_egress::PkgEgress::default()),
        Box::new(new_exec_ioc::NewExecIoc::default()),
        Box::new(mass_read::MassRead::default()),
        Box::new(pkg_subtree::InterpreterSpawn::default()),
        Box::new(pkg_subtree::Downloader),
        Box::new(pkg_subtree::NetcatExec),
        Box::new(pkg_subtree::AiCliInPkgSubtree),
    ]
}

/// Shared metadata builder so every userland rule reads like a policy.
#[allow(clippy::too_many_arguments)]
pub fn meta(
    name: &str,
    family: &str,
    severity: &str,
    title: &str,
    why: &str,
    expected: &str,
    rotate: &[&str],
    actions: &[&str],
    fp_hint: &str,
) -> PolicyMeta {
    PolicyMeta {
        name: name.into(),
        family: family.into(),
        severity: severity.into(),
        title: title.into(),
        rotate: rotate.iter().map(|s| s.to_string()).collect(),
        enforce: "none".into(),
        actions: actions.iter().map(|s| s.to_string()).collect(),
        why: why.into(),
        expected: expected.into(),
        fp_hint: fp_hint.into(),
        mode_default: "monitor".into(),
    }
}

/// `moat-x-sensor-mismatch`: raised in place of a policy alert when the kernel
/// reported a value the policy's own selectors exclude (see `selectors.rs`).
pub const SENSOR_MISMATCH: &str = "moat-x-sensor-mismatch";

pub fn sensor_mismatch_meta(why: &str) -> PolicyMeta {
    let mut m = meta(
        SENSOR_MISMATCH,
        "x",
        "low",
        "Sensor reported an event its own filter should have rejected",
        why,
        "A Tetragon upgrade that changes argument order or hook semantics, a policy edited \
         while it was loaded, and hooks whose arguments moatd re-validates only partially. \
         It is never caused by the program named in the alert, so ignoring it by exe is the \
         wrong move — ignore it by rule, or fix the policy.",
        &[],
        &["ignore"],
        "rule",
    );
    // Nothing to kill and nothing to quarantine: the finding is about the
    // sensor, not the process.
    m.enforce = "none".into();
    m
}

/// `moat-x-noisy-rule`: one rule flooded the last 24 h, so the noise guard
/// moved it to the timeline (BASELINE §4). Raised once per demotion.
pub const NOISY_RULE: &str = "moat-x-noisy-rule";

pub fn noisy_rule_meta(rule: &str, count: u64, threshold: u64) -> PolicyMeta {
    meta(
        NOISY_RULE,
        "x",
        "medium",
        &format!("{} is too noisy and was moved to the timeline", rule),
        &format!(
            "One rule raising {} alerts in 24 hours (the threshold is {}) is a bad rule or a new \
             workload, not {} incidents. Moat keeps recording it, stops notifying, and shows you \
             the handful of (actor, file) pairs behind the flood so you can decide once instead \
             of dismissing hundreds of times.",
            count, threshold, count
        ),
        "A new toolchain, a dotfile manager, a backup job, or a rule that is simply wrong for \
         this machine. Nothing is switched off: the alerts are still in alerts.jsonl and the \
         demotion clears itself after 24 quiet hours.",
        &[],
        &["ignore"],
        "rule",
    )
}

/// `moat-x-baseline-revoked`: a learned entry's actor stopped being official,
/// so the entry was disabled (LEARNING §1).
pub const BASELINE_REVOKED: &str = "moat-x-baseline-revoked";

pub fn baseline_revoked_meta(rule: &str) -> PolicyMeta {
    meta(
        BASELINE_REVOKED,
        "x",
        "low",
        &format!("A learned baseline entry for {} was disabled", rule),
        "Learned entries are re-checked on every pacman transaction. This one was earned by a \
         binary that a trusted repository shipped; that is no longer true (the package was \
         replaced, removed, or rebuilt from the AUR), so the suppression it granted has been \
         withdrawn rather than left standing on a changed fact.",
        "A package moving from a repo to an AUR build, a local `pacman -U`, or a binary that is \
         no longer owned by any package. The entry is commented out in baseline.toml with the \
         reason, so nothing is lost; re-learn it with `moatctl baseline relearn` once you are \
         happy with the new owner.",
        &[],
        &["ignore"],
        "rule",
    )
}

/// Does any ancestor (or the process itself) match one of these globs?
///
/// Both the ancestor's binary and each of its arguments are tried, because a
/// script with a shebang is reported as `binary: /usr/bin/bash` with the script
/// path sitting in `arguments` — matching only the binary would never see
/// `/usr/share/omarchy/bin/omarchy-agent-usage-daily`.
pub fn chain_matches_globs(table: &ProcTable, exec_id: &str, patterns: &[String]) -> Option<String> {
    if patterns.is_empty() {
        return None;
    }
    let matchers: Vec<globset::GlobMatcher> = patterns
        .iter()
        .filter_map(|p| match globset::Glob::new(p) {
            Ok(g) => Some(g.compile_matcher()),
            Err(e) => {
                log::warn!("ignoring unparseable glob {:?}: {}", p, e);
                None
            }
        })
        .collect();
    let mut chain: Vec<&ProcInfo> = Vec::new();
    if let Some(me) = table.get(exec_id) {
        chain.push(me);
    }
    chain.extend(table.ancestry(exec_id));
    for p in chain {
        let mut candidates: Vec<&str> = vec![p.exe.as_str()];
        candidates.extend(p.args.split_whitespace());
        for c in candidates {
            if matchers.iter().any(|m| m.is_match(c)) {
                return Some(c.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use crate::event::Process;

    pub fn proc(exec_id: &str, pid: u32, exe: &str, args: &str, parent: Option<&str>) -> Process {
        Process {
            exec_id: Some(exec_id.into()),
            pid: Some(pid),
            tid: Some(pid),
            uid: Some(1000),
            cwd: Some("/home/dan/proj".into()),
            binary: Some(exe.into()),
            arguments: Some(args.into()),
            start_time: Some("2026-09-03T16:21:06.900000000Z".into()),
            parent_exec_id: parent.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    /// A table with `fish -> npm -> node` already in it.
    pub fn table_with_install() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-term", 41100, "/usr/bin/alacritty", "", None));
        t.observe(&proc("e-fish", 41101, "/usr/bin/fish", "", Some("e-term")));
        t.observe(&proc("e-npm", 41201, "/usr/bin/npm", "install", Some("e-fish")));
        t.observe(&proc("e-node", 41250, "/usr/bin/node", "install.js", Some("e-npm")));
        t
    }

    /// A table with no terminal anywhere: systemd -> node.
    pub fn table_headless() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-sd", 1, "/usr/lib/systemd/systemd", "", None));
        t.observe(&proc("e-node", 41250, "/usr/bin/node", "server.js", Some("e-sd")));
        t
    }

    pub fn cfg() -> Config {
        Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{cfg, proc};
    use super::*;

    #[test]
    fn allowed_parent_globs_match_the_binary_or_any_argument() {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-sd", 1, "/usr/lib/systemd/systemd", "", None));
        // A shebang script is reported as `binary: /usr/bin/bash` with the
        // script path in `arguments`; matching only the binary would miss it.
        t.observe(&proc(
            "e-script",
            5000,
            "/usr/bin/bash",
            "/usr/share/omarchy/bin/omarchy-agent-usage-daily --json",
            Some("e-sd"),
        ));
        t.observe(&proc("e-cli", 5001, "/usr/bin/codex", "exec x", Some("e-script")));

        let pats = cfg().ai.headless_allowed_parents;
        let hit = chain_matches_globs(&t, "e-cli", &pats).expect("the argument must match");
        assert_eq!(hit, "/usr/share/omarchy/bin/omarchy-agent-usage-daily");

        // Same thing when the script itself is the binary.
        let mut t2 = ProcTable::new(8, 60);
        t2.observe(&proc(
            "e-script",
            5000,
            "/usr/share/omarchy/bin/omarchy-agent-usage-weekly",
            "",
            None,
        ));
        t2.observe(&proc("e-cli", 5001, "/usr/bin/claude", "-p x", Some("e-script")));
        assert!(chain_matches_globs(&t2, "e-cli", &pats).is_some());

        // An unrelated omarchy script is not covered, and an empty list never
        // matches anything.
        let mut t3 = ProcTable::new(8, 60);
        t3.observe(&proc("e-script", 5000, "/usr/share/omarchy/bin/omarchy-update", "", None));
        t3.observe(&proc("e-cli", 5001, "/usr/bin/claude", "-p x", Some("e-script")));
        assert!(chain_matches_globs(&t3, "e-cli", &pats).is_none());
        assert!(chain_matches_globs(&t2, "e-cli", &[]).is_none());
        // A broken glob is dropped with a warning, not a panic.
        assert!(chain_matches_globs(&t2, "e-cli", &["[".to_string()]).is_none());
    }

    #[test]
    fn the_sensor_mismatch_rule_explains_itself() {
        let m = sensor_mismatch_meta("because the kernel said so");
        assert_eq!(m.name, SENSOR_MISMATCH);
        assert_eq!(m.severity, "low");
        assert_eq!(m.family, "x");
        assert_eq!(m.why, "because the kernel said so");
        assert_eq!(m.actions, vec!["ignore"]);
        assert!(m.expected.contains("Tetragon"));
    }

    #[test]
    fn every_rule_has_a_unique_id_and_a_toggle() {
        let rules = all();
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "rule ids must be unique");
        assert_eq!(n, 8, "four gap rules plus the four that replaced pkg policies");

        // Every rule must be switchable off, or `[rules]` is a lie.
        let mut off = cfg();
        off.rules = crate::config::RuleToggles {
            ai_cli_headless: false,
            pkg_egress: false,
            new_exec_ioc: false,
            mass_read: false,
            pkg_subtree_interpreter_spawn: false,
            pkg_subtree_downloader: false,
            pkg_subtree_netcat_exec: false,
            ai_cli_in_pkg_subtree: false,
        };
        for r in &rules {
            assert!(r.enabled(&cfg()), "{} is off by default", r.id());
            assert!(!r.enabled(&off), "{} has no working toggle", r.id());
        }
    }
}
