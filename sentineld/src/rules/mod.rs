//! Userland rules — the detections Tetragon cannot express (NOTES "Gaps").
//!
//! Each rule is a struct implementing [`UserRule`], carries its own metadata
//! (the same shape a policy's annotations produce, so the alert builder does not
//! care where a finding came from), and has a config toggle in
//! `[rules]` of `sentinel.toml`.
//!
//! | rule id                      | gap it fills                                  |
//! |------------------------------|-----------------------------------------------|
//! | `sentinel-x-ai-cli-headless` | ancestry beyond one level (gap 1)             |
//! | `sentinel-x-pkg-egress`      | registry allowlists, no DNS in kernel (gap 4) |
//! | `sentinel-x-new-exec-ioc`    | sha256 of the executed file (gap 6)           |
//! | `sentinel-x-mass-read`       | counting inside a window (gap 5)              |

pub mod ai_cli;
pub mod mass_read;
pub mod netmatch;
pub mod new_exec_ioc;
pub mod pkg_egress;

use crate::config::Config;
use crate::event::{ExecEvent, HookHit};
use crate::explain::Finding;
use crate::feeds::Feeds;
use crate::policy::PolicyMeta;
use crate::proctable::{ProcInfo, ProcTable};

/// Package managers whose subtree we treat as "an install is running".
pub const PKG_MANAGERS: &[&str] = &[
    "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "makepkg",
    "pacman", "yay", "paru", "gem", "go", "composer",
];

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

/// Does this process (or an ancestor) look like a package install?
pub fn pkg_ancestor(table: &ProcTable, exec_id: &str) -> Option<ProcInfo> {
    table.chain_has(exec_id, PKG_MANAGERS)
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
