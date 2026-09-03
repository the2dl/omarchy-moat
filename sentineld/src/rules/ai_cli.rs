//! `sentinel-x-ai-cli-headless`.
//!
//! Fills NOTES gap 1: a policy can only see one level of parent, and there is
//! no selector for "is there a terminal in this chain". Two shapes fire:
//!
//! * **headless** — an AI CLI whose whole ancestry contains no terminal, no
//!   tmux/ssh session and no editor. A human did not type this;
//! * **auto-approved** — permission-skipping flags (`--dangerously-skip-permissions`,
//!   `--yolo`, …) while the parent is an interpreter inside a package-manager
//!   subtree. That is a postinstall script driving an agent with your keys.
//!
//! Note on shells: a bare `sh`/`bash` in the chain does *not* count as
//! interactive, because `npm` spawns one for every lifecycle script.

use crate::config::Config;
use crate::event::ExecEvent;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::rules::{
    meta, pkg_ancestor, RuleCtx, UserRule, AI_CLIS, INTERACTIVE, INTERPRETERS, LOGIN_SHELLS,
    SKIP_PERMISSION_FLAGS,
};
use crate::util::basename;

pub const ID: &str = "sentinel-x-ai-cli-headless";

#[derive(Default)]
pub struct AiCliHeadless;

impl UserRule for AiCliHeadless {
    fn id(&self) -> &'static str {
        ID
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.ai_cli_headless
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            ID,
            "ai",
            "high",
            "AI coding agent running without a human at the terminal",
            "An AI CLI started by a script, with no terminal in its process chain, is either \
             an automation you set up or a package's install script using your agent (and your \
             tokens) to do its work. Agents can read every file you can and open network \
             connections; a headless one has no prompt for you to say no to.",
            "Your own cron jobs, CI runners, editor integrations and shell aliases that pipe \
             a prompt into an agent. Ignore by exe or parent once you recognise it.",
            &["claude", "github-token"],
            &["kill", "ignore"],
            "parent",
        )
    }

    fn on_exec(&mut self, _ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some(proc) = ctx.table.get(exec_id) else {
            return Vec::new();
        };
        let comm = basename(&proc.exe);
        if !AI_CLIS.contains(&comm) {
            return Vec::new();
        }

        let chain = ctx.table.ancestry(exec_id);
        let flag = SKIP_PERMISSION_FLAGS
            .iter()
            .find(|f| arg_present(&proc.args, f));
        let parent_interp = chain
            .first()
            .filter(|p| INTERPRETERS.contains(&p.comm()))
            .cloned()
            .cloned();
        let pkg = pkg_ancestor(ctx.table, exec_id);

        // A terminal, tmux/ssh session or editor means a human is there. A bare
        // shell counts too — but only outside a package-manager subtree, since
        // npm spawns `sh` for every lifecycle script.
        let terminal = chain.iter().find(|p| INTERACTIVE.contains(&p.comm()));
        let shell = chain.iter().find(|p| LOGIN_SHELLS.contains(&p.comm()));
        let headless = terminal.is_none() && !(shell.is_some() && pkg.is_none());
        let auto_approved = flag.is_some() && parent_interp.is_some() && pkg.is_some();

        if !headless && !auto_approved {
            return Vec::new();
        }

        let mut m = self.meta();
        let mut evidence = Vec::new();
        let what;
        if auto_approved {
            m.severity = "critical".into();
            m.title = "AI coding agent auto-approved inside a package install".into();
            let pkg = pkg.as_ref().expect("checked above");
            what = format!(
                "{} was started with {} by {} inside a `{}` install, so it can act without asking you.",
                comm,
                flag.unwrap(),
                parent_interp.as_ref().map(|p| p.comm().to_string()).unwrap_or_default(),
                pkg.comm()
            );
            evidence.push(format!(
                "permission flag: {} in args {}",
                flag.unwrap(),
                proc.args
            ));
            evidence.push(format!(
                "package manager in ancestry: {} pid {} args {}",
                pkg.exe, pkg.pid, pkg.args
            ));
        } else {
            what = format!(
                "{} (an AI coding agent) ran with no terminal anywhere in its process chain.",
                comm
            );
            evidence.push(format!(
                "no terminal, tmux/ssh session, editor or interactive shell in the {} ancestor(s) examined",
                chain.len()
            ));
            if let Some(p) = pkg.as_ref() {
                evidence.push(format!("package manager in ancestry: {} pid {}", p.exe, p.pid));
            }
        }

        let Some(mut f) = ctx.finding(ID, m, exec_id) else {
            return Vec::new();
        };
        f.hook = "userland: ancestry has no interactive terminal".into();
        f.what_override = Some(what);
        f.extra_evidence = evidence;
        vec![f]
    }
}

/// Match a flag as a whole argument, so `--yolo` does not fire on
/// `--no-yolo-mode` or on a prompt that merely mentions it.
fn arg_present(args: &str, flag: &str) -> bool {
    args.split_whitespace()
        .any(|a| a == flag || a.starts_with(&format!("{}=", flag)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::Feeds;
    use crate::rules::testkit::{cfg, proc, table_headless, table_with_install};
    use crate::proctable::ProcTable;

    fn run(table: &ProcTable, exec_id: &str) -> Vec<Finding> {
        let cfg = cfg();
        let feeds = Feeds::default();
        let homes = vec!["/home/dan".to_string()];
        let ctx = RuleCtx {
            cfg: &cfg,
            table,
            feeds: &feeds,
            homes: &homes,
            now: 100,
            mode: "monitor",
        };
        AiCliHeadless.on_exec(&ExecEvent::default(), exec_id, &ctx)
    }

    #[test]
    fn a_terminal_in_the_chain_is_silence() {
        let mut t = table_with_install();
        t.observe(&proc("e-cli", 41300, "/home/dan/.local/bin/claude", "-p hi", Some("e-fish")));
        assert!(run(&t, "e-cli").is_empty(), "alacritty -> fish -> claude is a human");
    }

    #[test]
    fn headless_agent_fires_high() {
        let mut t = table_headless();
        t.observe(&proc("e-cli", 41300, "/home/dan/.local/bin/claude", "-p hi", Some("e-node")));
        let f = run(&t, "e-cli");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "high");
        assert_eq!(f[0].rule, ID);
        assert!(f[0].what_override.as_ref().unwrap().contains("no terminal"));
    }

    #[test]
    fn auto_approved_inside_an_install_is_critical() {
        let mut t = table_with_install();
        t.observe(&proc(
            "e-cli",
            41300,
            "/home/dan/.local/bin/claude",
            "--dangerously-skip-permissions -p \"fix it\"",
            Some("e-node"),
        ));
        let f = run(&t, "e-cli");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "critical");
        assert!(f[0]
            .extra_evidence
            .iter()
            .any(|e| e.contains("--dangerously-skip-permissions")));
        assert!(f[0].extra_evidence.iter().any(|e| e.contains("npm")));
    }

    #[test]
    fn a_shell_outside_an_install_counts_as_interactive() {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-fish", 41101, "/usr/bin/fish", "", None));
        t.observe(&proc("e-cli", 41300, "/home/dan/.local/bin/claude", "-p hi", Some("e-fish")));
        assert!(run(&t, "e-cli").is_empty(), "a shell with no install above it is a human");
    }

    #[test]
    fn a_shell_inside_an_install_does_not_count() {
        // systemd -> npm -> sh -> claude: the `sh` is a lifecycle script, not a
        // person, so this is still headless.
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-sd", 1, "/usr/lib/systemd/systemd", "", None));
        t.observe(&proc("e-npm", 41201, "/usr/bin/npm", "install", Some("e-sd")));
        t.observe(&proc("e-sh", 41240, "/usr/bin/sh", "-c claude", Some("e-npm")));
        t.observe(&proc("e-cli", 41300, "/home/dan/.local/bin/claude", "-p hi", Some("e-sh")));
        assert_eq!(run(&t, "e-cli").len(), 1);
    }

    #[test]
    fn a_non_agent_binary_is_ignored() {
        let mut t = table_headless();
        t.observe(&proc("e-x", 41300, "/usr/bin/curl", "https://x", Some("e-node")));
        assert!(run(&t, "e-x").is_empty());
    }

    #[test]
    fn flags_match_whole_arguments_only() {
        assert!(arg_present("--yolo -p x", "--yolo"));
        assert!(arg_present("--yolo=true", "--yolo"));
        assert!(!arg_present("-p \"do not use --yolo\"", "--yolo"));
        assert!(!arg_present("--yolo-dry-run", "--yolo"));
    }

    #[test]
    fn toggle_is_respected() {
        let mut c = cfg();
        c.rules.ai_cli_headless = false;
        assert!(!AiCliHeadless.enabled(&c));
        assert!(AiCliHeadless.enabled(&cfg()));
    }
}
