//! `moat-x-ai-cli-headless`.
//!
//! Fills NOTES gap 1: a policy can only see one level of parent, and there is
//! no selector for "is there a terminal in this chain". Two shapes fire:
//!
//! * **headless** — an AI CLI with no **controlling terminal** on itself or
//!   any ancestor, and (as a fallback for a chain we could not read /proc for)
//!   no terminal, tmux/ssh session or editor by name either. A human did not
//!   type this. The pty comes first because a name list cannot enumerate every
//!   session host: see the note in `context.rs` about `herdr`, 2026-09-05;
//! * **auto-approved** — permission-skipping flags (`--dangerously-skip-permissions`,
//!   `--yolo`, …) while the parent is an interpreter inside a package-manager
//!   subtree. That is a postinstall script driving an agent with your keys.
//!
//! Note on shells: a bare `sh`/`bash` in the chain does *not* count as
//! interactive, because `npm` spawns one for every lifecycle script.
//!
//! Two things the first live run taught this rule:
//!
//! * **Omarchy runs agents headlessly itself.**
//!   `/usr/share/omarchy/bin/omarchy-agent-usage-*` invoke `codex` and `claude`
//!   with no terminal, which is precisely the shape being detected. Ancestors
//!   matching `ai.headless_allowed_parents` therefore silence the rule. The
//!   globs are matched against each ancestor's binary *and* its arguments,
//!   because a shebang script is reported as `binary: /usr/bin/bash` with the
//!   script path in `arguments`.
//! * **A mise shim launch is one launch, not two.** `~/.local/share/mise/shims/claude`
//!   execs `…/installs/…/bin/claude`; alerting on both would double every
//!   agent start. The shim exec is skipped and the real binary is the one that
//!   alerts, so the alert names a path you can act on.

use crate::config::Config;
use crate::event::ExecEvent;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::rules::pkgtree;
use crate::rules::{
    chain_matches_globs, meta, RuleCtx, UserRule, AI_CLIS, INTERACTIVE, INTERPRETERS, LOGIN_SHELLS,
    SKIP_PERMISSION_FLAGS,
};
use crate::util::basename;

/// `~/.local/share/mise/shims/claude`, `~/.asdf/shims/node`: a launcher that
/// immediately execs the real binary. Alerting on it as well as on what it
/// execs turns one launch into two alerts.
pub fn is_version_manager_shim(exe: &str) -> bool {
    std::path::Path::new(exe)
        .parent()
        .and_then(|p| p.file_name())
        .map(|d| d == "shims")
        .unwrap_or(false)
}

pub const ID: &str = "moat-x-ai-cli-headless";

/// Argv that belongs to a bundled search/utility tool rather than to an agent
/// launch.
///
/// Deliberately conservative, and deliberately about **flags an agent launch
/// does not take** rather than a list of tool names -- a multi-call binary can
/// grow another applet tomorrow, and this must not need updating when it does.
/// A real agent launch is `claude -p "..."`, `claude --resume <id>`, or bare;
/// none of them pass `--glob`, `--hidden`, `-e <pattern>` or `--no-config`.
fn looks_like_a_tool_invocation(args: &str) -> bool {
    const TOOL_FLAGS: &[&str] = &[
        "--glob",
        "--hidden",
        "--no-config",
        "--no-ignore",
        "--files-with-matches",
        "--line-number",
        "--max-count",
        "--type-add",
        "--binary-files",
        "--json-lines",
    ];
    args.split_whitespace().any(|t| TOOL_FLAGS.contains(&t))
}

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
        // The binary's NAME is not the invocation. Modern agent CLIs ship as
        // multi-call binaries: `claude` re-execs itself as its own bundled
        // `rg`, `ugrep` and friends, so a plain file search inside an editing
        // session arrives here as "/…/installs/claude/2.1.258/claude" with
        // ripgrep's argv. On 2026-09-04 that fired this rule roughly once a
        // minute on a machine where an agent was working -- a permanent false
        // positive on a detection whose whole job is to notice the *rare* case
        // of an agent running with nobody watching.
        //
        // Two dead allowlist entries were written before the cause was found,
        // which is the argument for fixing the discriminator rather than adding
        // a third: `parent = "*/moat-sandbox"` can never match (the script ends
        // in `exec bwrap`, so the process becomes bwrap and never appears as an
        // ancestor), and a path glob missed `/usr/bin/moatctl (deleted)` after
        // pacman replaced the binary mid-run.
        if looks_like_a_tool_invocation(&proc.args) {
            log::debug!("{}: {} is running as a bundled tool, not as an agent", ID, proc.exe);
            return Vec::new();
        }
        // The shim is about to exec the real binary; let that one speak.
        if is_version_manager_shim(&proc.exe) {
            log::debug!("{}: skipping shim exec {}", ID, proc.exe);
            return Vec::new();
        }
        if let Some(hit) = chain_matches_globs(ctx.table, exec_id, &ctx.cfg.ai.headless_allowed_parents) {
            log::debug!("{}: allowed by ai.headless_allowed_parents ({})", ID, hit);
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
        let pkg = pkgtree::pkg_root_for(ctx.table, exec_id).cloned();

        // "Is a human at the terminal" is a question the kernel already
        // answers: a controlling terminal on the agent or any ancestor means
        // somebody opened a pty. Ask that FIRST.
        //
        // The name list below is the fallback for a chain whose /proc was
        // already gone, and it is a fallback rather than the rule for the
        // reason `context.rs` gives at length: on 2026-09-05 the user's own
        // Claude sessions ran under `herdr`, a session host on nobody's list,
        // and every name-based test in this daemon read them as unattended.
        // A list of terminal names cannot be finished; `tty_nr` needs no list.
        let tty = std::iter::once(proc)
            .chain(chain.iter().copied())
            .find(|p| p.tty.is_some_and(|t| t != 0));
        // A terminal, tmux/ssh session or editor means a human is there. A bare
        // shell counts too — but only outside a package-manager subtree, since
        // npm spawns `sh` for every lifecycle script.
        let terminal = chain.iter().find(|p| INTERACTIVE.contains(&p.comm()));
        let shell = chain.iter().find(|p| LOGIN_SHELLS.contains(&p.comm()));
        let headless =
            tty.is_none() && terminal.is_none() && !(shell.is_some() && pkg.is_none());
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
                "no controlling terminal on the process or any of the {} ancestor(s) examined, and \
                 no terminal, tmux/ssh session, editor or interactive shell among them",
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
        run_with(&cfg(), table, exec_id)
    }

    fn run_with(cfg: &Config, table: &ProcTable, exec_id: &str) -> Vec<Finding> {
        let feeds = Feeds::default();
        let homes = vec!["/home/dan".to_string()];
        let ctx = RuleCtx {
            rarity: &crate::rarity::RarityStore::default(),
            cfg,
            table,
            feeds: &feeds,
            homes: &homes,
            now: 100,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
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

    /// The 2026-09-05 shape: `systemd --user -> <session host> -> bash(pts/5)
    /// -> claude`. The host is on no list of terminal names and never will be,
    /// but the shell under it holds a pty, so a person is there.
    #[test]
    fn an_agent_under_an_unknown_session_host_with_a_pty_is_not_headless() {
        for host in ["/usr/bin/herdr", "/usr/bin/some-session-host-written-last-week"] {
            let mut t = ProcTable::new(8, 60);
            t.observe(&proc("e-sd", 1457, "/usr/lib/systemd/systemd", "--user", None));
            t.observe(&proc("e-host", 10618, host, "server", Some("e-sd")));
            t.observe(&proc("e-bash", 11311, "/usr/bin/bash", "", Some("e-host")));
            t.observe(&proc("e-cli", 11536, "/usr/bin/claude", "", Some("e-bash")));
            t.set_session("e-sd", Some(1457), Some(0));
            t.set_session("e-host", Some(10618), Some(0));
            t.set_session("e-bash", Some(10618), Some(34821));
            t.set_session("e-cli", Some(10618), Some(34821));
            assert!(run(&t, "e-cli").is_empty(), "{} -> bash(pts/5) -> claude is a human", host);
        }
    }

    /// The same question with the pty as the only variable, on a chain with no
    /// shell in it for the name fallback to catch: a wrapper under a session
    /// host, with and without a terminal.
    #[test]
    fn the_controlling_terminal_is_what_decides_headless_not_the_names() {
        let build = |tty: Option<u32>| {
            let mut t = ProcTable::new(8, 60);
            t.observe(&proc("e-sd", 1457, "/usr/lib/systemd/systemd", "--user", None));
            // A host name INTERACTIVE has never heard of, so the pty is the
            // only thing that can answer.
            t.observe(&proc("e-host", 10618, "/usr/bin/hostd", "server", Some("e-sd")));
            t.observe(&proc("e-wrap", 11311, "/usr/bin/node", "wrap.js", Some("e-host")));
            t.observe(&proc("e-cli", 11536, "/usr/bin/claude", "", Some("e-wrap")));
            t.set_session("e-sd", Some(1457), Some(0));
            t.set_session("e-host", Some(10618), Some(0));
            t.set_session("e-wrap", Some(10618), tty);
            t.set_session("e-cli", Some(10618), tty);
            t
        };
        assert!(run(&build(Some(34821)), "e-cli").is_empty(), "a pty is a person");

        let f = run(&build(Some(0)), "e-cli");
        assert_eq!(f.len(), 1, "the identical chain with no pty is headless");
        assert!(f[0]
            .extra_evidence
            .iter()
            .any(|e| e.contains("no controlling terminal")));
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

    /// Omarchy's own usage reporters run `codex`/`claude` with no terminal at
    /// all — exactly the shape this rule looks for. They were the loudest false
    /// positive of the first live run.
    fn usage_reporter_chain(script: &str, cli: &str) -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-sd", 1, "/usr/lib/systemd/systemd", "", None));
        t.observe(&proc("e-script", 5000, script, "--json", Some("e-sd")));
        t.observe(&proc("e-cli", 5001, cli, "exec 'summarise'", Some("e-script")));
        t
    }

    #[test]
    fn omarchy_agent_usage_scripts_are_allowed_by_default() {
        for script in [
            "/usr/share/omarchy/bin/omarchy-agent-usage-daily",
            "/usr/share/omarchy/bin/omarchy-agent-usage-weekly",
        ] {
            let t = usage_reporter_chain(script, "/usr/bin/codex");
            assert!(run(&t, "e-cli").is_empty(), "{} must be silent by default", script);
        }

        // Empty the list and the rule fires again: this is a config allowance,
        // not a hardcoded exemption.
        let t = usage_reporter_chain(
            "/usr/share/omarchy/bin/omarchy-agent-usage-daily",
            "/usr/bin/codex",
        );
        let mut c = cfg();
        c.ai.headless_allowed_parents.clear();
        assert_eq!(run_with(&c, &t, "e-cli").len(), 1);
    }

    #[test]
    fn an_unrelated_omarchy_script_is_not_allowed() {
        let t = usage_reporter_chain("/usr/share/omarchy/bin/omarchy-update", "/usr/bin/claude");
        assert_eq!(run(&t, "e-cli").len(), 1, "only the usage reporters are allowed");
    }

    /// A mise launch is `shims/claude` -> `installs/…/bin/claude`. One alert.
    #[test]
    fn a_mise_shim_chain_yields_one_alert() {
        let mut t = table_headless();
        t.observe(&proc(
            "e-shim",
            41300,
            "/home/dan/.local/share/mise/shims/claude",
            "-p hi",
            Some("e-node"),
        ));
        t.observe(&proc(
            "e-real",
            41300,
            "/home/dan/.local/share/mise/installs/npm-anthropic-ai-claude-code/2.0.1/bin/claude",
            "-p hi",
            Some("e-shim"),
        ));
        assert!(run(&t, "e-shim").is_empty(), "the shim is not the launch");
        let f = run(&t, "e-real");
        assert_eq!(f.len(), 1);
        assert!(f[0].proc.exe.contains("/installs/"), "the alert names the real binary");
        assert!(is_version_manager_shim("/home/dan/.local/share/mise/shims/claude"));
        assert!(!is_version_manager_shim("/usr/bin/claude"));
    }

    #[test]
    fn a_bundled_search_tool_is_not_an_agent_launch() {
        // `claude` ships as a multi-call binary and re-execs itself as its own
        // `rg`, so on 2026-09-04 every file search inside an editing session
        // arrived here as a headless agent launch -- about once a minute, on a
        // rule whose whole job is to notice the rare case.
        let rg = "--no-config --hidden --glob !.git --glob !.svn -e pattern .";
        assert!(looks_like_a_tool_invocation(rg));
        assert!(looks_like_a_tool_invocation("--files-with-matches --line-number foo"));

        // Real agent launches, which must still fire.
        assert!(!looks_like_a_tool_invocation(""));
        assert!(!looks_like_a_tool_invocation("-p \"read the bundle\""));
        assert!(!looks_like_a_tool_invocation("--resume 09cac212-f91a-424d"));
        assert!(!looks_like_a_tool_invocation("--permission-mode plan -- prompt"));
        assert!(!looks_like_a_tool_invocation("--dangerously-skip-permissions"));

        // Keyed on flags an agent launch does not take, not on a list of applet
        // names -- a multi-call binary can grow another tool tomorrow and this
        // must not need updating when it does.
        assert!(!looks_like_a_tool_invocation("--hiddenish"),
                "a substring is not a flag");
        assert!(!looks_like_a_tool_invocation("--glob=x"),
                "and neither is an --opt=value spelling");

        // The honest limit: an argument that IS the bare token counts, whatever
        // it meant. `claude` handed a file literally named `--glob` would be
        // read as a tool invocation and skipped. That direction is a missed
        // detection rather than a false positive, and the alternative -- knowing
        // each applet's real argv grammar -- costs far more than the case is
        // worth.
        assert!(looks_like_a_tool_invocation("a file called --glob"));
    }

    #[test]
    fn toggle_is_respected() {
        let mut c = cfg();
        c.rules.ai_cli_headless = false;
        assert!(!AiCliHeadless.enabled(&c));
        assert!(AiCliHeadless.enabled(&cfg()));
    }
}
