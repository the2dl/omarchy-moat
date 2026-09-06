//! Context: think like a developer (BASELINE §2b).
//!
//! A developer machine executes binaries out of `$HOME` all day, spawns shells
//! from build tools constantly and compiles test programs in `/tmp`. Judging the
//! action alone produces the 500-alerts-a-day problem; judging it in its
//! **context** does not. Every process gets exactly one context from its
//! ancestry — the daemon's own `exec_id` chain, not a guess:
//!
//! | context       | decided by                                                    |
//! |---------------|---------------------------------------------------------------|
//! | `pkg-install` | anything inside a package-manager subtree (`rules::pkgtree`)   |
//! | `interactive` | a controlling terminal on the process or any ancestor; else a name |
//! | `service`     | no pty anywhere, and a systemd/compositor/cron/D-Bus root      |
//! | `unknown`     | the ancestry is lost (pruned, or older than the daemon)        |
//!
//! **The controlling terminal is the mechanism; names are the fallback.**
//! This module used to walk the ancestry matching process NAMES against two
//! hand-maintained lists, and on 2026-09-05 that put nine of the thirteen
//! alerts on the badge in the one context BASELINE §2b never softens. The
//! user's Claude sessions run as `systemd --user (1457) -> herdr server (10618)
//! -> bash (11311, pts/5) -> claude (11536, pts/5)`. `herdr` is a session host
//! nobody's list had heard of, so the walk fell through it to `systemd` and
//! called a person typing at a prompt a `service`: a `git clone` writing a
//! vendored `.envrc` scored high instead of low, a `git rebase` of the dotfiles
//! repo touching `~/.config/systemd/user/*.service` high instead of medium, and
//! `claude`'s bundled `rg` reading `~/.config/gh/hosts.yml` high instead of
//! medium.
//!
//! Adding `herdr` to the list would have fixed that one host. The next one —
//! `zellij`, an ssh jump box, a tool written last week — would fail exactly the
//! same way and fail silently, which makes a name list a to-do list rather than
//! a design. `chain.rs::is_boundary` had already learned this on 2026-09-04 and
//! switched to the kernel's `sid == pid`; this module kept its own list and got
//! neither fix. The kernel records `tty_nr` on the same /proc line as `sid`, so
//! the general question — *is there a pty at the other end of this?* — costs
//! nothing extra to ask, and it is right for every terminal, multiplexer,
//! session host and `ssh` login that will ever exist.
//!
//! It also preserves what the ancestry walk got right by accident: a `setsid`
//! or `nohup` launched from a terminal keeps the pty it inherited, so the
//! user's own backgrounded work stays `interactive`.
//!
//! `pkg-install` wins over `interactive` even when the install was typed at a
//! prompt: the postinstall script is the attack surface this project exists for,
//! and "I typed `npm install`" says nothing about what the package then did.
//!
//! An **AI agent CLI** is deliberately transparent to the *name* walk. `claude`
//! is not a root of its own; the walk continues past it, so an agent started
//! from a terminal is `interactive` and the same agent started by a systemd
//! unit is `service` — which is exactly what BASELINE §2b asks for ("an AI
//! agent CLI that itself has an interactive root").
//!
//! **A pty is not proof of a human**, and this module does not pretend
//! otherwise. `python -c 'import pty; pty.spawn("/bin/bash")'` is the first
//! thing an attacker types after a reverse shell lands. The name walk had the
//! identical hole (a payload can `exec -a alacritty`), the honest claim is
//! "cheap, general and right about developer traffic", and the mitigations sit
//! elsewhere: context never takes `cred` below the timeline, never touches the
//! `shell` family, and `chain.rs` ignores context entirely.

use serde::{Deserialize, Serialize};

use crate::config::ContextConfig;
use crate::proctable::{ProcInfo, ProcTable};
use crate::rules::pkgtree;
use crate::util::basename;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Context {
    Interactive,
    PkgInstall,
    Service,
    /// The ancestry is lost: no context adjustment is applied.
    #[default]
    Unknown,
}

impl Context {
    pub fn as_str(self) -> &'static str {
        match self {
            Context::Interactive => "interactive",
            Context::PkgInstall => "pkg-install",
            Context::Service => "service",
            Context::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The names `rules::INTERACTIVE` does not carry.
///
/// There is exactly one list of interactive names in this daemon and it lives
/// in `rules::INTERACTIVE`, shared with `chain::is_boundary` and
/// `moat-x-ai-cli-headless`, because two lists answering the same question
/// drift and only one of them gets fixed — which is what happened to `herdr`.
///
/// This extension stays separate rather than being merged into that list
/// because the questions are not identical. "Is a person driving this?" is true
/// of `sudo` and of an IDE; "is this the root of a story?" is not. Merging them
/// would make every `sudo` a chain boundary and re-root every alert tree
/// beneath one, which is a behaviour change nobody asked for.
pub const INTERACTIVE_EXTRA: &[&str] = &[
    // terminals and multiplexers the shared list does not name
    "footclient", "terminator", "tilix", "zellij", "byobu",
    // privilege transitions: still a person, at a prompt
    "su", "sudo",
    // editors and IDEs
    "vi", "hx", "helix", "emacsclient", "kak", "micro",
    "code-insiders", "zeditor", "sublime_text",
    "idea", "pycharm", "goland", "webstorm", "clion", "rustrover", "phpstorm", "rubymine",
    "datagrip", "jetbrains-toolbox", "studio",
];

/// Started without a human at a prompt. This is where persistence lives, which
/// is why `service` never earns a downgrade.
pub const SERVICE_ROOTS: &[&str] = &[
    "systemd", "systemd-user", "init",
    "Hyprland", "hyprland", "quickshell", "uwsm", "hyprctl", "waybar", "sway", "river",
    "gdm", "gdm-session-worker", "sddm", "sddm-helper", "greetd", "ly", "lightdm",
    "cron", "crond", "anacron", "atd", "fcron",
    "dbus-daemon", "dbus-broker", "dbus-broker-launch", "xdg-desktop-portal",
    "gio-launch-desktop", "xdg-open", "plasmashell", "gnome-shell",
    "containerd", "dockerd", "podman", "supervisord", "runit", "s6-supervise",
];

/// An AI agent CLI is transparent: it inherits whatever root is above it.
pub const TRANSPARENT: &[&str] = &["claude", "codex", "gemini", "opencode", "amp", "q", "aider"];

/// What this NAME says, if anything.
///
/// The user's own `[context]` lists come first because they are an override:
/// a name the machine's owner has declared a service must not be out-voted by
/// a built-in default that happens to disagree.
fn name_context(comm: &str, cfg: &ContextConfig) -> Option<Context> {
    if cfg.interactive_roots.iter().any(|n| n == comm) {
        return Some(Context::Interactive);
    }
    if cfg.service_roots.iter().any(|n| n == comm) {
        return Some(Context::Service);
    }
    if crate::rules::INTERACTIVE.contains(&comm) || INTERACTIVE_EXTRA.contains(&comm) {
        return Some(Context::Interactive);
    }
    if SERVICE_ROOTS.contains(&comm) {
        return Some(Context::Service);
    }
    None
}

#[cfg(test)]
fn is_interactive_name(comm: &str, cfg: &ContextConfig) -> bool {
    name_context(comm, cfg) == Some(Context::Interactive)
}

/// The acting process and its (capped) ancestry, nearest first.
fn chain_of<'a>(table: &'a ProcTable, exec_id: &str) -> Vec<&'a ProcInfo> {
    let mut chain = Vec::new();
    if let Some(me) = table.get(exec_id) {
        chain.push(me);
    }
    chain.extend(table.ancestry(exec_id));
    chain
}

/// The nearest process in the chain that holds a controlling terminal.
///
/// `tty == None` means /proc was already gone when we looked, not "no tty";
/// `Some(0)` is the kernel saying there is none. Only a non-zero device is a
/// pty, and a pty means somebody opened one.
fn tty_holder<'a>(chain: &[&'a ProcInfo]) -> Option<(&'a ProcInfo, u32)> {
    chain
        .iter()
        .find_map(|p| p.tty.filter(|t| *t != 0).map(|t| (*p, t)))
}

/// The one context of `exec_id`, from its exact ancestry.
///
/// Decision order, and the order is the design:
///
/// 1. inside a package-manager subtree -> `pkg-install`, outright;
/// 2. a controlling terminal on the acting process or ANY ancestor within the
///    capped chain -> `interactive`;
/// 3. the name walk, nearest ancestor first, for the processes whose /proc was
///    already gone — transparent names skipped, interactive names, service
///    names, then the `.desktop` argument heuristic;
/// 4. `unknown`.
pub fn classify(table: &ProcTable, exec_id: &str, cfg: &ContextConfig) -> Context {
    // A package install wins outright, however it was started.
    if pkgtree::in_pkg_subtree(table, exec_id) {
        return Context::PkgInstall;
    }
    let chain = chain_of(table, exec_id);
    // The kernel's own answer, and the only one that generalises: a person is
    // at the other end of that pty, whatever program allocated it.
    if tty_holder(&chain).is_some() {
        return Context::Interactive;
    }
    // Nearest first: the closest root is the one that describes this process.
    // This is the fallback for a chain we could not read /proc for (the
    // processes had exited), exactly as `chain::is_boundary` falls back.
    for p in chain {
        let comm = basename(&p.exe);
        if TRANSPARENT.contains(&comm) {
            continue;
        }
        if let Some(ctx) = name_context(comm, cfg) {
            return ctx;
        }
        // A desktop entry is launched by the shell's launcher, which shows up
        // as `<something> --desktop <app>.desktop` more often than as a binary.
        if p.args.split_whitespace().any(|a| a.ends_with(".desktop")) {
            return Context::Service;
        }
    }
    Context::Unknown
}

/// The evidence line naming *why* this context was chosen.
///
/// It has to name the actual fact, not the conclusion: "root of the process
/// chain is systemd" was true of every Claude session on this machine and told
/// the user nothing about why their own typing had been called a service.
pub fn evidence(table: &ProcTable, exec_id: &str, ctx: Context, cfg: &ContextConfig) -> String {
    match ctx {
        Context::PkgInstall => match pkgtree::pkg_root_with_reason(table, exec_id) {
            Some((root, why)) => format!(
                "context: pkg-install — inside a `{}` subtree (matched on {}); a package install \
                 is never downgraded",
                root.comm(),
                why
            ),
            None => "context: pkg-install".to_string(),
        },
        Context::Interactive | Context::Service => {
            let chain = chain_of(table, exec_id);
            let root = chain
                .iter()
                .map(|p| basename(&p.exe))
                .find(|c| !TRANSPARENT.contains(c) && name_context(c, cfg).is_some())
                .unwrap_or("a desktop entry");
            match (ctx, tty_holder(&chain)) {
                (Context::Interactive, Some((p, tty))) => format!(
                    "context: interactive — pid {} ({}) has a controlling terminal (tty {})",
                    p.pid,
                    p.comm(),
                    tty
                ),
                // Only claim the absence when we actually read /proc for
                // somebody: an all-`None` chain means the processes had exited,
                // not that there was no pty.
                (Context::Service, _) if chain.iter().any(|p| p.tty.is_some()) => format!(
                    "context: service — no controlling terminal anywhere in the chain; root is {}",
                    root
                ),
                _ => format!("context: {} — root of the process chain is {}", ctx, root),
            }
        }
        Context::Unknown => {
            "context: unknown — the ancestry does not reach a terminal, a package manager or a \
             service manager, so no context adjustment was applied"
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::testkit::proc;

    fn dflt() -> ContextConfig {
        ContextConfig::default()
    }

    /// A row as the kernel reports it: id, pid, exe, args, parent, sid, tty.
    type Row<'a> = (&'a str, u32, &'a str, &'a str, Option<&'a str>, Option<u32>, Option<u32>);

    /// Every row states its own sid and tty, because `observe` reads them from
    /// the real /proc and the fixture pids belong to whatever happens to be
    /// running on the machine under test.
    fn table_tty(rows: &[Row]) -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        for (id, pid, exe, args, parent, sid, tty) in rows {
            t.observe(&proc(id, *pid, exe, args, *parent));
            t.set_session(id, *sid, *tty);
        }
        t
    }

    /// A chain moat could not read /proc for at all: every tty is `None`, so
    /// only the name walk can answer.
    fn table(rows: &[(&str, u32, &str, &str, Option<&str>)]) -> ProcTable {
        let rows: Vec<Row> = rows
            .iter()
            .map(|(id, pid, exe, args, parent)| (*id, *pid, *exe, *args, *parent, None, None))
            .collect();
        table_tty(&rows)
    }

    /// The shape measured on this machine on 2026-09-05, with the pids and the
    /// pty the kernel actually reported:
    /// `systemd --user -> herdr (sid == pid, tty 0) -> bash (pts/5) -> claude
    /// -> bash -> git`.
    ///
    /// `session_host` is the name of the thing between systemd and the shell.
    /// It is a parameter on purpose: the point of this fix is that the name
    /// must not matter.
    fn herdr_shape(session_host: &str, tty: Option<u32>) -> ProcTable {
        let host_exe = format!("/usr/bin/{}", session_host);
        table_tty(&[
            ("e-sd", 1457, "/usr/lib/systemd/systemd", "--user", None, Some(1457), Some(0)),
            (
                "e-host",
                10618,
                &host_exe,
                "server",
                Some("e-sd"),
                Some(10618),
                Some(0),
            ),
            ("e-bash", 11311, "/usr/bin/bash", "", Some("e-host"), Some(10618), tty),
            ("e-claude", 11536, "/usr/bin/claude", "", Some("e-bash"), Some(10618), tty),
            ("e-bash2", 11540, "/usr/bin/bash", "-c git", Some("e-claude"), Some(10618), tty),
            ("e-git", 11541, "/usr/bin/git", "clone https://x", Some("e-bash2"), Some(10618), tty),
        ])
    }

    /// (a) The bug this fix exists for. A session host moat has never heard of
    /// sits between systemd and the user's shell; the shell has a pty, so the
    /// person at the other end of it is what decides the context.
    #[test]
    fn a_pty_anywhere_in_the_chain_is_a_person_whatever_opened_it() {
        for host in ["herdr", "some-session-host-written-last-week", "mprocs"] {
            let t = herdr_shape(host, Some(34821));
            assert_eq!(
                classify(&t, "e-git", &dflt()),
                Context::Interactive,
                "{} -> bash(pts/5) -> claude -> git is a person typing",
                host
            );
            // Nearest holder first: the git process itself.
            let ev = evidence(&t, "e-git", Context::Interactive, &dflt());
            assert!(ev.contains("controlling terminal (tty 34821)"), "{}", ev);
            assert!(ev.contains("pid 11541 (git)"), "{}", ev);
        }
        // And the bash under the host, named as itself.
        let t = herdr_shape("herdr", Some(34821));
        let ev = evidence(&t, "e-bash", Context::Interactive, &dflt());
        assert!(ev.contains("pid 11311 (bash) has a controlling terminal (tty 34821)"), "{}", ev);
    }

    /// (b) The same agent with no pty anywhere is still a service, which is
    /// what BASELINE §2b asks for and what the old name walk got right.
    #[test]
    fn an_agent_under_systemd_with_no_pty_is_still_a_service() {
        let t = table_tty(&[
            ("e-sd", 1, "/usr/lib/systemd/systemd", "", None, Some(1), Some(0)),
            ("e-claude", 102, "/usr/bin/claude", "-p fix", Some("e-sd"), Some(102), Some(0)),
            ("e-sh", 103, "/usr/bin/sh", "-c ls", Some("e-claude"), Some(102), Some(0)),
        ]);
        assert_eq!(classify(&t, "e-sh", &dflt()), Context::Service);
        let ev = evidence(&t, "e-sh", Context::Service, &dflt());
        assert!(ev.contains("no controlling terminal anywhere in the chain"), "{}", ev);
        assert!(ev.contains("root is systemd"), "{}", ev);
    }

    /// (c) A compositor plugin: `quickshell` reported tty 0 on this machine.
    #[test]
    fn a_compositor_child_has_no_pty_and_is_a_service() {
        let t = table_tty(&[
            ("e-qs", 2100, "/usr/bin/quickshell", "", None, Some(2100), Some(0)),
            ("e-plug", 2101, "/usr/bin/bash", "plugin.sh", Some("e-qs"), Some(2100), Some(0)),
        ]);
        assert_eq!(classify(&t, "e-plug", &dflt()), Context::Service);
    }

    /// (d) The fallback: nothing left to read /proc for, so the names decide,
    /// exactly as they did before.
    #[test]
    fn a_chain_with_no_tty_information_falls_back_to_the_names() {
        let t = table(&[
            ("e-term", 100, "/usr/bin/alacritty", "", None),
            ("e-sh", 101, "/usr/bin/fish", "", Some("e-term")),
            ("e-node", 102, "/usr/bin/node", "x.js", Some("e-sh")),
        ]);
        assert_eq!(classify(&t, "e-node", &dflt()), Context::Interactive);
        let ev = evidence(&t, "e-node", Context::Interactive, &dflt());
        assert!(ev.contains("root of the process chain is alacritty"), "{}", ev);
    }

    /// (f) The escape hatch, for a session host moat cannot see a tty through.
    #[test]
    fn a_configured_interactive_root_answers_when_the_tty_cannot() {
        // `herdr` itself needs no config: it reached this module through
        // `rules::INTERACTIVE`, which is the point of sharing that list.
        assert_eq!(classify(&herdr_shape("herdr", None), "e-git", &dflt()), Context::Interactive);

        // The next host, though, is on no list — and with no pty to read there
        // is nothing else to go on, so it falls through to systemd.
        let t = herdr_shape("hostd", None);
        assert_eq!(classify(&t, "e-git", &dflt()), Context::Service, "no pty, no name: systemd wins");

        let cfg = ContextConfig {
            interactive_roots: vec!["hostd".into()],
            ..Default::default()
        };
        assert_eq!(classify(&t, "e-git", &cfg), Context::Interactive);
        assert!(evidence(&t, "e-git", Context::Interactive, &cfg)
            .contains("root of the process chain is hostd"));

        // And the mirror: a name that would otherwise read as interactive can
        // be declared a service.
        let t2 = table(&[
            ("e-x", 300, "/usr/bin/studio", "--headless", None),
            ("e-sh", 301, "/usr/bin/sh", "-c build", Some("e-x")),
        ]);
        assert_eq!(classify(&t2, "e-sh", &dflt()), Context::Interactive);
        let cfg2 = ContextConfig { service_roots: vec!["studio".into()], ..Default::default() };
        assert_eq!(classify(&t2, "e-sh", &cfg2), Context::Service);
    }

    /// The one list. `herdr` reached this module through `rules::INTERACTIVE`
    /// rather than through a copy of it, and `sudo` did NOT reach `chain.rs`.
    #[test]
    fn the_interactive_names_are_the_shared_list_plus_a_context_only_extension() {
        assert!(is_interactive_name("herdr", &dflt()), "the shared list is consulted");
        assert!(is_interactive_name("alacritty", &dflt()));
        assert!(is_interactive_name("sudo", &dflt()), "the extension is consulted");
        assert!(is_interactive_name("zellij", &dflt()));
        assert!(!is_interactive_name("systemd", &dflt()));
        // The extension must stay OUT of the shared list: adding `sudo` there
        // would make every `sudo` a chain boundary and re-root the stories
        // under it.
        for name in INTERACTIVE_EXTRA {
            assert!(
                !crate::rules::INTERACTIVE.contains(name),
                "{} is in both lists; one of them is now dead code",
                name
            );
        }
    }

    #[test]
    fn a_terminal_root_is_interactive() {
        for term in ["/usr/bin/alacritty", "/usr/bin/ghostty", "/usr/bin/tmux", "/usr/bin/nvim"] {
            let t = table(&[
                ("e-root", 100, term, "", None),
                ("e-sh", 101, "/usr/bin/fish", "", Some("e-root")),
                ("e-node", 102, "/usr/bin/node", "x.js", Some("e-sh")),
            ]);
            assert_eq!(classify(&t, "e-node", &dflt()), Context::Interactive, "{}", term);
        }
    }

    #[test]
    fn a_systemd_or_compositor_root_is_a_service() {
        for root in ["/usr/lib/systemd/systemd", "/usr/bin/Hyprland", "/usr/bin/quickshell", "/usr/bin/crond"] {
            let t = table(&[
                ("e-root", 1, root, "", None),
                ("e-node", 102, "/usr/bin/node", "server.js", Some("e-root")),
            ]);
            assert_eq!(classify(&t, "e-node", &dflt()), Context::Service, "{}", root);
        }
        // A desktop-entry launch is a service too.
        let t = table(&[
            ("e-l", 200, "/usr/bin/some-launcher", "--launch app.desktop", None),
            ("e-app", 201, "/usr/bin/app", "", Some("e-l")),
        ]);
        assert_eq!(classify(&t, "e-app", &dflt()), Context::Service);
    }

    #[test]
    fn a_package_install_wins_over_the_terminal_it_was_typed_in() {
        let t = table(&[
            ("e-term", 100, "/usr/bin/alacritty", "", None),
            ("e-fish", 101, "/usr/bin/fish", "", Some("e-term")),
            ("e-npm", 102, "/usr/bin/npm", "install", Some("e-fish")),
            ("e-sh", 103, "/usr/bin/sh", "-c postinstall", Some("e-npm")),
            ("e-node", 104, "/usr/bin/node", "postinstall.js", Some("e-sh")),
        ]);
        assert_eq!(classify(&t, "e-node", &dflt()), Context::PkgInstall);
        assert_eq!(classify(&t, "e-npm", &dflt()), Context::PkgInstall);
        // The shell above the install is still the person's.
        assert_eq!(classify(&t, "e-fish", &dflt()), Context::Interactive);
        assert!(evidence(&t, "e-node", Context::PkgInstall, &dflt()).contains("never downgraded"));

        // (e) And a pty does not change that. `npm install` typed at a prompt
        // leaves the pty on every process of the install, which is exactly the
        // case BASELINE §2b refuses to soften: the postinstall script is the
        // attack surface, and "I typed it" says nothing about what it did.
        let t = table_tty(&[
            ("e-term", 100, "/usr/bin/alacritty", "", None, Some(100), Some(34821)),
            ("e-fish", 101, "/usr/bin/fish", "", Some("e-term"), Some(100), Some(34821)),
            ("e-npm", 102, "/usr/bin/npm", "install", Some("e-fish"), Some(100), Some(34821)),
            ("e-sh", 103, "/usr/bin/sh", "-c post", Some("e-npm"), Some(100), Some(34821)),
            ("e-node", 104, "/usr/bin/node", "post.js", Some("e-sh"), Some(100), Some(34821)),
        ]);
        assert_eq!(classify(&t, "e-node", &dflt()), Context::PkgInstall);
        assert_eq!(classify(&t, "e-fish", &dflt()), Context::Interactive);
    }

    #[test]
    fn an_ai_cli_is_transparent_and_inherits_its_own_root() {
        let interactive = table(&[
            ("e-term", 100, "/usr/bin/ghostty", "", None),
            ("e-fish", 101, "/usr/bin/fish", "", Some("e-term")),
            ("e-claude", 102, "/usr/bin/claude", "-p fix", Some("e-fish")),
            ("e-sh", 103, "/usr/bin/sh", "-c ls", Some("e-claude")),
        ]);
        assert_eq!(classify(&interactive, "e-sh", &dflt()), Context::Interactive);

        let headless = table(&[
            ("e-sd", 1, "/usr/lib/systemd/systemd", "", None),
            ("e-claude", 102, "/usr/bin/claude", "-p fix", Some("e-sd")),
            ("e-sh", 103, "/usr/bin/sh", "-c ls", Some("e-claude")),
        ]);
        assert_eq!(classify(&headless, "e-sh", &dflt()), Context::Service);
    }

    #[test]
    fn a_lost_ancestry_is_unknown_and_says_so() {
        let t = table(&[("e-lonely", 500, "/usr/bin/node", "x.js", None)]);
        assert_eq!(classify(&t, "e-lonely", &dflt()), Context::Unknown);
        assert_eq!(classify(&t, "no-such-exec-id", &dflt()), Context::Unknown);
        assert!(evidence(&t, "e-lonely", Context::Unknown, &dflt()).contains("no context adjustment"));

        // (g) A process the kernel told us about, whose ancestry is gone and
        // which holds no pty, is still unknown — not a service. `unknown`
        // applies no adjustment at all, which is the honest answer.
        let t = table_tty(&[("e-orphan", 500, "/usr/bin/node", "x.js", None, Some(500), Some(0))]);
        assert_eq!(classify(&t, "e-orphan", &dflt()), Context::Unknown);
    }

    #[test]
    fn the_nearest_root_wins_over_a_more_distant_one() {
        // A terminal opened from the compositor is still interactive.
        let t = table(&[
            ("e-hypr", 1, "/usr/bin/Hyprland", "", None),
            ("e-term", 100, "/usr/bin/alacritty", "", Some("e-hypr")),
            ("e-fish", 101, "/usr/bin/fish", "", Some("e-term")),
        ]);
        assert_eq!(classify(&t, "e-fish", &dflt()), Context::Interactive);
        assert!(evidence(&t, "e-fish", Context::Interactive, &dflt()).contains("alacritty"));
    }
}
