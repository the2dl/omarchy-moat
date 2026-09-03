//! Context: think like a developer (BASELINE §2b).
//!
//! A developer machine executes binaries out of `$HOME` all day, spawns shells
//! from build tools constantly and compiles test programs in `/tmp`. Judging the
//! action alone produces the 500-alerts-a-day problem; judging it in its
//! **context** does not. Every process gets exactly one context from its
//! ancestry — the daemon's own `exec_id` chain, not a guess:
//!
//! | context       | roots                                                         |
//! |---------------|---------------------------------------------------------------|
//! | `pkg-install` | anything inside a package-manager subtree (`rules::pkgtree`)   |
//! | `interactive` | a terminal, tmux/zellij, an editor/IDE, an ssh login           |
//! | `service`     | systemd, a Wayland/desktop launcher, cron, a D-Bus activation  |
//! | `unknown`     | the ancestry is lost (pruned, or older than the daemon)        |
//!
//! `pkg-install` wins over `interactive` even when the install was typed at a
//! prompt: the postinstall script is the attack surface this project exists for,
//! and "I typed `npm install`" says nothing about what the package then did.
//!
//! An **AI agent CLI** is deliberately transparent. `claude` is not a root of
//! its own; the walk continues past it, so an agent started from a terminal is
//! `interactive` and the same agent started by a systemd unit is `service` —
//! which is exactly what BASELINE §2b asks for ("an AI agent CLI that itself has
//! an interactive root").

use serde::{Deserialize, Serialize};

use crate::proctable::ProcTable;
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

/// A human is driving this: terminals, multiplexers, editors and IDEs, and the
/// login paths that put a person at a prompt.
pub const INTERACTIVE_ROOTS: &[&str] = &[
    // terminals
    "alacritty", "foot", "footclient", "kitty", "ghostty", "wezterm", "wezterm-gui",
    "gnome-terminal-server", "konsole", "xterm", "urxvt", "st", "terminator", "tilix",
    // multiplexers
    "tmux", "tmux: server", "zellij", "screen", "byobu",
    // login paths
    "sshd", "login", "su", "sudo",
    // editors and IDEs
    "nvim", "vim", "vi", "hx", "helix", "emacs", "emacsclient", "kak", "micro",
    "code", "code-oss", "codium", "code-insiders", "zed", "zeditor", "sublime_text",
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

/// The one context of `exec_id`, from its exact ancestry.
pub fn classify(table: &ProcTable, exec_id: &str) -> Context {
    // A package install wins outright, however it was started.
    if pkgtree::in_pkg_subtree(table, exec_id) {
        return Context::PkgInstall;
    }
    let mut chain = Vec::new();
    if let Some(me) = table.get(exec_id) {
        chain.push(me);
    }
    chain.extend(table.ancestry(exec_id));
    // Nearest first: the closest root is the one that describes this process.
    for p in chain {
        let comm = basename(&p.exe);
        if TRANSPARENT.contains(&comm) {
            continue;
        }
        if INTERACTIVE_ROOTS.contains(&comm) {
            return Context::Interactive;
        }
        if SERVICE_ROOTS.contains(&comm) {
            return Context::Service;
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
pub fn evidence(table: &ProcTable, exec_id: &str, ctx: Context) -> String {
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
            let mut chain = Vec::new();
            if let Some(me) = table.get(exec_id) {
                chain.push(me);
            }
            chain.extend(table.ancestry(exec_id));
            let root = chain
                .iter()
                .map(|p| basename(&p.exe))
                .find(|c| {
                    !TRANSPARENT.contains(c)
                        && (INTERACTIVE_ROOTS.contains(c) || SERVICE_ROOTS.contains(c))
                })
                .unwrap_or("a desktop entry");
            format!("context: {} — root of the process chain is {}", ctx, root)
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

    fn table(rows: &[(&str, u32, &str, &str, Option<&str>)]) -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        for (id, pid, exe, args, parent) in rows {
            t.observe(&proc(id, *pid, exe, args, *parent));
        }
        t
    }

    #[test]
    fn a_terminal_root_is_interactive() {
        for term in ["/usr/bin/alacritty", "/usr/bin/ghostty", "/usr/bin/tmux", "/usr/bin/nvim"] {
            let t = table(&[
                ("e-root", 100, term, "", None),
                ("e-sh", 101, "/usr/bin/fish", "", Some("e-root")),
                ("e-node", 102, "/usr/bin/node", "x.js", Some("e-sh")),
            ]);
            assert_eq!(classify(&t, "e-node"), Context::Interactive, "{}", term);
        }
    }

    #[test]
    fn a_systemd_or_compositor_root_is_a_service() {
        for root in ["/usr/lib/systemd/systemd", "/usr/bin/Hyprland", "/usr/bin/quickshell", "/usr/bin/crond"] {
            let t = table(&[
                ("e-root", 1, root, "", None),
                ("e-node", 102, "/usr/bin/node", "server.js", Some("e-root")),
            ]);
            assert_eq!(classify(&t, "e-node"), Context::Service, "{}", root);
        }
        // A desktop-entry launch is a service too.
        let t = table(&[
            ("e-l", 200, "/usr/bin/some-launcher", "--launch app.desktop", None),
            ("e-app", 201, "/usr/bin/app", "", Some("e-l")),
        ]);
        assert_eq!(classify(&t, "e-app"), Context::Service);
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
        assert_eq!(classify(&t, "e-node"), Context::PkgInstall);
        assert_eq!(classify(&t, "e-npm"), Context::PkgInstall);
        // The shell above the install is still the person's.
        assert_eq!(classify(&t, "e-fish"), Context::Interactive);
        assert!(evidence(&t, "e-node", Context::PkgInstall).contains("never downgraded"));
    }

    #[test]
    fn an_ai_cli_is_transparent_and_inherits_its_own_root() {
        let interactive = table(&[
            ("e-term", 100, "/usr/bin/ghostty", "", None),
            ("e-fish", 101, "/usr/bin/fish", "", Some("e-term")),
            ("e-claude", 102, "/usr/bin/claude", "-p fix", Some("e-fish")),
            ("e-sh", 103, "/usr/bin/sh", "-c ls", Some("e-claude")),
        ]);
        assert_eq!(classify(&interactive, "e-sh"), Context::Interactive);

        let headless = table(&[
            ("e-sd", 1, "/usr/lib/systemd/systemd", "", None),
            ("e-claude", 102, "/usr/bin/claude", "-p fix", Some("e-sd")),
            ("e-sh", 103, "/usr/bin/sh", "-c ls", Some("e-claude")),
        ]);
        assert_eq!(classify(&headless, "e-sh"), Context::Service);
    }

    #[test]
    fn a_lost_ancestry_is_unknown_and_says_so() {
        let t = table(&[("e-lonely", 500, "/usr/bin/node", "x.js", None)]);
        assert_eq!(classify(&t, "e-lonely"), Context::Unknown);
        assert_eq!(classify(&t, "no-such-exec-id"), Context::Unknown);
        assert!(evidence(&t, "e-lonely", Context::Unknown).contains("no context adjustment"));
    }

    #[test]
    fn the_nearest_root_wins_over_a_more_distant_one() {
        // A terminal opened from the compositor is still interactive.
        let t = table(&[
            ("e-hypr", 1, "/usr/bin/Hyprland", "", None),
            ("e-term", 100, "/usr/bin/alacritty", "", Some("e-hypr")),
            ("e-fish", 101, "/usr/bin/fish", "", Some("e-term")),
        ]);
        assert_eq!(classify(&t, "e-fish"), Context::Interactive);
        assert!(evidence(&t, "e-fish", Context::Interactive).contains("alacritty"));
    }
}
