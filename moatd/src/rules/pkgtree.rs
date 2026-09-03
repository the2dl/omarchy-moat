//! Package-manager subtree classifier.
//!
//! The first live run killed the kernel-side version of this idea. Tetragon's
//! `matchParentBinaries` with `followChildren: true` matched processes that had
//! no package manager anywhere in their ancestry at all — `quickshell -> bash`,
//! `Xwayland -> bash`, `make` under `cmake` — because the parents map is keyed
//! by binary and is inherited far more widely than the name suggests
//! (TETRAGON-NOTES §6). The four `pkg` kernel policies were deleted; this module
//! is what replaces them.
//!
//! `process_exec` is always exported (line 1 of the export-allowlist), so the
//! daemon can decide "is this process inside a package install?" itself, from
//! the `exec_id`-keyed process table, with **exact** ancestry and the real argv.
//!
//! A process is a package-manager **root** when either:
//!
//! * its binary basename is one of [`PKG_ROOT_BINARIES`] — this is what catches
//!   `npm`, a mise shim (`~/.local/share/mise/shims/npm`) and the real binary it
//!   execs (`…/installs/node/*/bin/npm`) alike; or
//! * its arguments carry one of the markers below — this is what catches the
//!   shape that actually shows up in the export, where the binary is `node` and
//!   the package manager is a script it was handed:
//!   `node …/npm/bin/npm-cli.js install`.
//!
//! Every descendant inherits the flag; [`pkg_root_for`] hands back the
//! **outermost** root in the chain, so one `npm install` has one identity no
//! matter how many nested `npm`/`node` frames sit under it.
//!
//! Markers are matched per path segment, never as a bare substring: a
//! `pnpm-lock.yaml` on the command line is not a `pnpm` invocation.

use crate::proctable::{ProcInfo, ProcTable};
use crate::util::basename;

/// A process whose binary is one of these *is* a package-manager root.
pub const PKG_ROOT_BINARIES: &[&str] = &[
    "npm", "npx", "pnpm", "yarn", "bun", "corepack", "pip", "pip3", "uv", "poetry", "pipx",
    "cargo", "makepkg", "yay", "paru",
];

/// Script names that mean "this interpreter is running a package manager".
/// Matched against the basename of each argument token.
const SCRIPT_MARKERS: &[&str] = &["npm-cli.js", "npx-cli.js", "yarn.js"];

/// Tool names that mean a package manager even when they are an argument
/// (`bash /usr/bin/makepkg`, `node …/pnpm/bin/pnpm.cjs`). Matched against the
/// argument's basename with a script extension stripped.
const BARE_MARKERS: &[&str] = &["pnpm", "makepkg"];

/// `tool subcommand` markers: the tool must appear (as the binary or as an
/// argument) and the first following non-flag word must be one of `subs`.
struct Verb {
    tool: &'static str,
    subs: &'static [&'static str],
}

const VERB_MARKERS: &[Verb] = &[
    Verb {
        tool: "bun",
        subs: &["install", "add", "x"],
    },
    Verb {
        tool: "pip",
        subs: &["install"],
    },
    Verb {
        tool: "pip3",
        subs: &["install"],
    },
    Verb {
        tool: "uv",
        subs: &["pip", "sync", "add", "run", "tool"],
    },
    Verb {
        tool: "cargo",
        subs: &["build", "install", "run", "test", "add", "fetch", "update"],
    },
];

/// `…/node_modules/pnpm/bin/pnpm.cjs` -> `pnpm`; `/usr/bin/npm` -> `npm`.
fn tool_name(token: &str) -> &str {
    let base = basename(token);
    for ext in [".js", ".cjs", ".mjs", ".py"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem;
        }
    }
    base
}

/// Why this process counts as a package-manager root, or `None`.
///
/// The string is evidence text, so it names the thing that matched.
pub fn root_reason(exe: &str, args: &str) -> Option<String> {
    let comm = basename(exe);
    if PKG_ROOT_BINARIES.contains(&comm) {
        return Some(format!("binary basename `{}`", comm));
    }

    let toks: Vec<&str> = args.split_whitespace().collect();
    for m in SCRIPT_MARKERS {
        if toks.iter().any(|t| basename(t) == *m) {
            return Some(format!("argument `{}`", m));
        }
    }
    for m in BARE_MARKERS {
        if toks.iter().any(|t| tool_name(t) == *m) {
            return Some(format!("argument `{}`", m));
        }
    }
    for v in VERB_MARKERS {
        // The tool is either the binary itself (subcommand starts at argv[0] of
        // `arguments`, which excludes argv[0] of the process) or an argument.
        let start = if tool_name(exe) == v.tool {
            Some(0usize)
        } else {
            toks.iter().position(|t| tool_name(t) == v.tool).map(|i| i + 1)
        };
        let Some(start) = start else { continue };
        if let Some(sub) = toks[start..].iter().find(|t| !t.starts_with('-')) {
            if v.subs.contains(sub) {
                return Some(format!("arguments `{} {}`", v.tool, sub));
            }
        }
    }
    None
}

/// Is this single process a package-manager root?
pub fn is_pkg_root(p: &ProcInfo) -> bool {
    root_reason(&p.exe, &p.args).is_some()
}

/// The outermost package-manager root at or above `exec_id`, with the reason it
/// matched. `None` means "not inside a package install".
pub fn pkg_root_with_reason<'a>(
    table: &'a ProcTable,
    exec_id: &str,
) -> Option<(&'a ProcInfo, String)> {
    let mut best: Option<(&ProcInfo, String)> = None;
    if let Some(me) = table.get(exec_id) {
        if let Some(r) = root_reason(&me.exe, &me.args) {
            best = Some((me, r));
        }
    }
    // Nearest ancestor first, so the last hit is the outermost one.
    for p in table.ancestry(exec_id) {
        if let Some(r) = root_reason(&p.exe, &p.args) {
            best = Some((p, r));
        }
    }
    best
}

/// The outermost package-manager root at or above `exec_id`.
pub fn pkg_root_for<'a>(table: &'a ProcTable, exec_id: &str) -> Option<&'a ProcInfo> {
    pkg_root_with_reason(table, exec_id).map(|(p, _)| p)
}

/// Is `exec_id` inside a package-manager subtree (root included)?
pub fn in_pkg_subtree(table: &ProcTable, exec_id: &str) -> bool {
    pkg_root_for(table, exec_id).is_some()
}

/// The evidence line every pkg-subtree rule shares.
pub fn root_evidence(root: &ProcInfo, reason: &str) -> String {
    format!(
        "package-manager subtree root: {} pid {}{} (matched on {})",
        root.exe,
        root.pid,
        if root.args.is_empty() {
            String::new()
        } else {
            format!(" args {}", root.args)
        },
        reason
    )
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
    fn a_binary_basename_makes_a_root() {
        for exe in ["/usr/bin/npm", "/usr/bin/cargo", "/usr/bin/makepkg", "/usr/bin/yay"] {
            assert!(root_reason(exe, "install").is_some(), "{}", exe);
        }
        assert!(root_reason("/usr/bin/bash", "-c ls").is_none());
    }

    #[test]
    fn npm_invoked_through_node_is_a_root() {
        // The real shape in the export: the binary is node, npm is a script.
        let r = root_reason(
            "/home/dan/.local/share/mise/installs/node/26.5.0/bin/node",
            "/home/dan/.local/share/mise/installs/node/26.5.0/lib/node_modules/npm/bin/npm-cli.js install",
        );
        assert_eq!(r.as_deref(), Some("argument `npm-cli.js`"));

        let t = table(&[
            ("e-term", 41100, "/usr/bin/alacritty", "", None),
            ("e-fish", 41101, "/usr/bin/fish", "", Some("e-term")),
            (
                "e-npm",
                41201,
                "/usr/bin/node",
                "/usr/lib/node_modules/npm/bin/npm-cli.js install",
                Some("e-fish"),
            ),
            ("e-sh", 41240, "/usr/bin/sh", "-c node-gyp rebuild", Some("e-npm")),
            ("e-node", 41250, "/usr/bin/node", "install.js", Some("e-sh")),
        ]);
        let (root, why) = pkg_root_with_reason(&t, "e-node").unwrap();
        assert_eq!(root.pid, 41201);
        assert!(why.contains("npm-cli.js"));
        assert!(in_pkg_subtree(&t, "e-sh"));
    }

    #[test]
    fn a_mise_shim_and_the_binary_it_execs_are_both_roots_and_the_outermost_wins() {
        let t = table(&[
            ("e-fish", 41101, "/usr/bin/fish", "", None),
            (
                "e-shim",
                41200,
                "/home/dan/.local/share/mise/shims/npm",
                "install",
                Some("e-fish"),
            ),
            (
                "e-real",
                41201,
                "/home/dan/.local/share/mise/installs/node/26.5.0/bin/npm",
                "install",
                Some("e-shim"),
            ),
            ("e-node", 41250, "/usr/bin/node", "postinstall.js", Some("e-real")),
        ]);
        assert!(is_pkg_root(t.get("e-shim").unwrap()));
        assert!(is_pkg_root(t.get("e-real").unwrap()));
        // The shim is the outermost frame, so every descendant shares one root.
        assert_eq!(pkg_root_for(&t, "e-node").unwrap().pid, 41200);
        assert_eq!(pkg_root_for(&t, "e-real").unwrap().pid, 41200);
        assert_eq!(pkg_root_for(&t, "e-shim").unwrap().pid, 41200);
    }

    #[test]
    fn a_plain_shell_under_a_terminal_is_not_a_subtree() {
        let t = table(&[
            ("e-term", 41100, "/usr/bin/alacritty", "", None),
            ("e-bash", 41101, "/usr/bin/bash", "", Some("e-term")),
            ("e-vim", 41102, "/usr/bin/nvim", "notes.md", Some("e-bash")),
        ]);
        assert!(pkg_root_for(&t, "e-bash").is_none());
        assert!(pkg_root_for(&t, "e-vim").is_none());
        assert!(!in_pkg_subtree(&t, "e-vim"));
    }

    #[test]
    fn the_shapes_that_broke_the_kernel_policy_stay_quiet() {
        // quickshell -> bash and Xwayland -> bash both matched
        // matchParentBinaries followChildren with no package manager in sight.
        let t = table(&[
            ("e-qs", 900, "/usr/bin/quickshell", "-c omarchy", None),
            ("e-bash", 901, "/usr/bin/bash", "-c 'omarchy-cmd'", Some("e-qs")),
            ("e-x", 910, "/usr/bin/Xwayland", ":0", None),
            ("e-bash2", 911, "/usr/bin/bash", "-c xdg-open", Some("e-x")),
            ("e-cmake", 920, "/usr/bin/cmake", "--build .", None),
            ("e-make", 921, "/usr/bin/make", "-j8", Some("e-cmake")),
            ("e-cc", 922, "/usr/bin/cc", "-c foo.c", Some("e-make")),
        ]);
        for id in ["e-bash", "e-bash2", "e-make", "e-cc"] {
            assert!(pkg_root_for(&t, id).is_none(), "{} must not be in a pkg subtree", id);
        }
    }

    #[test]
    fn verb_markers_need_the_tool_and_the_subcommand() {
        assert!(root_reason("/usr/bin/python3", "-m pip install requests").is_some());
        assert!(root_reason("/usr/bin/python3", "-m pip list").is_none());
        assert!(root_reason("/usr/bin/env", "uv run main.py").is_some());
        assert!(root_reason("/usr/bin/env", "uv --help").is_none());
        assert!(root_reason("/usr/bin/sh", "-c 'cargo build --release'").is_none(),
            "a quoted command line is one token; the exec of cargo itself is what fires");
        assert!(root_reason("/usr/bin/bash", "/usr/bin/makepkg -si").is_some());
    }

    #[test]
    fn a_lockfile_argument_is_not_an_invocation() {
        assert!(root_reason("/usr/bin/git", "diff -- pnpm-lock.yaml").is_none());
        assert!(root_reason("/usr/bin/cat", "/home/dan/proj/pnpm-lock.yaml").is_none());
        assert!(root_reason("/usr/bin/node", "/usr/lib/node_modules/pnpm/bin/pnpm.cjs add left-pad").is_some());
    }
}
