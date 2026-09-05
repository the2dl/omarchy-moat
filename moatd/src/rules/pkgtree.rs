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
///
/// Being on this list is what gives a process tree `pkg-install` context, and
/// that context is load-bearing: BASELINE §2b escalates on it and never
/// downgrades inside it, `moat-x-pkg-egress` only fires inside it, and every
/// `moat-pkg-subtree-*` rule requires it. An ecosystem missing from here is not
/// detected weakly — its postinstall scripts get no install context at all, so
/// those rules structurally cannot fire.
///
/// Only tools whose *every* invocation fetches or builds third-party code
/// belong here unconditionally. Anything used routinely for non-install work
/// (`go run`, `dotnet build`) is verb-gated in `VERB_MARKERS` instead, so a
/// developer compiling their own code is not permanently inside an install.
pub const PKG_ROOT_BINARIES: &[&str] = &[
    // JavaScript / TypeScript
    "npm", "npx", "pnpm", "yarn", "bun", "corepack",
    // Python
    "pip", "pip3", "uv", "poetry", "pipx",
    // Rust
    "cargo",
    // Arch / AUR
    "makepkg", "yay", "paru",
    // Perl: cpanm and cpan only ever install, and both run the distribution's
    // own Makefile.PL/Build.PL as root of the build.
    "cpanm", "cpan",
    // JVM: a Maven or Gradle build downloads plugins and executes them as part
    // of the build itself -- there is no "just compile" mode that does not run
    // third-party code, which is why the ecosystem's supply-chain incidents are
    // build-plugin incidents.
    "mvn", "mvnw", "gradle", "gradlew",
    // Ruby: a native-extension gem runs extconf.rb at install time.
    "gem", "bundle", "bundler",
    // PHP
    "composer",
    // Homebrew formulas are Ruby that executes during install.
    "brew",
    // Elixir / Erlang
    "mix", "rebar3",
    // Haskell
    "cabal", "stack",
];

/// Script names that mean "this interpreter is running a package manager".
/// Matched against the basename of each argument token.
const SCRIPT_MARKERS: &[&str] = &["npm-cli.js", "npx-cli.js", "yarn.js"];

/// Tool names that mean a package manager even when they are an argument
/// (`bash /usr/bin/makepkg`, `node …/pnpm/bin/pnpm.cjs`). Matched against the
/// argument's basename with a script extension stripped, **and only when the
/// process itself is an interpreter**.
///
/// The interpreter gate is what the marker actually means: "this interpreter is
/// running a package manager". Without it the basename test fires on any
/// argument that merely ends in the name, which is how `moat-sandbox` came to
/// be classified as a package install on 2026-09-04 — it binds
/// `~/.local/share/pnpm` into the sandbox, so `bwrap --bind …/pnpm …/pnpm`
/// contained a token whose basename is `pnpm`.
///
/// That misclassification was not cosmetic. `pkg-install` context escalates an
/// AI CLI launch to high (BASELINE §2b), so every unattended triage pass raised
/// new high alerts about itself, which the next pass then triaged: 101 alerts of
/// one rule in a day, stopped only by the noise guard. The file's own header
/// already states the principle — markers match per path segment, never as a
/// bare substring — and a directory path ending in the name is the same error
/// as `pnpm-lock.yaml`.
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
    // Go has no postinstall hook, but `go generate` runs arbitrary commands,
    // cgo compiles and links C from the module, and `go test` runs the module's
    // own code. `go build`/`go run` on a module with cgo do the same. What is
    // deliberately absent is a bare `go` -- `go fmt`, `go vet`, `go doc` and
    // `go env` are not installs and a developer runs them constantly.
    Verb {
        tool: "go",
        subs: &["get", "install", "build", "run", "test", "generate", "mod", "work"],
    },
    // NuGet package scripts and MSBuild targets both execute during restore and
    // build. `dotnet new`, `dotnet --info` and friends do not.
    Verb {
        tool: "dotnet",
        subs: &["restore", "build", "run", "test", "tool", "add", "publish", "pack"],
    },
    // Deno fetches and executes remote modules directly; `deno run <url>` is
    // the install and the execution in one step.
    Verb {
        tool: "deno",
        subs: &["run", "install", "cache", "add", "task", "test", "compile"],
    },
    // A Nix build runs the derivation's builder, which is arbitrary code.
    Verb {
        tool: "nix",
        subs: &["build", "run", "shell", "develop", "profile", "env"],
    },
    Verb {
        tool: "nix-env",
        subs: &["-i", "--install", "-iA"],
    },
    Verb {
        tool: "nix-shell",
        subs: &["-p", "--packages", "--run"],
    },
    // conda/mamba packages carry post-link scripts.
    Verb {
        tool: "conda",
        subs: &["install", "create", "env", "update"],
    },
    Verb {
        tool: "mamba",
        subs: &["install", "create", "env", "update"],
    },
    Verb {
        tool: "micromamba",
        subs: &["install", "create", "env", "update"],
    },
    // No Verb for pip: it is already an unconditional root above, so every
    // invocation counts -- including `pip list` and `pip freeze`, which are not
    // installs. That is deliberate and predates this list: narrowing pip to a
    // verb set risks missing an install form nobody enumerated (`pip download`
    // and `pip wheel` both execute setup.py from the sdist), and the cost is
    // that a few read-only pip commands carry install context. Worth revisiting
    // with real false-positive data rather than by guesswork.
    // The oldest arbitrary-code-execution install in Python. Spelled without
    // the extension because `tool_name` strips `.py` before comparing, the same
    // normalisation that lets `node …/pnpm.cjs` match `pnpm`.
    Verb {
        tool: "setup",
        subs: &["install", "develop", "build", "bdist_wheel", "sdist"],
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

    // A shell handed a string of code is not the tools its code mentions.
    // `bash -c "cargo test 2>&1 | grep -E ..."` was marking the whole pipeline
    // as a cargo subtree, so `grep` -- an unrelated sibling -- inherited
    // pkg-install context and got scored as a package install running an AI CLI.
    // Whatever the code actually starts shows up as its own process and is
    // classified there; nothing is lost by declining to read the string.
    if crate::provenance::runs_inline_code(exe, args) {
        return None;
    }

    let toks: Vec<&str> = args.split_whitespace().collect();
    for m in SCRIPT_MARKERS {
        if toks.iter().any(|t| basename(t) == *m) {
            return Some(format!("argument `{}`", m));
        }
    }
    if crate::provenance::is_interpreter(comm) {
        for m in BARE_MARKERS {
            if toks.iter().any(|t| tool_name(t) == *m) {
                return Some(format!("argument `{}`", m));
            }
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
    fn a_bound_directory_that_ends_in_a_tool_name_is_not_that_tool() {
        // The 2026-09-04 self-loop: moat-sandbox binds ~/.local/share/pnpm into
        // the sandbox, so bwrap's argv carried a token whose basename is `pnpm`
        // and the whole triage subtree was classified as a package install.
        // pkg-install escalates an AI CLI launch to high, so every triage pass
        // raised alerts about itself for the next pass to triage: 101 alerts of
        // one rule in a day.
        let bwrap = "--ro-bind / / --bind /home/dan/.local/share/pnpm                      /home/dan/.local/share/pnpm -- claude -p";
        assert!(root_reason("/usr/bin/bwrap", bwrap).is_none(),
            "a bind mount is not an invocation");
        assert!(root_reason("/usr/bin/moat-sandbox", bwrap).is_none());

        // The interpreter cases the marker exists for still work.
        assert!(root_reason("/usr/bin/bash", "/usr/bin/makepkg -si").is_some());
        assert!(root_reason("/usr/bin/node", "/home/d/.local/share/pnpm/bin/pnpm.cjs add x").is_some());
        // ...and a non-interpreter naming makepkg in a path does not.
        assert!(root_reason("/usr/bin/rsync", "-a /src/makepkg /dst/makepkg").is_none());
    }

    #[test]
    fn a_shell_running_inline_code_is_not_the_tools_its_code_mentions() {
        // `cargo test 2>&1 | grep -E ...` marked the whole pipeline as a cargo
        // subtree, so `grep` -- an unrelated sibling -- inherited pkg-install
        // and was scored as a package install running an AI CLI. The real cargo
        // arrives as its own process and is classified there.
        assert!(root_reason("/usr/bin/bash", "-c cargo test 2>&1 | grep -E foo").is_none());
        assert!(root_reason("/usr/bin/sh", "-c 'pnpm add lodash'").is_none());
        assert!(root_reason("/usr/bin/bash", "-c echo makepkg").is_none());

        // But a module name is a tool identity, not code: `-m pip install` is a
        // pip invocation and has to stay one.
        assert!(root_reason("/usr/bin/python3", "-m pip install requests").is_some());
        // And a shell actually handed a script still counts.
        assert!(root_reason("/usr/bin/bash", "/usr/bin/makepkg").is_some());
    }

    #[test]
    fn the_ecosystems_a_developer_machine_actually_installs_from() {
        // Being unrecognised is not "weaker detection": with no pkg-install
        // context, BASELINE 2b never escalates, moat-x-pkg-egress cannot fire
        // (it requires an install subtree), and every moat-pkg-subtree-* rule
        // is structurally unable to match. A malicious RubyGem or Go module was
        // invisible to all of it.
        for exe in [
            "/usr/bin/gem", "/usr/bin/bundle", "/usr/bin/composer", "/usr/bin/brew",
            "/usr/bin/mvn", "/usr/bin/gradle", "/usr/bin/cpanm", "/usr/bin/mix",
            "/usr/bin/cabal", "/usr/bin/stack",
        ] {
            assert!(root_reason(exe, "install").is_some(), "{exe} should be an install root");
        }
    }

    #[test]
    fn a_compiler_is_only_an_install_when_it_is_fetching_or_running_code() {
        // `go` and `dotnet` are verb-gated rather than unconditional: a
        // developer runs `go fmt` and `go vet` all day and is not installing
        // anything. What IS an install is anything that fetches a module or
        // executes its code -- cgo compiles C from the module, `go generate`
        // runs arbitrary commands, `go test` runs the module's own tests.
        assert!(root_reason("/usr/bin/go", "build ./...").is_some());
        assert!(root_reason("/usr/bin/go", "generate ./...").is_some());
        assert!(root_reason("/usr/bin/go", "get example.com/x").is_some());
        assert!(root_reason("/usr/bin/go", "fmt ./...").is_none(), "fmt is not an install");
        assert!(root_reason("/usr/bin/go", "vet ./...").is_none());
        assert!(root_reason("/usr/bin/go", "env").is_none());

        assert!(root_reason("/usr/bin/dotnet", "restore").is_some());
        assert!(root_reason("/usr/bin/dotnet", "--info").is_none());

        // Deno fetches and executes remote code in one step.
        assert!(root_reason("/usr/bin/deno", "run https://example.com/x.ts").is_some());

        // pip is an unconditional root, so even `pip list` counts. See the
        // note in VERB_MARKERS: narrowing it risks missing an install form
        // nobody enumerated, and the cost is install context on a few read-only
        // commands.
        assert!(root_reason("/usr/bin/pip", "download requests").is_some());
        assert!(root_reason("/usr/bin/pip", "list").is_some(),
                "pip is unconditional; this documents the tradeoff rather than endorsing it");

        // The oldest arbitrary-code install in Python, run through an
        // interpreter rather than as a binary.
        assert!(root_reason("/usr/bin/python3", "setup.py install").is_some());
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
