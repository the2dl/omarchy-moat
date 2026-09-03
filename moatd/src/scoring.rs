//! Scoring: provenance and context adjust severity, within limits
//! (BASELINE §2 and §2b).
//!
//! Two adjustments run, in this order, after a base alert has been built and
//! **before** the allowlist and the dedupe window see it:
//!
//! 1. **Provenance** ([`provenance_delta`]). An official binary doing something
//!    a package binary normally does earns one step down for the
//!    persist/priv/exec/net families. `cred`, `rootkit` and `shell` earn
//!    nothing: an official binary reading your SSH key is still worth a look.
//! 2. **Context** ([`MATRIX`]). The same event scored by where it came from. The
//!    matrix is data, not code, so it can be reviewed as a table — the test
//!    `the_context_matrix_is_reviewable` prints it.
//!
//! Rules of the matrix, from the doc:
//!
//! * `pkg-install` never gets a downgrade, from provenance or from anything
//!   else. The postinstall script is the attack surface this project exists for.
//! * `interactive` downgrades by up to two steps for exec/persist/priv/net and
//!   one for cred, never below "timeline only" for cred.
//! * `service` downgrades nothing; it is where persistence lives.
//! * Nothing is ever *lowered* for a finding that matched a threat feed, for the
//!   `rootkit` family, or for the handful of rules in [`NEVER_LOWERED`]: those
//!   are facts about the file, not judgements about the workload.

use crate::alert::severity_rank;
use crate::context::Context;
use crate::provenance::{Actor, Provenance};

/// What one cell of the matrix does to the severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Leave whatever the rule decided.
    Unchanged,
    /// Set the severity outright. This is how context *raises* an alert.
    Sev(&'static str),
    /// "timeline only": severity `low`, surface `timeline`.
    Timeline,
    /// "nothing": still recorded, never surfaced. Low, timeline, and the record
    /// says the context is what silenced it.
    Nothing,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Unchanged => "no change",
            Outcome::Sev(s) => s,
            Outcome::Timeline => "timeline only",
            Outcome::Nothing => "nothing",
        }
    }
}

/// One row of BASELINE §2b's table.
#[derive(Debug, Clone, Copy)]
pub struct MatrixRow {
    /// Stable id, recorded on the alert so a decision can be traced back here.
    pub key: &'static str,
    /// The doc's own description of the event.
    pub event: &'static str,
    pub interactive: Outcome,
    pub pkg_install: Outcome,
    pub service: Outcome,
}

impl MatrixRow {
    pub fn outcome(&self, ctx: Context) -> Outcome {
        match ctx {
            Context::Interactive => self.interactive,
            Context::PkgInstall => self.pkg_install,
            Context::Service => self.service,
            // No context, no adjustment: guessing here is how a rule that
            // predates the daemon gets silently softened.
            Context::Unknown => Outcome::Unchanged,
        }
    }
}

/// BASELINE §2b, verbatim. Rows are tried in order, so the specific ones
/// (`/tmp` with a build tool above it) come before the general ones.
pub const MATRIX: &[MatrixRow] = &[
    MatrixRow {
        key: "cred-cloud-read",
        event: "node/python reads ~/.aws/credentials, ~/.config/gh/hosts.yml",
        interactive: Outcome::Sev("medium"),
        pkg_install: Outcome::Sev("critical"),
        service: Outcome::Sev("high"),
    },
    MatrixRow {
        key: "interpreter-spawn",
        event: "shell/interpreter spawned",
        interactive: Outcome::Timeline,
        pkg_install: Outcome::Sev("low"),
        service: Outcome::Sev("medium"),
    },
    MatrixRow {
        key: "exec-tmp-build",
        event: "exec from /tmp with a build tool in the chain (cmake try_compile, \
                cargo build scripts, pytest tmp dirs)",
        interactive: Outcome::Timeline,
        pkg_install: Outcome::Sev("low"),
        service: Outcome::Sev("medium"),
    },
    MatrixRow {
        key: "exec-project-tree",
        event: "exec of a binary under a project worktree, target/, node_modules/.bin, \
                .venv/bin, ~/.cargo/bin, ~/.local/bin, ~/go/bin, ~/.bun/bin, mise, pnpm",
        interactive: Outcome::Timeline,
        pkg_install: Outcome::Sev("medium"),
        service: Outcome::Sev("high"),
    },
    MatrixRow {
        key: "exec-opaque-dir",
        event: "exec of a binary under ~/.cache, ~/Downloads, ~/.config, a hidden dir, \
                or /tmp with no build tool in the chain",
        interactive: Outcome::Sev("medium"),
        pkg_install: Outcome::Sev("high"),
        service: Outcome::Sev("high"),
    },
    MatrixRow {
        key: "net-download",
        event: "curl/wget with a non-registry destination",
        interactive: Outcome::Timeline,
        pkg_install: Outcome::Sev("high"),
        service: Outcome::Sev("medium"),
    },
    MatrixRow {
        key: "persist-project-config",
        event: "write to .git/hooks/*, .husky/, .envrc, .vscode/tasks.json, \
                .claude/settings.json, CLAUDE.md inside the current project",
        interactive: Outcome::Sev("low"),
        pkg_install: Outcome::Sev("high"),
        service: Outcome::Sev("high"),
    },
    MatrixRow {
        key: "persist-user-startup",
        event: "write to a shell rc, autostart, a systemd user unit, or hyprland conf",
        interactive: Outcome::Sev("medium"),
        pkg_install: Outcome::Sev("critical"),
        service: Outcome::Sev("high"),
    },
    MatrixRow {
        key: "priv-debug",
        event: "ptrace / /proc/<pid>/mem by a debugger or profiler",
        interactive: Outcome::Timeline,
        pkg_install: Outcome::Sev("high"),
        service: Outcome::Sev("high"),
    },
    MatrixRow {
        key: "ai-cli-launch",
        event: "AI CLI launched",
        interactive: Outcome::Nothing,
        pkg_install: Outcome::Sev("high"),
        service: Outcome::Sev("medium"),
    },
];

pub fn row(key: &str) -> Option<&'static MatrixRow> {
    MATRIX.iter().find(|r| r.key == key)
}

/// Rules and findings nothing may soften. A feed hash match and a kernel-module
/// load are facts about the artefact; the workload's context does not change
/// them, and a `pkg-install` netcat is the exact thing this project watches for.
pub const NEVER_LOWERED: &[&str] = &[
    "moat-x-new-exec-ioc",
    "moat-pkg-subtree-netcat-exec",
    "moat-x-baseline-revoked",
    "moat-x-noisy-rule",
];

/// Per-rule provenance deltas for the userland (`moat-x-*`) and `pkg` rules,
/// the "per rule, documented in the rule table" row of BASELINE §2.
const RULE_DELTA: &[(&str, i8)] = &[
    // A coarse CIDR allowlist plus an official actor is the classic false
    // positive here (a mirror, a CDN that moved).
    ("moat-x-pkg-egress", -1),
    // 40 dotfiles in 10 s from an official backup tool is what backup tools do.
    ("moat-x-mass-read", -1),
    // One shell per lifecycle script, from an official interpreter.
    ("moat-pkg-subtree-interpreter-spawn", -1),
    // Everything below stays exactly where the rule put it.
    ("moat-x-ai-cli-headless", 0),
    ("moat-x-new-exec-ioc", 0),
    ("moat-x-sensor-mismatch", 0),
    ("moat-pkg-subtree-downloader", 0),
    ("moat-pkg-subtree-netcat-exec", 0),
    ("moat-ai-cli-in-pkg-subtree", 0),
];

/// BASELINE §2: how far provenance may move a family's severity.
pub fn provenance_delta(family: &str, rule: &str, p: Provenance) -> i8 {
    if !p.is_official() {
        // "no change" for foreign / user / unknown, in every row of the table.
        return 0;
    }
    if let Some((_, d)) = RULE_DELTA.iter().find(|(r, _)| *r == rule) {
        return *d;
    }
    match family {
        // An official binary reading your SSH key is still worth a look.
        "cred" | "rootkit" | "shell" => 0,
        "persist" | "priv" | "exec" | "net" => -1,
        // `pkg` and `ai` userland rules are covered by RULE_DELTA above; an
        // unlisted one keeps its severity rather than being softened by default.
        _ => 0,
    }
}

/// Move a severity by `delta` steps, clamped to `low`..`critical`.
pub fn step(sev: &str, delta: i8) -> &'static str {
    const LADDER: [&str; 4] = ["low", "medium", "high", "critical"];
    let cur = severity_rank(sev) as i8;
    let next = (cur + delta).clamp(0, 3) as usize;
    LADDER[next]
}

/// Everything the matrix needs to know about one event to place it in a row.
#[derive(Debug, Clone, Default)]
pub struct EventFacts<'a> {
    pub family: &'a str,
    pub rule: &'a str,
    pub hook: &'a str,
    /// The acting binary.
    pub exe: &'a str,
    /// The file the hook named, when there is one.
    pub file: Option<&'a str>,
    pub has_net: bool,
    pub has_ioc: bool,
    /// A build tool (cmake, make, ninja, cargo, gcc, clang, configure, pytest,
    /// go) is somewhere in the ancestry.
    pub build_tool_in_chain: bool,
    /// Human homes, for the `~/…` rows.
    pub homes: &'a [String],
}

/// Cloud and forge credentials that developer tooling reads by design — the
/// row the doc opens with.
const CLOUD_CRED_MARKERS: &[&str] = &[
    "/.aws/", "/.config/gh/", "/.config/gcloud/", "/.azure/", "/.kube/",
    "/.docker/config.json", "/.config/doctl/", "/.config/fly/", "/.netrc",
    "/.git-credentials", "/.npmrc", "/.pypirc",
];

/// Where a developer's own build output and tool shims live.
const PROJECT_TREE_MARKERS: &[&str] = &[
    "/target/debug/", "/target/release/", "/node_modules/.bin/", "/.venv/bin/",
    "/venv/bin/", "/.tox/", "/build/", "/dist/",
    "/.cargo/bin/", "/.local/bin/", "/go/bin/", "/.bun/bin/",
    "/.local/share/mise/", "/.local/share/pnpm/", "/.rustup/toolchains/",
    "/.nvm/versions/", "/.pyenv/versions/", "/.rbenv/",
];

/// Places a binary has no business appearing in.
const OPAQUE_MARKERS: &[&str] = &["/.cache/", "/Downloads/", "/.config/", "/.local/share/"];

const TMP_ROOTS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

const PROJECT_CONFIG_MARKERS: &[&str] = &[
    "/.git/hooks/", "/.husky/", "/.envrc", "/.vscode/tasks.json",
    "/.claude/settings.json", "/CLAUDE.md", "/.cursor/", "/AGENTS.md",
];

const STARTUP_MARKERS: &[&str] = &[
    "/.bashrc", "/.bash_profile", "/.zshrc", "/.zshenv", "/.profile", "/.zprofile",
    "/.config/fish/", "/.config/autostart/", "/.config/systemd/user/",
    "/.config/hypr/", "/.config/uwsm/", "/.xinitrc", "/.xprofile",
];

const DOWNLOADERS: &[&str] = &["curl", "wget", "aria2c", "xh", "http", "https", "httpie", "ftp"];

/// Build tools whose presence in the chain explains a binary in `/tmp`.
pub const BUILD_TOOLS: &[&str] = &[
    "cmake", "make", "gmake", "ninja", "meson", "cargo", "rustc", "gcc", "g++", "cc", "c++",
    "clang", "clang++", "ld", "configure", "autoconf", "automake", "libtool", "pytest",
    "go", "scons", "bazel", "buck2", "zig", "node-gyp", "cargo-build-script-build",
];

fn matches_any(path: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| path.contains(m))
}

fn under_tmp(path: &str) -> bool {
    TMP_ROOTS.iter().any(|r| path.starts_with(r))
}

/// Is the executed path inside a dotted directory under one of the homes?
fn in_hidden_home_dir(path: &str, homes: &[String]) -> bool {
    homes.iter().any(|h| {
        path.strip_prefix(h.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
            .map(|rest| rest.starts_with('.') && rest.contains('/'))
            .unwrap_or(false)
    })
}

/// True when the finding is about a binary being executed rather than a file
/// being read: the `exec` family, or any `bprm_check_security` hook.
fn is_exec_event(f: &EventFacts) -> bool {
    f.family == "exec" || f.hook == "bprm_check_security"
}

/// Which row of the matrix, if any, this event belongs to.
pub fn classify_row(f: &EventFacts) -> Option<&'static MatrixRow> {
    // AI CLIs first: the rule id is unambiguous and the file/exe tests below
    // would otherwise claim them.
    if f.family == "ai" || f.rule.contains("ai-cli") {
        return row("ai-cli-launch");
    }
    if f.rule == "moat-pkg-subtree-interpreter-spawn" {
        return row("interpreter-spawn");
    }
    if f.family == "cred" {
        if let Some(p) = f.file {
            if matches_any(p, CLOUD_CRED_MARKERS) {
                return row("cred-cloud-read");
            }
        }
        return None;
    }
    if f.family == "persist" {
        if let Some(p) = f.file {
            if matches_any(p, PROJECT_CONFIG_MARKERS) {
                return row("persist-project-config");
            }
            if matches_any(p, STARTUP_MARKERS) {
                return row("persist-user-startup");
            }
        }
        return None;
    }
    if f.family == "priv" {
        let ptrace = f.hook.contains("ptrace")
            || f.rule.contains("ptrace")
            || f.file.map(|p| p.starts_with("/proc/") && p.ends_with("/mem")).unwrap_or(false);
        if ptrace {
            return row("priv-debug");
        }
        return None;
    }
    if (f.has_net || f.family == "net" || f.rule.contains("downloader"))
        && DOWNLOADERS.contains(&crate::util::basename(f.exe))
    {
        return row("net-download");
    }
    if is_exec_event(f) {
        // The executed path is the file the hook named; fall back to the exe.
        let path = f.file.unwrap_or(f.exe);
        if under_tmp(path) {
            return row(if f.build_tool_in_chain {
                "exec-tmp-build"
            } else {
                "exec-opaque-dir"
            });
        }
        if matches_any(path, PROJECT_TREE_MARKERS) {
            return row("exec-project-tree");
        }
        if matches_any(path, OPAQUE_MARKERS) || in_hidden_home_dir(path, f.homes) {
            return row("exec-opaque-dir");
        }
    }
    None
}

/// The result of scoring, recorded on the alert (BASELINE §8).
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    pub severity_base: String,
    pub severity: String,
    pub severity_reason: String,
    /// `alerts` | `timeline` (BASELINE §5).
    pub surface: String,
    /// The matrix row that decided it, for the panel and for review.
    pub matrix_row: Option<&'static str>,
    /// The context said "nothing": recorded, never surfaced.
    pub context_silenced: bool,
}

impl Score {
    /// The severity a finding keeps when no adjustment applies.
    pub fn unadjusted(sev: &str) -> Score {
        Score {
            severity_base: sev.to_string(),
            severity: sev.to_string(),
            severity_reason: "no adjustment applied".into(),
            surface: surface_for(sev).into(),
            matrix_row: None,
            context_silenced: false,
        }
    }
}

/// BASELINE §5: critical and high go to the Alerts tab, everything else to the
/// timeline. A demoted rule is forced to `timeline` by the noise guard.
pub fn surface_for(sev: &str) -> &'static str {
    if severity_rank(sev) >= 2 {
        "alerts"
    } else {
        "timeline"
    }
}

fn never_lowered(f: &EventFacts) -> bool {
    f.has_ioc || f.family == "rootkit" || NEVER_LOWERED.contains(&f.rule)
}

/// Apply provenance (§2) and context (§2b) to a base severity.
pub fn score(
    base: &str,
    facts: &EventFacts,
    actor: &Actor,
    ctx: Context,
    provenance_downgrade: bool,
) -> Score {
    let mut sev = base.to_string();
    let mut reasons: Vec<String> = Vec::new();
    let mut timeline = false;
    let mut silenced = false;
    let locked = never_lowered(facts);

    // --- 1. provenance ------------------------------------------------------
    // A package install is never downgraded, by anything.
    if provenance_downgrade && ctx != Context::PkgInstall && !locked {
        let delta = provenance_delta(facts.family, facts.rule, actor.provenance);
        if delta != 0 {
            let next = step(&sev, delta);
            if next != sev {
                reasons.push(format!(
                    "actor is official{}",
                    actor
                        .package
                        .as_ref()
                        .map(|p| format!(" (package {})", p))
                        .unwrap_or_default()
                ));
                sev = next.to_string();
            }
        }
    }

    // --- 2. context ---------------------------------------------------------
    let matrix = classify_row(facts);
    match matrix.map(|r| r.outcome(ctx)) {
        Some(Outcome::Sev(target)) => {
            let lower = severity_rank(target) < severity_rank(&sev);
            if lower && locked {
                reasons.push(format!(
                    "{} context would score this {}, but this rule is never lowered",
                    ctx, target
                ));
            } else {
                if target != sev {
                    reasons.push(format!("{} context: {}", ctx, matrix.unwrap().event));
                }
                sev = target.to_string();
            }
        }
        Some(Outcome::Timeline) => {
            if locked {
                reasons.push(format!(
                    "{} context would keep this to the timeline, but this rule is never lowered",
                    ctx
                ));
            } else {
                reasons.push(format!("{} context: {} — timeline only", ctx, matrix.unwrap().event));
                sev = "low".into();
                timeline = true;
            }
        }
        Some(Outcome::Nothing) => {
            if locked {
                reasons.push(format!("{} context would silence this, but this rule is never lowered", ctx));
            } else {
                reasons.push(format!(
                    "{} context: {} — expected here, recorded but not surfaced",
                    ctx,
                    matrix.unwrap().event
                ));
                sev = "low".into();
                timeline = true;
                silenced = true;
            }
        }
        Some(Outcome::Unchanged) | None => {
            // No row, or a row that says nothing about this context: the
            // general rules of §2b apply.
            let delta = generic_context_delta(facts.family, ctx);
            if delta != 0 && !locked {
                let mut next = step(&sev, delta);
                // "never below timeline only for cred": credential reads are
                // always at least visible, and `low` is that floor.
                if facts.family == "cred" && severity_rank(next) < severity_rank("low") {
                    next = "low";
                }
                if next != sev {
                    reasons.push(format!(
                        "interactive session: a person is driving this ({} step{} down)",
                        -delta,
                        if delta == -1 { "" } else { "s" }
                    ));
                    sev = next.to_string();
                }
            }
        }
    }

    if ctx == Context::PkgInstall && reasons.is_empty() {
        reasons.push("package install: never downgraded".into());
    }

    let reason = if reasons.is_empty() {
        format!("{}: no adjustment applied (actor {}, context {})", sev, actor.provenance, ctx)
    } else if sev == base {
        format!("stays {}: {}", sev, reasons.join("; "))
    } else {
        format!("{} → {}: {}", base, sev, reasons.join("; "))
    };

    let surface = if timeline { "timeline" } else { surface_for(&sev) };
    Score {
        severity_base: base.to_string(),
        severity: sev,
        severity_reason: reason,
        surface: surface.to_string(),
        matrix_row: matrix.map(|r| r.key),
        context_silenced: silenced,
    }
}

/// §2b's general rules, for events with no row of their own.
fn generic_context_delta(family: &str, ctx: Context) -> i8 {
    match ctx {
        // "interactive downgrades by up to two steps for exec/persist/priv/net
        // and one step for cred".
        Context::Interactive => match family {
            "exec" | "persist" | "priv" | "net" => -2,
            "cred" => -1,
            _ => 0,
        },
        // "service downgrades nothing; it is where persistence lives."
        Context::Service => 0,
        // "pkg-install never gets a downgrade."
        Context::PkgInstall => 0,
        Context::Unknown => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(family: &'a str, rule: &'a str) -> EventFacts<'a> {
        EventFacts {
            family,
            rule,
            hook: "file_post_open",
            exe: "/usr/bin/node",
            ..Default::default()
        }
    }

    fn official() -> Actor {
        Actor {
            provenance: Provenance::Official,
            package: Some("hyprland 0.52.0-1".into()),
            script: None,
        }
    }

    fn user_actor() -> Actor {
        Actor {
            provenance: Provenance::User,
            package: None,
            script: None,
        }
    }

    // ------------------------------------------------------------ provenance

    #[test]
    fn provenance_downgrades_only_the_families_the_doc_names() {
        for family in ["persist", "priv", "exec", "net"] {
            assert_eq!(provenance_delta(family, "moat-x", Provenance::Official), -1, "{}", family);
        }
        for family in ["cred", "rootkit", "shell"] {
            assert_eq!(
                provenance_delta(family, "moat-x", Provenance::Official),
                0,
                "an official binary reading your SSH key is still worth a look ({})",
                family
            );
        }
        // Foreign / user / unknown: no change, in every row.
        for p in [Provenance::Foreign, Provenance::User, Provenance::Unknown] {
            for family in ["cred", "persist", "priv", "exec", "net", "rootkit", "shell"] {
                assert_eq!(provenance_delta(family, "moat-x", p), 0, "{} {}", family, p);
            }
        }
    }

    #[test]
    fn only_interpreter_spawn_moves_among_the_pkg_rules() {
        assert_eq!(
            provenance_delta("pkg", "moat-pkg-subtree-interpreter-spawn", Provenance::Official),
            -1
        );
        for rule in ["moat-pkg-subtree-downloader", "moat-pkg-subtree-netcat-exec"] {
            assert_eq!(provenance_delta("pkg", rule, Provenance::Official), 0, "{}", rule);
        }
    }

    #[test]
    fn severity_steps_clamp_at_both_ends() {
        assert_eq!(step("high", -1), "medium");
        assert_eq!(step("medium", -1), "low");
        assert_eq!(step("low", -1), "low");
        assert_eq!(step("critical", -2), "medium");
        assert_eq!(step("critical", 1), "critical");
    }

    // ---------------------------------------------------------------- matrix

    /// The matrix is data so it can be *reviewed*. This prints it; run with
    /// `cargo test the_context_matrix_is_reviewable -- --nocapture`.
    #[test]
    fn the_context_matrix_is_reviewable() {
        println!("\n| event | interactive | pkg-install | service |");
        println!("|---|---|---|---|");
        for r in MATRIX {
            println!(
                "| {} | {} | {} | {} |",
                r.event,
                r.interactive.label(),
                r.pkg_install.label(),
                r.service.label()
            );
        }
        assert_eq!(MATRIX.len(), 10, "BASELINE §2b defines ten rows");
        let mut keys: Vec<&str> = MATRIX.iter().map(|r| r.key).collect();
        let n = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), n, "matrix keys must be unique");
        for r in MATRIX {
            assert!(!r.event.is_empty(), "{} has no description", r.key);
            // pkg-install is never softer than interactive, in every row.
            let soft = |o: Outcome| match o {
                Outcome::Nothing => 0,
                Outcome::Timeline => 1,
                Outcome::Sev(s) => severity_rank(s) + 2,
                Outcome::Unchanged => 9,
            };
            assert!(
                soft(r.pkg_install) >= soft(r.interactive),
                "{}: pkg-install must never be softer than interactive",
                r.key
            );
        }
    }

    #[test]
    fn every_row_of_the_matrix_is_reachable_from_a_real_event() {
        let homes = vec!["/home/dan".to_string()];
        let cases: &[(&str, EventFacts)] = &[
            (
                "cred-cloud-read",
                EventFacts { file: Some("/home/dan/.aws/credentials"), ..facts("cred", "moat-cred-cloud-credentials-read") },
            ),
            ("interpreter-spawn", facts("pkg", "moat-pkg-subtree-interpreter-spawn")),
            (
                "exec-tmp-build",
                EventFacts {
                    hook: "bprm_check_security",
                    file: Some("/tmp/cc-test/a.out"),
                    build_tool_in_chain: true,
                    ..facts("exec", "moat-exec-untrusted-tmpfs")
                },
            ),
            (
                "exec-project-tree",
                EventFacts {
                    hook: "bprm_check_security",
                    file: Some("/home/dan/proj/node_modules/.bin/tsc"),
                    ..facts("exec", "moat-exec-untrusted-home")
                },
            ),
            (
                "exec-opaque-dir",
                EventFacts {
                    hook: "bprm_check_security",
                    file: Some("/home/dan/.cache/xyz/payload"),
                    homes: &homes,
                    ..facts("exec", "moat-exec-untrusted-home")
                },
            ),
            (
                "net-download",
                EventFacts { exe: "/usr/bin/curl", has_net: true, ..facts("net", "moat-x-pkg-egress") },
            ),
            (
                "persist-project-config",
                EventFacts { file: Some("/home/dan/proj/.git/hooks/pre-commit"), ..facts("persist", "moat-persist-git-hook-write") },
            ),
            (
                "persist-user-startup",
                EventFacts { file: Some("/home/dan/.zshrc"), ..facts("persist", "moat-persist-shell-rc-write") },
            ),
            (
                "priv-debug",
                EventFacts { hook: "ptrace_attach", ..facts("priv", "moat-priv-ptrace-attach") },
            ),
            ("ai-cli-launch", facts("ai", "moat-x-ai-cli-headless")),
        ];
        for (want, f) in cases {
            let got = classify_row(f).map(|r| r.key);
            assert_eq!(got, Some(*want), "facts {:?} landed on {:?}", f.rule, got);
        }
        // Something the matrix says nothing about falls through.
        assert!(classify_row(&facts("shell", "moat-shell-reverse-shell-connect")).is_none());
        assert!(classify_row(&EventFacts {
            file: Some("/home/dan/.ssh/id_ed25519"),
            ..facts("cred", "moat-cred-ssh-private-key-read")
        })
        .is_none());
    }

    #[test]
    fn tmp_execs_split_on_whether_a_build_tool_is_above_them() {
        let mut f = EventFacts {
            hook: "bprm_check_security",
            file: Some("/tmp/cc1234/conftest"),
            ..facts("exec", "moat-exec-untrusted-tmpfs")
        };
        assert_eq!(classify_row(&f).unwrap().key, "exec-opaque-dir");
        f.build_tool_in_chain = true;
        assert_eq!(classify_row(&f).unwrap().key, "exec-tmp-build");
    }

    // ---------------------------------------------------------------- scoring

    #[test]
    fn an_official_actor_takes_persist_one_step_down() {
        let f = EventFacts { file: Some("/etc/systemd/system/x.service"), ..facts("persist", "moat-persist-system-unit-write") };
        let s = score("high", &f, &official(), Context::Unknown, true);
        assert_eq!(s.severity_base, "high");
        assert_eq!(s.severity, "medium");
        assert_eq!(
            s.severity_reason,
            "high → medium: actor is official (package hyprland 0.52.0-1)"
        );
        assert_eq!(s.surface, "timeline");

        // A user actor gets nothing.
        let s = score("high", &f, &user_actor(), Context::Unknown, true);
        assert_eq!(s.severity, "high");
        assert_eq!(s.surface, "alerts");

        // And the whole thing switches off.
        let s = score("high", &f, &official(), Context::Unknown, false);
        assert_eq!(s.severity, "high");
    }

    #[test]
    fn a_package_install_is_never_downgraded() {
        let f = EventFacts { file: Some("/home/dan/.zshrc"), ..facts("persist", "moat-persist-shell-rc-write") };
        let s = score("high", &f, &official(), Context::PkgInstall, true);
        // Provenance is skipped entirely, and the matrix raises it instead.
        assert_eq!(s.severity, "critical");
        assert!(s.severity_reason.contains("pkg-install"), "{}", s.severity_reason);
        assert_eq!(s.surface, "alerts");
    }

    #[test]
    fn the_same_credential_read_scores_three_ways() {
        let f = EventFacts { file: Some("/home/dan/.aws/credentials"), ..facts("cred", "moat-cred-cloud-credentials-read") };
        assert_eq!(score("high", &f, &user_actor(), Context::Interactive, true).severity, "medium");
        assert_eq!(score("high", &f, &user_actor(), Context::PkgInstall, true).severity, "critical");
        assert_eq!(score("high", &f, &user_actor(), Context::Service, true).severity, "high");
        // Unknown context leaves the rule's own verdict alone.
        assert_eq!(score("high", &f, &user_actor(), Context::Unknown, true).severity, "high");
    }

    #[test]
    fn interactive_takes_two_steps_off_exec_and_one_off_cred() {
        // No matrix row: an SSH key read.
        let cred = EventFacts { file: Some("/home/dan/.ssh/id_ed25519"), ..facts("cred", "moat-cred-ssh-private-key-read") };
        let s = score("high", &cred, &user_actor(), Context::Interactive, true);
        assert_eq!(s.severity, "medium", "one step for cred");

        // A cred alert can never be silenced by context.
        let s = score("low", &cred, &user_actor(), Context::Interactive, true);
        assert_eq!(s.severity, "low", "credential reads are always at least visible");

        // A `shell` finding is not on the list, so interactive leaves it alone.
        let shell = facts("shell", "moat-shell-reverse-shell-connect");
        assert_eq!(score("critical", &shell, &user_actor(), Context::Interactive, true).severity, "critical");
    }

    #[test]
    fn timeline_only_means_low_and_the_timeline_tab() {
        let f = EventFacts {
            hook: "bprm_check_security",
            file: Some("/home/dan/proj/target/debug/app"),
            ..facts("exec", "moat-exec-untrusted-home")
        };
        let s = score("high", &f, &user_actor(), Context::Interactive, true);
        assert_eq!(s.severity, "low");
        assert_eq!(s.surface, "timeline");
        assert!(s.severity_reason.contains("timeline only"), "{}", s.severity_reason);
        assert_eq!(s.matrix_row, Some("exec-project-tree"));
        assert!(!s.context_silenced);

        // The same binary during an install is worth a medium.
        let s = score("high", &f, &user_actor(), Context::PkgInstall, true);
        assert_eq!(s.severity, "medium");
    }

    #[test]
    fn an_ai_cli_a_person_started_is_recorded_but_not_surfaced() {
        let f = facts("ai", "moat-x-ai-cli-headless");
        let s = score("high", &f, &user_actor(), Context::Interactive, true);
        assert!(s.context_silenced);
        assert_eq!(s.severity, "low");
        assert_eq!(s.surface, "timeline");
        assert_eq!(score("high", &f, &user_actor(), Context::PkgInstall, true).severity, "high");
        assert_eq!(score("high", &f, &user_actor(), Context::Service, true).severity, "medium");
    }

    #[test]
    fn a_feed_hash_match_and_the_rootkit_family_are_never_lowered() {
        let ioc = EventFacts {
            hook: "bprm_check_security",
            file: Some("/tmp/.x9k"),
            has_ioc: true,
            ..facts("exec", "moat-x-new-exec-ioc")
        };
        let s = score("critical", &ioc, &official(), Context::Interactive, true);
        assert_eq!(s.severity, "critical");
        assert!(s.severity_reason.contains("never lowered"), "{}", s.severity_reason);

        let rk = facts("rootkit", "moat-rootkit-kernel-module-load");
        assert_eq!(score("critical", &rk, &official(), Context::Interactive, true).severity, "critical");

        // A netcat inside an install is the exact thing this project watches.
        let nc = facts("pkg", "moat-pkg-subtree-netcat-exec");
        assert_eq!(score("critical", &nc, &official(), Context::Interactive, true).severity, "critical");
    }

    #[test]
    fn the_surface_follows_the_severity_table() {
        assert_eq!(surface_for("critical"), "alerts");
        assert_eq!(surface_for("high"), "alerts");
        assert_eq!(surface_for("medium"), "timeline");
        assert_eq!(surface_for("low"), "timeline");
    }
}
