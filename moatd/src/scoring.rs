//! Scoring: provenance and context adjust severity, within limits
//! (BASELINE §2 and §2b).
//!
//! Two adjustments run, after a base alert has been built and **before** the
//! allowlist and the dedupe window see it:
//!
//! 1. **Provenance** ([`provenance_delta`]). An official binary doing something
//!    a package binary normally does earns one step down for the
//!    persist/priv/exec/net families. `cred`, `rootkit` and `shell` earn
//!    nothing: an official binary reading your SSH key is still worth a look.
//! 2. **Context** ([`MATRIX`]). The same event scored by where it came from. The
//!    matrix is data, not code, so it can be reviewed as a table — the test
//!    `the_context_matrix_is_reviewable` prints it.
//!
//! The matrix goes first where it has an opinion. A cell holding
//! [`Outcome::Sev`] *sets* the severity outright, so a provenance step taken
//! before it was simply discarded — named in `severity_reason` and worth
//! nothing. On 2026-09-05 quickshell, an official binary from the `quickshell`
//! package, running an omarchy plugin script scored "medium → high: actor is
//! official (package quickshell); service context: exec-opaque-dir": the
//! official step is right there in the sentence and did not happen. So the
//! matrix decides the severity the context deserves and provenance then takes
//! its one step off that, under the same guards (§2: never for `pkg-install`,
//! never for a locked rule, never for cred/rootkit/shell).
//! [`Outcome::Timeline`] and [`Outcome::Nothing`] are already the floor and take
//! no provenance step. Where the matrix has no opinion the order is unchanged:
//! provenance, then §2b's general per-family rules.
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
/// Rules whose object is GLOBAL: they have no namespace to be scoped to, so
/// `render::split_container_enforcement` leaves them enforcing everywhere.
///
/// There is one kernel. A module load or a BPF program load from inside a
/// container is a fact about THIS machine, so the namespace step below must not
/// quieten it -- that would make starting a container the cheapest way to load a
/// rootkit and be merely watched doing it.
///
/// Mirrors the `moat.omarchy/namespace: "global"` annotation in `policies/`,
/// which only the renderer reads. `global_rules_match_the_annotated_policies`
/// fails if the two ever disagree.
pub const GLOBAL_RULES: &[&str] = &[
    "moat-rootkit-kernel-module-load",
    "moat-rootkit-bpf-prog-load",
    // /proc/sys/kernel is not namespaced: a container writing core_pattern sets
    // what the HOST runs on the next crash. Same argument as the two above.
    "moat-priv-sysctl-write",
];

pub const NEVER_LOWERED: &[&str] = &[
    "moat-x-new-exec-ioc",
    "moat-pkg-subtree-netcat-exec",
    "moat-x-baseline-revoked",
    "moat-x-noisy-rule",
    // A credential HARVEST keeps its severity whatever the context.
    //
    // `moat-x-mass-read` is one process reading many DISTINCT credential files
    // in seconds -- the stealer/TruffleHog signature, and a conclusion in its
    // own right, not a chain step. The interactive-context softening exists so
    // that a human doing ordinary work at a terminal is quieter; but the human
    // who was tricked into running a downloaded `exporter.py` is AT a terminal
    // too, and softening the harvest to the timeline is exactly how it reached
    // History and never Now (2026-09-06 reportkit). A harvest is a harvest
    // whether or not somebody is at the keyboard. Backup tools that legitimately
    // sweep credentials are a small, nameable set and are an allowlist entry,
    // not a reason to soften the signal for everything.
    "moat-x-mass-read",
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
        // An official binary reading your SSH key is still worth a look, and
        // /usr/bin/python encrypting your documents is not made safer by the
        // repository that shipped python.
        "cred" | "rootkit" | "shell" | "ransom" => 0,
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
    /// The SENSOR's answer only (`process.ns.mnt.is_host`), never the ancestry
    /// guess: this decides how loudly moat speaks, and a forged ancestor named
    /// `runc` must not buy quiet. See `Daemon::containerised_for_enforcement`.
    pub in_container: bool,
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
    /// **The product's thesis, as a boolean.** The matrix put this event at
    /// `high` or `critical` *because it happened inside a package install*.
    ///
    /// A `/tmp` exec is a building block on a developer's machine and a
    /// detection inside an install; that is the one cell where a `signal` rule
    /// reaches the badge on its own, and it is the one alert a noise-guard
    /// demotion may never move to the timeline. It is recorded rather than
    /// re-derived because both of those decisions are taken later — the noise
    /// guard retroactively, on records it reads back off disk
    /// (`engine::quieten_backlog`), long after the process is gone.
    pub pkg_install_escalation: bool,
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
            pkg_install_escalation: false,
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
    // `ransom` too: an interactive terminal is where a person typed `npm
    // install`, and the payload that then encrypts ~/Documents is no less a
    // payload for having a tty in its ancestry.
    f.has_ioc || f.family == "rootkit" || f.family == "ransom" || NEVER_LOWERED.contains(&f.rule)
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

    // The provenance step (§2), decided once. A package install is never
    // downgraded, by anything, and neither is a locked rule. *Where* it is
    // spent depends on the matrix: see the module header.
    let prov = if provenance_downgrade && ctx != Context::PkgInstall && !locked {
        provenance_delta(facts.family, facts.rule, actor.provenance)
    } else {
        0
    };

    // --- context (§2b) ------------------------------------------------------
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
                // The context has decided what this event is worth here; §2's
                // one step for an official actor comes off THAT, not off a
                // severity the matrix is about to overwrite.
                apply_provenance(&mut sev, &mut reasons, prov, actor);
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
            // No row, or a row that says nothing about this context: nothing
            // will overwrite the severity, so provenance goes first as §2
            // describes, and then the general rules of §2b apply.
            apply_provenance(&mut sev, &mut reasons, prov, actor);
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

    // --- the namespace step -------------------------------------------------
    //
    // `render::split_container_enforcement` scopes every enforcing selector to
    // the host mount namespace and adds a copy WITHOUT the action for everywhere
    // else. Its own contract is that container activity "stays on the timeline
    // and in the chain correlator"; nothing implemented the second half, so a
    // container reading its own /etc/shadow arrived on the badge as CRITICAL --
    // 241 of them from one postgres healthcheck loop on 2026-09-09, pinned into
    // the panel's window for ever by `is_protected`.
    //
    // Severity is a claim about this machine. For a namespace-split rule moat
    // has already decided it will not act inside a container, and a critical it
    // declined to act on is a number that means nothing a reader can use.
    //
    // This runs even for a `never_lowered` rule, which the context steps above
    // deliberately do not. Those resist a GUESS -- a tty in the ancestry, an
    // official package. This is not a guess: the policy loaded in the kernel has
    // no action in that namespace, so the decision was already taken upstream of
    // scoring. Refusing to say so here would only hide it.
    if facts.in_container && !GLOBAL_RULES.contains(&facts.rule) {
        if severity_rank(&sev) > severity_rank("low") || !timeline {
            reasons.push(
                "inside a container: moat does not enforce across the namespace \
                 boundary for this rule, so this is context about somebody else's \
                 filesystem — timeline only"
                    .into(),
            );
        }
        sev = "low".into();
        timeline = true;
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
    // Read off the matrix cell, not off the final severity: the question is
    // "does the matrix call this a detection because it happened inside an
    // install", and the answer must be the same whether or not a locked rule
    // or a provenance step moved the number afterwards.
    let pkg_install_escalation = ctx == Context::PkgInstall
        && matches!(matrix.map(|r| r.pkg_install), Some(Outcome::Sev(s)) if severity_rank(s) >= 2);
    Score {
        severity_base: base.to_string(),
        severity: sev,
        severity_reason: reason,
        surface: surface.to_string(),
        matrix_row: matrix.map(|r| r.key),
        context_silenced: silenced,
        pkg_install_escalation,
    }
}

/// BASELINE §4 and §5: the surface a finding actually gets, once the tier, the
/// noise guard and the allowlist have all had their say.
///
/// One function because the same three questions are asked in two places at two
/// different times: `explain::build_alert` when the alert is written, and
/// `engine::quieten_backlog` when a demotion reaches back over records already
/// on disk. They disagreed once already (2026-09-03, allowlisted rows recorded
/// as `alerts` while the panel drew them on the timeline) and the cost of
/// disagreeing again is a detection nobody sees.
///
/// The order is the argument:
///
/// 1. **Suppressed wins.** An allowlist entry is the user's own answer, and
///    nothing moat concludes afterwards overrides it.
/// 2. **A package-install escalation is never quietened.** A `/tmp` exec inside
///    an install IS a detection — that is the thing this project exists for —
///    so neither a `signal` tier nor a noise-guard demotion may move it. On
///    2026-09-04 a demotion did exactly that and hid a real dropper.
/// 3. **A `signal` rule and a demoted pattern go to the timeline.** Both are
///    statements that this row is not a conclusion on its own. Neither is a
///    suppression: the row is recorded in full and is a full chain trigger.
/// 4. Otherwise the severity decides, as §5 says.
pub fn final_surface(score: &Score, tier: &str, demoted: bool, suppressed: bool) -> &'static str {
    if suppressed {
        return "timeline";
    }
    if score.pkg_install_escalation && severity_rank(&score.severity) >= 2 {
        return "alerts";
    }
    if demoted || tier == crate::policy::TIER_SIGNAL {
        return "timeline";
    }
    if score.surface == "alerts" {
        "alerts"
    } else {
        "timeline"
    }
}

/// Spend the provenance step, recording it only when it actually moved
/// something. A step that lands on `low` and stays there is not a downgrade and
/// must not claim to be one.
fn apply_provenance(sev: &mut String, reasons: &mut Vec<String>, delta: i8, actor: &Actor) {
    if delta == 0 {
        return;
    }
    let next = step(sev, delta);
    if next != *sev {
        reasons.push(format!(
            "actor is official{}",
            actor
                .package
                .as_ref()
                .map(|p| format!(" (package {})", p))
                .unwrap_or_default()
        ));
        *sev = next.to_string();
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
            modified: None,
        }
    }

    fn user_actor() -> Actor {
        Actor {
            provenance: Provenance::User,
            package: None,
            script: None,
            modified: None,
        }
    }

    // ------------------------------------------------------------ provenance

    #[test]
    fn provenance_downgrades_only_the_families_the_doc_names() {
        for family in ["persist", "priv", "exec", "net"] {
            assert_eq!(provenance_delta(family, "moat-x", Provenance::Official), -1, "{}", family);
        }
        for family in ["cred", "rootkit", "shell", "ransom"] {
            assert_eq!(
                provenance_delta(family, "moat-x", Provenance::Official),
                0,
                "an official binary reading your SSH key is still worth a look ({})",
                family
            );
        }
        // Foreign / user / unknown: no change, in every row.
        for p in [Provenance::Foreign, Provenance::User, Provenance::Unknown] {
            for family in ["cred", "persist", "priv", "exec", "net", "rootkit", "shell", "ransom"] {
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
    fn the_matrix_decides_the_cell_and_provenance_still_takes_its_step() {
        // quickshell — an official binary from the `quickshell` package —
        // running an omarchy plugin script lands in the exec-opaque-dir row,
        // whose `service` cell is high. Provenance used to run first and be
        // thrown away by that cell, so the alert read "medium → high: actor is
        // official (package quickshell); service context: exec-opaque-dir":
        // the official step named in the sentence bought nothing. §2 gives an
        // official actor one step off the exec family, and it comes off what
        // the context decided.
        let homes = vec!["/home/dan".to_string()];
        let f = EventFacts {
            hook: "bprm_check_security",
            exe: "/usr/bin/quickshell",
            file: Some("/home/dan/.config/omarchy/plugins/io.github.x.thing/scripts/config"),
            homes: &homes,
            ..facts("exec", "moat-exec-untrusted-home")
        };
        let qs = Actor {
            provenance: Provenance::Official,
            package: Some("quickshell 0.3.1-1".into()),
            script: None,
            modified: None,
        };
        let s = score("medium", &f, &qs, Context::Service, true);
        assert_eq!(s.matrix_row, Some("exec-opaque-dir"));
        assert_eq!(s.severity, "medium");
        assert_eq!(s.surface, "timeline");
        assert_eq!(
            s.severity_reason,
            "stays medium: service context: exec of a binary under ~/.cache, ~/Downloads, \
             ~/.config, a hidden dir, or /tmp with no build tool in the chain; \
             actor is official (package quickshell 0.3.1-1)",
            "the order in the sentence is the order it happened"
        );

        // The same cell for a user actor is the whole point of the row.
        let s = score("medium", &f, &user_actor(), Context::Service, true);
        assert_eq!(s.severity, "high");
        assert_eq!(s.surface, "alerts");

        // ...and an official actor during a package install still gets nothing.
        assert_eq!(score("medium", &f, &qs, Context::PkgInstall, true).severity, "high");
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

    /// The one cell the whole product is about, recorded as a fact rather than
    /// re-derived: a `/tmp` exec is a building block on a developer's machine
    /// and a detection inside a package install.
    #[test]
    fn the_matrix_records_when_a_package_install_is_what_made_it_severe() {
        let tmp_exec = EventFacts {
            hook: "bprm_check_security",
            file: Some("/tmp/.stage2"),
            ..facts("exec", "moat-exec-untrusted-tmpfs")
        };
        let install = score("high", &tmp_exec, &official(), Context::PkgInstall, true);
        assert_eq!(install.matrix_row, Some("exec-opaque-dir"));
        assert_eq!(install.severity, "high");
        assert!(install.pkg_install_escalation);

        // The same event anywhere else is not an escalation, whatever it scores.
        for ctx in [Context::Interactive, Context::Service, Context::Unknown] {
            let s = score("high", &tmp_exec, &official(), ctx, true);
            assert!(!s.pkg_install_escalation, "{:?} is not a package install", ctx);
        }
        // And a row whose pkg-install cell is not high/critical is not one
        // either: an interpreter spawning inside an install is still low.
        let spawn = facts("pkg", "moat-pkg-subtree-interpreter-spawn");
        let s = score("low", &spawn, &official(), Context::PkgInstall, true);
        assert_eq!(s.matrix_row, Some("interpreter-spawn"));
        assert!(!s.pkg_install_escalation, "the cell is low, so there is nothing to protect");
    }

    /// The order of the three questions in `final_surface`, spelled out. Each
    /// line is a decision that has been got wrong at least once.
    #[test]
    fn the_surface_puts_suppression_first_and_a_package_install_above_the_tier() {
        let detection = crate::policy::TIER_DETECTION;
        let signal = crate::policy::TIER_SIGNAL;
        let plain = Score::unadjusted("high");

        assert_eq!(final_surface(&plain, detection, false, false), "alerts");
        // The user's own answer outranks everything moat concludes.
        assert_eq!(final_surface(&plain, detection, false, true), "timeline");
        // A declared building block, and a demoted pattern, both step aside.
        assert_eq!(final_surface(&plain, signal, false, false), "timeline");
        assert_eq!(final_surface(&plain, detection, true, false), "timeline");

        // ...but not inside a package install. This is the 2026-09-04 miss:
        // a /tmp dropper in a `preinstall` went to the timeline because the
        // machine's own builds had made a different shape of that rule noisy.
        let mut escalated = Score::unadjusted("high");
        escalated.pkg_install_escalation = true;
        assert_eq!(final_surface(&escalated, signal, false, false), "alerts");
        assert_eq!(final_surface(&escalated, detection, true, false), "alerts");
        assert_eq!(final_surface(&escalated, signal, true, false), "alerts");
        // Except when the user allowlisted it, which still wins.
        assert_eq!(final_surface(&escalated, signal, true, true), "timeline");
    }
}


#[cfg(test)]
mod namespace_step_tests {
    use super::*;
    use crate::provenance::{Actor, Provenance};

    fn facts<'a>(rule: &'a str, family: &'a str, in_container: bool, homes: &'a [String]) -> EventFacts<'a> {
        EventFacts {
            family,
            rule,
            hook: "file",
            exe: "/usr/bin/pg_isready",
            file: Some("/etc/shadow"),
            has_net: false,
            has_ioc: false,
            build_tool_in_chain: false,
            homes,
            in_container,
        }
    }

    // `provenance_downgrade: false` throughout: these tests are about the
    // namespace step alone, and an official actor moving the number by a step
    // would make a pass or a failure here mean two things.
    fn actor() -> Actor {
        Actor {
            provenance: Provenance::Official,
            ..Default::default()
        }
    }

    /// The case that started this: `pg_isready` in a postgres container reading
    /// the CONTAINER's /etc/shadow, 241 times, each one critical and each one
    /// pinned into the panel's window by `is_protected`.
    #[test]
    fn a_container_reading_its_own_shadow_file_is_timeline_not_critical() {
        let homes: Vec<String> = vec!["/home/dan".into()];
        let s = score(
            "critical",
            &facts("moat-cred-etc-shadow-read", "cred", true, &homes),
            &actor(),
            Context::Unknown,
            false,
        );
        assert_eq!(s.severity, "low");
        assert_eq!(s.surface, "timeline", "off the badge, still on the record");
        assert!(s.severity_reason.contains("namespace"), "{}", s.severity_reason);
    }

    /// The same read on the HOST is untouched. If this ever goes quiet, the
    /// change has switched off the rule rather than scoped it.
    #[test]
    fn the_same_read_on_the_host_is_still_critical() {
        let homes: Vec<String> = vec!["/home/dan".into()];
        let s = score(
            "critical",
            &facts("moat-cred-etc-shadow-read", "cred", false, &homes),
            &actor(),
            Context::Unknown,
            false,
        );
        assert_eq!(s.severity, "critical");
        assert_eq!(s.surface, "alerts");
    }

    /// There is one kernel. A module load from inside a container is a fact
    /// about THIS machine and keeps its severity, or starting a container
    /// becomes the cheapest way to load a rootkit and be merely watched.
    #[test]
    fn a_global_rule_is_not_quietened_by_a_container() {
        let homes: Vec<String> = vec![];
        for rule in GLOBAL_RULES {
            let s = score(
                "critical",
                &facts(rule, "rootkit", true, &homes),
                &actor(),
                Context::Unknown,
                false,
            );
            assert_eq!(s.severity, "critical", "{} was quietened", rule);
            assert_eq!(s.surface, "alerts", "{} left the badge", rule);
        }
    }

    /// A `never_lowered` rule IS lowered by this step, unlike by the context
    /// steps. Those resist a guess; this is not one -- the policy in the kernel
    /// has no action in that namespace, so moat already declined to act.
    #[test]
    fn the_namespace_step_applies_even_to_a_never_lowered_rule() {
        let homes: Vec<String> = vec![];
        let rule = NEVER_LOWERED[1]; // moat-pkg-subtree-netcat-exec
        assert!(!GLOBAL_RULES.contains(&rule));
        let s = score("high", &facts(rule, "pkg", true, &homes), &actor(), Context::Unknown, false);
        assert_eq!(s.severity, "low");
        assert_eq!(s.surface, "timeline");
    }

    /// The constant mirrors an annotation only the renderer reads. If someone
    /// marks a new policy global and forgets this list, that rule would be
    /// quietened inside containers while still being enforced there.
    #[test]
    fn global_rules_match_the_annotated_policies() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("policies");
        if !dir.is_dir() {
            return;
        }
        let mut annotated: Vec<String> = Vec::new();
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("yaml") {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            if !text.contains("moat.omarchy/namespace: \"global\"") {
                continue;
            }
            let name = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("name: "))
                .unwrap_or_default()
                .trim()
                .to_string();
            annotated.push(name);
        }
        annotated.sort();
        let mut expect: Vec<String> = GLOBAL_RULES.iter().map(|s| s.to_string()).collect();
        expect.sort();
        assert_eq!(
            annotated, expect,
            "policies/ and scoring::GLOBAL_RULES disagree about which rules are global"
        );
    }
}
