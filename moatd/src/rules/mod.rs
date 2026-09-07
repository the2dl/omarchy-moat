//! Userland rules — the detections Tetragon cannot express (NOTES "Gaps").
//!
//! Each rule is a struct implementing [`UserRule`], carries its own metadata
//! (the same shape a policy's annotations produce, so the alert builder does not
//! care where a finding came from), and has a config toggle in
//! `[rules]` of `moat.toml`.
//!
//! | rule id                             | gap it fills                                  |
//! |-------------------------------------|-----------------------------------------------|
//! | `moat-x-ai-cli-headless`            | ancestry beyond one level (gap 1)             |
//! | `moat-x-pkg-egress`                 | registry allowlists, no DNS in kernel (gap 4) |
//! | `moat-x-new-exec-ioc`               | sha256 of the executed file (gap 6)           |
//! | `moat-x-mass-read`                  | counting inside a window (gap 5)              |
//! | `moat-pkg-subtree-interpreter-spawn`| exact package-subtree membership              |
//! | `moat-pkg-subtree-downloader`       | exact package-subtree membership              |
//! | `moat-pkg-subtree-netcat-exec`      | exact package-subtree membership              |
//! | `moat-ai-cli-in-pkg-subtree`        | exact package-subtree membership              |
//! | `moat-shell-stdio-socket`           | fds 0/1/2 of a live process (no hook has them)|
//! | `moat-ransom-file-churn`            | read-then-destroy of the same path, counted   |
//! | `moat-ransom-snapshot-command`      | argv of `btrfs`/`snapper`/`restic`/`borg`     |
//!
//! `moat-ransom-file-churn` owns the kernel policy of the same name, the way
//! `moat-net-first-contact` does: the policy posts every unlink, rename,
//! truncate and read-open under the document directories, and only this rule
//! decides what they add up to.
//!
//! The four `pkg`/`ai` rules keep the ids and severities of the kernel policies they
//! replace, because docs, the allowlist and the shell plugin all name them.
//! Tetragon's `matchParentBinaries … followChildren` could not express "inside
//! a package install" without matching half the desktop (see `pkgtree`), so the
//! subtree test moved to userland while the rule ids stayed put.

pub mod exec_properties;
pub mod ai_cli;
pub mod mass_read;
pub mod netmatch;
pub mod net_first_contact;
pub mod new_exec_ioc;
pub mod pkg_egress;
pub mod pkg_subtree;
pub mod pkgtree;
pub mod ransom_churn;
pub mod ransom_snapshot;
pub mod self_proc_read;
pub mod shell_stdio_socket;

use crate::config::Config;
use crate::event::{ExecEvent, HookHit};
use crate::explain::Finding;
use crate::feeds::Feeds;
use crate::policy::PolicyMeta;
use crate::proctable::{ProcInfo, ProcTable};

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
    // A session host is a boundary whatever it is called. `herdr` sits between
    // the terminal and the shells on this machine, so on 2026-09-04 it became
    // the root of every tree below it and `chain.rs` welded an AUR attack to
    // three unrelated connections from a Claude session seven minutes earlier:
    // "7 things happened in 7 minutes under herdr" is shared ancestry, not a
    // sequence. See the note on this list's fragility below.
    "herdr",
];

// NOTE: this list is a hardcoded set of NAMES, and that is its weakness. Any
// terminal or session host not written here silently becomes the root of every
// tree beneath it, which turns one chain into a bag of unrelated events -- and
// nothing fails loudly when that happens.
//
// It is now a FALLBACK everywhere it is used, not the answer, because the
// general fix is to stop asking what a process is CALLED and ask what it IS,
// and /proc has both halves of that:
//
// * `chain::is_boundary` asks `sid == pid` -- a session leader is a session
//   boundary by definition, whatever it is named (2026-09-04);
// * `context::classify` and `moat-x-ai-cli-headless` ask whether the process or
//   any ancestor holds a controlling terminal -- a pty means somebody opened
//   one, whatever allocated it (2026-09-05, after `herdr` put nine of thirteen
//   badge alerts in the `service` context).
//
// The list is consulted only when /proc could not be read, i.e. the process had
// already exited. Adding a name here is a patch for one host; it is never the
// fix. `context.rs` extends it with `INTERACTIVE_EXTRA` (editors, `sudo`)
// rather than growing it, because "a person is driving this" and "this is the
// root of a story" are different questions and `sudo` answers them differently.

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

/// "no rule is armed on its own", for every caller that only exercises the
/// daemon-wide mode. A `static` rather than a temporary because `RuleCtx` holds
/// a borrow of the daemon's real set.
pub static NO_RULES_ARMED: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

/// An empty cred-session map, for tests that build a RuleCtx by hand.
pub static NO_CRED_SESSIONS: std::sync::LazyLock<std::collections::HashMap<u32, u64>> =
    std::sync::LazyLock::new(std::collections::HashMap::new);

pub struct RuleCtx<'a> {
    pub cfg: &'a Config,
    pub table: &'a ProcTable,
    /// Read-only: a rule may ask whether this machine has ever seen a tuple
    /// before, which is how "first contact" is told apart from "the registry
    /// you use every day". Rules never `observe` -- the engine owns that.
    pub rarity: &'a crate::rarity::RarityStore,
    pub feeds: &'a Feeds,
    /// Human homes, for "$HOME dotdir" tests.
    pub homes: &'a [String],
    pub now: u64,
    pub mode: &'a str,
    /// The rules armed INDIVIDUALLY while the daemon stays in monitor
    /// (`Daemon::enforcing_rules`). A userland rule that can kill has to read
    /// this as well as `mode`, or `moatctl set mode enforce --rule <it>` would
    /// arm a switch that nothing consults — which is what it did until
    /// 2026-09-05.
    pub armed: &'a std::collections::BTreeSet<String>,
    /// Session id -> when that session last read a credential file. Lets a net
    /// rule ask "did the task I belong to just read a secret", which is the
    /// exfil context that /24 familiarity would otherwise hide.
    pub cred_read_sessions: &'a std::collections::HashMap<u32, u64>,
}

impl RuleCtx<'_> {
    /// Is this rule allowed to end a process right now? The daemon-wide mode,
    /// or this one rule armed on its own. Mirrors `Daemon::mode_for`.
    pub fn enforcing(&self, rule: &str) -> bool {
        self.mode == "enforce" || self.armed.contains(rule)
    }

    /// Did the session of `exec_id` read a credential within `window` seconds?
    /// The exfil-context signal -- a connection right after a secret read is
    /// worth reporting even to a host whose /24 is familiar.
    pub fn session_read_cred_within(&self, exec_id: &str, window: u64) -> bool {
        let Some(sid) = self.table.get(exec_id).and_then(|p| p.sid) else {
            return false;
        };
        self.cred_read_sessions
            .get(&sid)
            .map(|t| self.now.saturating_sub(*t) <= window)
            .unwrap_or(false)
    }
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
        Box::new(net_first_contact::NetFirstContact::default()),
        Box::new(new_exec_ioc::NewExecIoc::default()),
        Box::new(mass_read::MassRead::default()),
        Box::new(exec_properties::ExecMemfd),
        Box::new(exec_properties::ExecPrivilegesRaised),
        Box::new(pkg_subtree::InterpreterSpawn::default()),
        Box::new(pkg_subtree::Downloader),
        Box::new(pkg_subtree::NetcatExec),
        Box::new(pkg_subtree::AiCliInPkgSubtree),
        Box::new(shell_stdio_socket::ShellStdioSocket::default()),
        Box::new(ransom_churn::RansomChurn::default()),
        Box::new(ransom_snapshot::SnapshotCommand),
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
        // BASELINE §4: a userland rule is a detection unless it says otherwise,
        // for the same reason a policy is — a rule that forgot to declare its
        // tier must keep asking, never go quiet. `signal` is set by the handful
        // of rules that are building blocks (`signal_meta`).
        tier: crate::policy::TIER_DETECTION.into(),
    }
}

/// The same builder, for a rule that is a **building block, not a detection**
/// (BASELINE §4, `moat.omarchy/tier: signal`).
///
/// `why` still has to stand on its own, and `signal` does not soften it: the
/// severity is unchanged, the rule is a full chain trigger, and it is recorded
/// exactly as before. What changes is that it never reaches the badge alone.
#[allow(clippy::too_many_arguments)]
pub fn signal_meta(
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
    let mut m = meta(name, family, severity, title, why, expected, rotate, actions, fp_hint);
    m.tier = crate::policy::TIER_SIGNAL.into();
    m
}

/// `moat-x-sensor-mismatch`: raised in place of a policy alert when the kernel
/// reported a value the policy's own selectors exclude (see `selectors.rs`).
pub const SENSOR_MISMATCH: &str = "moat-x-sensor-mismatch";

pub fn sensor_mismatch_meta(why: &str) -> PolicyMeta {
    let mut m = meta(
        SENSOR_MISMATCH,
        "x",
        "low",
        "Sensor reported an event its own filter should have rejected",
        why,
        "A Tetragon upgrade that changes argument order or hook semantics, a policy edited \
         while it was loaded, and hooks whose arguments moatd re-validates only partially. \
         There is one common cause that is NOT a sensor fault: the name reported is a \
         script, so the kernel matched its interpreter — which the selector does not \
         exclude -- and the two never disagreed. The record says so when that is what \
         happened. Otherwise it is never caused by the program named in the alert, so \
         ignoring it by exe is the wrong move -- ignore it by rule, or fix the policy.",
        &[],
        &["ignore"],
        "rule",
    );
    // Nothing to kill and nothing to quarantine: the finding is about the
    // sensor, not the process.
    m.enforce = "none".into();
    m
}

/// `moat-x-noisy-rule`: one rule flooded the last 24 h, so the noise guard
/// moved it to the timeline (BASELINE §4). Raised once per demotion.
pub const NOISY_RULE: &str = "moat-x-noisy-rule";

/// Rules that report on MOAT'S OWN INTEGRITY, and therefore cannot be silenced.
///
/// Everything else here can be allowlisted, and should be: a detection that is
/// wrong for your machine is noise, and telling Moat to stop asking is the
/// whole point of the allowlist. These are different. They do not describe
/// something a program did -- they describe Moat being weakened, stopped,
/// unwatched, or dropping events. An allowlist entry for "a protection was
/// turned off" makes every future weakening silent, which is precisely the
/// state an attacker wants and precisely what the alert exists to prevent.
///
/// So they carry no `ignore` action, and `cmd_ignore` refuses them outright.
/// The only thing to do with one is read it and close it.
pub const NEVER_SILENCE: &[&str] = &[
    PROTECTION_CHANGED,
    WAS_DOWN,
    UNWATCHED,
    SENSOR_THROTTLED,
    "moat-x-sensor-mismatch",
];

/// Something turned a protection off. Recorded as an alert, never only a log
/// line, because root's journal is not readable by the person being protected
/// and a weakening nobody can see is the same as no protection at all.
pub const PROTECTION_CHANGED: &str = "moat-x-protection-changed";

/// Moat was not running, and now it is.
pub const WAS_DOWN: &str = "moat-x-was-not-running";

pub fn was_down_meta(mins: u64) -> PolicyMeta {
    meta(
        WAS_DOWN,
        "x",
        "high",
        "Moat was not running for a while",
        &format!(
            "There is a {}-minute hole in the record: Moat stopped and started again, and \
             nothing that happened in between was seen by anything. Stopping the daemon needs \
             root, so this is either an update, a reboot, a crash -- or somebody with root \
             turning it off, which is the first thing worth doing if you want to work \
             unobserved.",
            mins
        ),
        "A package upgrade, a reboot, or you restarting it yourself. Expected right after either \
         of those and suspicious at any other time.",
        &[],
        // No `ignore`: see NEVER_SILENCE.
        &[],
        "rule",
    )
}

/// Alerts are piling up and no panel has asked for them.
pub const UNWATCHED: &str = "moat-x-nobody-is-watching";

pub fn unwatched_meta(unacked: u64, quiet_mins: u64) -> PolicyMeta {
    meta(
        UNWATCHED,
        "x",
        "high",
        "Alerts are waiting and nothing has been reading them",
        &format!(
            "{} alert(s) need an answer and no panel has asked Moat for its status in {} \
             minutes. Notifications are drawn by a program in your own session, so anything \
             running as you can stop them just by killing it -- and then Moat keeps recording \
             faithfully while nobody sees a thing. This is Moat noticing that itself.",
            unacked, quiet_mins
        ),
        "Logging out, locking the screen for a long time, or closing the panel on purpose. It \
         means nobody would have seen an alert during that window, not that anything attacked \
         you.",
        &[],
        // No `ignore`: see NEVER_SILENCE.
        &[],
        "rule",
    )
}

/// The sensor is dropping events, so there is a hole in the record.
pub const SENSOR_THROTTLED: &str = "moat-x-sensor-throttled";

pub fn sensor_throttled_meta(cgroup: &str) -> PolicyMeta {
    meta(
        SENSOR_THROTTLED,
        "x",
        "high",
        "The sensor hit its rate limit and is dropping events",
        &format!(
            "Tetragon throttled {}, which means events from it are being discarded rather than \
             recorded. Whatever ran in that window is not in the timeline and never will be. A \
             flood is the cheapest way to blind a sensor precisely because the evidence is the \
             thing that goes missing, so the throttle itself has to be the alert.",
            if cgroup.is_empty() { "a cgroup" } else { cgroup }
        ),
        "A genuinely busy build -- a large compile, a big npm install -- can reach the limit \
         without anything being wrong. What matters is whether a flood arrived at the same time \
         as something you would rather have seen.",
        &[],
        // No `ignore`: see NEVER_SILENCE.
        &[],
        "rule",
    )
}

pub fn protection_changed_meta(action: &str, who: &str) -> PolicyMeta {
    meta(
        PROTECTION_CHANGED,
        "x",
        "high",
        &format!("A protection was weakened: {}", action),
        &format!(
            "{} asked Moat to {}. The control socket is owned by the `moat` group, and on this \
             machine's threat model -- a hijacked package running as you -- the attacker is in \
             that group too. So every weakening is recorded here, with who asked, before it takes \
             effect. If that was you, this line is the receipt; if it was not, it is the first \
             thing that happened.",
            who, action
        ),
        "You turning something off on purpose: switching to monitor, disarming a rule, allowing a \
         program, or releasing a containment. Expected right after you touch a toggle, and never \
         at any other time.",
        &[],
        // No `ignore`: see NEVER_SILENCE.
        &[],
        "rule",
    )
}

pub fn noisy_rule_meta(rule: &str, count: u64, threshold: u64) -> PolicyMeta {
    meta(
        NOISY_RULE,
        "x",
        "medium",
        &format!("{} is too noisy and was moved to the timeline", rule),
        &format!(
            "One rule raising {} alerts in 24 hours (the threshold is {}) is a bad rule or a new \
             workload, not {} incidents. Moat keeps recording it, stops notifying, and shows you \
             the handful of (actor, file) pairs behind the flood so you can decide once instead \
             of dismissing hundreds of times.",
            count, threshold, count
        ),
        "A new toolchain, a dotfile manager, a backup job, or a rule that is simply wrong for \
         this machine. Nothing is switched off: the alerts are still in alerts.jsonl and the \
         demotion clears itself after 24 quiet hours.",
        &[],
        &["ignore"],
        "rule",
    )
}

/// `moat-x-baseline-revoked`: a learned entry's actor stopped being official,
/// so the entry was disabled (LEARNING §1).
pub const BASELINE_REVOKED: &str = "moat-x-baseline-revoked";

pub fn baseline_revoked_meta(rule: &str) -> PolicyMeta {
    meta(
        BASELINE_REVOKED,
        "x",
        "low",
        &format!("A learned baseline entry for {} was disabled", rule),
        "Learned entries are re-checked on every pacman transaction. This one was earned by a \
         binary that a trusted repository shipped; that is no longer true (the package was \
         replaced, removed, or rebuilt from the AUR), so the suppression it granted has been \
         withdrawn rather than left standing on a changed fact.",
        "A package moving from a repo to an AUR build, a local `pacman -U`, or a binary that is \
         no longer owned by any package. The entry is commented out in baseline.toml with the \
         reason, so nothing is lost; re-learn it with `moatctl baseline relearn` once you are \
         happy with the new owner.",
        &[],
        &["ignore"],
        "rule",
    )
}

/// Does any ancestor (or the process itself) match one of these globs?
///
/// Both the ancestor's binary and each of its arguments are tried, because a
/// script with a shebang is reported as `binary: /usr/bin/bash` with the script
/// path sitting in `arguments` — matching only the binary would never see
/// `/usr/share/omarchy/bin/omarchy-agent-usage-daily`.
pub fn chain_matches_globs(table: &ProcTable, exec_id: &str, patterns: &[String]) -> Option<String> {
    if patterns.is_empty() {
        return None;
    }
    let matchers: Vec<globset::GlobMatcher> = patterns
        .iter()
        .filter_map(|p| match globset::Glob::new(p) {
            Ok(g) => Some(g.compile_matcher()),
            Err(e) => {
                log::warn!("ignoring unparseable glob {:?}: {}", p, e);
                None
            }
        })
        .collect();
    let mut chain: Vec<&ProcInfo> = Vec::new();
    if let Some(me) = table.get(exec_id) {
        chain.push(me);
    }
    chain.extend(table.ancestry(exec_id));
    for p in chain {
        let mut candidates: Vec<&str> = vec![p.exe.as_str()];
        candidates.extend(p.args.split_whitespace());
        for c in candidates {
            if matchers.iter().any(|m| m.is_match(c)) {
                return Some(c.to_string());
            }
        }
    }
    None
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

    /// A table with `fish -> npm -> node` already in it, on a pty.
    ///
    /// The sids and ttys are stated rather than left to `observe`, which reads
    /// them from the real /proc: pid 41101 belongs to whatever happens to be
    /// running on the machine under test, and since 2026-09-05 the tty decides
    /// what these fixtures mean.
    pub fn table_with_install() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-term", 41100, "/usr/bin/alacritty", "", None));
        t.observe(&proc("e-fish", 41101, "/usr/bin/fish", "", Some("e-term")));
        t.observe(&proc("e-npm", 41201, "/usr/bin/npm", "install", Some("e-fish")));
        t.observe(&proc("e-node", 41250, "/usr/bin/node", "install.js", Some("e-npm")));
        for id in ["e-term", "e-fish", "e-npm", "e-node"] {
            t.set_session(id, Some(41100), Some(34821));
        }
        t
    }

    /// A table with no terminal and no pty anywhere: systemd -> node.
    pub fn table_headless() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-sd", 1, "/usr/lib/systemd/systemd", "", None));
        t.observe(&proc("e-node", 41250, "/usr/bin/node", "server.js", Some("e-sd")));
        for id in ["e-sd", "e-node"] {
            t.set_session(id, Some(1), Some(0));
        }
        t
    }

    pub fn cfg() -> Config {
        Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{cfg, proc};
    use super::*;

    #[test]
    fn allowed_parent_globs_match_the_binary_or_any_argument() {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-sd", 1, "/usr/lib/systemd/systemd", "", None));
        // A shebang script is reported as `binary: /usr/bin/bash` with the
        // script path in `arguments`; matching only the binary would miss it.
        t.observe(&proc(
            "e-script",
            5000,
            "/usr/bin/bash",
            "/usr/share/omarchy/bin/omarchy-agent-usage-daily --json",
            Some("e-sd"),
        ));
        t.observe(&proc("e-cli", 5001, "/usr/bin/codex", "exec x", Some("e-script")));

        let pats = cfg().ai.headless_allowed_parents;
        let hit = chain_matches_globs(&t, "e-cli", &pats).expect("the argument must match");
        assert_eq!(hit, "/usr/share/omarchy/bin/omarchy-agent-usage-daily");

        // Same thing when the script itself is the binary.
        let mut t2 = ProcTable::new(8, 60);
        t2.observe(&proc(
            "e-script",
            5000,
            "/usr/share/omarchy/bin/omarchy-agent-usage-weekly",
            "",
            None,
        ));
        t2.observe(&proc("e-cli", 5001, "/usr/bin/claude", "-p x", Some("e-script")));
        assert!(chain_matches_globs(&t2, "e-cli", &pats).is_some());

        // An unrelated omarchy script is not covered, and an empty list never
        // matches anything.
        let mut t3 = ProcTable::new(8, 60);
        t3.observe(&proc("e-script", 5000, "/usr/share/omarchy/bin/omarchy-update", "", None));
        t3.observe(&proc("e-cli", 5001, "/usr/bin/claude", "-p x", Some("e-script")));
        assert!(chain_matches_globs(&t3, "e-cli", &pats).is_none());
        assert!(chain_matches_globs(&t2, "e-cli", &[]).is_none());
        // A broken glob is dropped with a warning, not a panic.
        assert!(chain_matches_globs(&t2, "e-cli", &["[".to_string()]).is_none());
    }

    #[test]
    fn the_sensor_mismatch_rule_explains_itself() {
        let m = sensor_mismatch_meta("because the kernel said so");
        assert_eq!(m.name, SENSOR_MISMATCH);
        assert_eq!(m.severity, "low");
        assert_eq!(m.family, "x");
        assert_eq!(m.why, "because the kernel said so");
        assert_eq!(m.actions, vec!["ignore"]);
        assert!(m.expected.contains("Tetragon"));
    }

    #[test]
    fn every_rule_has_a_unique_id_and_a_toggle() {
        let rules = all();
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "rule ids must be unique");
        assert_eq!(
            n, 14,
            "four gap rules, the four that replaced pkg policies, net-first-contact, \
             the two that read binary_properties (memfd, privileges raised), \
             shell-stdio-socket, and the two ransom rules (file-churn, snapshot-command)"
        );

        // Every rule must be switchable off, or `[rules]` is a lie.
        let mut off = cfg();
        off.rules = crate::config::RuleToggles {
            ai_cli_headless: false,
            pkg_egress: false,
            net_first_contact: false,
            new_exec_ioc: false,
            mass_read: false,
            exec_memfd: false,
            exec_privileges_raised: false,
            pkg_subtree_interpreter_spawn: false,
            pkg_subtree_downloader: false,
            pkg_subtree_netcat_exec: false,
            ai_cli_in_pkg_subtree: false,
            shell_stdio_socket: false,
            ransom_file_churn: false,
            ransom_snapshot_command: false,
        };
        for r in &rules {
            assert!(r.enabled(&cfg()), "{} is off by default", r.id());
            assert!(!r.enabled(&off), "{} has no working toggle", r.id());
        }
    }
}
