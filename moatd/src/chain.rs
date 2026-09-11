//! Sequence correlation: several alerts in one process tree are one story.
//!
//! Every other detection in this daemon fires on one syscall in isolation. That
//! is what a rule engine does, and it is why the following ran on this machine
//! on 2026-09-04 without moat saying anything:
//!
//! ```text
//! node -e "import('moat-is-hijack-simulator')"
//!   16:41:02.1  read ~/.config/<app>/credentials      weak on its own
//!   16:41:02.6  websocket to 192.168.1.14:8081        LAN, unremarkable
//!   16:41:03.4  received a command over that socket   invisible to any rule
//!   16:41:03.9  rewrote its own node_modules source   allowlisted on purpose
//! ```
//!
//! Each line is weak, ambiguous, or deliberately excluded. As a sequence inside
//! one process tree in under two seconds it is unmistakable, and that is the
//! thing this module names: *"the fourth event changes the meaning of the
//! first"* (design README 3a).
//!
//! ## What makes a chain
//!
//! A chain is recognised when, inside one window:
//!
//! 1. **two or more alerts share a process tree** — not "the same session", not
//!    "the same user". See [`tree_key`]: the tree is rooted at the outermost
//!    process below the session boundary, so two commands typed into the same
//!    terminal are two trees, and one `npm install` is one tree however many
//!    processes it forks.
//! 2. **they cross two or more detection families** ([`CHAIN_FAMILIES`]).
//! 3. **at least one of them is `medium` or worse.** Two `low`s crossing
//!    families is what an ordinary package install looks like.
//! 4. **at least one of them is new on this machine** (`first_seen` or `rare`,
//!    LEARNING §1). A build that runs the same shape every afternoon is
//!    `common`, and a chain built out of `common` steps is a description of the
//!    user's job.
//!
//! Conditions 3 and 4 are not decoration. Without them `cargo run` — execute a
//! binary under `$HOME` (`exec`), open a socket (`net`) — is a two-family chain
//! in one tree, every time, on every developer machine in the world.
//!
//! ## Silenced alerts are context, never triggers
//!
//! An alert the user allowlisted joins a chain as a **context** step: it is shown in the story (design 2b wants the whole
//! sequence, that is the point of the screen) but it never counts towards
//! conditions 1-4 and never contributes to escalation. An allowlist entry is
//! the user saying "this event is fine"; honouring that is the promise the
//! whole allowlist rests on. What it is not is a statement about a sequence
//! nobody had seen when the entry was written, so the step still appears.
//!
//! That — and only that — is what `Observation::silenced` means. A noise-guard
//! demotion is **not** one of them: the guard measures frequency, not intent,
//! and a rule that got noisy must still be able to carry a sequence. Being on
//! the timeline is **not** one of them either. `scoring::surface_for` routes
//! by severity alone, so every `medium` and `low` alert is `surface:
//! "timeline"`; treating that as silence is what made moat miss the 20:41 lab
//! run on 2026-09-04, a `persist` write and a `cred` read one second apart in
//! one pid, because the `cred` half was `medium`. Weak-on-its-own is the
//! premise of the feature, not a reason to discount a step.
//!
//! ## Escalation is written down or it does not happen
//!
//! A chain's severity may be **higher than any member** — that is the entire
//! point — but [`escalate`] must name the pattern that raised it in
//! `severity_reason`, in the same `"high -> critical: ..."` shape the scoring
//! module uses. There is no silent path to a higher severity here.
//!
//! Member alerts are left exactly as they were: their own `severity`,
//! `suppressed_by` and `surface` are untouched, because they were decided by
//! rules about single events and are still correct about single events. The
//! chain record is the escalation.
//!
//! ## Bounded
//!
//! Everything here is capped: [`MAX_RECENT`] observations, [`MAX_CHAINS`] live
//! chains, [`MAX_STEPS`] steps in one chain, and every one of them ages out at
//! [`WINDOW_SECS`]. A machine that runs for a month holds the same number of
//! bytes as one that has run for a minute.

use serde::{Deserialize, Serialize};

use crate::alert::{severity_name, severity_rank, Ancestor};
use crate::rarity::Rarity;
use crate::rules::{INTERACTIVE, LOGIN_SHELLS};
use crate::util::basename;

pub const CHAIN_V: u32 = 1;

/// The eight detection families a chain may be built from.
///
/// Two are deliberately missing. `x` is moat's own housekeeping
/// (`moat-x-noisy-rule`, `moat-x-sensor-mismatch`, `moat-x-baseline-revoked`):
/// letting the daemon's self-diagnostics cross a family boundary would let moat
/// correlate its own noise into an incident. `ai` (`moat-x-ai-cli-headless`,
/// `moat-ai-cli-in-pkg-subtree`) is left out because an AI CLI is the single
/// busiest thing on the machine this was built for; it belongs in a chain as
/// evidence, not as one of the two families that creates one.
pub const CHAIN_FAMILIES: &[&str] = &[
    "cred", "net", "persist", "exec", "priv", "rootkit", "pkg", "shell", "ransom",
];

/// How far apart two alerts may be and still be one story.
///
/// Ten minutes, from design 3a: "Four things happened in nine minutes and they
/// were all the same program."
///
/// It is a sliding window, not a fixed one: an alert stays a chain candidate
/// while it is younger than this, and a chain that has not been touched for
/// this long is closed and its memory released. So an attack that keeps acting
/// keeps its chain alive, and a chain never spans a silence longer than the
/// window. `MAX_SPAN_SECS` is the other end of that.
pub const WINDOW_SECS: u64 = 600;

/// A chain that has been growing for this long stops accepting members even if
/// something touches it every nine minutes. Without this a long-lived daemon
/// (a build server, a desktop left on for a week) can hold one chain open
/// indefinitely and keep rewriting it.
pub const MAX_SPAN_SECS: u64 = 3_600;

/// Steps kept in one chain. Beyond this the count keeps rising and
/// `truncated` is set, because a story nobody can read is not a story, and
/// because every member alert carries a copy of the whole chain.
pub const MAX_STEPS: usize = 12;

/// Live chains held in memory. Oldest-touched is evicted first.
pub const MAX_CHAINS: usize = 32;

/// Alerts held as chain candidates. Sized so a burst cannot push a real
/// sequence out of the buffer before its second family arrives.
///
/// 2026-09-08: at 128 that sentence was false on this machine. One `cargo test`
/// of moatd itself put 330 chain-family observations into a single 60-second
/// window, which turns the whole ring over in about 23 seconds; of 997 measured
/// (credential read -> network) row pairs, 375 had more than 128 observations
/// pushed between them and so could never have met. That is also a cheap
/// blinding primitive: an unprivileged loop of allowlisted execs flushes every
/// pending candidate on the machine in under half a minute.
///
/// An `Observation` is small and the ring is per-daemon, so the memory this
/// costs is measured in tens of kilobytes. The eviction is still oldest-first
/// and everything still ages out at `WINDOW_SECS`; this only stops a burst
/// from being able to outrun the window.
pub const MAX_RECENT: usize = 1024;

/// One alert's place in the story.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The alert id this step is; `moatctl explain <id>` opens it.
    pub alert: String,
    pub ts: String,
    pub family: String,
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub pid: u32,
    pub exe: String,
    /// `trigger` — counted towards the chain and its severity — or `context`,
    /// which is an allowlisted or demoted alert shown for the story only.
    pub role: String,
}

impl Step {
    pub fn is_trigger(&self) -> bool {
        self.role == "trigger"
    }
}

/// What the alert record gains when its alert turns out to be part of a
/// sequence. Every member carries the whole chain, so a reader that opened one
/// alert can render design 2b without joining anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chain {
    pub v: u32,
    /// The id of the chain's first step, so a chain is namable and stable as it
    /// grows.
    pub id: String,
    /// The process every step descends from: the story's subject.
    pub ancestor: Ancestor,
    /// Families crossed by the trigger steps, in first-seen order.
    pub families: Vec<String>,
    /// May be higher than any member. `severity_reason` says why.
    pub severity: String,
    /// The highest severity any single member reached on its own.
    pub severity_base: String,
    /// One of three shapes, and never empty:
    /// `"high -> critical: <the pattern that raised it>"` when a sequence moved
    /// it, `"stays critical: <the pattern> — already at the highest severity"`
    /// when the pattern matched but a member was already at the ceiling, and
    /// `"stays high: cred and pkg in one process tree, no escalating sequence"`
    /// when nothing matched.
    pub severity_reason: String,
    pub first_ts: String,
    pub last_ts: String,
    pub span_secs: u64,
    /// In time order, oldest first. Trigger and context steps interleaved.
    pub steps: Vec<Step>,
    /// Steps seen; larger than `steps.len()` once `MAX_STEPS` is reached.
    pub steps_total: usize,
    pub truncated: bool,
    /// Every alert in this chain, including the ones past `MAX_STEPS`.
    ///
    /// Separate from `steps` because the two answer different questions.
    /// `steps` is the STORY, and it is capped so a busy tree cannot write an
    /// unbounded record onto every member. `members` is the SET, and capping
    /// it silently unstamped every alert past the twelfth: they helped form or
    /// grow the chain, `moatctl ack --chain` did not cover them, and the badge
    /// kept asking about alerts the user had already answered as part of a
    /// sequence.
    ///
    /// `#[serde(default)]` so chains written before this field existed still
    /// load; `member_ids()` falls back to `steps` for those.
    #[serde(default)]
    pub members: Vec<String>,
    /// How many of `steps_total` were TRIGGERS rather than context.
    ///
    /// Tracked because the headline has to say what moat is actually claiming
    /// happened, and `steps` is capped: on a truncated chain the stored steps
    /// cannot be counted to find out. Without it the summary said "128 things
    /// happened" (context and allowlisted reads included) and then "26 more
    /// were already allowed" -- adding a number that was already inside the
    /// first one.
    #[serde(default)]
    pub triggers_total: usize,
    /// One plain sentence about the sequence, for the verdict line of 3a.
    pub summary: String,
}

impl Chain {
    pub fn severity_rank(&self) -> u8 {
        severity_rank(&self.severity)
    }
    /// The ids of every alert in the chain — what a chain-level ack acts on.
    pub fn member_ids(&self) -> Vec<String> {
        if self.members.is_empty() {
            // A record from before `members` existed.
            return self.steps.iter().map(|s| s.alert.clone()).collect();
        }
        self.members.clone()
    }
}

/// One node of an alert's lineage: the acting process first, then its ancestors
/// nearest first, exactly as `ProcTable::ancestry` orders them.
#[derive(Debug, Clone)]
pub struct LineageNode {
    pub exec_id: String,
    pub pid: u32,
    pub exe: String,
    /// POSIX session id, when /proc could be read at exec time. This is what
    /// makes `is_boundary` a question about what a process IS rather than what
    /// it is called.
    pub sid: Option<u32>,
}

/// Everything the correlator needs about one alert, so it can be driven from a
/// test without a daemon.
#[derive(Debug, Clone)]
pub struct Observation {
    pub alert: String,
    /// RFC3339, as written into the alert record.
    pub ts: String,
    /// Unix seconds, for the window arithmetic.
    pub at: u64,
    pub family: String,
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub rarity: Rarity,
    /// Suppressed by the user's own allowlist. THAT is consent, and honouring
    /// it is the promise the allowlist rests on.
    ///
    /// A noise-guard demotion is deliberately NOT this: it is moat's own
    /// arithmetic about how often a rule fires here, and frequency is not
    /// consent. See the note in `engine.rs` where this is set.
    pub silenced: bool,
    /// Acting process first, then ancestors nearest first.
    pub lineage: Vec<LineageNode>,
}

impl Observation {
    fn rank(&self) -> u8 {
        severity_rank(&self.severity)
    }
    fn is_novel(&self) -> bool {
        !self.rarity.is_common()
    }
    fn step(&self, trigger: bool) -> Step {
        let me = self.lineage.first();
        Step {
            alert: self.alert.clone(),
            ts: self.ts.clone(),
            family: self.family.clone(),
            rule: self.rule.clone(),
            severity: self.severity.clone(),
            title: self.title.clone(),
            pid: me.map(|n| n.pid).unwrap_or(0),
            exe: me.map(|n| n.exe.clone()).unwrap_or_default(),
            role: if trigger { "trigger" } else { "context" }.into(),
        }
    }
}

/// Is this family one a chain may be built from?
pub fn is_chain_family(family: &str) -> bool {
    CHAIN_FAMILIES.contains(&family)
}

/// Is this process the end of the tree rather than part of it?
///
/// A session boundary is something *everything* on the desktop descends from,
/// so treating it as a shared ancestor would put every alert on the machine in
/// one chain. Three shapes:
///
/// * pid 1, and both systemd instances (system and `--user`);
/// * a terminal, multiplexer, editor or `sshd` — the `INTERACTIVE` list, which
///   already exists because `moat-x-ai-cli-headless` needs the same question
///   answered;
/// * a login shell whose own parent is one of those. This is the distinction
///   that matters most: a `bash` sitting under `alacritty` is where you type
///   two unrelated commands, while a `bash` under `npm` is a build step and a
///   perfectly good root for a story. When the parent is unknown (the ancestry
///   was pruned or hit its cap) a bare shell is treated as a boundary, because
///   the common case for an orphaned shell is a login shell.
pub fn is_boundary(exe: &str, parent_exe: Option<&str>, pid: u32, sid: Option<u32>) -> bool {
    let comm = basename(exe);
    if pid == 1 || comm == "systemd" || comm == "init" {
        return true;
    }
    // The kernel's own answer, and the only one that generalises.
    //
    // A session leader IS a session boundary -- that is what the id means. A
    // terminal, a multiplexer pane, an `sshd` session and anything else that
    // called setsid() all say so themselves, whatever the binary is named.
    //
    // The name list below is the fallback for when /proc could not be read
    // (the process had already exited), and it is a fallback rather than the
    // rule because a hardcoded set of terminal names fails silently for every
    // terminal nobody thought of: on 2026-09-04 `herdr` was missing from it,
    // became the root of every tree beneath it, and an AUR attack was welded to
    // three unrelated connections from a Claude session minutes earlier. The
    // kernel had known all along -- herdr was sid == pid.
    if sid == Some(pid) {
        return true;
    }
    if INTERACTIVE.contains(&comm) {
        return true;
    }
    if LOGIN_SHELLS.contains(&comm) {
        return match parent_exe {
            Some(p) => INTERACTIVE.contains(&basename(p)),
            None => true,
        };
    }
    false
}

/// The exec_id of the process this alert's tree is rooted at.
///
/// Walks outward from the acting process and stops at the first session
/// boundary; the last non-boundary process before it is the root. The acting
/// process itself is always eligible, so an alert *on* a terminal still gets a
/// key (its own) rather than none.
///
/// This is what makes "same process tree" mean the same thing for every alert:
/// two alerts are in one tree exactly when they agree on this key. It costs one
/// walk of an already-capped list and no pairwise comparison.
pub fn tree_key(lineage: &[LineageNode]) -> Option<(String, Ancestor)> {
    let first = lineage.first()?;
    let mut root = first;
    for (i, node) in lineage.iter().enumerate() {
        let parent = lineage.get(i + 1).map(|p| p.exe.as_str());
        // A process does not get to nominate ITSELF as a session boundary.
        //
        // `setsid()` is one call, so a payload can make `sid == pid` true of
        // itself whenever it likes. Testing the acting process meant a dropper
        // running inside a package build could step out of that build's tree --
        // the walk stopped at the dropper, its key became its own exec id, and
        // it correlated with nothing. That is a one-line evasion of the
        // sequence detection this module exists for.
        //
        // Ancestors are still tested, which is the case the signal was added
        // for: a terminal or multiplexer pane above the alert is a real session
        // boundary and the kernel says so. An alert ON a session leader still
        // gets a key -- its own -- because `root` starts at `first`.
        if i > 0 && is_boundary(&node.exe, parent, node.pid, node.sid) {
            break;
        }
        root = node;
    }
    // An unidentified process has no tree. Without this every alert whose
    // `exec_id` the table never learned would share the empty key, which is the
    // one way this module could merge genuinely unrelated alerts.
    if root.exec_id.is_empty() {
        return None;
    }
    Some((
        root.exec_id.clone(),
        // Identity only. Chain grouping is keyed on exec_id and this pair, and
        // must not start depending on the detail the panel reads.
        Ancestor::new(root.pid, root.exe.clone()),
    ))
}

/// What escalation actually reads. **Not** the step list.
///
/// [`Chain::steps`] is the STORY, and it is capped at [`MAX_STEPS`] because the
/// whole chain record is copied onto every member alert: an uncapped list on a
/// busy tree writes an enormous record, many times over. Correlation is a
/// different job with a different bound. It has to see EVERY observation, or the
/// thirteenth thing that happens in a tree cannot change what moat concluded
/// about the first twelve.
///
/// Running [`escalate`] over `steps` conflated the two, and a display limit
/// ended up governing detection: a chain that formed early out of ordinary build
/// noise filled its twelve slots and then took a credential read as step 13 —
/// which never appeared in `families`, never fired the `cred -> net` rung, and
/// left the severity where the build noise had put it.
///
/// So this holds the *answers* rather than the evidence, and every field is a
/// fixed size whatever the tree does: at most eight families (there are eight),
/// one rank each, a count, a last family, and three booleans of ordered
/// progress. It is folded on every trigger observation, whether or not the story
/// had room for that step.
///
/// Only triggers are offered to it. A step the user allowlisted cannot raise a
/// severity, or an allowlist entry would become a way to make moat shout louder.
#[derive(Debug, Clone, Default)]
pub struct Escalation {
    /// Trigger families in first-seen order — this is `Chain::families`.
    families: Vec<String>,
    /// The highest severity rank any trigger of that family reached, aligned
    /// with `families`. This is what `rung_is_real` asks.
    family_rank: Vec<u8>,
    /// The highest severity rank any single trigger reached: `severity_base`.
    max_rank: u8,
    /// Triggers seen, ever. The `anything -> persist` rung wants two.
    triggers: usize,
    /// The family of the most recent trigger, for the same rung.
    last: Option<String>,
    /// Greedy subsequence progress for the two ORDERED rungs, folded forward
    /// instead of re-scanned. Keeping the full family sequence would be the
    /// unbounded thing all over again; these three booleans answer exactly what
    /// `cred -> net` and `cred -> net -> persist` used to be scanned for, and
    /// they answer it identically because the scan was greedy too.
    cred: bool,
    cred_then_net: bool,
    cred_then_net_then_persist: bool,
    /// At least one trigger was `first_seen` or `rare` (LEARNING §1).
    ///
    /// `qualifies()` requires this to FORM a chain and no rung reads it today;
    /// it is tracked here because it is part of the same question — what is true
    /// of this sequence — and because deriving it from a capped list later would
    /// be the identical bug.
    novel: bool,
}

impl Escalation {
    /// Fold in one trigger. `family` and `severity` are the step's own.
    pub fn observe(&mut self, family: &str, severity: &str, novel: bool) {
        let rank = severity_rank(severity);
        self.triggers += 1;
        self.max_rank = self.max_rank.max(rank);
        self.novel |= novel;
        match self.families.iter().position(|f| f == family) {
            Some(i) => self.family_rank[i] = self.family_rank[i].max(rank),
            None => {
                self.families.push(family.to_string());
                self.family_rank.push(rank);
            }
        }
        self.last = Some(family.to_string());
        match family {
            "cred" => self.cred = true,
            "net" if self.cred => self.cred_then_net = true,
            "persist" if self.cred_then_net => self.cred_then_net_then_persist = true,
            _ => {}
        }
    }

    /// Families crossed by the triggers, in the order they were first seen.
    pub fn families(&self) -> &[String] {
        &self.families
    }

    /// Was any trigger new on this machine?
    pub fn has_novel_trigger(&self) -> bool {
        self.novel
    }

    fn has(&self, f: &str) -> bool {
        self.families.iter().any(|x| x == f)
    }

    /// Is the step that would carry a rung worth a rung?
    ///
    /// A combination rung says "this family, beside others, is worse than either
    /// alone". That only holds if the step itself was worth reporting: a `low`
    /// finding is one moat has already decided is barely news, and letting it
    /// raise a whole chain's severity means the chain says something none of its
    /// members do.
    fn rung_is_real(&self, families: &[&str]) -> bool {
        self.families
            .iter()
            .zip(self.family_rank.iter())
            .any(|(f, r)| families.contains(&f.as_str()) && *r >= severity_rank("medium"))
    }

    /// The state a list of steps implies. The formation path has the
    /// observations themselves and folds those instead; this is for callers
    /// that only hold the steps, and for the tests that drive the ladder
    /// directly.
    ///
    /// Novelty is not carried on a [`Step`], and no rung reads it, so it is
    /// `false` here. A live chain folds the real answer in.
    fn from_steps(steps: &[Step]) -> Escalation {
        let mut e = Escalation::default();
        for s in steps.iter().filter(|s| s.is_trigger()) {
            e.observe(&s.family, &s.severity, false);
        }
        e
    }
}

/// The severity of a sequence, and the sentence that justifies it.
///
/// The ladder, strongest first. Each rung is a shape that means something
/// specific, not a count of alerts:
///
/// | shape (in time order)          | result                                  |
/// |--------------------------------|-----------------------------------------|
/// | `cred` -> `net` -> `persist`   | `critical`: read, sent, and made durable |
/// | `cred` -> `net`                | one step up, at least `high`             |
/// | `rootkit` or `priv` + anything | one step up                              |
/// | anything -> `persist`          | one step up                              |
/// | four or more families          | one step up                              |
///
/// Nothing here can raise a chain by more than one step except the first rung,
/// which is the full theft shape and is `critical` by definition.
pub fn escalate_state(e: &Escalation) -> (String, String, String) {
    let base = e.max_rank;
    let base_name = severity_name(base).to_string();

    let families = e.families();
    let has = |f: &str| e.has(f);

    // `matched` says a named shape fired, which is a different fact from
    // "the rank went up": a chain whose worst member is already critical
    // cannot go up, and the shape is still the finding.
    let (rank, why, matched) = if e.cred_then_net_then_persist {
        (
            3,
            "a credential was read, this tree then connected out, and then it \
             arranged to run again"
                .to_string(),
            true,
        )
    } else if e.cred_then_net {
        (
            base.saturating_add(1).max(2),
            "a credential was read and the same process tree then connected out".to_string(),
            true,
        )
    // The combination-only rungs additionally require the ESCALATING step to
    // be at least `medium` -- the same floor `qualifies()` already applies to
    // form a chain at all.
    //
    // Without it a `low` signal carries a whole rung on its own, which is how
    // an ordinary package update reached critical: one setuid chmod that
    // granted no privilege, beside the net and pkg families every source build
    // produces. This does not touch the ORDERED rungs below `cred -> net`: a
    // sequence is meaningful even when each step is ordinary, and that is the
    // whole reason chains exist.
    } else if (has("rootkit") || has("priv")) && families.len() >= 2 && e.rung_is_real(&["rootkit", "priv"]) {
        (
            base.saturating_add(1),
            format!(
                "{} in the same tree as {}",
                if has("rootkit") { "a rootkit signal" } else { "a privilege signal" },
                other_families(families, if has("rootkit") { "rootkit" } else { "priv" })
            ),
            true,
        )
    } else if e.triggers >= 2
        && e.last.as_deref() == Some("persist")
        && e.rung_is_real(&["persist"])
    {
        (
            base.saturating_add(1),
            "the sequence ended by arranging to run again".to_string(),
            true,
        )
    } else if families.len() >= 4 {
        (
            base.saturating_add(1),
            format!("{} different kinds of behaviour in one process tree", families.len()),
            true,
        )
    } else {
        (
            base,
            format!(
                "{} in one process tree, no escalating sequence",
                list(families)
            ),
            false,
        )
    };

    let rank = rank.min(3);
    let name = severity_name(rank).to_string();
    let reason = if rank > base {
        format!("{} -> {}: {}", base_name, name, why)
    } else if matched {
        // The shape matched but a member was already at the ceiling. Saying
        // only "stays critical" would hide the sequence that is the actual
        // finding, and printing an arrow that did not happen would be a lie.
        format!("stays critical: {} — already at the highest severity", why)
    } else {
        format!("stays {}: {}", name, why)
    };
    (name, base_name, reason)
}

/// [`escalate_state`] over a list of steps, in time order.
///
/// A convenience for callers holding only the story — the tests below, mostly.
/// A LIVE chain must never come through here: `steps` is capped, and reading a
/// capped list is the bug [`Escalation`] exists to close.
pub fn escalate(steps: &[Step]) -> (String, String, String) {
    escalate_state(&Escalation::from_steps(steps))
}

fn other_families(families: &[String], except: &str) -> String {
    list(&families.iter().filter(|f| *f != except).cloned().collect::<Vec<_>>())
}

/// `"cred and net"`, `"cred, net and persist"` — the copy rules of design 3g
/// forbid a bare comma-joined list in a sentence.
fn list(items: &[String]) -> String {
    match items.len() {
        0 => "nothing".to_string(),
        1 => items[0].clone(),
        n => format!("{} and {}", items[..n - 1].join(", "), items[n - 1]),
    }
}

/// "2 seconds", "9 minutes", "3 hours" — never "0 seconds".
pub fn human_span(secs: u64) -> String {
    let (n, unit) = if secs < 120 {
        (secs.max(1), "second")
    } else if secs < 7_200 {
        (secs / 60, "minute")
    } else {
        (secs / 3_600, "hour")
    };
    format!("{} {}{}", n, unit, if n == 1 { "" } else { "s" })
}

/// The chain's own sentence: what happened, over how long, under what.
///
/// `families` is passed in rather than derived from the steps, for the same
/// reason the counts are: on a truncated chain the step list is twelve of a
/// hundred and twenty-eight, and a sentence that says "crossing net and exec"
/// beside a `families` array that says `cred` too is a record disagreeing with
/// itself. See [`Escalation`].
fn summarise(
    families: &[String],
    ancestor: &Ancestor,
    span: u64,
    total: usize,
    triggers_total: usize,
) -> String {
    // From the durable counters, not from the capped step list: on a truncated
    // chain `steps` holds twelve of a hundred and twenty-eight, and counting
    // it would understate both halves.
    let silenced = total.saturating_sub(triggers_total);
    // The headline counts what moat is ACTUALLY saying happened.
    //
    // `total` counts every observation in the tree, including steps the user
    // has already allowed and steps the noise guard demoted -- so an ordinary
    // package build read "128 things happened", of which 26 were explicitly
    // allowed and most of the rest were rules moat had itself decided were
    // routine. That number frightened without informing, and it is the first
    // thing anyone reads. The context steps are still listed underneath, and
    // the "already allowed" sentence below still accounts for them.
    //
    // `total` is also a checkpoint rather than a total on a growing chain --
    // republishing happens on powers of two -- which is a second reason not to
    // put it in the headline.
    let counted = triggers_total;
    let mut s = format!(
        "{} things happened in {} under {} (pid {}), crossing {}.",
        counted,
        human_span(span),
        basename(&ancestor.exe),
        ancestor.pid,
        list(families),
    );
    if silenced > 0 {
        // `steps` is capped at MAX_STEPS while `total` is not, so on a
        // truncated chain the count is a floor, not the figure. Saying "3 of
        // them" when only twelve of forty steps were counted would be a
        // straightforwardly false sentence.
        // "MORE", not "of them": the headline now counts triggers only, so
        // the allowed steps are in addition to it rather than a subset of it.
        // Getting this wrong would be the same class of error as the count
        // itself -- a sentence whose arithmetic does not close.
        // Exact in both cases now: both numbers come from counters that keep
        // counting after `steps` stops growing, so there is no "at least".
        s.push_str(&format!(
            " {} more {} already allowed on {} own.",
            silenced,
            if silenced == 1 { "was" } else { "were" },
            if silenced == 1 { "its" } else { "their" },
        ));
    }
    s
}

/// A candidate held in the ring while it waits for a second family.
#[derive(Debug, Clone)]
struct Recent {
    obs: Observation,
    tree: String,
    /// Set once this observation has been folded into a chain, so a chain that
    /// grows does not re-add the steps it already has.
    chained: bool,
}

/// One live chain, plus the bookkeeping the record does not carry.
#[derive(Debug, Clone)]
struct Live {
    chain: Chain,
    tree: String,
    first_at: u64,
    last_at: u64,
    /// Correlation state, folded on EVERY observation. `chain.steps` stops at
    /// [`MAX_STEPS`]; this does not, which is why severity and families are
    /// read from here and never from the step list. See [`Escalation`].
    state: Escalation,
}

/// The correlator. Bounded in every direction; see the module comment.
#[derive(Debug, Default)]
pub struct ChainStore {
    recent: Vec<Recent>,
    live: Vec<Live>,
    /// Chains recognised since start, for `status`.
    pub formed: u64,
}

impl ChainStore {
    pub fn new() -> ChainStore {
        ChainStore::default()
    }

    /// Live chains right now. Not the historical record — that is on disk, in
    /// the `chain` field of every member alert.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// The live chains, whether or not their latest state has been published.
    /// `status` counts them and tests read them; the record on disk is still
    /// the source of truth for anything a user acts on.
    pub fn open(&self) -> impl Iterator<Item = &Chain> {
        self.live.iter().map(|c| &c.chain)
    }

    /// Drop everything outside the window. Called on every observation, so the
    /// bound holds even if the daemon's periodic tick never runs, and from the
    /// tick, so an idle machine does not hold a closed chain for ever.
    pub fn prune(&mut self, now: u64) {
        self.recent
            .retain(|r| now.saturating_sub(r.obs.at) <= WINDOW_SECS);
        self.live.retain(|c| {
            now.saturating_sub(c.last_at) <= WINDOW_SECS
                && now.saturating_sub(c.first_at) <= MAX_SPAN_SECS
        });
    }

    /// Offer one alert to the correlator.
    ///
    /// Returns the chain it created or grew, or `None` — which is the answer
    /// almost every time, and has to stay cheap for that reason. The caller
    /// writes the returned chain onto every member alert.
    pub fn note(&mut self, obs: Observation) -> Option<Chain> {
        if !is_chain_family(&obs.family) {
            return None;
        }
        self.prune(obs.at);
        let (tree, ancestor) = tree_key(&obs.lineage)?;

        // Growing an existing chain first: once a sequence is recognised,
        // everything else in that tree belongs to the story, silenced or not.
        if let Some(i) = self.live.iter().position(|c| c.tree == tree) {
            let step = obs.step(!obs.silenced);
            let at = obs.at;
            let ts = step.ts.clone();
            let novel = obs.is_novel();
            self.push_recent(Recent { obs, tree, chained: true });
            let c = &mut self.live[i];
            let was_severity = c.chain.severity.clone();
            let was_families = c.chain.families.clone();
            c.last_at = at;

            // A STEP IS AN ALERT, AND AN ALERT APPEARS ONCE.
            //
            // `members` was already deduped by alert id; `steps`, `steps_total`
            // and -- the one that matters -- `state.observe` were not. That was
            // harmless while a fold RETURNED before `note_chain`, because a
            // repeat never arrived here. Since 2026-09-07 it does, so the same
            // alert re-observed 69 times (kubectl, one destination) would have
            // added 69 steps, counted 69 things as having happened, and fed the
            // severity machine 69 times off one event.
            //
            // "Sixteen things happened in two seconds" has to mean sixteen
            // THINGS. A repeat updates when the chain was last active and
            // nothing else.
            let already = c.chain.members.contains(&step.alert);
            if !already {
                c.chain.steps_total += 1;
                if step.is_trigger() {
                    c.chain.triggers_total += 1;
                    // BEFORE the cap, and regardless of it. This is the whole
                    // fix: the thirteenth observation still gets to change the
                    // verdict even though the story has no room to show it.
                    c.state.observe(&step.family, &step.severity, novel);
                }
                // The member is recorded whether or not the story has room.
                c.chain.members.push(step.alert.clone());
            }
            let added = !already && c.chain.steps.len() < MAX_STEPS;
            if added {
                c.chain.steps.push(step);
            } else if !already {
                c.chain.truncated = true;
            }
            c.chain.last_ts = ts;
            c.chain.span_secs = c.last_at.saturating_sub(c.first_at);
            // From the correlation state, never from `c.chain.steps`: the step
            // list is a capped presentation of the story and answering "what did
            // this tree do" out of it made MAX_STEPS a detection threshold.
            let (sev, base, reason) = escalate_state(&c.state);
            c.chain.severity = sev;
            c.chain.severity_base = base;
            c.chain.severity_reason = reason;
            let families = c.state.families().to_vec();
            c.chain.summary = summarise(
                &families,
                &c.chain.ancestor,
                c.chain.span_secs,
                c.chain.steps_total,
                c.chain.triggers_total,
            );
            c.chain.families = families;
            // Republishing costs one update line per member, so a tree that
            // trips a hundred distinct detections would otherwise write twelve
            // hundred lines and rotate `alerts.jsonl` inside one incident.
            // Once the step list is full the story on disk stops changing, so
            // publish only when it actually does: a step was added, the
            // severity moved, a new family appeared, or the count doubled —
            // which keeps the "and N more" line roughly honest at O(log n)
            // extra writes.
            let changed = added
                || c.chain.severity != was_severity
                || c.chain.families != was_families
                || c.chain.steps_total.is_power_of_two();
            if !changed {
                return None;
            }
            return Some(c.chain.clone());
        }

        // Not in a chain yet: does this observation complete one?
        let at = obs.at;
        let mut candidate: Vec<Observation> = self
            .recent
            .iter()
            .filter(|r| r.tree == tree && !r.chained)
            .map(|r| r.obs.clone())
            .collect();
        candidate.push(obs.clone());
        // Ids are monotonic, so an id sort is a time sort even when two alerts
        // share a millisecond — the reason `Daemon::next_id` exists.
        candidate.sort_by(|a, b| a.alert.cmp(&b.alert));

        let formed = qualifies(&candidate);
        self.push_recent(Recent {
            obs,
            tree: tree.clone(),
            chained: formed,
        });
        if !formed {
            return None;
        }
        for r in self.recent.iter_mut() {
            if r.tree == tree {
                r.chained = true;
            }
        }

        // Formation is deliberately NOT capped at MAX_STEPS, and that is not
        // an oversight -- it was tried on 2026-09-05 and reverted the same
        // hour.
        //
        // `member_ids()` is derived from `steps`, and the engine stamps the
        // chain onto exactly those alerts. Truncating here therefore does not
        // just shorten a story: it silently drops members, so an alert that
        // helped form the chain is left with `chain: None` and never reaches
        // the badge as part of it. The test
        // `a_noise_demoted_alert_is_still_a_chain_trigger` catches it.
        //
        // So the real bound at formation is MAX_RECENT (the correlator's own
        // window), not MAX_STEPS. Growth past formation IS capped, and sets
        // `truncated`. Anything claiming this record holds at most MAX_STEPS
        // lines is describing growth only.
        let steps: Vec<Step> = candidate
            .iter()
            .map(|o| o.step(!o.silenced))
            .collect();
        let total = steps.len();
        let formation_truncated = false;
        let first_at = candidate.first().map(|o| o.at).unwrap_or(at);
        let span = at.saturating_sub(first_at);
        // Folded from the OBSERVATIONS, in time order, so the live chain starts
        // with the real novelty answer rather than the one a `Step` can carry.
        // `candidate` is not capped, so this and `escalate(&steps)` agree here;
        // they stop agreeing the moment the chain grows, which is the point.
        let mut state = Escalation::default();
        for o in candidate.iter().filter(|o| !o.silenced) {
            state.observe(&o.family, &o.severity, o.is_novel());
        }
        let (severity, severity_base, severity_reason) = escalate_state(&state);
        let families = state.families().to_vec();
        let chain = Chain {
            v: CHAIN_V,
            id: steps[0].alert.clone(),
            ancestor: ancestor.clone(),
            severity,
            severity_base,
            severity_reason,
            first_ts: steps[0].ts.clone(),
            last_ts: steps[steps.len() - 1].ts.clone(),
            span_secs: span,
            summary: summarise(
                &families,
                &ancestor,
                span,
                total,
                steps.iter().filter(|x| x.is_trigger()).count(),
            ),
            families,
            members: steps.iter().map(|x| x.alert.clone()).collect(),
            triggers_total: steps.iter().filter(|x| x.is_trigger()).count(),
            steps,
            steps_total: total,
            truncated: formation_truncated,
        };
        self.formed += 1;
        if self.live.len() >= MAX_CHAINS {
            // Oldest activity goes first: a chain nothing has touched is the
            // one least likely to grow again.
            if let Some(i) = self
                .live
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| c.last_at)
                .map(|(i, _)| i)
            {
                self.live.remove(i);
            }
        }
        self.live.push(Live {
            state,
            chain: chain.clone(),
            tree,
            first_at,
            last_at: at,
        });
        Some(chain)
    }

    fn push_recent(&mut self, r: Recent) {
        // One slot per ALERT, not per observation. `note_chain` re-enters every
        // time a chain grows and (since 2026-09-07) folds re-observe an alert
        // that is already here, so without this the same id occupies slot after
        // slot and evicts genuine candidates to make room for copies of itself.
        if let Some(seat) = self.recent.iter_mut().find(|x| x.obs.alert == r.obs.alert) {
            *seat = r;
            return;
        }
        if self.recent.len() >= MAX_RECENT {
            self.recent.remove(0);
        }
        self.recent.push(r);
    }
}

/// The four conditions of the module comment, against a tree's observations in
/// time order. This is the whole false-positive surface of the feature, so it
/// is one readable function rather than four scattered guards.
fn qualifies(obs: &[Observation]) -> bool {
    let triggers: Vec<&Observation> = obs.iter().filter(|o| !o.silenced).collect();
    if triggers.len() < 2 {
        return false;
    }
    let mut families: Vec<&str> = triggers.iter().map(|o| o.family.as_str()).collect();
    families.sort_unstable();
    families.dedup();
    if families.len() < 2 {
        return false;
    }
    if !triggers.iter().any(|o| o.rank() >= severity_rank("medium")) {
        return false;
    }
    // Novelty is required so a machine doing the SAME benign thing every day
    // does not chain -- a build that runs one shape each afternoon is not a
    // sequence worth raising. But some triggers are conclusions that repetition
    // does not launder: a credential HARVEST (one process reading many
    // distinct secret files in seconds) is exfil-shaped whether it is the first
    // time or the fiftieth, and requiring it to also be "new on this machine"
    // meant a repeated attack to a familiar host stopped chaining once the
    // rarity settled. So a novelty-exempt trigger satisfies condition 4 on its
    // own. This is not scenario-specific: it keys on the general harvest
    // detector, not on any one payload.
    if !triggers.iter().any(|o| o.is_novel() || is_novelty_exempt(&o.rule)) {
        return false;
    }
    true
}

/// Triggers whose mere presence is enough to correlate, novel or not: a
/// conclusion that repeating does not make benign. Kept deliberately small.
fn is_novelty_exempt(rule: &str) -> bool {
    matches!(
        rule,
        // A credential harvest -- N distinct secret files read in seconds.
        "moat-x-mass-read"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node that reports its session, for the boundary tests.
    fn node_sid(exec_id: &str, pid: u32, exe: &str, sid: u32) -> LineageNode {
        LineageNode { exec_id: exec_id.into(), pid, exe: exe.into(), sid: Some(sid) }
    }

    fn node(exec_id: &str, pid: u32, exe: &str) -> LineageNode {
        LineageNode {
            exec_id: exec_id.into(),
            pid,
            exe: exe.into(), sid: None }
    }

    /// The tree of the 2026-09-04 simulation: one `node -e` typed at a shell.
    fn typed_at_a_shell(pid: u32) -> Vec<LineageNode> {
        vec![
            node(&format!("n-{}", pid), pid, "/usr/bin/node"),
            node("f-1", 900, "/usr/bin/fish"),
            node("a-1", 800, "/usr/bin/alacritty"),
            node("s-1", 1, "/usr/lib/systemd/systemd"),
        ]
    }

    fn obs(id: &str, at: u64, family: &str, sev: &str, lineage: Vec<LineageNode>) -> Observation {
        Observation {
            alert: id.into(),
            ts: crate::util::rfc3339_of(at),
            at,
            family: family.into(),
            rule: format!("moat-{}-something", family),
            severity: sev.into(),
            title: format!("a {} thing happened", family),
            rarity: Rarity::FirstSeen,
            silenced: false,
            lineage,
        }
    }

    // ------------------------------------------------------------ the tree

    /// `setsid` must not be an escape hatch from correlation.
    ///
    /// The session-id boundary is a kernel fact and the right signal for an
    /// ancestor -- but `setsid()` is one call, so a payload can assert it of
    /// itself. Testing the acting process let a dropper inside a package build
    /// step out of that build's tree and correlate with nothing, which is a
    /// one-line evasion of the whole sequence detection.
    /// "Sixteen things happened in two seconds" has to mean sixteen THINGS.
    ///
    /// Since 2026-09-07 a folded event reaches correlation (so a second process
    /// tree's step cannot vanish), which means the SAME alert id can arrive
    /// here many times -- kubectl produced 69 for one destination. Only
    /// `members` was deduped; steps, the total, and the severity machine were
    /// not, so one event would have counted as sixty-nine.
    #[test]
    fn one_alert_arriving_many_times_is_one_step() {
        let mut store = ChainStore::default();

        // Two genuinely different things: a chain forms and says so.
        store.note(obs("01SAME", 1_000, "net", "low", typed_at_a_shell(5000)));
        let c = store
            .note(obs("01OTHER", 1_001, "persist", "medium", typed_at_a_shell(5000)))
            .expect("two different things is a sequence");
        assert_eq!(c.steps_total, 2);

        // Now the SAME alert arrives forty more times, which is what a folded
        // event does since `emit` started correlating on the fold path.
        let mut last = c;
        for i in 0..40 {
            if let Some(c) = store.note(obs("01SAME", 1_002 + i, "net", "low", typed_at_a_shell(5000))) {
                last = c;
            }
        }
        assert_eq!(last.steps_total, 2, "forty arrivals of a known alert is still two things");
        assert_eq!(last.steps.len(), 2, "and two steps in the story");
        assert_eq!(last.members.len(), 2);
        assert!(!last.truncated, "a repeat must not look like a truncated story");

        // A genuinely new alert is still a third thing.
        let c3 = store
            .note(obs("01THIRD", 1_100, "exec", "medium", typed_at_a_shell(5000)))
            .expect("the chain grows");
        assert_eq!(c3.steps_total, 3, "a different alert is a different thing");
    }

    #[test]
    fn a_payload_cannot_setsid_its_way_out_of_the_tree_it_ran_in() {
        // Two stages under one build, each having made itself a session leader.
        let build = node_sid("e-mk", 5000, "/usr/bin/makepkg", 4000);
        let host = node_sid("e-hd", 4000, "/usr/bin/herdr", 4000);
        let stage1 = vec![node_sid("e-s1", 5100, "/tmp/lab/stage1", 5100), build.clone(), host.clone()];
        let stage2 = vec![node_sid("e-s2", 5200, "/tmp/lab/stage2", 5200), build.clone(), host.clone()];

        let a = tree_key(&stage1).expect("stage 1 has a tree");
        let b = tree_key(&stage2).expect("stage 2 has a tree");
        assert_eq!(a.0, b.0, "both stages belong to the build they ran inside");
        assert_eq!(a.1.exe, "/usr/bin/makepkg");

        // The ancestor case still works: a real session host above the alert
        // is still where the tree stops.
        let other = vec![node_sid("e-cl", 6000, "/usr/bin/claude", 5900), host.clone()];
        assert_ne!(tree_key(&other).expect("has a tree").0, a.0);
    }

    /// The same rule, for a session host that is not called "terminal".
    ///
    /// On 2026-09-04 an AUR attack was welded to three unrelated connections
    /// from a Claude session minutes earlier, because both trees passed through
    /// `herdr` and the walk anchored there: "7 things happened in 7 minutes
    /// under herdr" is shared ancestry, not a sequence. A chain is worth
    /// reading because its steps are related; an anchor high enough to cover a
    /// whole login makes every chain below it meaningless.
    #[test]
    fn a_session_host_is_a_boundary_whatever_it_is_called() {
        // Measured on this machine: herdr reported sid == pid, i.e. it told the
        // kernel it was a session leader. No list required.
        assert!(is_boundary("/usr/bin/herdr", Some("/usr/bin/foot"), 10618, Some(10618)));
        // And a process that is NOT a session leader is not a boundary just for
        // being unrecognised -- which is what made the old list dangerous.
        assert!(!is_boundary("/opt/some-new-tool/bin/tool", None, 4242, Some(4000)));

        // Two trees that meet only at that host are two trees.
        let attack = vec![
            node_sid("e-py", 2_584_229, "/usr/bin/python", 2_584_000),
            node_sid("e-mk", 2_584_100, "/usr/bin/makepkg", 2_584_000),
            node_sid("e-hd", 10_618, "/usr/bin/herdr", 10_618),
        ];
        let unrelated = vec![
            node_sid("e-cl", 11_545, "/usr/bin/claude", 11_314),
            node_sid("e-hd", 10_618, "/usr/bin/herdr", 10_618),
        ];
        let a = tree_key(&attack).expect("the attack has a tree");
        let b = tree_key(&unrelated).expect("the session has a tree");
        assert_ne!(a.0, b.0, "they must not share a key just by sharing a login");
        assert_eq!(a.1.exe, "/usr/bin/makepkg", "anchored at the build, not the session");
    }

    #[test]
    fn a_terminal_is_not_a_shared_ancestor() {
        // Two commands typed into one fish window are two trees, or every
        // alert on a desktop shares a root and the whole feature is noise.
        let (a, _) = tree_key(&typed_at_a_shell(41233)).unwrap();
        let (b, _) = tree_key(&typed_at_a_shell(41999)).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, "n-41233");
    }

    #[test]
    fn one_install_is_one_tree_however_many_processes_it_forks() {
        // npm -> sh -> node and npm -> curl are the same story (design 2b).
        let npm = node("npm-1", 41201, "/usr/bin/npm");
        let fish = node("f-1", 900, "/usr/bin/fish");
        let term = node("a-1", 800, "/usr/bin/alacritty");
        let deep = vec![
            node("nd-1", 41233, "/usr/bin/node"),
            node("sh-1", 41230, "/usr/bin/sh"),
            npm.clone(),
            fish.clone(),
            term.clone(),
        ];
        let shallow = vec![node("cu-1", 41240, "/usr/bin/curl"), npm, fish, term];
        let (a, anc) = tree_key(&deep).unwrap();
        let (b, _) = tree_key(&shallow).unwrap();
        assert_eq!(a, b, "both are under the same install");
        assert_eq!(anc.exe, "/usr/bin/npm", "the story's subject is the install");
    }

    #[test]
    fn a_shell_under_a_build_is_part_of_the_tree_a_shell_under_a_terminal_is_not() {
        assert!(is_boundary("/usr/bin/bash", Some("/usr/bin/alacritty"), 900, None));
        assert!(!is_boundary("/usr/bin/bash", Some("/usr/bin/npm"), 900, None));
        // An orphaned shell is assumed to be a login shell: the safe guess is
        // the one that does not merge unrelated trees.
        assert!(is_boundary("/usr/bin/bash", None, 900, None));
        assert!(is_boundary("/usr/lib/systemd/systemd", None, 1, None));
        assert!(is_boundary("/usr/bin/tmux", Some("/usr/bin/fish"), 700, None));
        assert!(!is_boundary("/usr/bin/node", Some("/usr/bin/npm"), 41233, None));
    }

    // ------------------------------------------------- the motivating case

    /// 2026-09-04: `node -e "import('moat-is-hijack-simulator')"` read a
    /// credential file, opened a websocket to a host on the LAN, and rewrote
    /// its own installed source — the last of which was allowlisted on
    /// purpose. Moat raised nothing. It has to raise something now, and the
    /// silenced step has to appear in the story without being what created it.
    #[test]
    fn the_npm_hijack_simulation_becomes_one_chain() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        assert!(s
            .note(obs("01A", 1_000, "cred", "high", tree()))
            .is_none(), "one event is not a chain");

        let c = s
            .note(obs("01B", 1_001, "net", "medium", tree()))
            .expect("credential read then egress in one tree is a chain");
        assert_eq!(c.id, "01A");
        assert_eq!(c.families, vec!["cred", "net"]);
        assert_eq!(c.ancestor.pid, 41233);
        // Higher than either member, and it says why.
        assert_eq!(c.severity_base, "high");
        assert_eq!(c.severity, "critical");
        assert!(
            c.severity_reason.starts_with("high -> critical:"),
            "escalation must be justified: {}",
            c.severity_reason
        );
        assert!(c.severity_reason.contains("connected out"));

        // The allowlisted source rewrite joins as context: shown, not counted.
        let mut silenced = obs("01C", 1_002, "persist", "medium", tree());
        silenced.silenced = true;
        let c = s.note(silenced).expect("an existing chain still grows");
        assert_eq!(c.steps.len(), 3);
        assert_eq!(c.steps[2].role, "context");
        assert_eq!(c.families, vec!["cred", "net"], "context adds no family");
        // The headline counts TRIGGERS -- what moat is actually saying
        // happened -- and the allowed step is reported in addition to it.
        assert!(c.summary.contains("2 things happened"), "{}", c.summary);
        assert!(c.summary.contains("1 more was already allowed"), "{}", c.summary);
        assert_eq!(c.member_ids(), vec!["01A", "01B", "01C"]);
    }

    /// The headline counts triggers, and the two numbers add up.
    ///
    /// A truncated chain used to print `steps_total` (context and allowlisted
    /// reads included) and then "N more were already allowed" -- a number that
    /// was already inside the first one. Both now come from counters that keep
    /// counting after `steps` stops growing.
    #[test]
    fn a_truncated_chains_headline_still_adds_up() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        let mut last = None;
        let (mut triggers, mut context) = (0usize, 0usize);
        for i in 0..(MAX_STEPS * 3) {
            let fam = if i % 2 == 0 { "exec" } else { "net" };
            let sev = if i == 0 { "high" } else { "low" };
            let mut o = obs(&format!("01ID{:03}", i), 1_000 + i as u64, fam, sev, tree());
            o.rarity = if i == 1 { Rarity::FirstSeen } else { Rarity::Common };
            // Every third one is allowlisted, i.e. context.
            o.silenced = i > 1 && i % 3 == 0;
            if o.silenced { context += 1 } else { triggers += 1 }
            // Keep the LATEST published chain: `note` republishes only when
            // something changed, so `.or(last)` would pin an early snapshot.
            if let Some(c) = s.note(o) {
                last = Some(c);
            }
        }
        let c = last.expect("a chain forms");
        assert!(c.truncated || c.steps_total > c.steps.len(), "this test needs a truncated chain");
        assert!(triggers > 0 && context > 0, "the fixture must produce both kinds");

        // The property that broke: the headline is the TRIGGER count, the
        // "more" clause is everything else, and the two add to steps_total.
        // Asserted against the chain's own counters rather than the numbers
        // this test fed in -- how many observations the correlator accepts is
        // a separate question from whether its arithmetic closes.
        let context_total = c.steps_total - c.triggers_total;
        assert!(
            c.triggers_total > c.steps.len(),
            "the counter must keep counting after `steps` is capped: {} vs {}",
            c.triggers_total,
            c.steps.len()
        );
        assert!(
            c.summary.contains(&format!("{} things happened", c.triggers_total)),
            "headline must count triggers: {}",
            c.summary
        );
        assert!(
            c.summary.contains(&format!("{} more", context_total)),
            "and the allowed ones are IN ADDITION to it, not inside it: {}",
            c.summary
        );
    }

    /// Every alert that formed a chain is a member of it.
    ///
    /// Pins the revert above: capping `steps` at formation drops member ids,
    /// so an alert that helped form the chain is stamped with nothing.
    #[test]
    fn a_large_formation_still_names_every_member() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        let mut last = None;
        for i in 0..(MAX_STEPS * 2) {
            let fam = if i % 2 == 0 { "exec" } else { "net" };
            let sev = if i == 0 { "high" } else { "low" };
            let id = format!("01ID{:03}", i);
            let mut o = obs(&id, 1_000 + i as u64, fam, sev, tree());
            o.rarity = if i == 1 { Rarity::FirstSeen } else { Rarity::Common };
            last = s.note(o).or(last);
        }
        let c = last.expect("a chain forms");
        assert!(
            c.member_ids().len() > MAX_STEPS,
            "formation must not drop members: {} named",
            c.member_ids().len()
        );
        assert!(c.member_ids().contains(&"01ID000".to_string()));
    }

    /// The 2026-09-04 20:41 miss, from the two records the live daemon wrote.
    ///
    /// A simulated npm C2 package rewrote `.git/config` and read a project
    /// token from the same pid one second apart. `chains_formed` stayed 0
    /// because `note_chain` treated `surface != "alerts"` as silence, and
    /// `scoring::surface_for` puts *every* medium on the timeline — so the
    /// `cred` half was demoted to a context step and only one trigger was
    /// left. All four documented conditions were satisfied; a fifth, undocumented
    /// one ("two members at high or worse") was not.
    ///
    /// What the user saw was one row: "a repository's git/config written by
    /// something other than git", with no sequence and no context.
    #[test]
    fn the_git_config_and_token_lab_run_correlates() {
        let mut s = ChainStore::new();
        // ancestry is one element: a bash the daemon never saw the parent of.
        let tree = || {
            vec![
                node("nd-1", 1_876_167, "/home/dan/.local/share/mise/installs/node/26.5.0/bin/node"),
                node("bh-1", 581_833, "/usr/bin/bash"),
            ]
        };
        // Both alerts carry the same second-resolution timestamp, so nothing
        // may order or deduplicate on `ts`.
        let mut persist = obs("01M1Q2ESWNFRTFES6AR42EG75S", 1_000, "persist", "high", tree());
        persist.rule = "moat-persist-git-config-write".into();
        persist.rarity = Rarity::FirstSeen;
        let mut cred = obs("01M1Q2ESXJACMACPP40PTSH25T", 1_000, "cred", "medium", tree());
        cred.rule = "moat-cred-project-token-read".into();
        cred.rarity = Rarity::Rare;

        assert!(s.note(persist).is_none(), "one event is not a chain");
        let c = s
            .note(cred)
            .expect("a high persist and a medium cred in one pid is a sequence");

        assert_eq!(c.steps.len(), 2);
        assert!(
            c.steps.iter().all(|x| x.is_trigger()),
            "a medium is a trigger; only an allowlist or the noise guard makes context"
        );
        assert_eq!(c.families, vec!["persist", "cred"]);
        // A one-element ancestry of a login shell still yields a tree: the
        // acting process is always eligible to be its own root.
        assert_eq!(c.ancestor.pid, 1_876_167);
        // No named escalating shape here (the sequence ends on `cred`, not
        // `persist`), so it correctly sits at its worst member and says so
        // rather than being talked up to critical.
        assert_eq!(c.severity, "high");
        assert_eq!(c.severity_base, "high");
        assert!(
            c.severity_reason.starts_with("stays high:")
                && c.severity_reason.contains("no escalating sequence"),
            "{}",
            c.severity_reason
        );
    }

    /// The general form of the same bug: a chain of two `medium`s is allowed by
    /// the documented conditions, so it must actually form. Both are on
    /// `surface: "timeline"` in the real record, which is a statement about
    /// severity and not about anybody's judgement of the event.
    #[test]
    fn two_mediums_crossing_families_still_form_a_chain() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        assert!(s.note(obs("01A", 1_000, "cred", "medium", tree())).is_none());
        assert!(
            s.note(obs("01B", 1_001, "net", "medium", tree())).is_some(),
            "the medium floor is a floor, not a requirement that everything clear it"
        );
    }

    #[test]
    fn the_full_theft_shape_is_critical_whatever_its_members_were() {
        let steps = [
            ("cred", "low"),
            ("net", "low"),
            ("persist", "low"),
        ]
        .iter()
        .enumerate()
        .map(|(i, (f, s))| obs(&format!("0{}", i), 1_000 + i as u64, f, s, vec![]).step(true))
        .collect::<Vec<_>>();
        let (sev, base, reason) = escalate(&steps);
        assert_eq!(base, "low");
        assert_eq!(sev, "critical");
        assert!(reason.starts_with("low -> critical:"), "{}", reason);
    }

    // ------------------------------------------- ordinary developer work

    /// The brief's own worry: "a build that reads a file, compiles, and writes
    /// output crosses families trivially". `cargo run` executes a binary under
    /// $HOME (exec) and that binary opens a socket (net) — two families, one
    /// tree, every single time. It is `common` on this machine, and that is
    /// what keeps it out.
    /// A credential harvest chains even when everything is `common`.
    ///
    /// Repeated testing (or a patient attacker) makes the reads and the exfil
    /// destination familiar; requiring novelty then meant the harvest+exfil
    /// stopped correlating. A harvest is exfil-shaped whatever its rarity.
    #[test]
    fn a_harvest_chains_even_when_nothing_is_novel() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);

        let mut harvest = obs("01A", 1_000, "cred", "high", tree());
        harvest.rule = "moat-x-mass-read".into();
        harvest.rarity = Rarity::Common;
        assert!(s.note(harvest).is_none(), "one step is not a chain");

        let mut exfil = obs("01B", 1_002, "net", "low", tree());
        exfil.rarity = Rarity::Common;
        assert!(
            s.note(exfil).is_some(),
            "harvest + egress is a chain even when both are common"
        );

        // Control: two ORDINARY common triggers still do not chain -- the
        // waiver is scoped to the harvest, not a hole in the novelty gate.
        let mut s2 = ChainStore::new();
        let mut a = obs("02A", 1_000, "exec", "high", tree());
        a.rarity = Rarity::Common;
        let mut b = obs("02B", 1_002, "net", "low", tree());
        b.rarity = Rarity::Common;
        assert!(s2.note(a).is_none());
        assert!(s2.note(b).is_none(), "ordinary common activity still needs novelty");
    }

    #[test]
    fn cargo_run_is_not_a_chain() {
        let mut s = ChainStore::new();
        let tree = || {
            vec![
                node("c-1", 5000, "/home/dan/proj/target/debug/app"),
                node("g-1", 4900, "/usr/bin/cargo"),
                node("f-1", 900, "/usr/bin/fish"),
                node("a-1", 800, "/usr/bin/alacritty"),
            ]
        };
        let mut a = obs("01A", 1_000, "exec", "medium", tree());
        a.rarity = Rarity::Common;
        let mut b = obs("01B", 1_002, "net", "medium", tree());
        b.rarity = Rarity::Common;
        assert!(s.note(a).is_none());
        assert!(
            s.note(b).is_none(),
            "a shape this machine sees every day is the job, not an incident"
        );
    }

    #[test]
    fn two_low_alerts_crossing_families_are_an_ordinary_install() {
        // npm spawning sh (pkg/low) and touching a file (persist/low) is what
        // every `npm install` on the machine looks like.
        let mut s = ChainStore::new();
        let tree = || {
            vec![
                node("sh-1", 41230, "/usr/bin/sh"),
                node("npm-1", 41201, "/usr/bin/npm"),
                node("f-1", 900, "/usr/bin/fish"),
                node("a-1", 800, "/usr/bin/alacritty"),
            ]
        };
        assert!(s.note(obs("01A", 1_000, "pkg", "low", tree())).is_none());
        assert!(
            s.note(obs("01B", 1_001, "persist", "low", tree())).is_none(),
            "nothing here reached medium"
        );
    }

    #[test]
    fn two_commands_in_one_terminal_are_not_a_chain() {
        let mut s = ChainStore::new();
        assert!(s
            .note(obs("01A", 1_000, "cred", "high", typed_at_a_shell(100)))
            .is_none());
        assert!(
            s.note(obs("01B", 1_002, "net", "high", typed_at_a_shell(200)))
                .is_none(),
            "sharing a terminal is not sharing a tree"
        );
    }

    #[test]
    fn one_family_twice_is_not_a_chain() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        assert!(s.note(obs("01A", 1_000, "cred", "high", tree())).is_none());
        assert!(
            s.note(obs("01B", 1_001, "cred", "high", tree())).is_none(),
            "the same detection twice is a count, not a sequence"
        );
    }

    #[test]
    fn two_silenced_alerts_never_make_a_chain() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        let mut a = obs("01A", 1_000, "cred", "high", tree());
        a.silenced = true;
        let mut b = obs("01B", 1_001, "net", "high", tree());
        b.silenced = true;
        assert!(s.note(a).is_none());
        assert!(
            s.note(b).is_none(),
            "an allowlist entry must not become a way to raise a critical"
        );
    }

    #[test]
    fn moats_own_meta_alerts_never_join_a_chain() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        assert!(s.note(obs("01A", 1_000, "cred", "high", tree())).is_none());
        assert!(
            s.note(obs("01B", 1_001, "x", "medium", tree())).is_none(),
            "moat-x-noisy-rule must not be able to complete a chain"
        );
        assert!(s.note(obs("01C", 1_002, "ai", "high", tree())).is_none());
    }

    // ------------------------------------------------------------- bounds

    #[test]
    fn alerts_further_apart_than_the_window_are_two_stories() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        assert!(s.note(obs("01A", 1_000, "cred", "high", tree())).is_none());
        assert!(
            s.note(obs("01B", 1_000 + WINDOW_SECS + 1, "net", "high", tree()))
                .is_none(),
            "the first event has aged out"
        );
    }

    #[test]
    fn a_month_of_alerts_holds_a_fixed_amount_of_memory() {
        let mut s = ChainStore::new();
        // One qualifying pair every simulated minute for 30 days, each in its
        // own tree, is 86_400 alerts.
        for i in 0..43_200u64 {
            let at = 1_000 + i * 60;
            let tree = || {
                vec![
                    node(&format!("p-{}", i), 10_000 + i as u32, "/usr/bin/node"),
                    node("f-1", 900, "/usr/bin/fish"),
                    node("a-1", 800, "/usr/bin/alacritty"),
                ]
            };
            s.note(obs(&format!("{:012}A", i), at, "cred", "high", tree()));
            s.note(obs(&format!("{:012}B", i), at, "net", "high", tree()));
        }
        assert!(s.formed > 40_000, "the test must actually form chains");
        assert!(
            s.recent.len() <= MAX_RECENT,
            "recent ring grew to {}",
            s.recent.len()
        );
        assert!(s.live.len() <= MAX_CHAINS, "live chains grew to {}", s.live.len());
        // And the window alone, without the caps, already emptied it.
        s.prune(1_000 + 43_200 * 60 + WINDOW_SECS + 1);
        assert_eq!(s.recent.len(), 0);
        assert_eq!(s.live.len(), 0);
    }

    #[test]
    fn a_chain_stops_growing_its_step_list_but_keeps_counting() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        s.note(obs("01A", 1_000, "cred", "high", tree()));
        s.note(obs("01B", 1_001, "net", "high", tree())).unwrap();
        let mut published = 0usize;
        for i in 0..40u64 {
            if s.note(obs(&format!("01C{:03}", i), 1_002 + i, "persist", "low", tree()))
                .is_some()
            {
                published += 1;
            }
        }
        let live = s.open().next().unwrap();
        assert_eq!(live.steps.len(), MAX_STEPS);
        assert_eq!(live.steps_total, 42);
        assert!(live.truncated);
        // And it stopped rewriting itself onto its members once the story on
        // disk stopped changing: 42 steps must not mean 42 republishes.
        assert!(published < 20, "republished {} times for 40 steps", published);
    }

    /// A display limit must not govern detection.
    ///
    /// `steps` is capped at `MAX_STEPS` because the whole chain record is copied
    /// onto every member alert, and that cap is right. Escalation used to be
    /// computed from that capped list, which is not: a chain that formed early
    /// out of ordinary build noise filled its twelve slots, and the credential
    /// read that arrived as observation thirteen never reached `families`, never
    /// moved the severity, and never fired a rung. The attack was told to come
    /// back later.
    ///
    /// Twelve is a number about how much of a story fits on a screen. It was
    /// deciding what moat detected.
    #[test]
    fn an_observation_past_the_step_cap_still_changes_the_verdict() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        // Every trigger, in order, as a Step -- the list the correlator WOULD
        // have had if `steps` were uncapped. The reference for "escalates
        // exactly as it would have without the cap".
        let mut uncapped: Vec<Step> = Vec::new();
        let mut last = None;

        // Ordinary build noise: alternating exec/net, one medium and one novel
        // so a chain forms at all, everything after it routine. Twelve
        // observations fill the story exactly.
        for i in 0..MAX_STEPS {
            let fam = if i % 2 == 0 { "exec" } else { "net" };
            let sev = if i == 0 { "medium" } else { "low" };
            let mut o = obs(&format!("01ID{:03}", i), 1_000 + i as u64, fam, sev, tree());
            o.rarity = if i == 0 { Rarity::FirstSeen } else { Rarity::Common };
            uncapped.push(o.step(true));
            if let Some(c) = s.note(o) {
                last = Some(c);
            }
        }
        let before = last.clone().expect("build noise forms a chain");
        assert_eq!(before.steps.len(), MAX_STEPS, "the story is full");
        assert_eq!(before.severity, "medium");
        assert!(!before.families.contains(&"cred".to_string()));

        // Observation thirteen: a credential read. There is no room for it in
        // the story, and that must not be the same thing as not having seen it.
        let mut cred = obs("01ID012", 1_012, "cred", "high", tree());
        cred.rarity = Rarity::FirstSeen;
        uncapped.push(cred.step(true));
        let c = s
            .note(cred)
            .expect("gaining a family and a severity is a change worth republishing");

        // (a) the family arrives,
        assert!(
            c.families.contains(&"cred".to_string()),
            "step 13 must reach `families`: {:?}",
            c.families
        );
        assert!(
            c.summary.contains("cred"),
            "and the sentence must agree with the array: {}",
            c.summary
        );
        // (b) the severity is what an uncapped list would have produced,
        assert_eq!(
            (
                c.severity.clone(),
                c.severity_base.clone(),
                c.severity_reason.clone()
            ),
            escalate(&uncapped),
            "escalation must not depend on how many steps the story could hold"
        );
        assert_eq!(c.severity, "high", "the cred read is the worst member now");
        // (c) and the story is still capped, and still says so.
        assert_eq!(c.steps.len(), MAX_STEPS);
        assert!(c.truncated);
        assert_eq!(c.steps_total, MAX_STEPS + 1);
        assert!(
            !c.steps.iter().any(|st| st.alert == "01ID012"),
            "the cap is unchanged: the thirteenth step is not in the story"
        );
        assert!(
            c.member_ids().contains(&"01ID012".to_string()),
            "but it is a member, so a chain ack still covers it"
        );

        // And the rungs keep working past the cap: the connection out AFTER the
        // credential read is `cred -> net`, which is the shape the whole module
        // exists to catch. Two more observations, neither of them in the story.
        let mut out = obs("01ID013", 1_013, "net", "medium", tree());
        out.rarity = Rarity::FirstSeen;
        uncapped.push(out.step(true));
        let c = s.note(out).expect("a severity move republishes");
        assert_eq!(
            (
                c.severity.clone(),
                c.severity_base.clone(),
                c.severity_reason.clone()
            ),
            escalate(&uncapped)
        );
        assert_eq!(c.severity, "critical");
        assert!(
            c.severity_reason.contains("a credential was read and the same process tree then connected out"),
            "{}",
            c.severity_reason
        );
        assert_eq!(c.steps.len(), MAX_STEPS, "still capped");
    }

    /// The formation path is untouched by the split.
    ///
    /// Formation folds the observations rather than the steps, so that the live
    /// chain starts with the real novelty answer. It must still agree with the
    /// step list it publishes, at any size -- including the large formations
    /// that are deliberately not capped.
    #[test]
    fn formation_still_escalates_from_its_whole_candidate_list() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        let mut steps: Vec<Step> = Vec::new();
        let mut last = None;
        // More than MAX_STEPS candidates before anything qualifies -- one
        // family crosses nothing, so they all sit in the ring -- and context
        // steps mixed in so "allowlisted steps never escalate" is exercised too.
        // The `net` at the end is what completes the second family.
        let n = MAX_STEPS + 4;
        for i in 0..n {
            let fam = if i + 1 == n { "net" } else { "exec" };
            let sev = if i == 0 { "high" } else { "low" };
            let mut o = obs(&format!("01ID{:03}", i), 1_000, fam, sev, tree());
            o.rarity = if i == 0 { Rarity::FirstSeen } else { Rarity::Common };
            o.silenced = i > 0 && i % 5 == 0 && i + 1 < n;
            steps.push(o.step(!o.silenced));
            if let Some(c) = s.note(o) {
                last = Some(c);
            }
        }
        let c = last.expect("a chain forms");
        assert!(c.steps.len() > MAX_STEPS, "formation is not capped");
        assert!(!c.truncated);
        assert_eq!(
            (
                c.severity.clone(),
                c.severity_base.clone(),
                c.severity_reason.clone()
            ),
            escalate(&c.steps),
            "the state-driven answer is the step-driven answer at formation"
        );
        // Families are the trigger families, first-seen order, context excluded.
        let want: Vec<String> = {
            let mut out: Vec<String> = Vec::new();
            for st in c.steps.iter().filter(|st| st.is_trigger()) {
                if !out.contains(&st.family) {
                    out.push(st.family.clone());
                }
            }
            out
        };
        assert_eq!(c.families, want);
        assert!(
            c.steps.iter().any(|st| !st.is_trigger()),
            "the fixture must contain a context step"
        );
    }

    #[test]
    fn a_chain_that_never_goes_quiet_still_closes() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        s.note(obs("01A", 1_000, "cred", "high", tree()));
        assert!(s.note(obs("01B", 1_001, "net", "high", tree())).is_some());
        // Touched every nine minutes for two hours: past MAX_SPAN_SECS the
        // chain is closed and a new sequence starts its own story.
        let mut t = 1_001;
        let mut ids = 0;
        while t < 1_000 + MAX_SPAN_SECS + WINDOW_SECS {
            t += WINDOW_SECS - 60;
            ids += 1;
            s.note(obs(&format!("01D{:03}", ids), t, "net", "medium", tree()));
        }
        assert!(s.live.len() <= 1);
        let live_first = s.live.first().map(|c| c.first_at).unwrap_or(t);
        assert!(
            t.saturating_sub(live_first) <= MAX_SPAN_SECS,
            "a chain outlived its span cap"
        );
    }

    // -------------------------------------------------------------- shape

    #[test]
    fn the_record_round_trips() {
        let mut s = ChainStore::new();
        let tree = || typed_at_a_shell(41233);
        s.note(obs("01A", 1_000, "cred", "high", tree()));
        let c = s.note(obs("01B", 1_001, "net", "medium", tree())).unwrap();
        let line = serde_json::to_string(&c).unwrap();
        assert!(!line.contains('\n'));
        let back: Chain = serde_json::from_str(&line).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn spans_read_like_english() {
        assert_eq!(human_span(0), "1 second");
        assert_eq!(human_span(2), "2 seconds");
        assert_eq!(human_span(540), "9 minutes");
        assert_eq!(human_span(10_800), "3 hours");
    }

    #[test]
    fn a_privilege_signal_beside_anything_else_moves_one_step() {
        let steps: Vec<Step> = [("exec", "medium"), ("priv", "medium")]
            .iter()
            .enumerate()
            .map(|(i, (f, s))| obs(&format!("0{}", i), 1_000 + i as u64, f, s, vec![]).step(true))
            .collect();
        let (sev, base, reason) = escalate(&steps);
        assert_eq!(base, "medium");
        assert_eq!(sev, "high");
        assert!(reason.contains("privilege signal"), "{}", reason);
    }

    #[test]
    fn a_sequence_with_no_escalating_shape_stays_where_it_was() {
        let steps: Vec<Step> = [("pkg", "medium"), ("exec", "high")]
            .iter()
            .enumerate()
            .map(|(i, (f, s))| obs(&format!("0{}", i), 1_000 + i as u64, f, s, vec![]).step(true))
            .collect();
        let (sev, base, reason) = escalate(&steps);
        assert_eq!(sev, "high");
        assert_eq!(base, "high");
        assert!(reason.starts_with("stays high:"), "{}", reason);
        assert!(reason.contains("pkg and exec"), "{}", reason);
    }
}
