//! The learning window, proposals, and the noise guard (BASELINE §3 and §4).
//!
//! Everything here is **visible and reversible**. A learned entry is a line in
//! `/etc/moat/allowlist.d/baseline.toml` with a comment saying how it was
//! earned; a proposal is a record in `state.json` carrying the exact TOML that
//! accepting it would write; a demotion is a named rule in `demoted_rules[]`
//! plus one alert explaining itself. Nothing is ever silently dropped.
//!
//! ## The window
//!
//! `installed_at` is stamped on the first run. For `learning_days` (7) after
//! that, a (rule, actor exe, parent exe, file dir) tuple that produces
//! **medium or low** alerts from an **official** actor on `learn_min_days` (3)
//! distinct days, and whose rarity is `common`, is written straight to
//! `baseline.toml`. High and critical are never learned; foreign and user actors
//! are never learned. After the window the same condition produces a
//! **proposal** instead, which the user accepts or dismisses.
//!
//! ## The noise guard
//!
//! More than `noisy_rule_per_day` (20) alerts from one rule in a rolling 24 h
//! demotes the rule: it still lands in `alerts.jsonl`, it just stops being an
//! Alerts-tab item (`surface: timeline`). One `moat-x-noisy-rule` alert names
//! the top five tuples and offers both "these are expected" (baseline entries
//! for exactly those tuples) and "keep watching" (undo). The demotion clears
//! itself once 24 h pass under the threshold.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::allowlist::{render_block, RuleSpec};

pub const BASELINE_V: u32 = 1;
pub const DAY: u64 = 86_400;

/// Rules moat raises about *itself*. Learning them would silence the machinery
/// that reports the machinery.
pub const NEVER_LEARN: &[&str] = &[
    "moat-x-noisy-rule",
    "moat-x-baseline-revoked",
    "moat-x-sensor-mismatch",
    "moat-x-new-exec-ioc",
];

/// One (rule, actor exe, parent exe, file dir) tuple and what we know about it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TupleStat {
    pub rule: String,
    pub exe: String,
    #[serde(default)]
    pub parent: String,
    #[serde(default)]
    pub dir: String,
    pub count: u64,
    /// Distinct `YYYY-MM-DD` days this tuple was seen on, newest last.
    #[serde(default)]
    pub days: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    /// The severity the last alert scored to.
    pub severity: String,
    /// The highest severity this tuple ever produced, after context and
    /// provenance adjusted it. Reported, but no longer the learning gate --
    /// see `max_base_rank`.
    #[serde(default)]
    pub max_rank: u8,
    /// The highest severity the *rules* ever gave this tuple, before the
    /// context matrix escalated it. This is what learning looks at.
    ///
    /// Gating on the escalated value was wrong on its own terms. BASELINE §2b
    /// escalates by context and never downgrades in `pkg-install`, so a tuple
    /// that scores medium every ordinary day is permanently barred from the
    /// baseline by one sighting inside a package build. On 2026-09-04 that was
    /// 628 of 1206 tuples, 295 of them official -- the single largest reason
    /// nothing had ever been learned. The severity a *detection* assigns is a
    /// statement about the action; the escalation is a statement about the
    /// circumstances, and circumstances are exactly what a baseline is for.
    #[serde(default)]
    pub max_base_rank: u8,
    pub provenance: String,
    pub context: String,
    #[serde(default)]
    pub package: Option<String>,
    pub rarity: String,
    /// Ever suppressed by an allowlist entry.
    #[serde(default)]
    pub suppressed: bool,
    /// Ever raised while its rule was demoted.
    #[serde(default)]
    pub demoted: bool,
    #[serde(default)]
    pub learned: bool,
    #[serde(default)]
    pub proposed: bool,
    #[serde(default)]
    pub dismissed: bool,
}

impl TupleStat {
    pub fn key(&self) -> String {
        tuple_key(&self.rule, &self.exe, &self.parent, &self.dir)
    }

    /// The allowlist rule this tuple would become.
    pub fn spec(&self) -> RuleSpec {
        RuleSpec {
            name: self.rule.clone(),
            exe: (!self.exe.is_empty()).then(|| self.exe.clone()),
            file: (!self.dir.is_empty()).then(|| format!("{}/*", self.dir.trim_end_matches('/'))),
            parent: (!self.parent.is_empty()).then(|| self.parent.clone()),
            // A learned proposal never names a script: it is built from what
            // was observed, and the interpreter case wants a hand-written
            // entry that says which script, not a guess.
            script: None,
            // A learned proposal never names a domain either, and this one
            // is not an omission to be filled in later. The baseline learns
            // what it has SEEN, and "this machine has connected to that
            // address a few times" is exactly the observation a beaconing
            // implant produces -- learning from it would let a C2 quieten its
            // own alert by being patient. A domain entry is only ever written
            // because a person looked at an alert and disagreed with it.
            domain: None,
        }
    }

    pub fn toml(&self) -> String {
        render_block(&self.spec())
    }

    /// The comment written above a learned or accepted entry.
    pub fn comment(&self, how: &str) -> String {
        format!(
            "{} {}: seen {} time{} on {} distinct day{} ({} .. {}), actor {}{}, context {}, rarity {}",
            how,
            today(),
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.days.len(),
            if self.days.len() == 1 { "" } else { "s" },
            date_part(&self.first_seen),
            date_part(&self.last_seen),
            self.provenance,
            self.package.as_ref().map(|p| format!(" ({})", p)).unwrap_or_default(),
            self.context,
            self.rarity
        )
    }
}

pub fn tuple_key(rule: &str, exe: &str, parent: &str, dir: &str) -> String {
    format!("{}|{}|{}|{}", rule, exe, parent, dir)
}

/// A recurring pattern waiting for the user's yes or no (BASELINE §3).
/// The field names are fixed by BASELINE §8 "Resolved shapes".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub rule: String,
    pub exe: String,
    pub parent: String,
    pub dir: String,
    pub count: u64,
    pub days: usize,
    pub first_seen: String,
    pub last_seen: String,
    /// Exactly what accepting would append to `baseline.toml`.
    pub toml: String,
    /// Internal: which tuple it came from.
    #[serde(default)]
    pub key: String,
    /// Why this is being proposed. Empty means the ordinary route: a
    /// recurring, official, medium/low pattern that the baseline is confident
    /// about. Non-empty means moat is NOT vouching for it and the sentence
    /// says what it is instead -- see `REDEMOTED_REASON`.
    #[serde(default)]
    pub reason: String,
}

/// A pattern the noise guard has had to quieten again and again.
///
/// Deliberately worded as an observation rather than a recommendation. moat
/// has no opinion on whether this is safe: it is reporting that the same shape
/// keeps flooding, that the circuit breaker keeps tripping, and that a person
/// could end the cycle with one decision. Auto-allowing it would be the exact
/// mistake this project keeps finding -- repetition is not consent, and an
/// attacker who runs daily can manufacture repetition.
/// How many times one pattern may be demoted before Moat offers to make the
/// decision permanent. Three: enough that it is clearly a habit of this
/// machine and not one bad afternoon.
pub const REDEMOTE_PROPOSE_AT: u64 = 3;

pub const REDEMOTED_REASON: &str =
    "the noise guard has had to quieten this pattern repeatedly; Moat is not vouching for it, only noting that you keep being asked about it";

/// A rule the noise guard put on the timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Demotion {
    pub rule: String,
    /// The (rule, exe, parent, dir) tuple this demotion is scoped to. **Always
    /// set**: there is no such thing as a rule-wide demotion any more, see
    /// `note_alert`.
    #[serde(default)]
    pub tuple: String,
    /// unix seconds
    pub since: u64,
    /// The 24 h count that tripped it.
    pub count: u64,
    /// unix seconds of the last alert from this rule.
    pub last_seen: u64,
    /// How many distinct patterns of this rule are quiet now, this one
    /// included. Past `noisy_rule_fanout` the alert says the rule itself is the
    /// problem; nothing is silenced by it.
    #[serde(default)]
    pub patterns_quiet: usize,
}

/// Everything the baseline persists, in `<state_dir>/baseline.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BaselineState {
    #[serde(default)]
    pub v: u32,
    pub installed_at: u64,
    /// unix seconds at which the learning window closes.
    pub learning_until: u64,
    #[serde(default)]
    pub tuples: HashMap<String, TupleStat>,
    #[serde(default)]
    pub proposals: Vec<Proposal>,
    /// Demotions scoped to one (rule, exe, parent, dir) tuple. Keyed by the
    /// tuple, so a noisy shape goes quiet without silencing shapes of the same
    /// rule that nobody has seen yet.
    #[serde(default)]
    pub demoted_tuples: BTreeMap<String, Demotion>,
    /// How many times the noise guard has demoted each tuple, across clears.
    ///
    /// A demotion is a circuit breaker: it forgets on purpose, so a pattern
    /// that recurs costs the same 20 badge alerts every time it comes back.
    /// For an OFFICIAL actor the baseline eventually learns the pattern and
    /// the cycle ends; for anything else -- a build tree under /tmp, an AUR
    /// package, a locally compiled tool -- nothing ever graduates, because
    /// automatic trust from repetition is precisely what an attacker can
    /// manufacture. This counter is how the cycle becomes visible instead:
    /// past `REDEMOTE_PROPOSE_AT` it is offered as a proposal for a person to
    /// accept or refuse.
    #[serde(default)]
    pub redemotions: BTreeMap<String, u64>,
    /// rule -> hour bucket (unix hours) -> alerts in that hour.
    #[serde(default)]
    pub windows: HashMap<String, BTreeMap<u64, u64>>,
    /// Learned entries, by tuple key, so provenance can be re-checked.
    #[serde(default)]
    pub learned: BTreeMap<String, LearnedEntry>,
}

/// A line moat wrote into `baseline.toml` by itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedEntry {
    pub key: String,
    pub rule: String,
    pub exe: String,
    pub written: String,
    /// Set once provenance stopped being official and the entry was disabled.
    #[serde(default)]
    pub revoked: Option<String>,
    /// Who approved this, when a human did.
    ///
    /// `accept` puts a reviewed proposal into the same collection as an
    /// automatically learned entry, and until 2026-09-09 nothing told them
    /// apart -- so a rule added to withdraw entries the LEARNER should never
    /// have written could also withdraw one a person had read and approved.
    /// A human's decision is not moat's to revisit on a heuristic.
    #[serde(default)]
    pub accepted_by: Option<String>,
}

/// What `observe` decided to do about one alert.
#[derive(Debug, Clone, PartialEq)]
pub enum Learned {
    /// Nothing changed.
    None,
    /// Written to `baseline.toml` during the learning window.
    Entry { key: String, toml: String, comment: String },
    /// Recorded as a proposal for the user to accept.
    Proposed { id: String },
}

/// One alert's worth of facts, as the baseline sees it.
#[derive(Debug, Clone)]
pub struct Observation<'a> {
    pub rule: &'a str,
    pub exe: &'a str,
    pub parent: &'a str,
    /// Directory of the file the alert names, `""` when it names none.
    pub dir: &'a str,
    pub severity: &'a str,
    /// What the rule itself decided, before provenance and context adjusted it.
    pub severity_base: &'a str,
    pub provenance: &'a str,
    pub package: Option<String>,
    pub context: &'a str,
    pub rarity: &'a str,
    pub suppressed: bool,
    pub demoted: bool,
    pub ts: String,
    pub now: u64,
}

pub struct Baseline {
    pub state: BaselineState,
    path: PathBuf,
    group: String,
    pub learning_days: u64,
    pub learn_min_days: usize,
    pub noisy_rule_per_day: u64,
    /// How many distinct demoted patterns of one rule make the rule itself the
    /// problem. **Nothing is silenced at this point**: it is the count at which
    /// `moat-x-noisy-rule` stops saying "one shape of this rule floods" and
    /// starts saying "this rule is wrong for this machine" (BASELINE §4).
    pub noisy_rule_fanout: usize,
    dirty: bool,
    last_save: u64,
    pub save_every: u64,
}

impl Baseline {
    /// Load, stamping `installed_at` on the first run. `installed_at_hint`
    /// comes from `state.json`, which is where BASELINE §3 says it lives; the
    /// tuple store is kept beside it so state.json stays readable.
    pub fn load(
        state_dir: &Path,
        group: &str,
        learning_days: u64,
        learn_min_days: usize,
        noisy_rule_per_day: u64,
        installed_at_hint: Option<u64>,
        now: u64,
    ) -> Baseline {
        let path = state_dir.join("baseline.json");
        let mut state: BaselineState = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let mut dirty = false;
        if state.installed_at == 0 {
            state.installed_at = installed_at_hint.unwrap_or(now);
            state.learning_until = state.installed_at + learning_days * DAY;
            state.v = BASELINE_V;
            dirty = true;
            log::info!(
                "baseline: first run, learning until {}",
                crate::util::rfc3339_of(state.learning_until)
            );
        }
        if state.learning_until == 0 {
            state.learning_until = state.installed_at + learning_days * DAY;
            dirty = true;
        }
        Baseline {
            state,
            path,
            group: group.to_string(),
            learning_days,
            learn_min_days,
            noisy_rule_per_day,
            noisy_rule_fanout: 5,
            dirty,
            last_save: 0,
            save_every: 60,
        }
    }

    // ------------------------------------------------------------ the window

    pub fn learning(&self, now: u64) -> bool {
        now < self.state.learning_until
    }

    pub fn learning_ends(&self) -> String {
        crate::util::rfc3339_of(self.state.learning_until)
    }

    /// `moatctl baseline relearn [--days N]`: restart the window, for after a
    /// big change (new job, new toolchain) or after a rule retune.
    ///
    /// The day counters and `max_rank` start over; `count`, `first_seen` and
    /// `learned` stay, so the export keeps its history and entries already in
    /// `baseline.toml` are untouched.
    ///
    /// Resetting `max_rank` is what makes this an escape hatch rather than a
    /// no-op. It is a running maximum that never decays, so a single high — one
    /// scored under rules that have since been retuned, or under a context
    /// escalation that no longer applies — otherwise keeps a tuple out of the
    /// baseline permanently, and no command could get it back. Clearing it is
    /// safe because it is self-healing: a tuple that still scores high re-poisons
    /// itself on its very next alert, so only tuples that have genuinely stopped
    /// being severe stay clean.
    pub fn relearn(&mut self, days: Option<u64>, now: u64) -> u64 {
        let days = days.unwrap_or(self.learning_days);
        self.state.learning_until = now + days * DAY;
        for t in self.state.tuples.values_mut() {
            t.proposed = false;
            t.dismissed = false;
            t.days.clear();
            t.max_rank = 0;
            t.max_base_rank = 0;
        }
        self.state.proposals.clear();
        self.dirty = true;
        self.state.learning_until
    }

    // ------------------------------------------------------------- observing

    /// Record one alert against its tuple and decide whether it earns a
    /// baseline entry (during the window) or a proposal (after it).
    pub fn observe(&mut self, o: &Observation) -> Learned {
        let key = tuple_key(o.rule, o.exe, o.parent, o.dir);
        let day = date_part(&o.ts);
        let rank = crate::alert::severity_rank(o.severity);
        let e = self.state.tuples.entry(key.clone()).or_insert_with(|| TupleStat {
            rule: o.rule.to_string(),
            exe: o.exe.to_string(),
            parent: o.parent.to_string(),
            dir: o.dir.to_string(),
            first_seen: o.ts.clone(),
            ..Default::default()
        });
        e.count += 1;
        e.last_seen = o.ts.clone();
        e.severity = o.severity.to_string();
        e.max_rank = e.max_rank.max(rank);
        e.max_base_rank = e.max_base_rank.max(crate::alert::severity_rank(o.severity_base));
        e.provenance = o.provenance.to_string();
        e.package = o.package.clone();
        e.context = o.context.to_string();
        e.rarity = o.rarity.to_string();
        e.suppressed |= o.suppressed;
        e.demoted |= o.demoted;
        if !e.days.iter().any(|d| d == &day) {
            e.days.push(day);
            // 64 days of history is more than any decision here needs.
            if e.days.len() > 64 {
                e.days.remove(0);
            }
        }
        self.dirty = true;

        let stat = e.clone();
        if !self.eligible(&stat) {
            return Learned::None;
        }
        if self.learning(o.now) {
            let entry = self.state.tuples.get_mut(&key).expect("just inserted");
            entry.learned = true;
            self.state.learned.insert(
                key.clone(),
                LearnedEntry {
                    key: key.clone(),
                    rule: stat.rule.clone(),
                    exe: stat.exe.clone(),
                    written: o.ts.clone(),
                    revoked: None,
                    accepted_by: None,
                },
            );
            Learned::Entry {
                key,
                toml: stat.toml(),
                comment: stat.comment("learned"),
            }
        } else {
            let entry = self.state.tuples.get_mut(&key).expect("just inserted");
            entry.proposed = true;
            let id = ulid::Ulid::new().to_string();
            self.state.proposals.push(Proposal {
                id: id.clone(),
                rule: stat.rule.clone(),
                exe: stat.exe.clone(),
                parent: stat.parent.clone(),
                dir: stat.dir.clone(),
                count: stat.count,
                days: stat.days.len(),
                first_seen: stat.first_seen.clone(),
                last_seen: stat.last_seen.clone(),
                toml: stat.toml(),
                key,
                // The ordinary route: the baseline IS confident about this one.
                reason: String::new(),
            });
            Learned::Proposed { id }
        }
    }

    /// BASELINE §3 + LEARNING §1: medium or low, official actor, enough
    /// distinct days, and `common` rarity.
    fn eligible(&self, t: &TupleStat) -> bool {
        self.blocked_by(t).is_none()
    }

    /// Which gate stops this tuple being learned, in the order `eligible`
    /// applies them, or `None` when nothing does.
    ///
    /// The export reports this. A reviewer reading "seen 400 times over 5 days
    /// and still not learned" needs to know *which* condition is the one to act
    /// on, and `max_rank` in particular is invisible in the row itself — it is
    /// a high this tuple produced once, days ago, possibly under rules that have
    /// since changed.
    fn blocked_by(&self, t: &TupleStat) -> Option<String> {
        if t.learned {
            return Some("already learned".into());
        }
        if t.proposed {
            return Some("already proposed".into());
        }
        if t.dismissed {
            return Some("dismissed by the user".into());
        }
        if NEVER_LEARN.contains(&t.rule.as_str()) {
            return Some(format!("{} is never learned", t.rule));
        }
        // High and critical are never learned -- judged on what the RULE said,
        // not on what the context matrix escalated it to, and on the tuple's
        // whole history rather than its latest sighting.
        //
        // A hard ceiling stays on the escalated value at `critical`: whatever
        // the base severity, a tuple that has ever reached critical is not
        // something to quietly learn.
        if t.max_base_rank > crate::alert::severity_rank("medium") {
            return Some(format!(
                "the rule scored it {} once; learning stops at medium (`moatctl baseline relearn` clears this)",
                crate::alert::severity_name(t.max_base_rank)
            ));
        }
        if t.max_rank >= crate::alert::severity_rank("critical") {
            return Some("reached critical once; never learned whatever the rule scored".into());
        }
        if t.provenance != "official" {
            return Some(format!("actor is {}, not official", t.provenance));
        }
        // An interpreter is not an identity.
        //
        // The tuple is (rule, actor exe, parent exe, file dir), and for
        // `python3 build.py` the exe is `/usr/bin/python3` -- which is official,
        // scores medium, recurs daily, and is therefore a model citizen by every
        // gate above. The entry it earns says "python, under this parent, in
        // this directory", and the NEXT script to match that shape inherits it
        // without ever having been observed. Revocation re-checks the
        // interpreter, which never stopped being official.
        //
        // This project's own rule is that an interpreter takes the provenance of
        // its script (`provenance::is_interpreter`, and the allowlist's `script`
        // matcher exists for exactly this). Learning cannot express that -- a
        // learned entry is built from what was observed and deliberately never
        // names a script (`TupleStat::spec`) -- so the honest move is to refuse
        // rather than to write a grant broader than the evidence. A user who
        // wants this can write the entry by hand, naming the script.
        if crate::provenance::path_is_not_identity(crate::util::basename(&t.exe)) {
            return Some(format!(
                "{} is an interpreter: the tuple names the interpreter, not the code it ran, so a learned entry would cover scripts nobody has seen. Write the entry by hand with `script = ...` if this is expected.",
                crate::util::basename(&t.exe)
            ));
        }
        if t.days.len() < self.learn_min_days {
            return Some(format!(
                "seen on {} of {} distinct days",
                t.days.len(),
                self.learn_min_days
            ));
        }
        // A tuple cannot be proposed until it has been ordinary for a while.
        if t.rarity != "common" {
            return Some(format!("rarity is {}, not common", t.rarity));
        }
        None
    }

    // --------------------------------------------------------- the proposals

    /// Offer a repeatedly-demoted pattern as a decision, once.
    ///
    /// Built from the tuple key rather than from a `TupleStat`, because the
    /// patterns that reach here are exactly the ones the baseline refused to
    /// track: not official, so `note` never recorded a stat for them. That is
    /// the point -- this is the path for everything the ordinary route will
    /// never propose, and it carries `reason` so no reader mistakes it for the
    /// baseline vouching.
    fn propose_redemoted(&mut self, rule: &str, tuple: &str, count: u64, times: u64, now: u64) {
        // Once per tuple. Re-proposing every time it trips would turn a
        // helpful offer into the same flood it is trying to end.
        if self.state.proposals.iter().any(|p| p.key == tuple) {
            return;
        }
        let parts: Vec<&str> = tuple.splitn(4, '|').collect();
        if parts.len() != 4 {
            return;
        }
        let (exe, parent, dir) = (parts[1].to_string(), parts[2].to_string(), parts[3].to_string());
        let spec = RuleSpec {
            name: rule.to_string(),
            exe: (!exe.is_empty()).then(|| exe.clone()),
            file: (!dir.is_empty()).then(|| format!("{}/*", dir.trim_end_matches('/'))),
            parent: (!parent.is_empty()).then(|| parent.clone()),
            script: None,
            // Never learned; see `Tuple::spec`.
            domain: None,
        };
        let id = ulid::Ulid::new().to_string();
        self.state.proposals.push(Proposal {
            id,
            rule: rule.to_string(),
            exe,
            parent,
            dir,
            count,
            days: times as usize,
            first_seen: crate::util::rfc3339_of(now),
            last_seen: crate::util::rfc3339_of(now),
            toml: render_block(&spec),
            key: tuple.to_string(),
            reason: REDEMOTED_REASON.to_string(),
        });
        self.dirty = true;
        log::info!(
            "noise guard: {} has been quietened {} times for one pattern; proposing it",
            rule,
            times
        );
    }

    pub fn proposals(&self) -> &[Proposal] {
        &self.state.proposals
    }

    pub fn proposal(&self, id: &str) -> Option<&Proposal> {
        self.state.proposals.iter().find(|p| p.id == id)
    }

    /// Take a proposal out of the list. Returns it plus the comment to write.
    pub fn accept(&mut self, id: &str, who: &str) -> Result<(Proposal, String), String> {
        let idx = self
            .state
            .proposals
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| format!("no proposal {}", id))?;
        let p = self.state.proposals.remove(idx);
        let comment = match self.state.tuples.get(&p.key) {
            Some(t) => format!("{} — accepted by {}", t.comment("learned"), who),
            None => format!("accepted by {} on {}: {} from {}", who, today(), p.rule, p.exe),
        };
        if let Some(t) = self.state.tuples.get_mut(&p.key) {
            t.learned = true;
            t.proposed = false;
        }
        self.state.learned.insert(
            p.key.clone(),
            LearnedEntry {
                key: p.key.clone(),
                rule: p.rule.clone(),
                exe: p.exe.clone(),
                written: crate::util::now_rfc3339(),
                revoked: None,
                accepted_by: Some(who.to_string()),
            },
        );
        self.dirty = true;
        Ok((p, comment))
    }

    pub fn dismiss(&mut self, id: &str) -> Result<Proposal, String> {
        let idx = self
            .state
            .proposals
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| format!("no proposal {}", id))?;
        let p = self.state.proposals.remove(idx);
        if let Some(t) = self.state.tuples.get_mut(&p.key) {
            t.proposed = false;
            // Dismissed means "do not ask me again", not "ask me tomorrow".
            t.dismissed = true;
        }
        self.dirty = true;
        Ok(p)
    }

    /// Propose baseline entries for a named set of tuples: the `if_expected`
    /// option on a `moat-x-noisy-rule` alert.
    pub fn propose_keys(&mut self, keys: &[String]) -> Vec<Proposal> {
        let mut out = Vec::new();
        for key in keys {
            let Some(t) = self.state.tuples.get_mut(key) else {
                continue;
            };
            if t.learned || t.proposed {
                continue;
            }
            t.proposed = true;
            t.dismissed = false;
            let t = t.clone();
            let p = Proposal {
                id: ulid::Ulid::new().to_string(),
                rule: t.rule.clone(),
                exe: t.exe.clone(),
                parent: t.parent.clone(),
                dir: t.dir.clone(),
                count: t.count,
                days: t.days.len(),
                first_seen: t.first_seen.clone(),
                last_seen: t.last_seen.clone(),
                toml: t.toml(),
                key: key.clone(),
                reason: String::new(),
            };
            self.state.proposals.push(p.clone());
            out.push(p);
        }
        self.dirty = true;
        out
    }

    // -------------------------------------------------------- the noise guard

    /// Count one alert against its rule's rolling 24 h window. Returns the
    /// demotion when this alert is the one that crossed the threshold.
    /// Count one alert against the noise guard, and demote if it floods.
    ///
    /// **Counted per tuple, not per rule.** Demoting a whole rule silences every
    /// shape it can ever match, including shapes nobody has seen yet, and on
    /// 2026-09-04 that cost a real detection: `moat-exec-untrusted-tmpfs` had
    /// fired 320 times from this machine's own builds (`bash` and `bwrap` out of
    /// cargo's tempdirs, plus moat's own test binaries), so the rule was
    /// demoted. When a package `preinstall` then downloaded a binary into /tmp
    /// and executed it -- a tuple never seen before, and the exact thing the
    /// rule exists for -- the alert went to the timeline instead of the badge.
    ///
    /// The thing that made the rule noisy had nothing in common with the thing
    /// that tripped it except the rule id. Scoping the demotion to the tuple
    /// keeps every noisy shape as quiet as it is today while leaving an unseen
    /// shape loud, so this can only ever reduce what reaches the badge for
    /// patterns already established, and never hides a new one.
    ///
    /// **There is no rule-wide demotion.** There was one: a "fan-out backstop"
    /// that silenced a whole rule once `noisy_rule_fanout` of its patterns had
    /// each gone quiet on their own. It was removed on 2026-09-05 with the
    /// `signal` tier, and the two changes are the same change.
    ///
    /// The backstop existed because some rules flood in general rather than in
    /// one shape, and the guard was the only mechanism moat had for saying
    /// "this rule is a building block, not a detection". It said it through a
    /// 24 h circuit breaker that forgets, which is the wrong instrument for a
    /// permanent fact about a rule: on 2026-09-04 it hid a real `/tmp` dropper
    /// inside a package install, and on 2026-09-05 moat's own test suite
    /// re-created the same rule-wide silence in seconds. The demoted set it
    /// arrived at was, every time, the same seven rules — which is a
    /// declaration the rules can simply make (`moat.omarchy/tier: signal`).
    ///
    /// So the fan-out no longer silences anything. A *detection* rule that
    /// floods across many patterns is a rule bug, and the output for a rule bug
    /// is the `moat-x-noisy-rule` alert saying so, plus the per-pattern
    /// demotions that were happening anyway — never a rule-wide silence, which
    /// covers shapes nobody has seen yet and is exactly how a real detection
    /// gets lost.
    pub fn note_alert(&mut self, rule: &str, tuple: &str, now: u64) -> Option<Demotion> {
        let hour = now / 3_600;
        let cutoff = hour.saturating_sub(23);

        let w = self.state.windows.entry(tuple.to_string()).or_default();
        *w.entry(hour).or_insert(0) += 1;
        w.retain(|h, _| *h >= cutoff);
        let count: u64 = w.values().sum();
        self.dirty = true;

        if let Some(d) = self.state.demoted_tuples.get_mut(tuple) {
            d.last_seen = now;
            d.count = count;
            return None;
        }
        if count <= self.noisy_rule_per_day {
            return None;
        }

        let mut d = Demotion {
            rule: rule.to_string(),
            tuple: tuple.to_string(),
            since: now,
            count,
            last_seen: now,
            patterns_quiet: 0,
        };
        self.state.demoted_tuples.insert(tuple.to_string(), d.clone());
        d.patterns_quiet = self
            .state
            .demoted_tuples
            .values()
            .filter(|t| t.rule == rule)
            .count();
        let seen = self.state.redemotions.entry(tuple.to_string()).or_insert(0);
        *seen += 1;
        let times = *seen;
        if times >= REDEMOTE_PROPOSE_AT {
            self.propose_redemoted(rule, tuple, count, times, now);
        }
        log::warn!(
            "noise guard: {} raised {} alerts in 24 h for one pattern; demoting that pattern \
             to the timeline (other patterns of this rule stay on the badge)",
            rule,
            count
        );
        if d.patterns_quiet >= self.noisy_rule_fanout {
            // Said out loud, and nothing else. See `note_alert`'s doc: a
            // detection rule that floods across many shapes is a rule bug, and
            // the fix for a rule bug is a person changing the rule -- not a
            // 24 h silence over every shape of it, including the ones nobody
            // has seen.
            log::warn!(
                "noise guard: {} is now quiet in {} distinct patterns. That is the rule being \
                 wrong for this machine rather than one noisy shape -- it wants retuning, or a \
                 `moat.omarchy/tier: signal` declaration if it is a building block. Nothing has \
                 been silenced beyond those {} patterns.",
                rule,
                d.patterns_quiet,
                d.patterns_quiet
            );
        }
        Some(d)
    }

    /// Is this exact pattern demoted?
    ///
    /// The `rule` argument is kept for the call sites' readability and because
    /// the tuple key embeds it; there is no rule-wide state left to consult.
    pub fn is_demoted_tuple(&self, _rule: &str, tuple: &str) -> bool {
        self.state.demoted_tuples.contains_key(tuple)
    }

    /// Every rule with at least one quietened pattern.
    ///
    /// The list a *person* wants: what has Moat stopped asking me about, and
    /// what can I turn back on. `undemote` on any of these clears every pattern
    /// under it.
    pub fn demoted_rules(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for d in self.state.demoted_tuples.values() {
            if !out.contains(&d.rule) {
                out.push(d.rule.clone());
            }
        }
        out.sort();
        out
    }

    /// How many individual patterns are quiet, for the panel's Rules tab.
    pub fn demoted_pattern_count(&self) -> usize {
        self.state.demoted_tuples.len()
    }

    /// "keep watching": clear a demotion on request.
    /// "keep watching" a rule: clears every pattern-scoped demotion under it,
    /// because a user asking to be told about a rule again means all of it, not
    /// the shapes that happen not to be quiet.
    pub fn undemote(&mut self, rule: &str) -> bool {
        let mut hit = false;
        let tuples: Vec<String> = self
            .state
            .demoted_tuples
            .iter()
            .filter(|(_, d)| d.rule == rule)
            .map(|(k, _)| k.clone())
            .collect();
        for t in tuples {
            self.state.demoted_tuples.remove(&t);
            // Start the window over, or the next alert re-demotes instantly.
            self.state.windows.remove(&t);
            hit = true;
        }
        if hit {
            self.state.windows.remove(rule);
            self.dirty = true;
        }
        hit
    }

    /// Demotions clear themselves once 24 h pass under the threshold.
    /// Returns the rules that came back.
    pub fn clear_stale_demotions(&mut self, now: u64) -> Vec<String> {
        let hour = now / 3_600;
        let cutoff = hour.saturating_sub(23);
        let mut cleared = Vec::new();
        // Every demotion is pattern-scoped. Without this they would be
        // permanent, which is a worse promise than a circuit breaker.
        let tuples: Vec<(String, String, u64)> = self
            .state
            .demoted_tuples
            .iter()
            .map(|(k, d)| (k.clone(), d.rule.clone(), d.since))
            .collect();
        for (tuple, rule, since) in tuples {
            let count: u64 = self
                .state
                .windows
                .get(&tuple)
                .map(|w| w.iter().filter(|(h, _)| **h >= cutoff).map(|(_, c)| *c).sum())
                .unwrap_or(0);
            if count <= self.noisy_rule_per_day && now.saturating_sub(since) >= DAY {
                self.state.demoted_tuples.remove(&tuple);
                self.dirty = true;
                if !cleared.contains(&rule) {
                    cleared.push(rule);
                }
            }
        }
        cleared
    }

    /// The five (actor, file) tuples a demoted rule fires on most.
    pub fn top_tuples(&self, rule: &str, n: usize) -> Vec<TupleStat> {
        let mut v: Vec<TupleStat> = self
            .state
            .tuples
            .values()
            .filter(|t| t.rule == rule)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then(a.exe.cmp(&b.exe)));
        v.truncate(n);
        v
    }

    // ------------------------------------------------------------- revocation

    /// Learned entries whose actor is no longer official, with the reason.
    /// The caller has the provenance classifier; this only knows the keys.
    pub fn learned_entries(&self) -> Vec<LearnedEntry> {
        self.state
            .learned
            .values()
            .filter(|e| e.revoked.is_none())
            .cloned()
            .collect()
    }

    /// Backfill a human approval recovered from the on-disk comment.
    ///
    /// `accepted_by` was added on 2026-09-09; entries written before it
    /// deserialise as None and would otherwise look like something the learner
    /// wrote. `accept` has always written "accepted by <who>" into the block's
    /// comment, so the record survived even though the field did not.
    pub fn mark_accepted_by(&mut self, key: &str, who: &str) {
        if let Some(e) = self.state.learned.get_mut(key) {
            e.accepted_by = Some(who.to_string());
            self.dirty = true;
        }
    }

    pub fn mark_revoked(&mut self, key: &str, reason: &str) {
        if let Some(e) = self.state.learned.get_mut(key) {
            e.revoked = Some(reason.to_string());
        }
        if let Some(t) = self.state.tuples.get_mut(key) {
            t.learned = false;
        }
        self.dirty = true;
    }

    // ----------------------------------------------------------------- export

    /// LEARNING §8 step 1: every tuple with its counts, days, window and
    /// severity, suppressed and demoted ones included and marked.
    pub fn export(&self, since: Option<&str>) -> Vec<serde_json::Value> {
        let mut rows: Vec<&TupleStat> = self
            .state
            .tuples
            .values()
            .filter(|t| match since {
                Some(s) => t.last_seen.as_str() >= s,
                None => true,
            })
            .collect();
        rows.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.rule.cmp(&b.rule))
                .then(a.exe.cmp(&b.exe))
        });
        rows.iter()
            .map(|t| {
                serde_json::json!({
                    "rule": t.rule,
                    "exe": t.exe,
                    "provenance": t.provenance,
                    "package": t.package,
                    "parent": t.parent,
                    "dir": t.dir,
                    "context": t.context,
                    "severity": t.severity,
                    "count": t.count,
                    "days": t.days.len(),
                    "first_seen": t.first_seen,
                    "last_seen": t.last_seen,
                    "rarity": t.rarity,
                    "suppressed": t.suppressed,
                    // This tuple's own demotion. It used to be OR'd with a
                    // rule-wide one; there is no such thing any more, and a row
                    // that reads `demoted: true` now means this exact shape.
                    "demoted": t.demoted || self.is_demoted_tuple(&t.rule, &t.key()),
                    "learned": t.learned,
                    "max_severity": crate::alert::severity_name(t.max_rank),
                    "max_rule_severity": crate::alert::severity_name(t.max_base_rank),
                    "eligible": self.eligible(t),
                    "blocked_by": self.blocked_by(t),
                    "toml": t.toml(),
                })
            })
            .collect()
    }

    // ---------------------------------------------------------- persistence

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn save_if_due(&mut self, now: u64, force: bool) {
        if !self.dirty {
            return;
        }
        if !force && now.saturating_sub(self.last_save) < self.save_every {
            return;
        }
        self.state.v = BASELINE_V;
        let body = match serde_json::to_string(&self.state) {
            Ok(b) => format!("{}\n", b),
            Err(e) => {
                log::warn!("baseline.json: {}", e);
                return;
            }
        };
        match crate::util::atomic_write(&self.path, body.as_bytes(), 0o640) {
            Ok(_) => {
                let _ = crate::util::secure_path(&self.path, &self.group, 0o640);
                self.dirty = false;
                self.last_save = now;
            }
            Err(e) => log::warn!("baseline.json: {}", e),
        }
    }

    /// The `baseline` block of `status` (BASELINE §8 "Resolved shapes").
    pub fn status(&self, now: u64) -> serde_json::Value {
        serde_json::json!({
            "learning": self.learning(now),
            "learning_ends": self.learning_ends(),
            "proposals": self.state.proposals.len(),
            "learned": self.state.learned.values().filter(|e| e.revoked.is_none()).count(),
            "demoted": self.demoted_rules(),
        })
    }
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// `2026-09-03T16:21:07.123Z` -> `2026-09-03`.
pub fn date_part(ts: &str) -> String {
    ts.split('T').next().unwrap_or(ts).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline(dir: &Path, now: u64) -> Baseline {
        Baseline::load(dir, "moat", 7, 3, 20, None, now)
    }

    const NOW: u64 = 1_800_000_000;

    fn obs<'a>(day: u64, sev: &'a str, prov: &'a str, rarity: &'a str) -> Observation<'a> {
        let now = NOW + day * DAY;
        Observation {
            rule: "moat-cred-ssh-private-key-read",
            exe: "/usr/bin/restic",
            parent: "/usr/bin/systemd",
            dir: "/home/dan/.ssh",
            severity: sev,
            severity_base: sev,
            provenance: prov,
            package: Some("restic 0.18-1".into()),
            context: "service",
            rarity,
            suppressed: false,
            demoted: false,
            ts: crate::util::rfc3339_of(now),
            now,
        }
    }

    // -------------------------------------------------------------- learning

    #[test]
    fn three_distinct_days_of_an_official_medium_is_learned_during_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        assert!(b.learning(NOW));
        assert_eq!(b.observe(&obs(0, "medium", "official", "common")), Learned::None);
        assert_eq!(b.observe(&obs(1, "medium", "official", "common")), Learned::None);
        let got = b.observe(&obs(2, "low", "official", "common"));
        match got {
            Learned::Entry { toml, comment, .. } => {
                assert!(toml.contains("name = \"moat-cred-ssh-private-key-read\""));
                assert!(toml.contains("exe = \"/usr/bin/restic\""));
                assert!(toml.contains("file = \"/home/dan/.ssh/*\""));
                assert!(toml.contains("parent = \"/usr/bin/systemd\""));
                assert!(comment.starts_with("learned "), "{}", comment);
                assert!(comment.contains("3 distinct days"), "{}", comment);
                assert!(comment.contains("actor official (restic 0.18-1)"), "{}", comment);
            }
            other => panic!("expected an entry, got {:?}", other),
        }
        // And it only happens once.
        assert_eq!(b.observe(&obs(3, "medium", "official", "common")), Learned::None);
    }

    /// A learned entry names the ACTOR, and for an interpreter the actor is
    /// not the code that ran. `python3 build.py` is official, medium and
    /// daily -- a model citizen by every other gate -- and the entry it would
    /// earn covers any other script under the same parent and directory,
    /// including ones nobody has ever seen. Revocation re-checks python3,
    /// which never stops being official.
    #[test]
    fn an_interpreter_is_never_learned_because_the_tuple_does_not_name_the_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        let py = |day: u64| {
            let mut o = obs(day, "medium", "official", "common");
            o.exe = "/usr/bin/python3.14";
            o.package = Some("python 3.14-1".into());
            o
        };
        // Three official medium days: everything the restic tuple needed.
        assert_eq!(b.observe(&py(0)), Learned::None);
        assert_eq!(b.observe(&py(1)), Learned::None);
        assert_eq!(
            b.observe(&py(2)),
            Learned::None,
            "an interpreter tuple must not become an allowlist entry"
        );
    }

    #[test]
    fn nothing_high_foreign_or_rare_is_ever_learned() {
        let dir = tempfile::tempdir().unwrap();
        for (sev, prov, rarity, why) in [
            ("high", "official", "common", "high is never learned"),
            ("medium", "foreign", "common", "foreign actors are never learned"),
            ("medium", "user", "common", "user actors are never learned"),
            ("medium", "official", "rare", "a tuple must be ordinary first"),
        ] {
            let sub = dir.path().join(why.replace(' ', "-"));
            std::fs::create_dir_all(&sub).unwrap();
            let mut b = baseline(&sub, NOW);
            for d in 0..5 {
                assert_eq!(b.observe(&obs(d, sev, prov, rarity)), Learned::None, "{}", why);
            }
        }
    }

    #[test]
    fn one_high_in_the_history_disqualifies_the_tuple_forever() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        b.observe(&obs(0, "high", "official", "common"));
        for d in 1..6 {
            assert_eq!(b.observe(&obs(d, "medium", "official", "common")), Learned::None);
        }
    }

    #[test]
    fn after_the_window_the_same_pattern_becomes_a_proposal() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        // Close the window.
        b.state.learning_until = NOW;
        for d in 0..2 {
            assert_eq!(b.observe(&obs(d, "medium", "official", "common")), Learned::None);
        }
        let Learned::Proposed { id } = b.observe(&obs(2, "medium", "official", "common")) else {
            panic!("expected a proposal");
        };
        let p = b.proposal(&id).unwrap().clone();
        assert_eq!(p.rule, "moat-cred-ssh-private-key-read");
        assert_eq!(p.days, 3);
        assert_eq!(p.count, 3);
        assert!(p.toml.contains("[[rule]]"));
        assert!(!p.first_seen.is_empty() && !p.last_seen.is_empty());

        // Accept it: it leaves the list and carries a comment naming who.
        let (accepted, comment) = b.accept(&id, "dan").unwrap();
        assert_eq!(accepted.id, id);
        assert!(comment.contains("accepted by dan"), "{}", comment);
        assert!(b.proposals().is_empty());
        assert!(b.accept(&id, "dan").is_err());
    }

    #[test]
    fn a_dismissed_proposal_is_not_offered_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        b.state.learning_until = NOW;
        for d in 0..3 {
            b.observe(&obs(d, "medium", "official", "common"));
        }
        let id = b.proposals()[0].id.clone();
        b.dismiss(&id).unwrap();
        assert!(b.proposals().is_empty());
        for d in 3..8 {
            assert_eq!(b.observe(&obs(d, "medium", "official", "common")), Learned::None);
        }
    }

    #[test]
    fn relearn_reopens_the_window_and_clears_the_pending_questions() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        b.state.learning_until = NOW;
        for d in 0..3 {
            b.observe(&obs(d, "medium", "official", "common"));
        }
        assert_eq!(b.proposals().len(), 1);
        let until = b.relearn(Some(14), NOW);
        assert_eq!(until, NOW + 14 * DAY);
        assert!(b.learning(NOW));
        assert!(b.proposals().is_empty());
        // The tuple is askable again, but the day counters restarted with the
        // window: the old three days do not carry over, so one observation is
        // not enough and three fresh ones are.
        assert_eq!(b.observe(&obs(4, "medium", "official", "common")), Learned::None);
        assert_eq!(b.observe(&obs(5, "medium", "official", "common")), Learned::None);
        assert!(matches!(b.observe(&obs(6, "medium", "official", "common")), Learned::Entry { .. }));
    }

    #[test]
    fn context_escalation_does_not_bar_a_tuple_from_the_baseline() {
        // BASELINE §2b escalates by context and never downgrades in
        // pkg-install, so a tuple that scores medium every ordinary day was
        // permanently barred by one sighting inside a package build. That was
        // 628 of 1206 tuples on this machine on 2026-09-04 -- the largest
        // single reason nothing had ever been learned.
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        for d in 0..2 {
            let mut o = obs(d, "high", "official", "common");
            o.severity_base = "medium"; // the rule said medium; context said high
            assert_eq!(b.observe(&o), Learned::None, "day {d} is not yet three days");
        }
        // The third distinct day is the one that learns it.
        let mut o = obs(2, "high", "official", "common");
        o.severity_base = "medium";
        assert!(matches!(b.observe(&o), Learned::Entry { .. }),
                "the rule scored it medium; context is what a baseline is for");
    }

    #[test]
    fn a_rule_that_really_scores_high_is_still_never_learned() {
        // The other half: D1 relaxes what "high" means, it does not remove the
        // gate. A detection that itself says high stays out.
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        for d in 0..5 {
            let mut o = obs(d, "high", "official", "common");
            o.severity_base = "high";
            assert_eq!(b.observe(&o), Learned::None, "day {d}");
        }
    }

    #[test]
    fn anything_that_ever_reached_critical_stays_out_whatever_the_rule_said() {
        // The hard ceiling. A medium-at-base tuple that context took all the
        // way to critical is not something to quietly learn.
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        let mut first = obs(0, "critical", "official", "common");
        first.severity_base = "medium";
        b.observe(&first);
        for d in 1..5 {
            let mut o = obs(d, "medium", "official", "common");
            o.severity_base = "medium";
            assert_eq!(b.observe(&o), Learned::None, "day {d}");
        }
    }

    #[test]
    fn relearn_clears_a_max_rank_left_by_rules_that_have_since_been_retuned() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        // One high, then the rule is retuned and the same tuple scores medium.
        b.observe(&obs(0, "high", "official", "common"));
        for d in 1..4 {
            assert_eq!(b.observe(&obs(d, "medium", "official", "common")), Learned::None);
        }
        // max_rank is a running maximum, so the retune alone never frees it.
        for d in 4..8 {
            assert_eq!(b.observe(&obs(d, "medium", "official", "common")), Learned::None);
        }
        b.relearn(None, NOW + 8 * DAY);
        for d in 8..10 {
            assert_eq!(b.observe(&obs(d, "medium", "official", "common")), Learned::None);
        }
        assert!(matches!(
            b.observe(&obs(10, "medium", "official", "common")),
            Learned::Entry { .. }
        ));
    }

    #[test]
    fn relearn_does_not_rescue_a_tuple_that_is_still_severe() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        b.observe(&obs(0, "high", "official", "common"));
        b.relearn(None, NOW + DAY);
        // Clearing max_rank is self-healing: the next high sets it straight back.
        for d in 1..6 {
            assert_eq!(b.observe(&obs(d, "high", "official", "common")), Learned::None);
        }
    }

    #[test]
    fn the_export_names_the_gate_that_is_holding_a_tuple_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        for d in 0..3 {
            b.observe(&obs(d, "high", "official", "common"));
        }
        let rows = b.export(None);
        let row = &rows[0];
        assert_eq!(row["eligible"], serde_json::json!(false));
        assert_eq!(row["max_severity"], serde_json::json!("high"));
        let why = row["blocked_by"].as_str().expect("a reason");
        assert!(why.contains("the rule scored it high once"), "{why}");
        assert!(why.contains("relearn"), "{why}");
        // Both severities are reported, because they now mean different things:
        // one is what the detection said, the other what context made of it.
        assert_eq!(row["max_rule_severity"], serde_json::json!("high"));
    }

    // ----------------------------------------------------------- noise guard

    /// A pattern that keeps coming back becomes a decision, not a habit.
    ///
    /// The noise guard forgets on purpose, so an unofficial pattern that
    /// recurs costs the same badge flood every time it returns and never
    /// graduates -- the baseline only learns OFFICIAL actors, deliberately,
    /// because automatic trust from repetition is what an attacker can
    /// manufacture. This is the escape hatch that keeps a person in the loop.
    #[test]
    fn a_pattern_demoted_again_and_again_is_offered_as_a_decision() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        let rule = "moat-exec-untrusted-tmpfs";
        // A REAL tuple key: `propose_redemoted` parses it back into its four
        // fields to build the allowlist block, so a placeholder would be
        // silently ignored -- which is what this test caught first time.
        let key = tuple_key(rule, "/usr/bin/bash", "/usr/bin/makepkg", "/tmp/build");
        let tuple = key.as_str();
        let mut now = NOW;

        for round in 1..=REDEMOTE_PROPOSE_AT {
            // Flood past the threshold, which demotes the pattern.
            for _ in 0..=(b.noisy_rule_per_day + 1) {
                b.note_alert(rule, tuple, now);
                now += 1;
            }
            assert!(b.is_demoted_tuple(rule, tuple), "round {} must demote", round);
            // A quiet day clears it, and the cycle begins again.
            now += DAY * 2;
            b.clear_stale_demotions(now);
        }

        let props: Vec<&Proposal> = b.proposals().iter().filter(|p| p.key == tuple).collect();
        assert_eq!(props.len(), 1, "offered once, not once per flood");
        assert!(
            !props[0].reason.is_empty(),
            "and marked as an observation, not the baseline vouching for it"
        );
        assert!(props[0].toml.contains(rule), "{}", props[0].toml);
    }

    #[test]
    fn a_noisy_pattern_is_demoted_exactly_once_and_only_that_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        let rule = "moat-persist-hypr-config-write";
        for i in 0..20 {
            assert!(b.note_alert(rule, "t1", NOW + i).is_none(), "20 is not over 20");
        }
        assert!(!b.is_demoted_tuple(rule, "t1"));
        let d = b.note_alert(rule, "t1", NOW + 21).expect("the 21st crosses it");
        assert_eq!(d.rule, rule);
        assert_eq!(d.tuple, "t1");
        assert_eq!(d.count, 21);
        assert!(b.is_demoted_tuple(rule, "t1"));
        // No second alert about the same demotion.
        assert!(b.note_alert(rule, "t1", NOW + 22).is_none());

        // The whole point: a shape of the same rule that nobody has seen is
        // still loud. On 2026-09-04 the rule-wide version of this silenced a
        // real supply-chain exec because the machine's own builds had made a
        // *different* shape of the same rule noisy.
        assert!(!b.is_demoted_tuple(rule, "t2"), "an unseen pattern stays on the badge");
        assert_eq!(d.patterns_quiet, 1, "one shape of this rule is quiet, not the rule");
    }

    /// A rule that floods across many shapes says so and silences NOTHING it
    /// has not seen.
    ///
    /// This test asserted the opposite until 2026-09-05: the "fan-out backstop"
    /// demoted the whole rule once five of its patterns had gone quiet, so
    /// every shape of it — including shapes nobody had ever seen — went to the
    /// timeline for 24 h. That is how a real `/tmp` dropper inside a package
    /// install was hidden on 2026-09-04, and moat's own test suite re-created
    /// the same rule-wide silence in seconds.
    ///
    /// The backstop existed because the noise guard was the only mechanism that
    /// could say "this rule is a building block, not a detection". Rules say it
    /// themselves now (`moat.omarchy/tier: signal`), and what is left over — a
    /// DETECTION rule flooding in general — is a rule bug. The output for a rule
    /// bug is the report, not a blanket silence: a 24 h circuit breaker that
    /// forgets cannot fix a rule, and while it is tripped it is covering shapes
    /// that were never noisy.
    #[test]
    fn a_rule_noisy_across_many_patterns_reports_itself_and_silences_nothing_unseen() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        let rule = "moat-x-pkg-egress";
        let mut last = None;
        for t in 0..5 {
            let tuple = format!("tuple-{t}");
            for i in 0..22 {
                if let Some(d) = b.note_alert(rule, &tuple, NOW + t * 100 + i) {
                    last = Some(d);
                }
            }
        }
        let d = last.expect("each flooding pattern is demoted on its own");
        assert_eq!(d.rule, rule);
        assert_eq!(d.tuple, "tuple-4", "every demotion is scoped to one pattern");
        assert_eq!(
            d.patterns_quiet, 5,
            "and it carries the fan-out count, which is what the alert reports"
        );
        assert!(d.patterns_quiet >= b.noisy_rule_fanout, "past the fan-out threshold");
        // The five flooding shapes are quiet, one at a time.
        for t in 0..5 {
            assert!(b.is_demoted_tuple(rule, &format!("tuple-{t}")));
        }
        // A shape nobody has seen is still loud. This is the whole change.
        assert!(
            !b.is_demoted_tuple(rule, "never-seen"),
            "a rule flooding in five known shapes must not silence a sixth nobody has seen"
        );
        // The rule is still listed as quietened, so a person can undemote it.
        assert_eq!(b.demoted_rules(), vec![rule]);
        assert_eq!(b.demoted_pattern_count(), 5);
    }

    #[test]
    fn a_demotion_clears_itself_after_a_quiet_day_and_on_request() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        let rule = "moat-x-pkg-egress";
        for i in 0..25 {
            b.note_alert(rule, "t1", NOW + i);
        }
        assert!(b.is_demoted_tuple(rule, "t1"));
        // Still noisy: nothing clears.
        assert!(b.clear_stale_demotions(NOW + 100).is_empty());
        // A day later with the window aged out.
        assert_eq!(b.clear_stale_demotions(NOW + DAY + 3_600), vec![rule]);
        assert!(!b.is_demoted_tuple(rule, "t1"));

        // "keep watching" clears it immediately and resets the window.
        for i in 0..25 {
            b.note_alert(rule, "t1", NOW + 2 * DAY + i);
        }
        assert!(b.is_demoted_tuple(rule, "t1"));
        assert!(b.undemote(rule));
        assert!(!b.is_demoted_tuple(rule, "t1"));
        assert!(!b.undemote(rule), "already cleared");
        assert!(b.note_alert(rule, "t1", NOW + 2 * DAY + 100).is_none(), "the window restarted");
    }

    #[test]
    fn the_top_tuples_of_a_noisy_rule_can_be_proposed_wholesale() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        for i in 0..8u64 {
            let exe = format!("/usr/bin/tool{}", i % 3);
            let ts = crate::util::rfc3339_of(NOW + i);
            b.observe(&Observation {
                rule: "moat-persist-hypr-config-write",
                exe: &exe,
                parent: "/usr/bin/Hyprland",
                dir: "/home/dan/.config/hypr",
                severity: "low",
                severity_base: "low",
                provenance: "official",
                package: None,
                context: "service",
                rarity: "common",
                suppressed: false,
                demoted: true,
                ts,
                now: NOW + i,
            });
        }
        let top = b.top_tuples("moat-persist-hypr-config-write", 5);
        assert_eq!(top.len(), 3);
        assert!(top[0].count >= top[1].count);

        let keys: Vec<String> = top.iter().map(|t| t.key()).collect();
        let made = b.propose_keys(&keys);
        assert_eq!(made.len(), 3);
        assert!(made.iter().all(|p| p.toml.contains("moat-persist-hypr-config-write")));
        // Idempotent: proposing the same tuples again adds nothing.
        assert!(b.propose_keys(&keys).is_empty());
    }

    // ---------------------------------------------------------------- export

    #[test]
    fn the_export_carries_every_field_the_reviewer_needs() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        let mut o = obs(0, "medium", "official", "common");
        o.suppressed = true;
        b.observe(&o);
        b.observe(&obs(1, "medium", "foreign", "rare"));
        let rows = b.export(None);
        assert_eq!(rows.len(), 1, "the same tuple both times");
        let r = &rows[0];
        for k in [
            "rule", "exe", "provenance", "parent", "dir", "context", "severity", "count",
            "days", "first_seen", "last_seen", "rarity", "suppressed", "demoted", "toml",
        ] {
            assert!(r.get(k).is_some(), "export row has no {}", k);
        }
        assert_eq!(r["count"], 2);
        assert_eq!(r["suppressed"], true, "suppressed tuples are included and marked");
        assert_eq!(r["eligible"], false, "the last sighting was foreign");

        // `--since` filters on last_seen.
        assert!(b.export(Some("2099-01-01")).is_empty());
        assert_eq!(b.export(Some("1970-01-01")).len(), 1);
    }

    // ----------------------------------------------------------- persistence

    #[test]
    fn installed_at_is_stamped_once_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = baseline(dir.path(), NOW);
            assert_eq!(b.state.installed_at, NOW);
            assert_eq!(b.state.learning_until, NOW + 7 * DAY);
            b.observe(&obs(0, "medium", "official", "common"));
            b.save_if_due(NOW, true);
        }
        let b2 = baseline(dir.path(), NOW + 100 * DAY);
        assert_eq!(b2.state.installed_at, NOW, "not re-stamped");
        assert!(!b2.learning(NOW + 100 * DAY));
        assert_eq!(b2.state.tuples.len(), 1);
    }

    #[test]
    fn a_corrupt_state_file_starts_over_rather_than_crashing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("baseline.json"), b"{{{").unwrap();
        let b = baseline(dir.path(), NOW);
        assert_eq!(b.state.installed_at, NOW);
    }

    #[test]
    fn moats_own_meta_rules_are_never_learned() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        for rule in NEVER_LEARN {
            for d in 0..5 {
                let now = NOW + d * DAY;
                let r = b.observe(&Observation {
                    rule,
                    exe: "/usr/bin/moatd",
                    parent: "",
                    dir: "",
                    severity: "low",
                    severity_base: "low",
                    provenance: "official",
                    package: None,
                    context: "service",
                    rarity: "common",
                    suppressed: false,
                    demoted: false,
                    ts: crate::util::rfc3339_of(now),
                    now,
                });
                assert_eq!(r, Learned::None, "{}", rule);
            }
        }
    }

    #[test]
    fn a_revoked_entry_stops_counting_as_learned() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = baseline(dir.path(), NOW);
        for d in 0..3 {
            b.observe(&obs(d, "medium", "official", "common"));
        }
        assert_eq!(b.learned_entries().len(), 1);
        let key = b.learned_entries()[0].key.clone();
        b.mark_revoked(&key, "the owning package is no longer official");
        assert!(b.learned_entries().is_empty());
        assert_eq!(b.status(NOW)["learned"], 0);
    }
}
