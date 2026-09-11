//! The alert record of CONTRACT §4, and the folded view readers get.
//!
//! Nothing is ever rewritten in place: state changes are appended as
//! `{"v":1,"id":"<same id>","update":{...}}` lines and folded by id.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const ALERT_V: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessRef {
    pub pid: u32,
    pub uid: u32,
    pub exe: String,
    pub args: String,
    pub cwd: String,
    pub start_ts: String,
    /// Did this run in a container? From the sensor's `process.ns.mnt.is_host`
    /// at event time. `None` when the sensor did not say.
    ///
    /// Exported because it decides whether a row reaches the badge, and a
    /// decision nobody can see is a decision nobody can check: verifying the
    /// container switch on 2026-09-08 meant inferring it from severity_reason
    /// strings, which is how a host `makepkg` sat demoted for three hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_container: Option<bool>,
    pub ancestry: Vec<Ancestor>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Ancestor {
    pub pid: u32,
    pub exe: String,
    /// Everything below is what the detail panel reads, and every field is
    /// `default` so a record written by an older daemon still parses -- the
    /// store is append-only and years of alerts predate this.
    ///
    /// It is deliberately NOT in the feed: `cmd_feed` strips it, because the
    /// panel polls that several times a minute and only needs the names for the
    /// collapsed chain. The full row arrives with `explain`, which the card
    /// already fetches when it is opened.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub args: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub start_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// What else this process started, besides the one that led to the alert.
    ///
    /// CAPPED. See `engine::MAX_SIBLINGS`: unbounded, this one field reached
    /// 730 KB on a single alert and made the mean record 47 KB.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub others: Vec<Sibling>,
    /// How many there actually were, which is not `others.len()` once the cap
    /// bites. The panel's "N other children" label is built from this: saying
    /// "20" when a cargo build started 554 of them would be a quieter lie than
    /// saying nothing, and this row exists to answer "what else was that shell
    /// doing".
    #[serde(default, skip_serializing_if = "is_zero")]
    pub others_total: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl Ancestor {
    /// The two fields every caller has. Chain identity is built from these and
    /// nothing else, so it is unaffected by the detail above.
    pub fn new(pid: u32, exe: String) -> Ancestor {
        Ancestor {
            pid,
            exe,
            ..Default::default()
        }
    }
}

/// A process an ancestor started that is not on the path to the alert.
///
/// "What else was that shell doing" is how a person tells a build from an
/// intrusion, and it is the one thing the flat chain could never show.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Sibling {
    pub pid: u32,
    pub exe: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub args: String,
    /// `exited` / `running`, and the signal if one killed it. Stated rather
    /// than inferred from a missing field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileRef {
    pub path: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetRef {
    pub dst_ip: String,
    pub dst_port: u16,
    /// The name this machine most recently resolved to `dst_ip`, as the
    /// program asked for it, from systemd-resolved's query stream
    /// (`names.rs`, docs/DNS.md). `None` means NOT RECORDED -- a literal-IP
    /// connection, a resolution that bypassed resolved (DoH in a browser, a
    /// container with its own DNS), an answer older than `names.retain_secs`,
    /// or the stream being off -- never "there was no name". moat never
    /// resolves anything itself: a reverse lookup would answer a different
    /// question and add queries of moat's own.
    #[serde(default)]
    pub domain: Option<String>,
    /// Seconds between that resolution and this connection. The name is
    /// keyed by address, not by process, so a large age is the reader's cue
    /// that a CDN address may since have been handed to someone else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_age_secs: Option<u64>,
    /// The process that ASKED for this name, from the varlink kprobe
    /// (`moat-net-dns-query`). `"<exe> (pid N)"`.
    ///
    /// Separate from `domain`, and a stronger claim. `domain` is keyed by
    /// ADDRESS -- this machine resolved that name to that address recently, so
    /// a connection there probably belongs to it. This is keyed by the NAME and
    /// observed in the asking process's own context, so it says who looked it
    /// up rather than inferring it.
    ///
    /// `None` is NOT RECORDED, never "nobody asked": a Go binary with its own
    /// resolver never touches nss, a literal-IP connection has no lookup at
    /// all, and a lookup from before moatd started is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_queried_by: Option<String>,
    /// The owner name of the record that answered, when a CNAME chain ended
    /// somewhere other than the name asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_cname: Option<String>,
}

impl NetRef {
    pub fn new(dst_ip: impl Into<String>, dst_port: u16) -> NetRef {
        NetRef {
            dst_ip: dst_ip.into(),
            dst_port,
            domain: None,
            domain_age_secs: None,
            domain_cname: None,
            domain_queried_by: None,
        }
    }

    /// `ip:port`, with the name the record has for it: `142.251.154.119:443
    /// (www.google.com)`. An absent name adds nothing here; the explain block
    /// says "not recorded" in a line of its own.
    pub fn endpoint(&self) -> String {
        match &self.domain {
            Some(d) => format!("{}:{} ({})", self.dst_ip, self.dst_port, d),
            None => format!("{}:{}", self.dst_ip, self.dst_port),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IocRef {
    pub source: String,
    pub matched: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExplainOption {
    pub scope: String,
    /// Ready to paste: `moatctl ignore <id> --scope exe`.
    pub cmd: String,
    /// The exact TOML block that command would write.
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IfExpected {
    /// The policy's `fp-hint`: the scope we recommend first.
    pub hint: String,
    pub options: Vec<ExplainOption>,
    /// Where the block lands.
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Explain {
    pub what: String,
    pub why: String,
    pub evidence: Vec<String>,
    pub expected: String,
    pub if_expected: IfExpected,
    pub next: Vec<String>,
}

/// Tamper-evidence stamp for carry-forward rotation (`store::rotate`).
///
/// Append-only is a security property: `alerts.jsonl` is never rewritten in
/// place. Rotation, however, carries the *protected* rows forward into the
/// fresh generation by writing them again as folded Full lines — so a carried
/// line is a second, moatd-authored copy of a row whose original now lives in
/// `alerts.1.jsonl`. Stamping it says so out loud: a re-serialised carried row
/// is distinguishable from the original write, and a reader can tell how many
/// rotations a row has survived. Absent on every original write; old readers
/// ignore the unknown key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Carried {
    /// RFC3339 time of the rotation that carried this row forward.
    pub at: String,
    /// How many times this row has been carried across a rotation (1 on the
    /// first carry, incremented each time it survives another).
    pub generation: u64,
}

/// The rules whose meta-alerts are always retention-protected (P5).
///
/// These are moat telling on *itself* — protection was turned off, the sensor
/// disagrees with policy or is throttled, moat was not running, nobody is
/// watching, a baseline was revoked, a rule went noisy. They are exactly the
/// rows a flood would want to bury, so they never rotate or evict on volume.
/// An EXPLICIT list, not a `moat-x-` prefix match: `moat-x-mass-read` and the
/// other detection rules in that namespace are ordinary detections.
pub const PROTECTED_META_RULES: &[&str] = &[
    "moat-x-protection-changed",
    "moat-x-sensor-mismatch",
    "moat-x-sensor-throttled",
    "moat-x-was-not-running",
    "moat-x-nobody-is-watching",
    "moat-x-baseline-revoked",
    "moat-x-noisy-rule",
    "moat-x-binary-modified",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub v: u32,
    pub id: String,
    pub ts: String,
    pub severity: String,
    pub rule: String,
    pub family: String,
    pub title: String,
    pub summary: String,
    pub process: ProcessRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc: Option<IocRef>,
    pub rotate: Vec<String>,
    pub explain: Explain,
    /// `none` | `killed` | `quarantined`. Only ever `killed` once a
    /// `process_exit` with `signal: SIGKILL` confirmed it (NOTES §7).
    pub action_taken: String,
    pub actions: Vec<String>,
    pub acked: bool,
    /// WHO answered this, when it was answered.
    ///
    /// An ack is not privileged and should not be: it is the commonest thing a
    /// person does here, and a sudo prompt per click is how the meaningful
    /// prompt gets waved through. But "not privileged" must not mean
    /// "unattributed" -- a payload in the `moat` group can list alert ids and
    /// ack them, and clearing the badge is how it stops being looked at. The
    /// alert itself is never destroyed (this log is append-only); what an ack
    /// changes is whether anyone is asked about it, so the record of who asked
    /// for that is the thing that has to survive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_by: Option<String>,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,

    // --- BASELINE §8 -------------------------------------------------------
    /// Who acted: provenance, the owning package, and the script when an
    /// interpreter took its class from one.
    #[serde(default)]
    pub actor: crate::provenance::Actor,
    /// `interactive` | `pkg-install` | `service` | `unknown`.
    #[serde(default)]
    pub context: crate::context::Context,
    /// The severity the rule itself decided, before provenance and context.
    #[serde(default)]
    pub severity_base: String,
    /// "high → medium: actor is official (package hyprland)".
    #[serde(default)]
    pub severity_reason: String,
    /// `alerts` | `timeline` (BASELINE §5). A demoted rule is forced to
    /// `timeline` without being suppressed.
    #[serde(default = "default_surface")]
    pub surface: String,
    /// `detection` (the default) or `signal` — the rule's own declaration
    /// (BASELINE §4). A `signal` row is a building block: recorded in full, a
    /// full chain trigger, never on the badge on its own. Absent means
    /// `detection`, so an old record and a rule that says nothing both read as
    /// a detection.
    #[serde(default = "default_tier")]
    pub tier: String,
    /// The context matrix put this at high/critical *because it was inside a
    /// package install* (BASELINE §2b). The one outcome neither the `signal`
    /// tier nor a noise-guard demotion may quieten, which is why it is on the
    /// record and not re-derived: the noise guard reaches back over alerts
    /// already written (`engine::quieten_backlog`).
    #[serde(default)]
    pub pkg_install_escalation: bool,
    /// `null`, or the allowlist entry that suppressed it: `"user.toml#1"`,
    /// `"baseline.toml#3"`. Demoted rules are **not** suppressed.
    #[serde(default)]
    pub suppressed_by: Option<String>,
    /// `first_seen` | `rare` | `common` (LEARNING §1).
    #[serde(default)]
    pub rarity: crate::rarity::Rarity,
    /// The plain sentence behind `rarity`.
    #[serde(default)]
    pub rarity_text: String,
    /// The unattended agent verdict, once one has been recorded
    /// (LEARNING §2c). Absent until auto-triage has run on this alert, and
    /// absent forever when `[analysis] auto_triage = "off"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triage: Option<crate::triage::Triage>,
    /// LEARNING §4 and §9: the snapshot taken before any kill. Absent until the
    /// capture finishes, then appended as an `update` line — the alert must not
    /// wait on a filesystem walk to be written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident: Option<crate::incident::Incident>,
    /// CONTRACT §4 "Chain", design 2b/3a: the sequence this alert turned out to
    /// be one step of. Absent on the overwhelming majority of alerts — a chain
    /// is by design a rare thing — and appended as an `update` line when one is
    /// recognised, because the fourth event is what changes the meaning of the
    /// first and the first was written three seconds earlier.
    ///
    /// Every member of a chain carries the whole chain, so a reader that opened
    /// one alert can draw the story without joining anything. The chain's
    /// `severity` may be higher than this alert's own; the alert's own severity
    /// is never rewritten, because it is still the right answer about a single
    /// event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<crate::chain::Chain>,
    /// The chain this alert is a step of, by id -- and a chain's `id` IS its
    /// first step's alert id, so this names the ANCHOR: the one member whose
    /// record carries the chain in full on disk.
    ///
    /// The whole chain used to be appended to every member on every growth,
    /// which is quadratic: a 488-step chain from one `makepkg` run (2026-09-10)
    /// wrote about 48 MB on its final step alone and rotated the store ten
    /// times in eleven minutes. Now the chain is written once, against the
    /// anchor, and every other member gets this. `Store` rehydrates at fold
    /// time, so a reader still finds the whole chain on every member; the
    /// "every member carries the whole chain" promise above is kept at read
    /// time rather than write time. Records written before this field existed
    /// still carry the chain inline and fold exactly as they did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// What is actually *in* the files this alert implicated (`content.rs`).
    ///
    /// Empty on almost every alert: content analysis only runs when a chain
    /// reaches `high`, and it is appended as an `update` line for the same
    /// reason `incident` is — the alert must not wait on a file read to be
    /// written. Purely descriptive: nothing in here changes `severity`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<crate::content::FileAnalysis>,
    /// Set only when `store::rotate` carried this row forward into a fresh
    /// generation of `alerts.jsonl`; tamper-evidence that this Full line is a
    /// re-serialised copy, not the original write. Absent on every original
    /// write, and never set by an update line — see `Carried`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried: Option<Carried>,
    /// Not serialised: only the live daemon uses it, to tie a later
    /// `process_exit` back to the alert that predicted the kill.
    #[serde(skip)]
    pub exec_id: String,
}

fn default_surface() -> String {
    "alerts".to_string()
}

fn default_tier() -> String {
    crate::policy::TIER_DETECTION.to_string()
}

impl Alert {
    pub fn severity_rank(&self) -> u8 {
        severity_rank(&self.severity)
    }

    /// Is this the alert whose record carries its chain on disk? The anchor is
    /// the chain's first step, so the chain's id is this alert's id.
    pub fn is_chain_anchor(&self) -> bool {
        self.chain.as_ref().is_some_and(|c| c.id == self.id)
    }

    /// Suppressed alerts are recorded but never notified and never counted
    /// (BASELINE §8). A demoted rule keeps `suppressed_by: null` and is filtered
    /// out of the badge by its `surface` instead.
    pub fn is_suppressed(&self) -> bool {
        self.suppressed_by.is_some()
    }

    /// Is this row a **building block rather than a detection** (BASELINE §4)?
    ///
    /// A `signal` rule declares that it is right about what it saw and weak
    /// about what it means. The one exception is the cell the whole product is
    /// about: the context matrix calling the same event high or critical
    /// *because it happened inside a package install*. There the row is a
    /// detection like any other — it is on the badge, it takes a snapshot, and
    /// it is queued for triage.
    ///
    /// Everything that asks "should a person be asked about this row" asks this
    /// one question, so the badge, the snapshot, the triage queue and the noise
    /// guard cannot drift apart.
    pub fn is_building_block(&self) -> bool {
        self.tier == crate::policy::TIER_SIGNAL && !self.pkg_install_escalation
    }

    /// **Retention follows importance, not arrival order.** A protected row is
    /// one that must survive a flood: it is neither dropped from the feed
    /// window (`cmd_feed`), rotated out on volume (`store::rotate` carries it
    /// forward), nor allowed to let its incident snapshot be pruned
    /// (`engine`'s incident keep-set). One predicate for all three, so they
    /// cannot drift.
    ///
    /// Protected iff ANY of:
    /// * **P1 badge** — surfaced, unacked, not suppressed. This is exactly the
    ///   `unacked` predicate in `store.rs`: the thing a person still has to
    ///   answer.
    /// * **P2 acted** — something was done (`killed`/`quarantined`/…), acked or
    ///   not: the record of a response must outlive the noise around it.
    /// * **P3 story** — a step in a chain that reached `high` or above.
    /// * **P4 indexed** — it has an incident snapshot on disk; the row is what
    ///   pins that evidence.
    /// * **P5 meta** — one of the self-health rules in `PROTECTED_META_RULES`.
    /// * **P6 answered-but-grave** — surfaced and `high`+ severity, even once
    ///   acked: a critical that was looked at is still the last thing to lose.
    pub fn is_protected(&self) -> bool {
        let high = severity_rank("high");
        // P1: on the badge, unacked, not suppressed (mirrors `AlertStore::unacked`).
        if self.surface == "alerts" && !self.acked && !self.is_suppressed() {
            return true;
        }
        // P2: a response was taken.
        if self.action_taken != "none" {
            return true;
        }
        // P3: a member of a high+ chain.
        if self
            .chain
            .as_ref()
            .is_some_and(|c| severity_rank(&c.severity) >= high)
        {
            return true;
        }
        // P4: it holds an incident snapshot.
        if self.incident.is_some() {
            return true;
        }
        // P5: a self-health / protection meta alert.
        if PROTECTED_META_RULES.contains(&self.rule.as_str()) {
            return true;
        }
        // P6: surfaced and grave, even if answered.
        if self.surface == "alerts" && self.severity_rank() >= high {
            return true;
        }
        false
    }

    /// The baseline's tuple for this alert: (rule, actor exe, parent exe, file
    /// dir). Built from the stored record, so it agrees with what
    /// `engine::note_baseline` fed the baseline when the alert was raised.
    ///
    /// Used to decide whether an unattended triage pass has already read this
    /// exact shape (LEARNING §2c). A re-fire of a tuple an agent has already
    /// explained is the same question with a new id, and paying for the answer
    /// again is the single largest avoidable cost in the feature.
    pub fn tuple_key(&self) -> String {
        let dir = self
            .file
            .as_ref()
            .map(|f| crate::rarity::dir_of(&f.path))
            .unwrap_or_default();
        // `Finding::parent_exe` is `ancestry.first()`, and the stored record
        // keeps that same ordering.
        let parent = self
            .process
            .ancestry
            .first()
            .map(|a| a.exe.clone())
            .unwrap_or_default();
        crate::baseline::tuple_key(&self.rule, &self.process.exe, &parent, &dir)
    }

    /// BASELINE §8 "Resolved shapes": timeline rows group on the script an
    /// interpreter was running when there is one, otherwise on the binary.
    pub fn group_key(&self) -> &str {
        self.actor
            .script
            .as_deref()
            .unwrap_or(self.process.exe.as_str())
    }
}

pub fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

/// The inverse of `severity_rank`, for reporting a stored rank back to a human.
pub fn severity_name(rank: u8) -> &'static str {
    match rank {
        3 => "critical",
        2 => "high",
        1 => "medium",
        _ => "low",
    }
}

/// One appended state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateLine {
    pub v: u32,
    pub id: String,
    pub update: Map<String, Value>,
}

impl UpdateLine {
    pub fn new(id: &str) -> UpdateLine {
        UpdateLine {
            v: ALERT_V,
            id: id.to_string(),
            update: Map::new(),
        }
    }
    pub fn set(mut self, key: &str, value: Value) -> Self {
        self.update.insert(key.to_string(), value);
        self
    }
}

/// Apply an update line to an alert, the way every reader must.
pub fn fold(alert: &mut Alert, update: &Map<String, Value>) {
    for (k, v) in update {
        match (k.as_str(), v) {
            ("acked", Value::Bool(b)) => alert.acked = *b,
            ("acked_by", Value::String(s)) => alert.acked_by = Some(s.clone()),
            ("action_taken", Value::String(s)) => alert.action_taken = s.clone(),
            ("count", Value::Number(n)) => alert.count = n.as_u64(),
            ("severity", Value::String(s)) => alert.severity = s.clone(),
            ("ts", Value::String(s)) => alert.ts = s.clone(),
            ("surface", Value::String(s)) => alert.surface = s.clone(),
            ("suppressed_by", Value::String(s)) => alert.suppressed_by = Some(s.clone()),
            ("suppressed_by", Value::Null) => alert.suppressed_by = None,
            ("incident", v) => {
                alert.incident = serde_json::from_value(v.clone()).ok();
            }
            // A chain only ever grows, and a malformed one must not blank a
            // sequence already recorded — same rule as `triage`, for the same
            // reason: losing the story is worse than showing a stale one.
            ("chain", Value::Null) => alert.chain = None,
            ("chain", v) => {
                if let Ok(c) = serde_json::from_value(v.clone()) {
                    alert.chain = Some(c);
                }
            }
            // Membership by reference; the store fills `chain` in from the
            // anchor (`store::Cache::hydrate`).
            ("chain_id", Value::String(s)) => alert.chain_id = Some(s.clone()),
            ("chain_id", Value::Null) => alert.chain_id = None,
            // Content analysis arrives after the fact, like `incident`. Folding
            // it also folds its one-line summaries into `explain.evidence`,
            // which is what every reader — the panel, `moatctl show`, the
            // bundle — already renders. Deriving them here rather than storing
            // them twice means the sanitising in `FileAnalysis::evidence`
            // cannot be bypassed by a reader that builds its own line, and the
            // dedupe below keeps a re-fold from stuttering.
            ("content", v) => {
                if let Ok(c) = serde_json::from_value::<Vec<crate::content::FileAnalysis>>(v.clone())
                {
                    for line in c.iter().flat_map(|f| f.evidence()) {
                        if !alert.explain.evidence.contains(&line) {
                            alert.explain.evidence.push(line);
                        }
                    }
                    alert.content = c;
                }
            }
            // A malformed verdict must not silently blank an existing one, so
            // this folds only what parses; `triage: null` is the explicit undo.
            ("triage", Value::Null) => alert.triage = None,
            ("triage", v) => {
                if let Ok(t) = serde_json::from_value(v.clone()) {
                    alert.triage = Some(t);
                }
            }
            _ => {}
        }
    }
}

/// One line of `alerts.jsonl`: either a full alert or an update.
pub enum Record {
    Full(Box<Alert>),
    Update(UpdateLine),
}

pub fn parse_record(line: &str) -> Option<Record> {
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("update").is_some() {
        serde_json::from_value::<UpdateLine>(v).ok().map(Record::Update)
    } else {
        serde_json::from_value::<Alert>(v)
            .ok()
            .map(|a| Record::Full(Box::new(a)))
    }
}

/// Shared fixture: other modules' tests need a realistic alert.
#[cfg(test)]
pub mod tests_support {
    use super::*;

    pub fn demo_alert(id: &str) -> Alert {
        Alert {
            v: ALERT_V,
            id: id.into(),
            ts: "2026-09-03T16:21:07.123Z".into(),
            severity: "high".into(),
            rule: "moat-cred-ssh-private-key-read".into(),
            family: "cred".into(),
            title: "Private SSH key read by an unexpected program".into(),
            summary: "node (pid 41233) read /home/dan/.ssh/id_rsa.".into(),
            process: ProcessRef {
                pid: 41233,
                uid: 1000,
                exe: "/usr/bin/node".into(),
                args: "setup.mjs".into(),
                cwd: "/home/dan/proj".into(),
                start_ts: "2026-09-03T16:21:06.900Z".into(),
                in_container: None,
                ancestry: vec![Ancestor::new(41230, "/usr/bin/sh".into())],
            },
            file: Some(FileRef {
                path: "/home/dan/.ssh/id_rsa".into(),
                sha256: None,
            }),
            net: None,
            ioc: None,
            rotate: vec!["ssh-key".into()],
            explain: Explain {
                what: "node read your private SSH key.".into(),
                why: "why".into(),
                evidence: vec!["hook: ...".into()],
                expected: "expected".into(),
                if_expected: IfExpected {
                    hint: "exe".into(),
                    options: vec![ExplainOption {
                        scope: "exe".into(),
                        cmd: "moatctl ignore 01J8ZK6B4Q3M7N9P2R5S8T1V4W --scope exe".into(),
                        line: "[[rule]]\nname = \"x\"\n".into(),
                    }],
                    file: "/etc/moat/allowlist.d/user.toml".into(),
                },
                next: vec!["rotate".into()],
            },
            action_taken: "none".into(),
            actions: vec!["kill".into()],
            acked: false,
            acked_by: None,
            mode: "monitor".into(),
            count: None,
            actor: crate::provenance::Actor {
                provenance: crate::provenance::Provenance::User,
                package: None,
                script: None,
                modified: None,
            },
            context: crate::context::Context::PkgInstall,
            severity_base: "high".into(),
            severity_reason: "stays high: package install: never downgraded".into(),
            surface: "alerts".into(),
            tier: crate::policy::TIER_DETECTION.into(),
            pkg_install_escalation: false,
            suppressed_by: None,
            rarity: crate::rarity::Rarity::FirstSeen,
            rarity_text: "first time /usr/bin/node has read /home/dan/.ssh on this machine".into(),
            triage: None,
            incident: None,
            chain: None,
            chain_id: None,
            content: Vec::new(),
            carried: None,
            exec_id: "abc".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::demo_alert;
    use super::*;

    fn demo() -> Alert {
        demo_alert("01J8ZK6B4Q3M7N9P2R5S8T1V4W")
    }

    #[test]
    fn a_full_alert_round_trips_as_one_line() {
        let a = demo();
        let line = serde_json::to_string(&a).unwrap();
        assert!(!line.contains('\n'));
        assert!(!line.contains("exec_id"), "internal field must not leak");
        assert!(!line.contains("\"count\""), "absent optionals are omitted");
        assert!(!line.contains("\"net\""));
        // The baseline fields are part of the record, always.
        for k in [
            "\"actor\"", "\"context\"", "\"severity_base\"", "\"severity_reason\"",
            "\"surface\"", "\"suppressed_by\"", "\"rarity\"", "\"rarity_text\"",
        ] {
            assert!(line.contains(k), "record has no {}", k);
        }
        match parse_record(&line).unwrap() {
            Record::Full(b) => {
                let mut back = *b;
                back.exec_id = a.exec_id.clone();
                assert_eq!(back, a);
            }
            _ => panic!("should parse as a full alert"),
        }
    }

    #[test]
    fn updates_fold_by_id() {
        let mut a = demo();
        let u = UpdateLine::new(&a.id)
            .set("acked", Value::Bool(true))
            .set("action_taken", Value::String("killed".into()))
            .set("count", Value::from(3u64));
        let line = serde_json::to_string(&u).unwrap();
        match parse_record(&line).unwrap() {
            Record::Update(u) => {
                assert_eq!(u.id, a.id);
                fold(&mut a, &u.update);
            }
            _ => panic!("should parse as an update"),
        }
        assert!(a.acked);
        assert_eq!(a.action_taken, "killed");
        assert_eq!(a.count, Some(3));
    }

    #[test]
    fn suppression_and_surface_fold_like_every_other_field() {
        let mut a = demo();
        assert!(!a.is_suppressed());
        let u = UpdateLine::new(&a.id)
            .set("suppressed_by", Value::String("baseline.toml#3".into()))
            .set("surface", Value::String("timeline".into()));
        fold(&mut a, &u.update);
        assert!(a.is_suppressed());
        assert_eq!(a.suppressed_by.as_deref(), Some("baseline.toml#3"));
        assert_eq!(a.surface, "timeline");
        let clear = UpdateLine::new(&a.id).set("suppressed_by", Value::Null);
        fold(&mut a, &clear.update);
        assert!(!a.is_suppressed());
    }

    /// LEARNING §9: the snapshot reaches readers as an update line, so the
    /// alert can be written the instant it is raised.
    #[test]
    fn an_incident_folds_in_from_an_update_line() {
        let mut a = demo();
        assert!(a.incident.is_none());
        assert!(!serde_json::to_string(&a).unwrap().contains("incident"));
        let u = UpdateLine::new(&a.id).set(
            "incident",
            serde_json::json!({
                "dir": "/var/lib/moat/incidents/01J",
                "files": [{"name": "process.json", "size": 4096, "sha256": "ab"}],
            }),
        );
        let line = serde_json::to_string(&u).unwrap();
        match parse_record(&line).unwrap() {
            Record::Update(u) => fold(&mut a, &u.update),
            _ => panic!("should parse as an update"),
        }
        let inc = a.incident.as_ref().unwrap();
        assert_eq!(inc.dir, "/var/lib/moat/incidents/01J");
        assert_eq!(inc.files[0].name, "process.json");
        assert_eq!(inc.files[0].size, 4096);
        // And it round-trips on the full record.
        let line = serde_json::to_string(&a).unwrap();
        match parse_record(&line).unwrap() {
            Record::Full(b) => assert_eq!(b.incident, a.incident),
            _ => panic!("should parse as a full alert"),
        }
    }

    /// CONTRACT §4: a chain is recognised after its members are already on
    /// disk, so it can only ever reach a reader as an update line — and it has
    /// to survive being re-sent as the chain grows.
    #[test]
    fn a_chain_folds_in_and_keeps_growing() {
        let mut a = demo();
        assert!(a.chain.is_none());
        assert!(!serde_json::to_string(&a).unwrap().contains("chain"));
        let two = serde_json::json!({
            "v": 1, "id": "01A",
            "ancestor": {"pid": 41201, "exe": "/usr/bin/npm"},
            "families": ["cred", "net"],
            "severity": "critical", "severity_base": "high",
            "severity_reason": "high -> critical: a credential was read and the \
                                same process tree then connected out",
            "first_ts": "2026-09-04T16:41:02.100Z",
            "last_ts": "2026-09-04T16:41:02.600Z",
            "span_secs": 1,
            "steps": [
                {"alert":"01A","ts":"2026-09-04T16:41:02.100Z","family":"cred",
                 "rule":"moat-cred-registry-token-read","severity":"high",
                 "title":"t","pid":41233,"exe":"/usr/bin/node","role":"trigger"},
                {"alert":"01B","ts":"2026-09-04T16:41:02.600Z","family":"net",
                 "rule":"moat-net-suspicious-port-egress","severity":"medium",
                 "title":"t","pid":41233,"exe":"/usr/bin/node","role":"trigger"}
            ],
            "steps_total": 2, "truncated": false, "summary": "s",
        });
        let id = a.id.clone();
        fold(&mut a, &UpdateLine::new(&id).set("chain", two.clone()).update);
        let c = a.chain.as_ref().unwrap();
        assert_eq!(c.severity, "critical");
        assert_eq!(c.steps.len(), 2);

        // It round-trips on the full record.
        let line = serde_json::to_string(&a).unwrap();
        match parse_record(&line).unwrap() {
            Record::Full(b) => assert_eq!(b.chain, a.chain),
            _ => panic!("should parse as a full alert"),
        }

        // A third step arrives as another update on the same id.
        let mut three = two;
        three["steps_total"] = serde_json::json!(3);
        fold(&mut a, &UpdateLine::new(&id).set("chain", three).update);
        assert_eq!(a.chain.as_ref().unwrap().steps_total, 3);

        // Garbage must not blank a story already recorded.
        fold(&mut a, &UpdateLine::new(&id).set("chain", Value::from(7)).update);
        assert!(a.chain.is_some(), "a malformed chain must be ignored, not applied");
    }

    /// The member's half of the chain record: a reference to the anchor,
    /// absent by default, folded from an update line, kept on the full record.
    #[test]
    fn a_chain_id_folds_in_and_round_trips() {
        let mut a = demo();
        assert!(a.chain_id.is_none());
        assert!(!serde_json::to_string(&a).unwrap().contains("chain_id"));
        assert!(!a.is_chain_anchor());
        let id = a.id.clone();
        fold(&mut a, &UpdateLine::new(&id).set("chain_id", Value::from("01A")).update);
        assert_eq!(a.chain_id.as_deref(), Some("01A"));
        assert!(a.chain.is_none(), "a reference is not the chain itself");
        let line = serde_json::to_string(&a).unwrap();
        match parse_record(&line).unwrap() {
            Record::Full(b) => assert_eq!(b.chain_id.as_deref(), Some("01A")),
            _ => panic!("should parse as a full alert"),
        }
        // Garbage is ignored; null is the explicit undo.
        fold(&mut a, &UpdateLine::new(&id).set("chain_id", Value::from(7)).update);
        assert_eq!(a.chain_id.as_deref(), Some("01A"));
        fold(&mut a, &UpdateLine::new(&id).set("chain_id", Value::Null).update);
        assert!(a.chain_id.is_none());
    }

    #[test]
    fn the_anchor_is_the_member_whose_id_is_the_chains() {
        let mut a = demo();
        let mut c: crate::chain::Chain = serde_json::from_value(serde_json::json!({
            "v": 1, "id": a.id,
            "ancestor": {"pid": 1, "exe": "/usr/bin/npm"},
            "families": ["cred"], "severity": "high", "severity_base": "high",
            "severity_reason": "r", "first_ts": "t", "last_ts": "t", "span_secs": 1,
            "steps": [], "steps_total": 0, "truncated": false, "summary": "s",
        }))
        .unwrap();
        a.chain = Some(c.clone());
        assert!(a.is_chain_anchor());
        c.id = "01SOMEONEELSE".into();
        a.chain = Some(c);
        assert!(!a.is_chain_anchor());
    }

    #[test]
    fn the_timeline_groups_on_the_script_when_there_is_one() {
        let mut a = demo();
        assert_eq!(a.group_key(), "/usr/bin/node");
        a.actor.script = Some("/home/dan/proj/setup.mjs".into());
        assert_eq!(a.group_key(), "/home/dan/proj/setup.mjs");
    }

    /// An alert written by an older moatd has none of the §8 fields; it must
    /// still load, because alerts.jsonl outlives upgrades.
    #[test]
    fn a_pre_baseline_record_still_parses() {
        let mut v = serde_json::to_value(demo()).unwrap();
        let o = v.as_object_mut().unwrap();
        for k in ["actor", "context", "severity_base", "severity_reason", "surface", "suppressed_by", "rarity", "rarity_text"] {
            o.remove(k);
        }
        let line = serde_json::to_string(&v).unwrap();
        match parse_record(&line).unwrap() {
            Record::Full(a) => {
                assert_eq!(a.surface, "alerts");
                assert_eq!(a.context, crate::context::Context::Unknown);
                assert_eq!(a.actor.provenance, crate::provenance::Provenance::Unknown);
                assert!(!a.is_suppressed());
            }
            _ => panic!("should parse"),
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
    }

    /// A plain, answered, low timeline row is protected by nothing.
    fn unprotected() -> Alert {
        let mut a = demo();
        a.surface = "timeline".into();
        a.severity = "low".into();
        a.acked = true;
        a.action_taken = "none".into();
        a.rule = "moat-fs-something-ordinary".into();
        a.chain = None;
        a.incident = None;
        assert!(!a.is_protected(), "baseline fixture must be unprotected");
        a
    }

    #[test]
    fn p1_badge_unacked_surfaced_unsuppressed_is_protected() {
        let mut a = unprotected();
        a.surface = "alerts".into();
        a.acked = false;
        a.suppressed_by = None;
        assert!(a.is_protected());
        // Suppressing it takes it off the badge, so P1 no longer applies.
        a.suppressed_by = Some("user.toml#1".into());
        assert!(!a.is_protected(), "a suppressed row is not on the badge");
        // Acking it drops P1 too (it is low, so P6 does not save it).
        a.suppressed_by = None;
        a.acked = true;
        assert!(!a.is_protected());
    }

    #[test]
    fn p2_acted_is_protected_even_when_acked() {
        let mut a = unprotected();
        a.action_taken = "killed".into();
        assert!(a.is_protected(), "a response outlives the noise, acked or not");
        a.action_taken = "quarantined".into();
        assert!(a.is_protected());
        a.action_taken = "none".into();
        assert!(!a.is_protected());
    }

    #[test]
    fn p3_high_chain_is_protected_but_a_low_chain_is_not() {
        let chain_of = |severity: &str| -> crate::chain::Chain {
            serde_json::from_value(serde_json::json!({
                "v": 1, "id": "01A",
                "ancestor": {"pid": 1, "exe": "/usr/bin/npm"},
                "families": ["cred"],
                "severity": severity, "severity_base": severity,
                "severity_reason": "r",
                "first_ts": "t", "last_ts": "t", "span_secs": 1,
                "steps": [], "steps_total": 0, "truncated": false, "summary": "s",
            }))
            .unwrap()
        };
        let mut a = unprotected();
        a.chain = Some(chain_of("medium"));
        assert!(!a.is_protected(), "a medium chain is not a P3 story");
        a.chain = Some(chain_of("high"));
        assert!(a.is_protected());
        a.chain = Some(chain_of("critical"));
        assert!(a.is_protected());
    }

    #[test]
    fn p4_incident_is_protected() {
        let mut a = unprotected();
        a.incident = Some(crate::incident::Incident {
            dir: "/var/lib/moat/incidents/01J".into(),
            files: Vec::new(),
        });
        assert!(a.is_protected());
    }

    #[test]
    fn p5_meta_rules_are_protected_and_the_list_is_explicit() {
        for rule in PROTECTED_META_RULES {
            let mut a = unprotected();
            a.rule = (*rule).into();
            assert!(a.is_protected(), "{} must be protected", rule);
        }
        // Not a prefix match: an ordinary detection in the moat-x- namespace
        // is not protected on its rule name alone.
        let mut a = unprotected();
        a.rule = "moat-x-mass-read".into();
        assert!(!a.is_protected(), "moat-x-mass-read is a detection, not meta");
    }

    #[test]
    fn p6_answered_but_grave_is_protected() {
        let mut a = unprotected();
        a.surface = "alerts".into();
        a.acked = true;
        a.severity = "high".into();
        assert!(a.is_protected(), "a looked-at high is still the last to lose");
        a.severity = "critical".into();
        assert!(a.is_protected());
        // A medium on the badge, once acked, is neither P1 nor P6.
        a.severity = "medium".into();
        assert!(!a.is_protected());
        // And P6 needs the badge surface: a grave *timeline* row is not P6.
        a.severity = "high".into();
        a.surface = "timeline".into();
        assert!(!a.is_protected());
    }

    #[test]
    fn a_carried_stamp_round_trips_and_is_absent_by_default() {
        let a = demo();
        let line = serde_json::to_string(&a).unwrap();
        assert!(!line.contains("carried"), "an original write carries no stamp");
        let mut c = demo();
        c.carried = Some(Carried { at: "2026-09-06T00:00:00Z".into(), generation: 2 });
        let line = serde_json::to_string(&c).unwrap();
        assert!(line.contains("\"carried\""));
        match parse_record(&line).unwrap() {
            Record::Full(b) => {
                assert_eq!(b.carried, Some(Carried { at: "2026-09-06T00:00:00Z".into(), generation: 2 }));
            }
            _ => panic!("should parse as a full alert"),
        }
    }
}
