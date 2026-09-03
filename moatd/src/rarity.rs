//! Rarity: continuous learning without a black box (LEARNING §1).
//!
//! Real ML is the wrong tool here — no labels, one machine, and an
//! unexplainable score contradicts the whole point. What hunting teams actually
//! do with Sysmon data is **rarity**: how unusual is this exact combination on
//! *this* machine. The daemon keeps decayed counters (half-life 30 days by
//! default) for four tuples:
//!
//! | tuple                                     | answers                                  |
//! |-------------------------------------------|------------------------------------------|
//! | (actor exe, parent exe)                   | has this parent ever launched this before |
//! | (actor exe, file dir)                     | has this program touched this place before |
//! | (actor exe, dst /24 or domain, dst port)  | has this program talked here before       |
//! | (pkg root exe, child exe)                 | has npm/pip ever spawned this before      |
//!
//! Every alert gets `rarity` (`first_seen` | `rare` | `common`) and a plain
//! `rarity_text` sentence. **Rarity never changes severity on its own**: it is
//! evidence, and it gates baseline proposals (a tuple must be `common` before it
//! can be proposed) — BASELINE §3 via LEARNING §1.
//!
//! Counters keep updating forever, including for alerts that were suppressed:
//! learning never stops, the learning *window* only controls whether a proposal
//! auto-applies.
//!
//! Persisted to `<state_dir>/rarity.json`, atomically, every 60 s and on
//! shutdown.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const RARITY_V: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rarity {
    #[default]
    FirstSeen,
    Rare,
    Common,
}

impl Rarity {
    pub fn as_str(self) -> &'static str {
        match self {
            Rarity::FirstSeen => "first_seen",
            Rarity::Rare => "rare",
            Rarity::Common => "common",
        }
    }
    pub fn is_common(self) -> bool {
        self == Rarity::Common
    }
}

impl std::fmt::Display for Rarity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One decayed counter. `decayed` halves every `half_life_days`; `total` is the
/// honest raw count, which is what "seen 41 times" quotes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counter {
    #[serde(rename = "d")]
    pub decayed: f64,
    #[serde(rename = "t")]
    pub total: u64,
    /// unix seconds
    #[serde(rename = "f")]
    pub first_seen: u64,
    #[serde(rename = "l")]
    pub last_seen: u64,
}

/// The four tuple kinds, each knowing how to name itself in a sentence.
#[derive(Debug, Clone, PartialEq)]
pub enum Tuple {
    /// (actor exe, parent exe)
    Parent { exe: String, parent: String },
    /// (actor exe, file dir) for cred/persist reads and writes
    File { exe: String, dir: String, verb: String },
    /// (actor exe, dst /24 or domain, dst port)
    Net { exe: String, dst: String, port: u16 },
    /// (pkg root exe, child exe)
    PkgChild { root: String, child: String },
}

impl Tuple {
    pub fn kind(&self) -> &'static str {
        match self {
            Tuple::Parent { .. } => "parent",
            Tuple::File { .. } => "file",
            Tuple::Net { .. } => "net",
            Tuple::PkgChild { .. } => "pkgchild",
        }
    }

    /// Storage key. `\u{1}` cannot appear in a path, so no separator collision.
    pub fn key(&self) -> String {
        let parts: Vec<String> = match self {
            Tuple::Parent { exe, parent } => vec![parent.clone(), exe.clone()],
            Tuple::File { exe, dir, .. } => vec![exe.clone(), dir.clone()],
            Tuple::Net { exe, dst, port } => vec![exe.clone(), dst.clone(), port.to_string()],
            Tuple::PkgChild { root, child } => vec![root.clone(), child.clone()],
        };
        format!("{}\u{1}{}", self.kind(), parts.join("\u{1}"))
    }

    /// "‹subject› has ‹done› ‹object›", the middle of every rarity sentence.
    pub fn phrase(&self) -> String {
        match self {
            Tuple::Parent { exe, parent } => format!("{} has launched {}", parent, exe),
            Tuple::File { exe, dir, verb } => format!("{} has {} {}", exe, verb, dir),
            Tuple::Net { exe, dst, port } => format!("{} has connected to {}:{}", exe, dst, port),
            Tuple::PkgChild { root, child } => format!("{} has spawned {}", root, child),
        }
    }

    /// (actor exe, file dir) for a path, with the access word the hook gave us.
    pub fn file(exe: &str, path: &str, verb: &str) -> Tuple {
        Tuple::File {
            exe: exe.to_string(),
            dir: dir_of(path),
            verb: verb.to_string(),
        }
    }

    /// (actor exe, dst /24, dst port). A domain is used verbatim when known.
    pub fn net(exe: &str, ip: &str, port: u16, domain: Option<&str>) -> Tuple {
        Tuple::Net {
            exe: exe.to_string(),
            dst: domain.map(|d| d.to_string()).unwrap_or_else(|| slash24(ip)),
            port,
        }
    }
}

/// `/home/dan/.aws/credentials` -> `/home/dan/.aws`. A bare path keeps `/`.
pub fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => path.to_string(),
    }
}

/// `1.2.3.4` -> `1.2.3.0/24`. IPv6 and anything unparseable is kept as-is.
pub fn slash24(ip: &str) -> String {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        return format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
    }
    ip.to_string()
}

/// What the alert record carries.
#[derive(Debug, Clone, PartialEq)]
pub struct RarityInfo {
    pub class: Rarity,
    /// One plain sentence for the panel.
    pub text: String,
    pub kind: &'static str,
    pub key: String,
    pub total: u64,
    pub first_seen: u64,
}

impl RarityInfo {
    pub fn unknown() -> RarityInfo {
        RarityInfo {
            class: Rarity::FirstSeen,
            text: "no rarity history for this combination yet".into(),
            kind: "none",
            key: String::new(),
            total: 0,
            first_seen: 0,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RarityFile {
    v: u32,
    updated: String,
    counters: HashMap<String, Counter>,
}

pub struct RarityStore {
    path: PathBuf,
    group: String,
    counters: HashMap<String, Counter>,
    pub half_life_days: f64,
    pub rare_max_count: u64,
    pub rare_max_age_days: u64,
    dirty: bool,
    last_save: u64,
    /// Save interval, seconds. LEARNING §1 fixes this at 60.
    pub save_every: u64,
}

/// Beyond this many counters the coldest are dropped: a machine that executes
/// unique paths forever must not grow the file without bound.
const MAX_COUNTERS: usize = 50_000;

impl RarityStore {
    pub fn load(path: &Path, group: &str, half_life_days: f64, rare_max_count: u64, rare_max_age_days: u64) -> RarityStore {
        let counters = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<RarityFile>(&t).ok())
            .map(|f| f.counters)
            .unwrap_or_default();
        log::info!("rarity: {} counters from {}", counters.len(), path.display());
        RarityStore {
            path: path.to_path_buf(),
            group: group.to_string(),
            counters,
            half_life_days: if half_life_days > 0.0 { half_life_days } else { 30.0 },
            rare_max_count,
            rare_max_age_days,
            dirty: false,
            last_save: crate::util::unix_secs(),
            save_every: 60,
        }
    }

    pub fn len(&self) -> usize {
        self.counters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    fn decay(&self, c: &Counter, now: u64) -> f64 {
        let dt = now.saturating_sub(c.last_seen) as f64 / 86_400.0;
        c.decayed * 0.5f64.powf(dt / self.half_life_days)
    }

    /// Look a tuple up **without** recording it.
    pub fn peek(&self, t: &Tuple, now: u64) -> RarityInfo {
        let key = t.key();
        match self.counters.get(&key) {
            None => RarityInfo {
                class: Rarity::FirstSeen,
                text: format!("first time {} on this machine", t.phrase()),
                kind: t.kind(),
                key,
                total: 0,
                first_seen: 0,
            },
            Some(c) => {
                let stale_after = self.rare_max_age_days * 86_400;
                let age = now.saturating_sub(c.last_seen);
                let class = if c.total < self.rare_max_count || age > stale_after {
                    Rarity::Rare
                } else {
                    Rarity::Common
                };
                let mut text = format!(
                    "{}: seen {} time{} since {}",
                    t.phrase(),
                    c.total,
                    if c.total == 1 { "" } else { "s" },
                    date_of(c.first_seen)
                );
                if age > stale_after {
                    text.push_str(&format!(", but nothing in the last {} days", age / 86_400));
                }
                RarityInfo {
                    class,
                    text,
                    kind: t.kind(),
                    key,
                    total: c.total,
                    first_seen: c.first_seen,
                }
            }
        }
    }

    /// Classify against the history **before** this event, then record it. That
    /// order is what makes "first time" mean first time.
    pub fn observe(&mut self, t: &Tuple, now: u64) -> RarityInfo {
        let info = self.peek(t, now);
        let key = info.key.clone();
        let decayed_before = self.counters.get(&key).map(|c| self.decay(c, now)).unwrap_or(0.0);
        let e = self.counters.entry(key).or_insert_with(|| Counter {
            decayed: 0.0,
            total: 0,
            first_seen: now,
            last_seen: now,
        });
        e.decayed = decayed_before + 1.0;
        e.total += 1;
        e.last_seen = now;
        if e.first_seen == 0 {
            e.first_seen = now;
        }
        self.dirty = true;
        if self.counters.len() > MAX_COUNTERS {
            self.prune(now);
        }
        info
    }

    /// Drop the coldest counters. A tuple whose decayed weight is under a
    /// twentieth of one sighting has not been seen in roughly four half-lives.
    pub fn prune(&mut self, now: u64) {
        let before = self.counters.len();
        let hl = self.half_life_days;
        self.counters.retain(|_, c| {
            let dt = now.saturating_sub(c.last_seen) as f64 / 86_400.0;
            c.decayed * 0.5f64.powf(dt / hl) >= 0.05
        });
        if self.counters.len() != before {
            self.dirty = true;
            log::debug!("rarity: pruned {} cold counters", before - self.counters.len());
        }
    }

    /// Atomic write, at most once per `save_every` seconds unless forced.
    pub fn save_if_due(&mut self, now: u64, force: bool) {
        if !self.dirty {
            return;
        }
        if !force && now.saturating_sub(self.last_save) < self.save_every {
            return;
        }
        let file = RarityFile {
            v: RARITY_V,
            updated: crate::util::now_rfc3339(),
            counters: self.counters.clone(),
        };
        let body = match serde_json::to_string(&file) {
            Ok(b) => format!("{}\n", b),
            Err(e) => {
                log::warn!("rarity.json: {}", e);
                return;
            }
        };
        match crate::util::atomic_write(&self.path, body.as_bytes(), 0o640) {
            Ok(_) => {
                let _ = crate::util::secure_path(&self.path, &self.group, 0o640);
                self.dirty = false;
                self.last_save = now;
            }
            Err(e) => log::warn!("rarity.json: {}", e),
        }
    }
}

fn date_of(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "an unknown date".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn store(dir: &Path) -> RarityStore {
        RarityStore::load(&dir.join("rarity.json"), "moat", 30.0, 3, 14)
    }

    fn tuple() -> Tuple {
        Tuple::file("/usr/bin/node", "/home/dan/.aws/credentials", "read")
    }

    #[test]
    fn the_first_sighting_is_first_seen_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        let i = s.observe(&tuple(), 1_000_000);
        assert_eq!(i.class, Rarity::FirstSeen);
        assert_eq!(
            i.text,
            "first time /usr/bin/node has read /home/dan/.aws on this machine"
        );
        assert_eq!(i.kind, "file");
    }

    #[test]
    fn under_three_sightings_is_rare_and_then_it_is_common() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        let now = 1_700_000_000;
        assert_eq!(s.observe(&tuple(), now).class, Rarity::FirstSeen);
        assert_eq!(s.observe(&tuple(), now + 10).class, Rarity::Rare);
        assert_eq!(s.observe(&tuple(), now + 20).class, Rarity::Rare);
        let i = s.observe(&tuple(), now + 30);
        assert_eq!(i.class, Rarity::Common, "the fourth sighting sees three before it");
        assert!(i.text.contains("seen 3 times since"), "{}", i.text);
    }

    #[test]
    fn a_tuple_nobody_has_touched_in_a_fortnight_goes_back_to_rare() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        let now = 1_700_000_000;
        for i in 0..10 {
            s.observe(&tuple(), now + i);
        }
        assert_eq!(s.peek(&tuple(), now + 100).class, Rarity::Common);
        let stale = s.peek(&tuple(), now + 20 * DAY);
        assert_eq!(stale.class, Rarity::Rare);
        assert!(stale.text.contains("nothing in the last 19 days"), "{}", stale.text);
    }

    #[test]
    fn the_decayed_weight_halves_over_a_half_life() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        let now = 1_700_000_000;
        for i in 0..8 {
            s.observe(&tuple(), now + i);
        }
        let key = tuple().key();
        let c = s.counters.get(&key).unwrap().clone();
        assert!((c.decayed - 8.0).abs() < 0.01);
        let later = s.decay(&c, now + 30 * DAY);
        assert!((later - 4.0).abs() < 0.05, "half-life is 30 days, got {}", later);
        // Raw totals never decay: "seen 8 times" stays honest.
        assert_eq!(c.total, 8);
    }

    #[test]
    fn all_four_tuple_kinds_have_distinct_keys_and_readable_sentences() {
        let ts = [
            Tuple::Parent { exe: "/usr/bin/node".into(), parent: "/usr/bin/npm".into() },
            Tuple::file("/usr/bin/node", "/home/dan/.aws/credentials", "read"),
            Tuple::net("/usr/bin/node", "185.220.101.55", 4444, None),
            Tuple::PkgChild { root: "/usr/bin/npm".into(), child: "/usr/bin/node".into() },
        ];
        let mut keys: Vec<String> = ts.iter().map(|t| t.key()).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 4);
        assert_eq!(ts[0].phrase(), "/usr/bin/npm has launched /usr/bin/node");
        assert_eq!(ts[2].phrase(), "/usr/bin/node has connected to 185.220.101.0/24:4444");
        assert_eq!(ts[3].phrase(), "/usr/bin/npm has spawned /usr/bin/node");
        // A known domain beats the /24.
        let d = Tuple::net("/usr/bin/node", "1.2.3.4", 443, Some("registry.npmjs.org"));
        assert!(d.phrase().contains("registry.npmjs.org:443"));
    }

    #[test]
    fn dirs_and_prefixes_are_derived_the_boring_way() {
        assert_eq!(dir_of("/home/dan/.aws/credentials"), "/home/dan/.aws");
        assert_eq!(dir_of("/etc/passwd"), "/etc");
        assert_eq!(dir_of("/x"), "/");
        assert_eq!(dir_of("relative"), "relative");
        assert_eq!(slash24("10.1.2.3"), "10.1.2.0/24");
        assert_eq!(slash24("2001:db8::1"), "2001:db8::1");
        assert_eq!(slash24("999.1.2.3"), "999.1.2.3");
    }

    #[test]
    fn counters_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        {
            let mut s = store(dir.path());
            for i in 0..5 {
                s.observe(&tuple(), now + i);
            }
            s.save_if_due(now, true);
        }
        assert!(dir.path().join("rarity.json").exists());
        let s2 = store(dir.path());
        assert_eq!(s2.len(), 1);
        let i = s2.peek(&tuple(), now + 60);
        assert_eq!(i.class, Rarity::Common);
        assert_eq!(i.total, 5);
    }

    #[test]
    fn a_save_is_rate_limited_but_a_forced_one_always_lands() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        let now = crate::util::unix_secs();
        s.observe(&tuple(), now);
        s.save_if_due(now, false);
        assert!(!dir.path().join("rarity.json").exists(), "too soon for the 60 s timer");
        s.save_if_due(now, true);
        assert!(dir.path().join("rarity.json").exists());
        // Nothing new: no rewrite.
        s.save_if_due(now + 1000, true);
    }

    #[test]
    fn cold_counters_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        let now = 1_700_000_000;
        s.observe(&tuple(), now);
        s.observe(
            &Tuple::Parent { exe: "/usr/bin/node".into(), parent: "/usr/bin/npm".into() },
            now + 200 * DAY,
        );
        s.prune(now + 200 * DAY);
        assert_eq!(s.len(), 1, "the 200-day-old file tuple is gone");
    }

    #[test]
    fn a_corrupt_file_is_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rarity.json"), b"{not json").unwrap();
        let s = store(dir.path());
        assert!(s.is_empty());
    }
}
