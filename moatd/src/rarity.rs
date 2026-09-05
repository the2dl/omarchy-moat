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
    pub fn key_of(&self) -> String {
        self.key()
    }

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
            exe: collapse_volatile(exe),
            dir: dir_of(path),
            verb: verb.to_string(),
        }
    }

    /// (parent exe, child exe) for an exec.
    pub fn parent(exe: &str, parent: &str) -> Tuple {
        Tuple::Parent {
            exe: collapse_volatile(exe),
            parent: collapse_volatile(parent),
        }
    }

    /// (install root, what it spawned).
    pub fn pkg_child(root: &str, child: &str) -> Tuple {
        Tuple::PkgChild {
            root: collapse_volatile(root),
            child: collapse_volatile(child),
        }
    }

    /// (actor exe, dst /24, dst port). A domain is used verbatim when known.
    pub fn net(exe: &str, ip: &str, port: u16, domain: Option<&str>) -> Tuple {
        Tuple::Net {
            exe: collapse_volatile(exe),
            dst: domain.map(|d| d.to_string()).unwrap_or_else(|| slash24(ip)),
            port,
        }
    }
}

/// `/home/dan/.aws/credentials` -> `/home/dan/.aws`. A bare path keeps `/`.
pub fn dir_of(path: &str) -> String {
    let dir = match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => path.to_string(),
    };
    collapse_volatile(&dir)
}

/// Temp roots whose immediate child is usually a per-run scratch directory.
const TEMP_ROOTS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

/// Replace the random part of a per-run scratch directory with `*`.
///
/// `/tmp/bun-dl-UfNh13/x` -> `/tmp/bun-dl-*/x`
/// `/tmp/moat-keyv-lab-1788533528861-694175` -> `/tmp/moat-keyv-lab-*`
/// `/tmp/.tmpAb12Cd/nc` -> `/tmp/.tmp*/nc`
///
/// Every dedup mechanism moat has keys on the (rule, exe, parent, dir) tuple:
/// the baseline learns on it, the noise guard demotes on it, and triage
/// inherits a verdict on it. `mktemp` defeats all three at once by producing a
/// fresh directory name per run, so a tool that uses one isnever learned,
/// never quietened, and pays for a fresh agent call every single time. On
/// 2026-09-04 eight of eight queued triage calls were distinct `first_seen`
/// tuples for what were really three repeating shapes.
///
/// Only the segment directly under a temp root is collapsed, and only its
/// trailing random-looking run -- so `/tmp/moat-sandbox-test.FkzONpNE/bin/x`
/// keeps `bin/x`, which is the part that carries meaning.
pub fn collapse_volatile(dir: &str) -> String {
    let Some(root) = TEMP_ROOTS.iter().find(|r| dir.starts_with(**r)) else {
        return dir.to_string();
    };
    let rest = &dir[root.len()..];
    let (first, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    match collapse_segment(first) {
        Some(c) => format!("{}{}{}", root, c, tail),
        None => dir.to_string(),
    }
}

/// `bun-dl-UfNh13` -> `bun-dl-*`, or `None` when nothing looks random.
///
/// A run is "random" when it is at least six characters and mixes cases or
/// mixes letters with digits -- which `mktemp` guarantees and an ordinary name
/// like `systemd-private` or `cargo` does not.
fn collapse_segment(seg: &str) -> Option<String> {
    // `mktemp -d name-XXXXXX` and friends often stack more than one random run
    // (`moat-keyv-lab-<epoch_ms>-<pid>`), so strip them repeatedly. The
    // separator that introduced a run stays in the prefix, so the collapsed
    // name still reads as the tool that made it.
    let mut end = seg.len();
    let mut stripped = false;
    loop {
        // A previous pass leaves the prefix ending in the separator that
        // introduced the run it removed; skip back over it to find the next.
        let mut search = end;
        while search > 0 && matches!(seg.as_bytes()[search - 1], b'-' | b'.' | b'_') {
            search -= 1;
        }
        let Some(start) = random_run_start(&seg[..search]) else { break };
        if start == 0 {
            // The whole remaining name is random. Collapsing that would merge
            // every unrelated scratch directory on the machine into one tuple,
            // so a bare `/tmp/aB12cD` keeps its identity.
            break;
        }
        end = start;
        stripped = true;
    }
    if !stripped {
        return None;
    }
    Some(format!("{}*", &seg[..end]))
}

/// Where the trailing random run begins, or `None` if there isn't one.
///
/// Returns the **rightmost** valid boundary, i.e. the shortest run that still
/// looks random. `.tmpAb12Cd` splits at the case change into `.tmp` + `Ab12Cd`
/// rather than at the dot into `.` + `tmpAb12Cd` -- the whole alnum run also
/// looks random, and taking it would throw away the part that names the tool.
///
/// Two boundaries count: the start of the trailing alphanumeric run (a
/// separator preceded it, as in `name-XXXXXX`) and a lowercase -> uppercase or
/// digit transition inside it (`mktemp` appended straight onto a prefix).
fn random_run_start(seg: &str) -> Option<usize> {
    let b = seg.as_bytes();
    let mut run_start = seg.len();
    while run_start > 0 && b[run_start - 1].is_ascii_alphanumeric() {
        run_start -= 1;
    }
    if run_start == seg.len() {
        return None;
    }
    for k in (run_start..=seg.len().saturating_sub(6)).rev() {
        let boundary = k == run_start
            || (b[k - 1].is_ascii_lowercase()
                && (b[k].is_ascii_uppercase() || b[k].is_ascii_digit()));
        if boundary && is_random_run(&seg[k..]) {
            return Some(k);
        }
    }
    None
}

/// Six or more alphanumerics that no human chose: all digits (a timestamp or a
/// pid), mixed case, or letters mixed with digits. `private`, `cargo` and
/// `build` are none of those.
fn is_random_run(run: &str) -> bool {
    if run.len() < 6 {
        return false;
    }
    let has_digit = run.bytes().any(|b| b.is_ascii_digit());
    let has_upper = run.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = run.bytes().any(|b| b.is_ascii_lowercase());
    let all_digits = run.bytes().all(|b| b.is_ascii_digit());
    all_digits || (has_upper && has_lower) || (has_digit && (has_upper || has_lower))
}

/// `1.2.3.4` -> `1.2.3.0/24`. IPv6 and anything unparseable is kept as-is.
/// How far apart the first and last sighting must be before a destination
/// counts as familiar. One hour: long enough that a burst inside a single
/// install or a single payload run cannot buy it, short enough that anything
/// a person actually uses earns it the first day.
pub const FAMILIAR_MIN_SPREAD_SECS: u64 = 3600;

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

#[derive(Default)]
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

impl RarityStore {
    /// Has this exact tuple ever been counted? Read-only, for rules that need
    /// "first contact" without the mutation `observe` performs.
    /// Is this destination genuinely familiar, or merely touched once?
    ///
    /// `has_seen` answers "is there a counter", which a single connection
    /// creates -- and `moat-net-first-contact` used that as its whole filter,
    /// so ONE connection to a C2 silenced every later beacon to that /24
    /// forever. No root, no CLI, no privilege: the attacker's own first packet
    /// bought permanent silence for the rest.
    ///
    /// Familiarity has to cost something an attacker cannot cheaply pay, and
    /// the thing they cannot fake is elapsed time on a machine they have just
    /// reached. So: seen enough times AND across a real span, not N times in
    /// one burst. A registry or a NAS earns that within a day of ordinary use,
    /// which is what the rule's own doc promises; a dropper that beacons four
    /// times in ten seconds does not.
    pub fn is_familiar(&self, t: &Tuple, now: u64) -> bool {
        let Some(c) = self.counters.get(&t.key()) else {
            return false;
        };
        if c.total < self.rare_max_count.max(2) {
            return false;
        }
        let spread = c.last_seen.saturating_sub(c.first_seen);
        let stale = now.saturating_sub(c.last_seen) > self.rare_max_age_days * 86_400;
        spread >= FAMILIAR_MIN_SPREAD_SECS && !stale
    }

    /// Forget every `net` counter whose destination matches `dst`.
    ///
    /// Returns the keys dropped. This exists because "have we talked to this
    /// host before" is a fact about a NETWORK, and networks change: a
    /// re-provisioned host, a new office, a lab address reused for something
    /// else. Without a way to forget, `moat-net-first-contact` can never
    /// report that destination again, and the only remedy is deleting the
    /// whole store and losing every other thing the machine has learned.
    ///
    /// Deliberately matches on the destination alone, across every exe and
    /// port: a person clearing a host means the host.
    ///
    /// The argument is normalised the way `Tuple::net` normalises it, which
    /// means an IPv4 address clears its whole **/24**. That is not a shortcut
    /// -- it is what the store actually holds, because a CDN hands out a new
    /// address from the same block on every request and per-address counters
    /// would never become common. Callers are told, because "I cleared one
    /// host" and "I cleared 254 of them" are different acts.
    pub fn forget_dst(&mut self, dst: &str) -> Vec<String> {
        let dst = slash24(dst);
        let needle = format!("\u{1}{}\u{1}", dst);
        let hits: Vec<String> = self
            .counters
            .keys()
            .filter(|k| k.starts_with("net\u{1}") && k.contains(&needle))
            .cloned()
            .collect();
        for k in &hits {
            self.counters.remove(k);
        }
        hits
    }

    pub fn has_seen(&self, t: &Tuple) -> bool {
        self.counters.contains_key(&t.key())
    }
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

        // A cold-only prune can free NOTHING, and then it runs on every event.
        //
        // A counter inserted this second has `decayed >= 1.0` and `last_seen ==
        // now`, so `1.0 * 0.5^0 = 1.0` clears the 0.05 floor and it always
        // survives. Under a flood of FRESH unique tuples -- and `Tuple::net`
        // takes an attacker-chosen destination verbatim, so they cost nothing
        // to mint -- `len()` stays above the cap, prune frees nothing, and
        // `observe` therefore calls it again on the next event: a full retain
        // with an `f64::powf` per entry, per event, over a map that keeps
        // growing. The file grows without bound too, and is re-parsed whole on
        // every restart.
        //
        // So the cap is a cap: when the cheap pass cannot get under it, drop
        // the coldest by decayed weight until it does.
        if self.counters.len() > MAX_COUNTERS {
            let mut weights: Vec<f64> = self
                .counters
                .values()
                .map(|c| {
                    let dt = now.saturating_sub(c.last_seen) as f64 / 86_400.0;
                    c.decayed * 0.5f64.powf(dt / hl)
                })
                .collect();
            let cut = self.counters.len() - MAX_COUNTERS;
            // The cut-th smallest weight; everything at or below it goes.
            weights.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let threshold = weights[cut.min(weights.len() - 1)];
            let over = self.counters.len();
            let mut dropped = 0usize;
            self.counters.retain(|_, c| {
                if dropped >= cut {
                    return true;
                }
                let dt = now.saturating_sub(c.last_seen) as f64 / 86_400.0;
                if c.decayed * 0.5f64.powf(dt / hl) <= threshold {
                    dropped += 1;
                    return false;
                }
                true
            });
            self.dirty = true;
            log::warn!(
                "rarity: at the {} cap; dropped {} of {} coldest counters",
                MAX_COUNTERS,
                over - self.counters.len(),
                over
            );
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

    #[test]
    fn a_per_run_scratch_directory_collapses_to_one_shape() {
        // mktemp defeats every dedup moat has at once: the baseline learns on
        // the tuple, the noise guard demotes on it, and triage inherits a
        // verdict on it. On 2026-09-04 eight of eight queued agent calls were
        // distinct first_seen tuples for three repeating shapes.
        assert_eq!(dir_of("/tmp/bun-dl-UfNh13/bun"), "/tmp/bun-dl-*");
        assert_eq!(dir_of("/tmp/bun-dl-yk8MDc/bun"), "/tmp/bun-dl-*",
                   "two runs of the same tool are one tuple");
        // Stacked random runs (epoch-ms and pid) both go.
        assert_eq!(
            dir_of("/tmp/moat-keyv-lab-1788533528861-694175/.npmrc"),
            "/tmp/moat-keyv-lab-*"
        );
        // The meaningful tail survives; only the scratch segment collapses.
        assert_eq!(
            dir_of("/tmp/moat-sandbox-test.FkzONpNE/bin/moat-shim-probe"),
            "/tmp/moat-sandbox-test.*/bin"
        );
        assert_eq!(dir_of("/tmp/.tmpAb12Cd/nc"), "/tmp/.tmp*",
                   "mktemp appended straight onto the prefix; the case change is the boundary");
    }

    #[test]
    fn the_actor_is_collapsed_too_not_just_what_it_touched() {
        // The fix above was applied to `dir` and not to `exe`, so a tool run
        // from a mktemp directory still minted a brand-new tuple every run.
        // On 2026-09-04 that left 83 of 306 `moat-exec-untrusted-tmpfs` alerts
        // permanently `first_seen` for one repeating shape -- `cargo test` --
        // and `first_seen` is exactly what the triage ceiling refuses to
        // demote, so the pattern could never settle by any route.
        let a = Tuple::parent(
            "/tmp/moat-sandbox-test.NWESSLJw/home/proj/noscan-bin/bwrap",
            "/usr/bin/cargo",
        );
        let b = Tuple::parent(
            "/tmp/moat-sandbox-test.FkzONpNE/home/proj/noscan-bin/bwrap",
            "/usr/bin/cargo",
        );
        assert_eq!(a.key(), b.key(), "two runs of the same tool are one tuple");
        assert!(a.phrase().contains("/tmp/moat-sandbox-test.*/home/proj/noscan-bin/bwrap"));

        // Every component, so no construction site can be the one that forgets.
        assert_eq!(
            Tuple::file("/tmp/bun-dl-UfNh13/bun", "/home/dan/.npmrc", "read").key(),
            Tuple::file("/tmp/bun-dl-yk8MDc/bun", "/home/dan/.npmrc", "read").key()
        );
        assert_eq!(
            Tuple::net("/tmp/bun-dl-UfNh13/bun", "10.0.0.5", 443, None).key(),
            Tuple::net("/tmp/bun-dl-yk8MDc/bun", "10.0.0.5", 443, None).key()
        );
        assert_eq!(
            Tuple::pkg_child("/usr/bin/npm", "/tmp/bun-dl-UfNh13/bun").key(),
            Tuple::pkg_child("/usr/bin/npm", "/tmp/bun-dl-yk8MDc/bun").key()
        );

        // An ordinary binary is untouched, which is nearly all of them.
        assert_eq!(
            Tuple::parent("/usr/bin/node", "/usr/bin/npm").key(),
            Tuple::Parent { exe: "/usr/bin/node".into(), parent: "/usr/bin/npm".into() }.key()
        );
    }

    #[test]
    fn an_ordinary_directory_name_is_left_alone() {
        // Collapsing too eagerly would merge unrelated things into one tuple
        // and hide a real difference, so the test is deliberately strict:
        // 6+ characters AND mixed case or letters-with-digits.
        assert_eq!(dir_of("/tmp/systemd-private/x"), "/tmp/systemd-private");
        assert_eq!(dir_of("/tmp/cargo/x"), "/tmp/cargo");
        assert_eq!(dir_of("/tmp/build/x"), "/tmp/build");
        // A name that is ONLY random keeps its identity: collapsing it would
        // merge every unrelated scratch directory into one tuple.
        assert_eq!(dir_of("/tmp/aB12cD/x"), "/tmp/aB12cD");
        // Outside a temp root nothing is touched at all.
        assert_eq!(
            dir_of("/home/dan/.cache/yay/flea-0.1.3/src/x"),
            "/home/dan/.cache/yay/flea-0.1.3/src"
        );
        assert_eq!(dir_of("/usr/bin/Xy12ab/thing"), "/usr/bin/Xy12ab");
    }
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

#[cfg(test)]
mod cap_tests {
    use super::*;

    /// A flood of FRESH tuples must not defeat the cap.
    ///
    /// The prune only dropped counters whose decayed weight had fallen below a
    /// floor, and a counter created this second is at its maximum -- so under a
    /// flood of never-seen tuples it freed nothing, `len()` stayed over the cap,
    /// and `observe` re-ran the whole scan on every subsequent event. The
    /// cheapest input is a network tuple, whose destination the attacker names.
    #[test]
    fn a_flood_of_new_tuples_cannot_defeat_the_cap() {
        let mut s = RarityStore::default();
        let now = 1_800_000_000u64;
        for i in 0..(MAX_COUNTERS + 2_000) {
            s.observe(&Tuple::net("/tmp/x/beacon", &format!("10.0.{}.{}", i / 256, i % 256), 443, None), now);
        }
        assert!(
            s.counters.len() <= MAX_COUNTERS,
            "the cap held at {} counters",
            s.counters.len()
        );

        // And a hot counter is not what gets dropped: the one seen most often
        // is still there.
        let hot = Tuple::net("/usr/bin/curl", "1.1.1.1", 443, None);
        for _ in 0..50 {
            s.observe(&hot, now);
        }
        for i in 0..5_000 {
            s.observe(&Tuple::net("/tmp/x/beacon", &format!("172.16.{}.{}", i / 256, i % 256), 443, None), now);
        }
        assert!(s.has_seen(&hot), "the coldest go first, not the busiest");
    }
}
