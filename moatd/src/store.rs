//! `alerts.jsonl` — append only.
//!
//! CONTRACT §4: one JSON object per line, no pretty printing, nothing is ever
//! rewritten in place. State changes append `{"v":1,"id":..,"update":{..}}`
//! lines that readers fold by id. Rotation at 20 MB renames to
//! `alerts.1.jsonl`; the plugin re-opens on inode change, as does `Tailer`.
//!
//! The file is 0640 root:moat so the user's group can read it and only the
//! daemon can write it. Outside root (dev mode) the chown is skipped.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::alert::{fold, parse_record, Alert, Record, UpdateLine};
use crate::receipt::{Receipt, ReceiptLine};

/// (inode, length) of the live and rotated files when the fold was last
/// brought up to date. Two stats say whether the files are still what the
/// fold was built from; anything else -- a rotation, a truncation, a write by
/// something that is not this store -- and the fold is rebuilt from disk.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Stamp {
    live: Option<(u64, u64)>,
    rotated: Option<(u64, u64)>,
}

impl Stamp {
    fn of(live: &Path, rotated: &Path) -> Stamp {
        let one = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.ino(), m.len()));
        Stamp {
            live: one(live),
            rotated: one(rotated),
        }
    }
}

/// The folded log, held between reads.
///
/// PERFORMANCE, and it is the whole reason this exists. `status()` is computed
/// by the panel's poll every 10 s and by `write_state` every 5 s, and each one
/// used to parse both files -- 30 MB, ~30k lines -- from the top, twice
/// (`unacked` and `digest`), plus two more passes for the receipts. Measured
/// on this machine: 0.49 CPU-seconds per `moatctl status`, which at that
/// cadence was ~16% of a core with nothing happening. The store is the only
/// writer, so it folds each line as it appends it and the parse never has to
/// happen again; the stamp catches the cases where that is not true.
struct Cache {
    map: BTreeMap<String, Alert>,
    receipts: Vec<Receipt>,
    stamp: Stamp,
}

impl Cache {
    fn fold_line(&mut self, line: &str) {
        match parse_record(line) {
            Some(Record::Full(a)) => {
                let id = a.id.clone();
                self.map.insert(id.clone(), *a);
                self.hydrate(&id);
                self.propagate(&id);
            }
            Some(Record::Update(u)) => {
                let Some(a) = self.map.get_mut(&u.id) else {
                    return;
                };
                fold(a, &u.update);
                if u.update.contains_key("chain_id") {
                    self.hydrate(&u.id);
                }
                if u.update.contains_key("chain") {
                    self.propagate(&u.id);
                }
            }
            None => {
                // Cheap pre-filter: most lines are alerts.
                if line.contains("\"receipt\"") {
                    if let Ok(r) = serde_json::from_str::<ReceiptLine>(line) {
                        self.receipts.push(r.receipt);
                    }
                }
            }
        }
    }

    /// Give `id` the chain its `chain_id` names, copied from the anchor.
    ///
    /// The chain is on disk ONCE, on the anchor (`Alert::chain_id`); every
    /// other member holds a reference. The fold is what readers see, so the
    /// reference is resolved here and nowhere else -- `load`, `find`,
    /// `unacked`, `ledger`, the carry set and `cmd_feed` all read `chain` off
    /// the folded alert exactly as they did when it was inlined.
    ///
    /// An inline copy the member already carries (a record from before
    /// `chain_id` existed, or a carried row whose anchor was not carried) is
    /// replaced only by one at least as grown: a chain only ever grows, and
    /// the anchor's copy is the newest write, so this is the same "keep the
    /// most grown" rule `cmd_feed` applies.
    fn hydrate(&mut self, id: &str) {
        let Some(a) = self.map.get(id) else {
            return;
        };
        let Some(cid) = a.chain_id.clone() else {
            return;
        };
        if cid == id {
            return;
        }
        let own = a.chain.as_ref().map(|c| c.steps_total);
        let Some(chain) = self.map.get(&cid).and_then(|anchor| anchor.chain.as_ref()) else {
            return;
        };
        if chain.id != cid || own.is_some_and(|t| t > chain.steps_total) {
            return;
        }
        let chain = chain.clone();
        if let Some(a) = self.map.get_mut(id) {
            a.chain = Some(chain);
        }
    }

    /// `id`'s chain changed and `id` is the anchor: every member that names
    /// it gets the new copy, so a member never holds an earlier snapshot than
    /// the anchor. This is the invariant `moatctl ack --chain` and the panel
    /// rely on, and it is what the write side used to pay for by appending the
    /// chain to every member. Memory work only: nothing is written.
    fn propagate(&mut self, id: &str) {
        let Some(chain) = self.map.get(id).and_then(|a| a.chain.as_ref()) else {
            return;
        };
        if chain.id != id {
            return;
        }
        let chain = chain.clone();
        for m in chain.member_ids() {
            if m == id {
                continue;
            }
            if let Some(member) = self.map.get_mut(&m) {
                if member.chain_id.as_deref() == Some(id) {
                    member.chain = Some(chain.clone());
                }
            }
        }
    }
}

pub struct AlertStore {
    path: PathBuf,
    rotated: PathBuf,
    max_bytes: u64,
    /// Carry-forward caps for rotation. `carry_max_bytes` is well under
    /// `max_bytes` so the carried set can never itself trip a rotation.
    carry_max_bytes: u64,
    carry_max: usize,
    group: String,
    file: Option<File>,
    size: u64,
    cache: Mutex<Option<Cache>>,
}

/// What collapses into one thing to decide about, mirroring the panel's
/// `incidentKey`: a chain is one story however many steps it has; otherwise one
/// detection by one program is one decision however many times it repeats.
///
/// The program is the interpreter's SCRIPT when there is one, so `gcloud` and
/// `some-other.py` do not merge just because both ran through python3.
fn incident_key(a: &Alert) -> String {
    if let Some(chain) = a.chain.as_ref() {
        if !chain.id.is_empty() {
            return format!("chain\u{1}{}", chain.id);
        }
    }
    let script = a.actor.script.as_deref().unwrap_or("");
    let exe = if script.is_empty() { a.process.exe.as_str() } else { script };
    let program = exe.rsplit('/').next().unwrap_or(exe);
    format!("{}\u{1}{}", a.rule, program)
}

impl AlertStore {
    pub fn open(
        path: &Path,
        rotated: &Path,
        max_bytes: u64,
        carry_max_bytes: u64,
        carry_max: usize,
        group: &str,
    ) -> std::io::Result<AlertStore> {
        let mut s = AlertStore {
            path: path.to_path_buf(),
            rotated: rotated.to_path_buf(),
            max_bytes,
            carry_max_bytes,
            carry_max,
            group: group.to_string(),
            file: None,
            size: 0,
            cache: Mutex::new(None),
        };
        // Complete or discard a carry-forward rotation that a crash interrupted,
        // BEFORE opening the live file for append.
        s.reconcile_staging()?;
        s.reopen()?;
        Ok(s)
    }

    /// Where rotation stages the carried rows before the two renames.
    fn staging(&self) -> PathBuf {
        self.path.with_extension("new")
    }

    /// Crash recovery for carry-forward rotation. `rotate` does two renames:
    /// `alerts.jsonl -> alerts.1.jsonl`, then `alerts.new -> alerts.jsonl`. If
    /// `alerts.new` survives a restart, a crash landed between writing it and
    /// finishing:
    ///   * live still present  -> the first rename had not happened, so the
    ///     staged file is stale scaffolding; discard it (live is authoritative).
    ///   * live missing        -> the crash was between the two renames; finish
    ///     the second one so no data is lost.
    fn reconcile_staging(&self) -> std::io::Result<()> {
        let staging = self.staging();
        if !staging.exists() {
            return Ok(());
        }
        if self.path.exists() {
            log::warn!(
                "discarding stale {} (live log intact)",
                staging.display()
            );
            std::fs::remove_file(&staging)?;
        } else {
            log::warn!(
                "completing interrupted rotation: {} -> {}",
                staging.display(),
                self.path.display()
            );
            std::fs::rename(&staging, &self.path)?;
            let _ = crate::util::secure_path(&self.path, &self.group, 0o640);
        }
        Ok(())
    }

    fn reopen(&mut self) -> std::io::Result<()> {
        if let Some(p) = self.path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        self.size = f.metadata().map(|m| m.len()).unwrap_or(0);
        let _ = crate::util::secure_path(&self.path, &self.group, 0o640);
        self.file = Some(f);
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        if self.file.is_none() {
            self.reopen()?;
        }
        let f = self.file.as_mut().expect("reopened above");
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.flush()?;
        self.size += line.len() as u64 + 1;
        // Keep the fold current rather than throw it away: this line is the
        // only thing that changed, and we are the ones who wrote it.
        if let Some(c) = self.cache_lock().as_mut() {
            c.fold_line(line);
            c.stamp = Stamp::of(&self.path, &self.rotated);
        }
        if self.size >= self.max_bytes {
            self.rotate()?;
        }
        Ok(())
    }

    /// Rotate, carrying the protected rows forward (R1).
    ///
    /// Plain rename-over-`.1` rotation dropped importance on the floor: a flood
    /// that filled 20 MiB permanently rotated a contained, critical exfil chain
    /// out of the log — and, because the incident keep-set is derived from the
    /// alert rows, rotating the row let its snapshot be pruned too. Carry-
    /// forward writes the `is_protected()` rows into the fresh generation as
    /// folded Full lines (stamped `carried`, so they stay tamper-evident), so
    /// retention follows importance rather than the 20 MiB clock.
    ///
    /// Append-only is preserved: this never rewrites `alerts.1.jsonl`; it writes
    /// NEW lines into a fresh live file and renames the old one aside untouched.
    fn rotate(&mut self) -> std::io::Result<()> {
        log::info!(
            "rotating {} at {} bytes -> {}",
            self.path.display(),
            self.size,
            self.rotated.display()
        );

        // Built from the current (up-to-date) fold, before anything is renamed.
        let (carried, evicted_wanted) = self.protected_carry_set();
        if evicted_wanted > 0 {
            // ONE line per rotation; never an alert row (that would be one more
            // line in the very flood this guards against).
            log::warn!(
                "alerts carry-forward at rotation: over cap, evicted {} row(s) that still wanted a human",
                evicted_wanted
            );
        }
        let staging = self.staging();
        self.write_carried(&staging, &carried)?;

        self.file = None;
        // The fold is dropped so the next read refolds from disk: after the two
        // renames, alerts.1.jsonl is the former live file and alerts.jsonl holds
        // the carried rows (whose Full lines re-fold to the same ids).
        *self.cache_lock() = None;
        std::fs::rename(&self.path, &self.rotated)?; // crash point A
        std::fs::rename(&staging, &self.path)?; // crash point B
        self.reopen()
    }

    /// The protected rows to carry across a rotation, id-ordered, stamped
    /// `carried`, and capped. Returns the rows plus how many still-wanted-a-
    /// human rows the caps had to evict.
    ///
    /// A chain travels the way it is stored: once, on its anchor. The fold
    /// holds every member hydrated, so writing the rows as they are would put
    /// the whole chain into every carried member -- 488 members times ~100 KB
    /// for the 2026-09-10 `makepkg` chain, which is more than the byte cap and
    /// would evict most of the story to make room for copies of itself. So a
    /// member whose anchor is ALSO in the set is written with `chain_id` only,
    /// and the caps are measured on what is actually written.
    ///
    /// The anchor is not pulled in on a member's behalf. When the chain is
    /// `high`+, every member is P3-protected and the anchor comes along on the
    /// same predicate; when it is not, a member protected for its own reasons
    /// keeps its chain inline -- today's format -- so nothing depends on a row
    /// that was never going to be carried. What the caps must not do is evict
    /// the anchor from under a member that was stripped against it, and the
    /// plain order would: eviction is oldest-first within a tier, and the
    /// anchor is the oldest member by construction. `apply_carry_caps` orders
    /// an anchor after every member that depends on it.
    fn protected_carry_set(&self) -> (Vec<Alert>, usize) {
        let now = crate::util::now_rfc3339();
        let mut rows: Vec<Alert> = self.with_fold(|c| {
            c.map
                .values()
                .filter(|a| a.is_protected())
                .cloned()
                .collect()
        });
        // Stamp BEFORE capping so the byte cap accounts for what is actually
        // written. `generation` grows each time a row survives another rotation.
        for a in &mut rows {
            let generation = a.carried.as_ref().map(|c| c.generation).unwrap_or(0) + 1;
            a.carried = Some(crate::alert::Carried {
                at: now.clone(),
                generation,
            });
        }
        let evicted_wanted = self.apply_carry_caps(&mut rows);
        (rows, evicted_wanted)
    }

    /// Evict least-important-then-oldest until `rows` is within both caps.
    /// Returns how many evicted rows still wanted a human (P1: surfaced,
    /// unacked, unsuppressed) — the honest cost of the eviction.
    ///
    /// Strips the shared chains first (see `protected_carry_set`), so the byte
    /// cap is measured on the lines that will be written, and sorts an anchor
    /// after the members that were stripped against it, at the strongest of
    /// their priorities: a chain's record outlives its last surviving member,
    /// never the other way round.
    fn apply_carry_caps(&self, rows: &mut Vec<Alert>) -> usize {
        let anchor_of = strip_shared_chains(rows);
        let sizes: Vec<u64> = rows.iter().map(line_len).collect();
        let bytes: u64 = sizes.iter().sum();
        if rows.len() <= self.carry_max && bytes <= self.carry_max_bytes {
            return 0;
        }
        // Eviction order mirrors incident.rs prune: least important first, and
        // oldest first within a tier. `rows` is already id-ascending (oldest
        // first), so a stable sort by ascending priority puts the first victim
        // at the front. An anchor's key is lifted to its youngest, most
        // important dependant's, and it sorts after that one on the tie.
        let mut key: Vec<(u8, usize, u8)> = (0..rows.len())
            .map(|i| (carry_priority(&rows[i]), i, 0))
            .collect();
        for (i, anchor) in anchor_of.iter().enumerate() {
            let Some(j) = *anchor else { continue };
            let (p, idx, _) = key[i];
            let k = &mut key[j];
            *k = (k.0.max(p), k.1.max(idx), 1);
        }
        let mut order: Vec<usize> = (0..rows.len()).collect();
        order.sort_by_key(|&x| key[x]);

        let mut kept_count = rows.len();
        let mut kept_bytes = bytes;
        let mut evict = std::collections::HashSet::new();
        let mut evicted_wanted = 0usize;
        for &victim in &order {
            if kept_count <= self.carry_max && kept_bytes <= self.carry_max_bytes {
                break;
            }
            evict.insert(victim);
            kept_count -= 1;
            kept_bytes = kept_bytes.saturating_sub(sizes[victim]);
            if still_wanted_a_human(&rows[victim]) {
                evicted_wanted += 1;
            }
        }
        let mut i = 0;
        rows.retain(|_| {
            let keep = !evict.contains(&i);
            i += 1;
            keep
        });
        evicted_wanted
    }

    /// Write carried rows into the staging file as folded Full lines and fsync.
    ///
    /// A RAW write loop on purpose: it must NOT go through `write_line`, whose
    /// size-check would recurse straight back into `rotate`.
    fn write_carried(&self, staging: &Path, carried: &[Alert]) -> std::io::Result<()> {
        let mut buf = String::new();
        for a in carried {
            buf.push_str(&serde_json::to_string(a)?);
            buf.push('\n');
        }
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(staging)?;
        f.write_all(buf.as_bytes())?;
        f.flush()?;
        f.sync_all()?;
        let _ = crate::util::secure_path(staging, &self.group, 0o640);
        Ok(())
    }

    pub fn append_alert(&mut self, a: &Alert) -> std::io::Result<()> {
        let line = serde_json::to_string(a)?;
        self.write_line(&line)
    }

    pub fn append_update(&mut self, u: &UpdateLine) -> std::io::Result<()> {
        let line = serde_json::to_string(u)?;
        self.write_line(&line)
    }

    /// LEARNING §3: an install receipt is its own line kind,
    /// `{"v":1,"receipt":{…}}`. It shares the file with the alerts so the
    /// timeline is one stream, and `parse_record` returns `None` for it, so no
    /// reader can mistake it for an alert or count it in the badge.
    pub fn append_receipt(&mut self, r: &Receipt) -> std::io::Result<()> {
        let line = serde_json::to_string(&r.line())?;
        self.write_line(&line)
    }

    fn cache_lock(&self) -> std::sync::MutexGuard<'_, Option<Cache>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Fold both files from the top: rotated first, then live, so an update
    /// in the live file lands on a record that was rotated out.
    fn fold_from_disk(&self) -> Cache {
        // Stamped BEFORE reading: a write that lands mid-read makes the next
        // call's stamp differ, and it re-folds.
        let stamp = Stamp::of(&self.path, &self.rotated);
        let mut c = Cache {
            map: BTreeMap::new(),
            receipts: Vec::new(),
            stamp,
        };
        for p in [&self.rotated, &self.path] {
            let Ok(text) = std::fs::read_to_string(p) else {
                continue;
            };
            for line in text.lines() {
                c.fold_line(line);
            }
        }
        c
    }

    /// Run `f` over the current fold, rebuilding it first if the files on
    /// disk are not the ones it was built from.
    fn with_fold<R>(&self, f: impl FnOnce(&Cache) -> R) -> R {
        let mut guard = self.cache_lock();
        let fresh = guard
            .as_ref()
            .map(|c| c.stamp == Stamp::of(&self.path, &self.rotated))
            .unwrap_or(false);
        if !fresh {
            *guard = Some(self.fold_from_disk());
        }
        f(guard.as_ref().expect("folded above"))
    }

    /// Every receipt, oldest first.
    pub fn receipts(&self) -> Vec<Receipt> {
        self.with_fold(|c| c.receipts.clone())
    }

    /// Every alert, updates folded, oldest first. ULIDs sort chronologically so
    /// the map order is the timeline.
    pub fn load(&self) -> Vec<Alert> {
        self.with_fold(|c| c.map.values().cloned().collect())
    }

    /// How many alerts satisfy `pred`, without cloning any of them.
    pub fn count_alerts(&self, pred: impl Fn(&Alert) -> bool) -> usize {
        self.with_fold(|c| c.map.values().filter(|a| pred(a)).count())
    }

    pub fn find(&self, id: &str) -> Option<Alert> {
        self.with_fold(|c| c.map.get(id).cloned())
    }

    /// Unacked counts by severity, for `status` -- and it means the BADGE.
    ///
    /// Suppressed alerts (an allowlist or baseline entry matched) are recorded
    /// but never counted — BASELINE §8. Neither is anything on the timeline:
    /// every medium and low is there by construction, and a demoted or
    /// triage-demoted high carries `surface: "timeline"` precisely so that it
    /// is not waiting on anyone. This used to count them anyway, so `moatctl
    /// status` printed "unacked critical 5 high 243 medium 627 low 776" over
    /// a badge of 1, and the watchdog kept its own filter with the surface
    /// clause this one lacked. One predicate, used by both.
    pub fn unacked(&self) -> BTreeMap<String, u64> {
        let mut counts: BTreeMap<String, u64> = ["critical", "high", "medium", "low"]
            .iter()
            .map(|s| (s.to_string(), 0))
            .collect();
        self.with_fold(|c| {
            for a in c.map.values() {
                if !a.acked && !a.is_suppressed() && a.surface == "alerts" {
                    *counts.entry(a.severity.clone()).or_insert(0) += 1;
                }
            }
        });
        counts
    }

    /// The three numbers `moatctl status` and the panel print, in the three
    /// words they print them in.
    ///
    /// One count was never three questions. `unacked` counts the badge and is
    /// right about it, but everything downstream printed it under a word --
    /// "unacked" -- that a person reads as a backlog, so a day of quickshell
    /// plugin execs read as 1,854 things waiting for an answer. 48% of those
    /// records were allowlisted (the user had already answered) and the rest
    /// were timeline rows that were never a question. Naming the three
    /// populations separately is the whole fix; nothing is filtered or dropped.
    ///
    /// * **needs you** — on the badge, unacked, not suppressed. `unacked`
    ///   summed, and the only number a person is being asked about.
    /// * **recorded** — timeline rows. Everything moat saw, wrote down and did
    ///   not ask about, including every `signal`-tier building block.
    /// * **suppressed** — an allowlist entry matched. Recorded and never
    ///   counted, BASELINE §8.
    /// * **signal** — the part of `recorded` that came from a `signal` rule, so
    ///   "recorded" can be read as "how much of this is scaffolding".
    pub fn ledger(&self) -> Ledger {
        let mut l = Ledger::default();
        // `needs_you` counts THINGS TO DECIDE ABOUT, not rows.
        //
        // A chain that reaches `high` re-stamps every trigger member onto the
        // badge (`engine::note_chain`), because a sequence whose every step is
        // a building block still has to be findable -- the 2026-09-04 AUR case.
        // The side effect is that one finding arrives as N rows. Measured
        // 2026-09-07: `needs you 30` against five chains and nine loose alerts,
        // while the panel -- which groups by chain, then by (rule, program) --
        // showed 6 and was right. Two numbers for one question, and the bigger
        // one is the one that makes a person stop reading.
        //
        // So this counts the same groups the panel does. The severity
        // breakdown printed beneath it still counts rows, which is what a
        // severity breakdown is for.
        let mut queued: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        self.with_fold(|c| {
            for a in c.map.values() {
                if a.is_suppressed() {
                    l.suppressed += 1;
                } else if a.surface == "alerts" {
                    if !a.acked {
                        queued.insert(incident_key(a));
                    }
                } else {
                    l.recorded += 1;
                    if a.tier == crate::policy::TIER_SIGNAL {
                        l.signal += 1;
                    }
                }
            }
        });
        l.needs_you = queued.len() as u64;
        l
    }
}

/// Drop the inline chain from every row whose anchor is also in `rows` and
/// carries that chain; the reference in `chain_id` is enough, and `Cache::
/// hydrate` puts the chain back when the row is read. Returns, per row, the
/// index of the anchor it was stripped against. Rows whose anchor is absent
/// keep their inline copy, so they do not depend on a row that is not there.
fn strip_shared_chains(rows: &mut [Alert]) -> Vec<Option<usize>> {
    let anchors: std::collections::HashMap<&str, usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, a)| a.is_chain_anchor())
        .map(|(i, a)| (a.id.as_str(), i))
        .collect();
    let anchor_of: Vec<Option<usize>> = rows
        .iter()
        .map(|a| {
            let cid = a.chain_id.as_deref()?;
            if cid == a.id || a.chain.as_ref().is_none_or(|c| c.id != cid) {
                return None;
            }
            anchors.get(cid).copied()
        })
        .collect();
    for (a, anchor) in rows.iter_mut().zip(&anchor_of) {
        if anchor.is_some() {
            a.chain = None;
        }
    }
    anchor_of
}

/// Serialized on-disk size of one carried row, including its newline.
fn line_len(a: &Alert) -> u64 {
    serde_json::to_string(a).map(|s| s.len() as u64 + 1).unwrap_or(0)
}

/// A carried row's importance tier for eviction: HIGHER survives longer, so the
/// caps evict the lowest first. Mirrors the order in the plan and incident.rs
/// prune: P6-only (0) < P5 (1) < P4/P3/P2 (2) < P1 (3). A row is classed by its
/// STRONGEST protecting reason, so it is evicted only as its best claim allows.
fn carry_priority(a: &Alert) -> u8 {
    use crate::alert::{severity_rank, PROTECTED_META_RULES};
    // P1: on the badge, unacked, unsuppressed — the thing still to be answered.
    if a.surface == "alerts" && !a.acked && !a.is_suppressed() {
        return 3;
    }
    // P2/P3/P4: acted on, a high+ story, or a snapshot on disk.
    if a.action_taken != "none"
        || a.incident.is_some()
        || a.chain
            .as_ref()
            .is_some_and(|c| severity_rank(&c.severity) >= severity_rank("high"))
    {
        return 2;
    }
    // P5: a self-health / protection meta alert.
    if PROTECTED_META_RULES.contains(&a.rule.as_str()) {
        return 1;
    }
    // P6-only: surfaced and grave, but already answered.
    0
}

/// Did this evicted row still want a human? Same predicate as the badge (P1),
/// so the warning counts exactly the rows a person had not yet answered.
fn still_wanted_a_human(a: &Alert) -> bool {
    a.surface == "alerts" && !a.acked && !a.is_suppressed()
}

/// What is in `alerts.jsonl`, split by what it asks of a person
/// (`AlertStore::ledger`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ledger {
    pub needs_you: u64,
    pub recorded: u64,
    pub suppressed: u64,
    pub signal: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::tests_support::demo_alert;
    use serde_json::Value;

    fn store(dir: &Path, max: u64) -> AlertStore {
        // Generous carry caps: the carry-forward tests that exercise the caps
        // set their own store with tight ones.
        AlertStore::open(
            &dir.join("alerts.jsonl"),
            &dir.join("alerts.1.jsonl"),
            max,
            u64::MAX,
            usize::MAX,
            "moat",
        )
        .unwrap()
    }

    fn store_caps(dir: &Path, max: u64, carry_max_bytes: u64, carry_max: usize) -> AlertStore {
        AlertStore::open(
            &dir.join("alerts.jsonl"),
            &dir.join("alerts.1.jsonl"),
            max,
            carry_max_bytes,
            carry_max,
            "moat",
        )
        .unwrap()
    }

    #[test]
    fn appends_and_folds_updates() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        let a = demo_alert("01AAAAAAAAAAAAAAAAAAAAAAAA");
        s.append_alert(&a).unwrap();
        s.append_update(&UpdateLine::new(&a.id).set("acked", Value::Bool(true)))
            .unwrap();
        let all = s.load();
        assert_eq!(all.len(), 1);
        assert!(all[0].acked);
    }

    #[test]
    fn ulid_order_is_the_timeline() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        for id in ["01CCCCCCCCCCCCCCCCCCCCCCCC", "01AAAAAAAAAAAAAAAAAAAAAAAA"] {
            s.append_alert(&demo_alert(id)).unwrap();
        }
        let ids: Vec<String> = s.load().into_iter().map(|a| a.id).collect();
        assert_eq!(ids, vec!["01AAAAAAAAAAAAAAAAAAAAAAAA", "01CCCCCCCCCCCCCCCCCCCCCCCC"]);
    }

    #[test]
    fn rotation_keeps_history_readable() {
        let dir = tempfile::tempdir().unwrap();
        // Size the limit so exactly one rotation happens after the third alert.
        let line = serde_json::to_string(&demo_alert("01AAAAAAAAAAAAAAAAAAAAAAAA")).unwrap();
        let mut s = store(dir.path(), (line.len() as u64 + 1) * 3);
        for i in 0..5 {
            s.append_alert(&demo_alert(&format!("01{:024}", i))).unwrap();
        }
        assert!(dir.path().join("alerts.1.jsonl").exists(), "should have rotated");
        // Rotated + current are both read back.
        assert_eq!(s.load().len(), 5);
    }

    // ---- carry-forward rotation (R1) ------------------------------------

    /// A plain timeline row: surfaced nowhere, low, answered — protected by
    /// nothing, so rotation is free to drop it.
    fn timeline_row(id: &str) -> Alert {
        let mut a = demo_alert(id);
        a.surface = "timeline".into();
        a.severity = "low".into();
        a.acked = true;
        a.action_taken = "none".into();
        a.chain = None;
        a.incident = None;
        a.rule = "moat-fs-ordinary".into();
        assert!(!a.is_protected(), "timeline_row must be unprotected");
        a
    }

    #[test]
    fn rotation_carries_a_protected_row_across_two_rotations() {
        let dir = tempfile::tempdir().unwrap();
        let line = serde_json::to_string(&timeline_row("01T00000000000000000000000")).unwrap();
        // Small enough to rotate several times over the run.
        let mut s = store(dir.path(), (line.len() as u64 + 1) * 4);

        // demo_alert is surfaced+high+unacked => P1/P6 protected.
        let prot = demo_alert("01P00000000000000000000001");
        s.append_alert(&prot).unwrap();
        for i in 0..20 {
            s.append_alert(&timeline_row(&format!("01T{:023}", i))).unwrap();
        }
        assert!(dir.path().join("alerts.1.jsonl").exists(), "should have rotated");

        // The live file holds the carried protected row, tamper-stamped.
        let live = std::fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap();
        assert!(live.contains("01P00000000000000000000001"), "protected row is in live");
        assert!(live.contains("\"carried\""), "carried rows are stamped");

        // It survives across the rotations; the earliest timeline row does not.
        let ids: std::collections::HashSet<String> =
            s.load().into_iter().map(|a| a.id).collect();
        assert!(ids.contains("01P00000000000000000000001"), "protected row survived");
        assert!(!ids.contains("01T00000000000000000000000"), "oldest timeline row rotated out");
        // And the folded protected row shows the carry stamp with a grown gen.
        let got = s.find("01P00000000000000000000001").unwrap();
        let c = got.carried.expect("carried stamp present after rotation");
        assert!(c.generation >= 1);
    }

    #[test]
    fn an_update_line_still_folds_onto_a_carried_row() {
        let dir = tempfile::tempdir().unwrap();
        let line = serde_json::to_string(&timeline_row("01T00000000000000000000000")).unwrap();
        let mut s = store(dir.path(), (line.len() as u64 + 1) * 4);

        let prot = demo_alert("01P00000000000000000000001");
        s.append_alert(&prot).unwrap();
        for i in 0..8 {
            s.append_alert(&timeline_row(&format!("01T{:023}", i))).unwrap();
        }
        assert!(dir.path().join("alerts.1.jsonl").exists());
        // An update lands on the id AFTER it has been carried forward.
        s.append_update(&UpdateLine::new(&prot.id).set("count", Value::from(5u64)))
            .unwrap();
        let got = s.find(&prot.id).unwrap();
        assert_eq!(got.count, Some(5), "update folds onto the carried Full line");
        assert!(got.carried.is_some(), "and the carry stamp is preserved");
    }

    #[test]
    fn carry_caps_evict_least_important_first() {
        let dir = tempfile::tempdir().unwrap();
        let line = serde_json::to_string(&timeline_row("01T00000000000000000000000")).unwrap();
        // carry_max = 2 rows; max small enough to rotate.
        let mut s = store_caps(dir.path(), (line.len() as u64 + 1) * 6, u64::MAX, 2);

        // P1: surfaced, unacked, high.
        let p1 = demo_alert("01A00000000000000000000001");
        // P5: a meta rule, otherwise unremarkable.
        let mut p5 = timeline_row("01B00000000000000000000002");
        p5.rule = "moat-x-noisy-rule".into();
        assert!(p5.is_protected());
        // P6-only: surfaced + high but already answered.
        let mut p6 = demo_alert("01C00000000000000000000003");
        p6.acked = true;
        assert!(p6.is_protected());
        assert_eq!(carry_priority(&p6), 0, "P6-only is the lowest tier");

        s.append_alert(&p1).unwrap();
        s.append_alert(&p5).unwrap();
        s.append_alert(&p6).unwrap();
        // Filler timeline to cross the rotation size.
        for i in 0..10 {
            s.append_alert(&timeline_row(&format!("01T{:023}", i))).unwrap();
        }
        assert!(dir.path().join("alerts.1.jsonl").exists(), "should have rotated");

        // The live file carried only the two most important; the P6-only went.
        let live = std::fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap();
        assert!(live.contains("01A00000000000000000000001"), "P1 kept");
        assert!(live.contains("01B00000000000000000000002"), "P5 kept");
        assert!(!live.contains("01C00000000000000000000003"), "P6-only evicted first");
    }

    #[test]
    fn a_crash_between_the_two_renames_is_completed_on_open() {
        let dir = tempfile::tempdir().unwrap();
        // Crash point: staging written, live already renamed aside (missing).
        std::fs::write(dir.path().join("alerts.new"), "carried-line\n").unwrap();
        // open() reconciles before it appends.
        let s = store(dir.path(), 1 << 20);
        assert!(dir.path().join("alerts.jsonl").exists(), "second rename completed");
        assert!(!dir.path().join("alerts.new").exists(), "staging consumed");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap(),
            "carried-line\n"
        );
        drop(s);
    }

    #[test]
    fn a_stale_staging_file_is_discarded_when_the_live_log_survives() {
        let dir = tempfile::tempdir().unwrap();
        // Crash point: staging written, but the first rename had not run, so the
        // live log is intact and authoritative.
        std::fs::write(dir.path().join("alerts.jsonl"), "real\n").unwrap();
        std::fs::write(dir.path().join("alerts.new"), "stale\n").unwrap();
        let s = store(dir.path(), 1 << 20);
        assert!(!dir.path().join("alerts.new").exists(), "stale staging discarded");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap(),
            "real\n",
            "live log untouched"
        );
        drop(s);
    }

    #[test]
    fn an_update_for_an_unknown_id_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        s.append_update(&UpdateLine::new("01ZZZ").set("acked", Value::Bool(true)))
            .unwrap();
        assert!(s.load().is_empty());
    }

    #[test]
    fn unacked_counts_by_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        let mut a = demo_alert("01AAAAAAAAAAAAAAAAAAAAAAAA");
        a.severity = "critical".into();
        s.append_alert(&a).unwrap();
        let mut b = demo_alert("01BBBBBBBBBBBBBBBBBBBBBBBB");
        b.severity = "high".into();
        s.append_alert(&b).unwrap();
        s.append_update(&UpdateLine::new(&b.id).set("acked", Value::Bool(true)))
            .unwrap();
        let c = s.unacked();
        assert_eq!(c["critical"], 1);
        assert_eq!(c["high"], 0);
        assert_eq!(c["low"], 0);
    }

    #[test]
    fn a_suppressed_alert_is_stored_but_never_counted() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        let mut a = demo_alert("01AAAAAAAAAAAAAAAAAAAAAAAA");
        a.severity = "critical".into();
        a.suppressed_by = Some("baseline.toml#2".into());
        s.append_alert(&a).unwrap();
        assert_eq!(s.load().len(), 1, "it is on the timeline");
        assert_eq!(s.unacked()["critical"], 0, "and out of the badge");

        // Suppression can also arrive as an update line.
        let mut b = demo_alert("01BBBBBBBBBBBBBBBBBBBBBBBB");
        b.severity = "high".into();
        s.append_alert(&b).unwrap();
        assert_eq!(s.unacked()["high"], 1);
        s.append_update(&UpdateLine::new(&b.id).set("suppressed_by", Value::from("user.toml#1")))
            .unwrap();
        assert_eq!(s.unacked()["high"], 0);
    }

    /// Three populations, three names, and every record in exactly one of them.
    ///
    /// The bug this closes is a wording bug with a real cost: `unacked` was
    /// right about the badge and was printed under a word people read as a
    /// backlog, so a day of quickshell plugin execs showed as "1,854" next to a
    /// badge of 13. Nothing here filters anything — it names what is already
    /// there.
    /// `needs_you` counts THINGS TO DECIDE ABOUT, not rows.
    ///
    /// 2026-09-07: a chain that reaches `high` re-stamps every trigger member
    /// onto the badge, so five chains and nine loose alerts read as
    /// `needs you 30` while the panel -- which groups by chain, then by (rule,
    /// program) -- showed 6. Two numbers for one question, and the bigger one
    /// is the one that makes a person stop reading.
    #[test]
    fn needs_you_counts_decisions_not_rows() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);

        // Nine steps of ONE chain, all raised onto the badge as the daemon
        // raises them.
        for i in 0..9 {
            let mut a = demo_alert(&format!("01C0000000000000000000000{}", i));
            a.surface = "alerts".into();
            a.acked = false;
            a.chain = Some(crate::chain::Chain {
                v: 1,
                id: "01CHAIN".into(),
                ancestor: crate::alert::Ancestor::new(9000, "/usr/bin/bash".into()),
                families: vec!["net".into()],
                severity: "high".into(),
                severity_base: "medium".into(),
                severity_reason: "r".into(),
                first_ts: crate::util::now_rfc3339(),
                last_ts: crate::util::now_rfc3339(),
                span_secs: 1,
                steps: vec![],
                steps_total: 9,
                truncated: false,
                members: Vec::new(),
                triggers_total: 9,
                summary: "s".into(),
            });
            s.append_alert(&a).unwrap();
        }
        // Sixty-eight repeats of one detection by one program.
        for i in 0..68 {
            let mut a = demo_alert(&format!("01R{:022}", i));
            a.surface = "alerts".into();
            a.acked = false;
            a.rule = "moat-exec-untrusted-home".into();
            a.process.exe = "/usr/bin/npm".into();
            s.append_alert(&a).unwrap();
        }
        // And one unrelated thing.
        let mut other = demo_alert("01Z0000000000000000000000A");
        other.surface = "alerts".into();
        other.acked = false;
        other.rule = "moat-cred-ssh-private-key-read".into();
        other.process.exe = "/usr/bin/cat".into();
        s.append_alert(&other).unwrap();

        assert_eq!(
            s.ledger().needs_you,
            3,
            "one chain, one repeated detection, one other = three decisions"
        );
        // The severity breakdown still counts ROWS: that is what it is for.
        let rows: u64 = s.unacked().values().sum();
        assert_eq!(rows, 78, "78 rows behind those three decisions");
    }

    #[test]
    fn the_ledger_splits_the_file_into_needs_you_recorded_and_suppressed() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        let mut put = |id: &str, surface: &str, tier: &str, sup: Option<&str>, acked: bool| {
            let mut a = demo_alert(id);
            a.surface = surface.into();
            a.tier = tier.into();
            a.suppressed_by = sup.map(|x| x.to_string());
            a.acked = acked;
            s.append_alert(&a).unwrap();
        };
        put("01L00000000000000000000001", "alerts", "detection", None, false);
        put("01L00000000000000000000002", "alerts", "detection", None, true);
        put("01L00000000000000000000003", "timeline", "detection", None, false);
        put("01L00000000000000000000004", "timeline", "signal", None, false);
        put("01L00000000000000000000005", "timeline", "signal", None, false);
        // A suppressed row is suppressed first, whatever else it looks like.
        put("01L00000000000000000000006", "timeline", "signal", Some("user.toml#1"), false);

        let l = s.ledger();
        assert_eq!(l.needs_you, 1, "acked rows have been answered");
        assert_eq!(l.recorded, 3);
        assert_eq!(l.signal, 2, "the part of `recorded` that is scaffolding");
        assert_eq!(l.suppressed, 1);
        // `needs_you` is `unacked` as one number, and always will be.
        assert_eq!(l.needs_you, s.unacked().values().sum::<u64>());
        assert_eq!(
            l.needs_you + l.recorded + l.suppressed + 1,
            s.load().len() as u64,
            "every record is in exactly one population (+1 for the acked badge row)"
        );
    }

    /// Receipts live in the same file and must be invisible to every alert
    /// reader: not in `load()`, not in `unacked()`, never a badge.
    #[test]
    fn receipts_share_the_file_without_ever_looking_like_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        let mut a = demo_alert("01AAAAAAAAAAAAAAAAAAAAAAAA");
        a.severity = "critical".into();
        s.append_alert(&a).unwrap();

        let mut t = crate::receipt::Tracker::default();
        let root = crate::proctable::ProcInfo {
            exec_id: "e".into(),
            pid: 41201,
            uid: 1000,
            exe: "/usr/bin/npm".into(),
            args: "install".into(),
            cwd: "/home/dan/app".into(),
            start_time: crate::util::rfc3339_of(1_000),
            ..Default::default()
        };
        t.ensure(&root, 1_000);
        let r = t.finish(&root, Some(0), 1_041);
        s.append_receipt(&r).unwrap();
        s.append_alert(&demo_alert("01BBBBBBBBBBBBBBBBBBBBBBBB")).unwrap();

        assert_eq!(s.load().len(), 2, "the receipt is not an alert");
        assert_eq!(s.unacked()["critical"], 1);
        let got = s.receipts();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].root_exe, "/usr/bin/npm");
        assert_eq!(got[0].duration_s, 41);
    }

    #[test]
    fn mode_is_640() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        s.append_alert(&demo_alert("01AAAAAAAAAAAAAAAAAAAAAAAA")).unwrap();
        let mode = std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn garbage_lines_do_not_stop_the_reader() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        s.append_alert(&demo_alert("01AAAAAAAAAAAAAAAAAAAAAAAA")).unwrap();
        {
            let mut f = OpenOptions::new().append(true).open(s.path()).unwrap();
            f.write_all(b"not json\n{\"partial\":\n").unwrap();
        }
        s.append_alert(&demo_alert("01BBBBBBBBBBBBBBBBBBBBBBBB")).unwrap();
        assert_eq!(s.load().len(), 2);
    }

    // ---- chains: written once, read everywhere ---------------------------

    /// A chain over `members`, anchored on the first of them, as the engine
    /// would serialise it.
    fn chain_over(members: &[&str], severity: &str) -> crate::chain::Chain {
        let steps: Vec<crate::chain::Step> = members
            .iter()
            .take(crate::chain::MAX_STEPS)
            .map(|m| crate::chain::Step {
                alert: m.to_string(),
                ts: "2026-09-10T10:00:00Z".into(),
                family: "cred".into(),
                rule: "moat-cred-registry-token-read".into(),
                severity: "medium".into(),
                title: "t".into(),
                pid: 1,
                exe: "/usr/bin/node".into(),
                role: "trigger".into(),
            })
            .collect();
        crate::chain::Chain {
            v: 1,
            id: members[0].to_string(),
            ancestor: crate::alert::Ancestor::new(9000, "/usr/bin/npm".into()),
            families: vec!["cred".into(), "net".into()],
            severity: severity.into(),
            severity_base: "medium".into(),
            severity_reason: "r".into(),
            first_ts: "2026-09-10T10:00:00Z".into(),
            last_ts: "2026-09-10T10:00:01Z".into(),
            span_secs: 1,
            steps,
            steps_total: members.len(),
            truncated: members.len() > crate::chain::MAX_STEPS,
            members: members.iter().map(|m| m.to_string()).collect(),
            triggers_total: members.len(),
            summary: "s".into(),
        }
    }

    /// Write a grown chain the way `engine::write_chain` does: the chain on
    /// the anchor, a `chain_id` on each member.
    fn grow(s: &mut AlertStore, members: &[&str], severity: &str) {
        let c = chain_over(members, severity);
        s.append_update(
            &UpdateLine::new(members[0])
                .set("chain", serde_json::to_value(&c).unwrap())
                .set("chain_id", Value::from(members[0])),
        )
        .unwrap();
        for m in &members[1..] {
            s.append_update(&UpdateLine::new(m).set("chain_id", Value::from(members[0]))).unwrap();
        }
    }

    const A: &str = "01CHAIN0000000000000000A00";
    const B: &str = "01CHAIN0000000000000000B00";
    const C: &str = "01CHAIN0000000000000000C00";

    /// THE invariant: every member carries the whole chain. It used to be paid
    /// for at write time by appending the chain to every member on every
    /// growth; now it is kept at read time. The trap is a member that joined
    /// early holding an early snapshot -- `moatctl ack --chain` on it would
    /// silently miss whoever joined later -- and it has to hold both on the
    /// fold the writer keeps and on a fold rebuilt from disk.
    #[test]
    fn a_member_sees_the_siblings_that_joined_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        for id in [A, B, C] {
            s.append_alert(&demo_alert(id)).unwrap();
        }
        grow(&mut s, &[A, B], "medium");
        let b = s.find(B).unwrap();
        assert_eq!(b.chain_id.as_deref(), Some(A));
        assert_eq!(b.chain.as_ref().unwrap().member_ids(), vec![A, B]);

        // C joins. Only the anchor gets the new chain; B gets nothing at all.
        grow(&mut s, &[A, B, C], "medium");
        for id in [A, B, C] {
            let a = s.find(id).unwrap();
            assert_eq!(
                a.chain.as_ref().map(|c| c.member_ids()),
                Some(vec![A.to_string(), B.to_string(), C.to_string()]),
                "{} holds an earlier snapshot",
                id
            );
        }

        // The chain is on disk exactly once per growth: two growths, two copies.
        let text = std::fs::read_to_string(s.path()).unwrap();
        assert_eq!(text.matches("\"steps\"").count(), 2, "the chain was inlined on a member");

        // And a reader that folds the file from the top sees the same thing.
        drop(s);
        let s = store(dir.path(), 1 << 20);
        for id in [A, B, C] {
            let a = s.find(id).unwrap();
            assert_eq!(a.chain.as_ref().unwrap().member_ids().len(), 3, "{} lost siblings on refold", id);
        }
        // A plain update on a member, which is what an ack is, does not
        // disturb the chain it was given.
        drop(s);
        let mut s = store(dir.path(), 1 << 20);
        s.append_update(&UpdateLine::new(B).set("acked", Value::Bool(true))).unwrap();
        let b = s.find(B).unwrap();
        assert!(b.acked);
        assert_eq!(b.chain.as_ref().unwrap().member_ids().len(), 3);
    }

    /// Records written before `chain_id` existed carry the chain inline on
    /// every member and name no anchor. They fold exactly as they did, and a
    /// mixed file -- an old chain grown by a new daemon -- converges on the
    /// anchor's copy, which is the newest.
    #[test]
    fn an_inline_chain_from_an_older_daemon_still_folds() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        for id in [A, B, C] {
            s.append_alert(&demo_alert(id)).unwrap();
        }
        let two = serde_json::to_value(chain_over(&[A, B], "medium")).unwrap();
        for id in [A, B] {
            s.append_update(&UpdateLine::new(id).set("chain", two.clone())).unwrap();
        }
        for id in [A, B] {
            let a = s.find(id).unwrap();
            assert!(a.chain_id.is_none(), "an old record names no anchor");
            assert_eq!(a.chain.as_ref().unwrap().member_ids(), vec![A, B]);
        }
        assert!(s.find(C).unwrap().chain.is_none());

        // A new daemon grows the same chain: B is given a reference, and the
        // anchor's copy replaces B's older inline one.
        grow(&mut s, &[A, B, C], "medium");
        for id in [A, B, C] {
            let a = s.find(id).unwrap();
            assert_eq!(a.chain.as_ref().unwrap().member_ids().len(), 3, "{}", id);
        }
        drop(s);
        let s = store(dir.path(), 1 << 20);
        for id in [A, B, C] {
            assert_eq!(s.find(id).unwrap().chain.as_ref().unwrap().member_ids().len(), 3);
        }
    }

    /// A reference whose anchor is missing is just a reference: the member
    /// shows no chain rather than a made-up one, and an inline copy it already
    /// had is kept.
    #[test]
    fn a_member_without_its_anchor_keeps_what_it_has() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        s.append_alert(&demo_alert(B)).unwrap();
        s.append_update(&UpdateLine::new(B).set("chain_id", Value::from(A))).unwrap();
        let b = s.find(B).unwrap();
        assert_eq!(b.chain_id.as_deref(), Some(A));
        assert!(b.chain.is_none());

        let two = serde_json::to_value(chain_over(&[A, B], "medium")).unwrap();
        s.append_update(&UpdateLine::new(B).set("chain", two)).unwrap();
        assert_eq!(s.find(B).unwrap().chain.as_ref().unwrap().member_ids(), vec![A, B]);
    }

    /// Rotation carries a `high` chain the way the file stores it: once, on
    /// the anchor. Every member is P3-protected, so the anchor comes along on
    /// the same predicate, and the carried members are references.
    #[test]
    fn rotation_carries_a_high_chain_once_and_every_member_still_has_it() {
        let dir = tempfile::tempdir().unwrap();
        let line = serde_json::to_string(&timeline_row("01T00000000000000000000000")).unwrap();
        let mut s = store(dir.path(), (line.len() as u64 + 1) * 40);
        // All acked and on the timeline, so nothing but P3 protects them.
        let mut ids = Vec::new();
        for i in 0..30 {
            let id = format!("01CHAIN{:019}", i);
            let mut a = timeline_row(&id);
            a.rule = "moat-cred-registry-token-read".into();
            s.append_alert(&a).unwrap();
            ids.push(id);
        }
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        grow(&mut s, &refs, "high");
        for i in 0..60 {
            s.append_alert(&timeline_row(&format!("01T{:023}", i))).unwrap();
        }
        assert!(dir.path().join("alerts.1.jsonl").exists(), "should have rotated");

        let live = std::fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap();
        assert_eq!(live.matches("\"steps\"").count(), 1, "the chain was carried more than once");
        assert_eq!(live.matches("\"chain_id\"").count(), 30, "every member was carried");

        for id in &ids {
            let a = s.find(id).unwrap();
            assert_eq!(a.chain.as_ref().map(|c| c.member_ids().len()), Some(30), "{} lost its chain", id);
        }
        // The carried anchor has no `chain_id` of its own to resolve; the
        // carried members do, and the rotated file is gone from the fold's
        // point of view once alerts.1.jsonl rotates again.
        drop(s);
        let s = store(dir.path(), 1 << 20);
        for id in &ids {
            assert_eq!(s.find(id).unwrap().chain.as_ref().unwrap().member_ids().len(), 30);
        }
    }

    /// The anchor is not carried on a member's behalf: a member protected for
    /// its own reasons, whose anchor is not, keeps its chain inline -- the
    /// format every record used to have -- so it depends on nothing that was
    /// not written.
    #[test]
    fn a_carried_member_whose_anchor_stays_behind_keeps_the_chain_inline() {
        let dir = tempfile::tempdir().unwrap();
        let line = serde_json::to_string(&timeline_row("01T00000000000000000000000")).unwrap();
        let mut s = store(dir.path(), (line.len() as u64 + 1) * 12);
        // Anchor: unprotected. Member: on the badge (P1).
        s.append_alert(&timeline_row(A)).unwrap();
        s.append_alert(&demo_alert(B)).unwrap();
        grow(&mut s, &[A, B], "medium");
        assert!(!s.find(A).unwrap().is_protected());
        assert!(s.find(B).unwrap().is_protected());
        for i in 0..20 {
            s.append_alert(&timeline_row(&format!("01T{:023}", i))).unwrap();
        }
        assert!(dir.path().join("alerts.1.jsonl").exists());
        let live = std::fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap();
        // A Full line opens `{"v":1,"id":<id>,"ts":...}`; the chain's own `id`
        // inside the member's inline copy is followed by `ancestor`.
        assert!(!live.contains(&format!("\"id\":\"{}\",\"ts\"", A)), "the anchor was not protected");
        assert!(live.contains("\"steps\""), "the member carries its chain inline");
        drop(s);
        // Rotate the rotated file away too, so only the carried copy is left.
        let mut s = store(dir.path(), (line.len() as u64 + 1) * 12);
        for i in 20..60 {
            s.append_alert(&timeline_row(&format!("01T{:023}", i))).unwrap();
        }
        let b = s.find(B).unwrap();
        assert!(s.find(A).is_none());
        assert_eq!(b.chain.as_ref().map(|c| c.member_ids()), Some(vec![A.to_string(), B.to_string()]));
    }

    /// The caps evict oldest-first within a tier, and the anchor is the oldest
    /// member by construction, so the plain order would evict the record a
    /// surviving member was stripped against. An anchor goes after its
    /// dependants.
    #[test]
    fn carry_caps_never_evict_an_anchor_from_under_a_member() {
        let dir = tempfile::tempdir().unwrap();
        let line = serde_json::to_string(&timeline_row("01T00000000000000000000000")).unwrap();
        // Room for two rows: one of the three P3 members has to go.
        let mut s = store_caps(dir.path(), (line.len() as u64 + 1) * 12, u64::MAX, 2);
        for id in [A, B, C] {
            let mut a = timeline_row(id);
            a.rule = "moat-cred-registry-token-read".into();
            s.append_alert(&a).unwrap();
        }
        grow(&mut s, &[A, B, C], "high");
        for i in 0..20 {
            s.append_alert(&timeline_row(&format!("01T{:023}", i))).unwrap();
        }
        assert!(dir.path().join("alerts.1.jsonl").exists());
        let live = std::fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap();
        assert!(live.contains(&format!("\"id\":\"{}\",\"ts\"", A)), "anchor evicted first");
        assert!(!live.contains(&format!("\"id\":\"{}\",\"ts\"", B)), "the oldest dependant goes first");
        assert!(live.contains(&format!("\"id\":\"{}\",\"ts\"", C)));
        assert_eq!(live.matches("\"steps\"").count(), 1);
        // Rotate again so nothing but the carried rows remains, then C must
        // still have its chain -- from the carried anchor.
        drop(s);
        let mut s = store_caps(dir.path(), (line.len() as u64 + 1) * 12, u64::MAX, 2);
        for i in 20..60 {
            s.append_alert(&timeline_row(&format!("01T{:023}", i))).unwrap();
        }
        assert!(s.find(B).is_none());
        let c = s.find(C).unwrap();
        assert_eq!(c.chain.as_ref().map(|c| c.member_ids().len()), Some(3));
    }

    /// Timing probe, not a test: `MOAT_BENCH_DIR=<dir with alerts.jsonl and
    /// alerts.1.jsonl> cargo test --release --lib store::tests::bench_load -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_load() {
        let Ok(dir) = std::env::var("MOAT_BENCH_DIR") else { return };
        let dir = std::path::PathBuf::from(dir);
        let s = AlertStore::open(&dir.join("alerts.jsonl"), &dir.join("alerts.1.jsonl"), u64::MAX, u64::MAX, usize::MAX, "moat").unwrap();
        for _ in 0..3 {
            let t = std::time::Instant::now();
            let n = s.load().len();
            let t_load = t.elapsed();
            let t = std::time::Instant::now();
            let r = s.receipts().len();
            let t_rec = t.elapsed();
            let t = std::time::Instant::now();
            let u = s.unacked();
            let t_un = t.elapsed();
            let t = std::time::Instant::now();
            let cnt = s.count_alerts(|a| !a.is_suppressed());
            let t_cnt = t.elapsed();
            eprintln!("BENCH load() {} alerts in {:?}; receipts() {} in {:?}; unacked() {:?} in {:?}; count_alerts {} in {:?}", n, t_load, r, t_rec, u, t_un, cnt, t_cnt);
        }
    }
}
