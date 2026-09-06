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
                self.map.insert(a.id.clone(), *a);
            }
            Some(Record::Update(u)) => {
                if let Some(a) = self.map.get_mut(&u.id) {
                    fold(a, &u.update);
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
}

pub struct AlertStore {
    path: PathBuf,
    rotated: PathBuf,
    max_bytes: u64,
    group: String,
    file: Option<File>,
    size: u64,
    cache: Mutex<Option<Cache>>,
}

impl AlertStore {
    pub fn open(path: &Path, rotated: &Path, max_bytes: u64, group: &str) -> std::io::Result<AlertStore> {
        let mut s = AlertStore {
            path: path.to_path_buf(),
            rotated: rotated.to_path_buf(),
            max_bytes,
            group: group.to_string(),
            file: None,
            size: 0,
            cache: Mutex::new(None),
        };
        s.reopen()?;
        Ok(s)
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

    fn rotate(&mut self) -> std::io::Result<()> {
        log::info!(
            "rotating {} at {} bytes -> {}",
            self.path.display(),
            self.size,
            self.rotated.display()
        );
        self.file = None;
        // The old rotated file is gone with this rename, and so are its
        // alerts; the fold has to be rebuilt from what is left.
        *self.cache_lock() = None;
        std::fs::rename(&self.path, &self.rotated)?;
        self.reopen()
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
        self.with_fold(|c| {
            for a in c.map.values() {
                if a.is_suppressed() {
                    l.suppressed += 1;
                } else if a.surface == "alerts" {
                    if !a.acked {
                        l.needs_you += 1;
                    }
                } else {
                    l.recorded += 1;
                    if a.tier == crate::policy::TIER_SIGNAL {
                        l.signal += 1;
                    }
                }
            }
        });
        l
    }
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
        AlertStore::open(
            &dir.join("alerts.jsonl"),
            &dir.join("alerts.1.jsonl"),
            max,
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

    /// Timing probe, not a test: `MOAT_BENCH_DIR=<dir with alerts.jsonl and
    /// alerts.1.jsonl> cargo test --release --lib store::tests::bench_load -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_load() {
        let Ok(dir) = std::env::var("MOAT_BENCH_DIR") else { return };
        let dir = std::path::PathBuf::from(dir);
        let s = AlertStore::open(&dir.join("alerts.jsonl"), &dir.join("alerts.1.jsonl"), u64::MAX, "moat").unwrap();
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
