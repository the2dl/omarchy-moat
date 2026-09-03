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
use std::path::{Path, PathBuf};

use crate::alert::{fold, parse_record, Alert, Record, UpdateLine};

pub struct AlertStore {
    path: PathBuf,
    rotated: PathBuf,
    max_bytes: u64,
    group: String,
    file: Option<File>,
    size: u64,
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

    /// Every alert, updates folded, oldest first. ULIDs sort chronologically so
    /// the map order is the timeline.
    pub fn load(&self) -> Vec<Alert> {
        let mut map: BTreeMap<String, Alert> = BTreeMap::new();
        for p in [&self.rotated, &self.path] {
            let Ok(text) = std::fs::read_to_string(p) else {
                continue;
            };
            for line in text.lines() {
                match parse_record(line) {
                    Some(Record::Full(a)) => {
                        map.insert(a.id.clone(), *a);
                    }
                    Some(Record::Update(u)) => {
                        if let Some(a) = map.get_mut(&u.id) {
                            fold(a, &u.update);
                        }
                    }
                    None => {}
                }
            }
        }
        map.into_values().collect()
    }

    pub fn find(&self, id: &str) -> Option<Alert> {
        self.load().into_iter().find(|a| a.id == id)
    }

    /// Unacked counts by severity, for `status`.
    pub fn unacked(&self) -> BTreeMap<String, u64> {
        let mut counts: BTreeMap<String, u64> = ["critical", "high", "medium", "low"]
            .iter()
            .map(|s| (s.to_string(), 0))
            .collect();
        for a in self.load() {
            if !a.acked {
                *counts.entry(a.severity.clone()).or_insert(0) += 1;
            }
        }
        counts
    }
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
}
