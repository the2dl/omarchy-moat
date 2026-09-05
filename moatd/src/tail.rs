//! A line tailer that survives Tetragon's log rotation.
//!
//! Tetragon rotates by rename (`--export-file-max-size-mb`), so the fd we hold
//! keeps pointing at `tetragon.log.1` and stops growing. We therefore stat the
//! *path* on every poll and reopen when the inode changes; a shrink means the
//! file was truncated in place, so we restart from offset 0. The same tailer is
//! used by `moatctl list` for `alerts.jsonl`, which rotates the same way.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The most one poll will read. 8 MiB is ~40 seconds of this machine's idle
/// Tetragon output and several seconds of a flood, so a real burst still drains
/// within a few polls while a hostile one cannot size the buffer at will.
const MAX_POLL_BYTES: u64 = 8 * 1024 * 1024;

pub struct Tailer {
    path: PathBuf,
    file: Option<File>,
    inode: u64,
    pos: u64,
    pending: String,
    /// Start at offset 0 rather than at the end. False is what the daemon wants
    /// for a live log (do not replay a week of events on restart); true is what
    /// dev mode and tests want.
    from_start: bool,
    opened_once: bool,
}

impl Tailer {
    pub fn new(path: impl Into<PathBuf>, from_start: bool) -> Tailer {
        Tailer {
            path: path.into(),
            file: None,
            inode: 0,
            pos: 0,
            pending: String::new(),
            from_start,
            opened_once: false,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True while the file exists and we hold a handle on it.
    pub fn attached(&self) -> bool {
        self.file.is_some()
    }

    /// Return every complete line that appeared since the last poll.
    /// Never blocks; a missing file yields an empty vector.
    ///
    /// At most `MAX_POLL_BYTES` per call: whatever is left is read by the next
    /// poll, 200 ms later, so a burst is drained steadily instead of in one
    /// unbounded allocation.
    pub fn poll(&mut self) -> Vec<String> {
        self.reopen_if_needed();
        let Some(file) = self.file.as_mut() else {
            return Vec::new();
        };
        // Bounded per poll. An unbounded `read_to_end` hands the attacker the
        // size of this daemon's working set: an exec loop that outruns one poll
        // makes the next buffer bigger, which makes the next poll slower.
        let mut buf = Vec::new();
        if file
            .take(MAX_POLL_BYTES)
            .read_to_end(&mut buf)
            .is_err()
        {
            self.file = None;
            return Vec::new();
        }
        if buf.is_empty() {
            return Vec::new();
        }
        self.pos += buf.len() as u64;
        self.pending.push_str(&String::from_utf8_lossy(&buf));

        // ONE drain, not one per line.
        //
        // `String::drain(..=idx)` memmoves everything after the cut to the
        // front, so draining line by line is quadratic in the size of the
        // buffer. Measured on this machine: 1 MB of pending took 12 ms, 8 MB
        // took 864 ms, 16 MB took 3.48 s -- 16x the data for 290x the time.
        //
        // That curve is a weapon. Any unprivileged exec loop that pushes one
        // poll past its 200 ms interval leaves a bigger buffer for the next
        // poll, which is then slower still, and the daemon never catches up:
        // the sensor is blind for exactly as long as the attacker keeps going,
        // and nothing reports that it happened. Cutting once at the last
        // newline makes the work linear and the feedback loop impossible.
        let mut out = Vec::new();
        let keep = self.pending.rfind('\n').map(|i| i + 1).unwrap_or(0);
        if keep > 0 {
            let complete: String = self.pending.drain(..keep).collect();
            for line in complete.lines() {
                let line = line.trim_end_matches(['\n', '\r']);
                if !line.is_empty() {
                    out.push(line.to_string());
                }
            }
        }
        // A partial line stays in `pending` until its newline arrives; the JSON
        // exporter writes one object per line, so half a line is never valid.
        out
    }

    fn reopen_if_needed(&mut self) {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => {
                self.file = None;
                return;
            }
        };
        let rotated = self.file.is_some() && meta.ino() != self.inode;
        let truncated = self.file.is_some() && meta.len() < self.pos;
        if self.file.is_some() && !rotated && !truncated {
            return;
        }
        if rotated {
            log::info!("{}: rotated (new inode), reopening", self.path.display());
        } else if truncated {
            log::info!("{}: truncated, restarting from 0", self.path.display());
        }
        let Ok(mut f) = File::open(&self.path) else {
            self.file = None;
            return;
        };
        // Only the very first attach honours `from_start = false`; after a
        // rotation we must read the new file from its beginning or we lose
        // whatever was written between the rename and this poll.
        let start_at_end = !self.from_start && !self.opened_once;
        let pos = if start_at_end {
            f.seek(SeekFrom::End(0)).unwrap_or(0)
        } else {
            f.seek(SeekFrom::Start(0)).unwrap_or(0)
        };
        self.inode = meta.ino();
        self.pos = pos;
        self.pending.clear();
        self.file = Some(f);
        self.opened_once = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append(p: &Path, s: &str) {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).unwrap();
        f.write_all(s.as_bytes()).unwrap();
    }

    #[test]
    fn reads_existing_then_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        append(&p, "a\nb\n");
        let mut t = Tailer::new(&p, true);
        assert_eq!(t.poll(), vec!["a", "b"]);
        assert!(t.poll().is_empty());
        append(&p, "c\n");
        assert_eq!(t.poll(), vec!["c"]);
    }

    #[test]
    fn partial_lines_wait_for_their_newline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        append(&p, "{\"a\":");
        let mut t = Tailer::new(&p, true);
        assert!(t.poll().is_empty());
        append(&p, "1}\n");
        assert_eq!(t.poll(), vec!["{\"a\":1}"]);
    }

    #[test]
    fn rename_rotation_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        append(&p, "one\n");
        let mut t = Tailer::new(&p, true);
        assert_eq!(t.poll(), vec!["one"]);

        std::fs::rename(&p, dir.path().join("t.log.1")).unwrap();
        append(&p, "two\n");
        assert_eq!(t.poll(), vec!["two"], "must follow the new inode");
    }

    #[test]
    fn truncation_restarts_from_zero() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        append(&p, "aaaa\nbbbb\n");
        let mut t = Tailer::new(&p, true);
        assert_eq!(t.poll().len(), 2);
        std::fs::write(&p, "c\n").unwrap();
        assert_eq!(t.poll(), vec!["c"]);
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("later.log");
        let mut t = Tailer::new(&p, true);
        assert!(t.poll().is_empty());
        assert!(!t.attached());
        append(&p, "x\n");
        assert_eq!(t.poll(), vec!["x"]);
        assert!(t.attached());
    }

    #[test]
    fn from_end_skips_history_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        append(&p, "old\n");
        let mut t = Tailer::new(&p, false);
        assert!(t.poll().is_empty());
        append(&p, "new\n");
        assert_eq!(t.poll(), vec!["new"]);
    }
}
