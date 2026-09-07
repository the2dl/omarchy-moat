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
    /// poll, so a burst is drained steadily instead of in one unbounded
    /// allocation. The run loop does not sleep while polls keep returning
    /// lines, so "the next poll" during a burst is immediate, not an interval
    /// later -- that was true before `LogWaker` and is why the daemon keeps
    /// pace with the sensor once it is awake.
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

// ------------------------------------------------------------------ the waker

/// Blocks until the log changes, instead of sleeping a fixed interval.
///
/// ## Why
///
/// The run loop only sleeps when a poll returned nothing, so it already keeps
/// pace with the sensor once events are flowing -- but it starts up to one
/// whole poll interval late. Measured end to end on this machine on
/// 2026-09-06: **221 ms** from the eighth read-then-destroy of a ransomware
/// sweep to the alert being recorded and SIGKILL sent, of which ~200 ms was
/// that one sleep and ~21 ms was everything else (export write, parse,
/// ancestry walk, rule evaluation, alert write, signal). A payload crosses the
/// threshold well inside the interval, so the full interval was paid nearly
/// every time -- roughly 70 more documents destroyed, at 300 files/s, than a
/// prompt wake-up would have cost.
///
/// Halving the interval would have bought half of that and four times the idle
/// wake-ups on a laptop. This buys all of it and *fewer* wake-ups than today,
/// because the kernel says when the file changed rather than being asked five
/// times a second.
///
/// ## What it watches, and why it is the directory
///
/// The parent directory, not the file. Tetragon rotates by rename, so a watch
/// on the file itself follows the old inode into `tetragon.log.1` and goes
/// quiet exactly when the log is busiest. A directory watch reports
/// modification of the entries inside it, so it covers the writes AND the
/// rotation that creates the next file, with no re-arming.
///
/// ## The wakeup that cannot be lost
///
/// inotify QUEUES. An event that lands between the tailer's empty poll and the
/// wait below is already in the queue when we get there, so `poll(2)` returns
/// immediately rather than sleeping through data that has already arrived.
/// That ordering is the whole reason this is safe to substitute for a sleep.
///
/// The timeout is kept at the old poll interval, so every periodic thing the
/// run loop does on the way round -- state writes, the feeds check, `tick` --
/// keeps exactly the cadence it had. This only ever shortens the wait.
pub struct LogWaker {
    fd: libc::c_int,
}

impl LogWaker {
    /// `None` when inotify is unavailable or the directory cannot be watched;
    /// the caller then sleeps as before. A missing waker is slower, never
    /// wrong.
    pub fn new(log: &Path) -> Option<LogWaker> {
        use std::os::unix::ffi::OsStrExt;
        let dir = log.parent()?;
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        let wd = unsafe {
            libc::inotify_add_watch(
                fd,
                c.as_ptr(),
                libc::IN_MODIFY | libc::IN_CREATE | libc::IN_MOVED_TO,
            )
        };
        if wd < 0 {
            unsafe { libc::close(fd) };
            return None;
        }
        Some(LogWaker { fd })
    }

    /// Wait for the log to change, or for `timeout`, whichever comes first.
    pub fn wait(&self, timeout: std::time::Duration) {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        // EINTR (SIGHUP for a reload, SIGTERM on the way out) just means go
        // round the loop, which is what the caller does next anyway.
        if unsafe { libc::poll(&mut pfd, 1, ms) } > 0 {
            self.drain();
        }
    }

    /// Empty the queue, or the fd stays readable and the loop spins. The
    /// CONTENT is irrelevant -- the tailer reads the file itself; this only
    /// answers "has anything happened".
    fn drain(&self) {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n <= 0 {
                break;
            }
        }
    }
}

impl Drop for LogWaker {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod waker_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn a_write_wakes_it_long_before_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("tetragon.log");
        std::fs::write(&log, "").unwrap();
        let w = LogWaker::new(&log).expect("inotify");

        let t = Instant::now();
        std::thread::spawn({
            let log = log.clone();
            move || {
                std::thread::sleep(Duration::from_millis(30));
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
                f.write_all(b"{}\n").unwrap();
            }
        });
        w.wait(Duration::from_millis(2000));
        let waited = t.elapsed();
        assert!(
            waited < Duration::from_millis(1000),
            "a write must wake it, not the timeout: waited {:?}",
            waited
        );
    }

    #[test]
    fn a_quiet_log_waits_the_whole_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("tetragon.log");
        std::fs::write(&log, "").unwrap();
        let w = LogWaker::new(&log).expect("inotify");

        let t = Instant::now();
        w.wait(Duration::from_millis(150));
        let waited = t.elapsed();
        assert!(
            waited >= Duration::from_millis(140),
            "nothing happened, so the cadence the run loop relies on must hold: {:?}",
            waited
        );
    }

    /// The queue is why this can replace a sleep without losing an event that
    /// arrived while we were not looking.
    #[test]
    fn an_event_that_arrived_before_the_wait_does_not_sleep() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("tetragon.log");
        std::fs::write(&log, "").unwrap();
        let w = LogWaker::new(&log).expect("inotify");

        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        f.write_all(b"{}\n").unwrap();
        drop(f);

        let t = Instant::now();
        w.wait(Duration::from_millis(2000));
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "inotify queues: a write before the wait must return at once"
        );
    }
}
