//! The process table.
//!
//! Tetragon gives every event a `process` and a `parent`, and (only with
//! `--enable-ancestors`) an `ancestors[]` list. We cannot rely on the latter, so
//! the daemon keeps its own table keyed by `exec_id` and walks
//! `parent_exec_id` upwards — capped at 8 hops (CONTRACT §6.2).
//!
//! Entries live 60 s past `process_exit`, because a kprobe event for a process
//! can be written after its exit line, and because a kill confirmation arrives
//! on the exit event itself.

use std::collections::HashMap;

use crate::event::{ExecEvent, ExitEvent, Process};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcInfo {
    pub exec_id: String,
    pub pid: u32,
    pub uid: u32,
    pub exe: String,
    pub args: String,
    pub cwd: String,
    pub start_time: String,
    pub parent_exec_id: Option<String>,
    /// unix seconds at which we saw the exit event.
    pub exited_at: Option<u64>,
    /// `process_exit.signal`, the only proof that a kill actually happened.
    pub exit_signal: Option<String>,
    /// Did this run in a container? Captured from the event's `process.ns` at
    /// the moment the sensor saw it, which is the only moment it can be
    /// captured: reading `/proc/<pid>/ns/mnt` later fails for exactly the
    /// processes this is about -- a `psql` or a `pg_isready` in a compose stack
    /// is gone microseconds after the open that raised the alert.
    ///
    /// `None` means the sensor did not say (`--enable-process-ns` off, or an
    /// older daemon). Never guessed.
    pub in_container: Option<bool>,
    /// Grave capabilities held at exec, from `process.cap` (docs/LPE.md item 6).
    /// Empty means "held none", not "unknown": Tetragon omits an empty set.
    pub caps: Vec<String>,
    /// `false` when the process was outside the host user namespace at exec.
    /// `None` when the sensor did not say.
    pub user_ns_host: Option<bool>,
    /// Set when `exe` is not what the kernel reported: a `/proc/self/fd/<n>`
    /// binary we resolved (or failed to). Shown as evidence on every alert.
    pub exe_note: Option<String>,
    /// POSIX session id, read from /proc at exec time. `None` when the process
    /// was already gone.
    ///
    /// Tetragon does not carry it: its `Process` message has `exec_id`, `pid`,
    /// `uid`, `auid`, `cwd`, `binary`, `arguments`, `flags`, `start_time` and
    /// `parent_exec_id`, and none of those separate two panes of one login.
    /// `auid` is the *login* uid and is identical across them; the systemd
    /// cgroup is identical too, because every pane of a terminal shares one
    /// `app-*.scope`. Measured on this machine on 2026-09-04.
    ///
    /// The session id is the thing that does separate them, and the kernel has
    /// had it all along: `herdr` was `sid == pid` (a session leader), and a
    /// Claude pane under it was session 11314. Reading it is what lets
    /// `chain.rs` ask what a process IS instead of what it is CALLED.
    pub sid: Option<u32>,
    /// The controlling terminal (`tty_nr`), read from the SAME /proc line as
    /// `sid` at exec time. `None` = /proc was unreadable (the process had
    /// already gone); `Some(0)` = there is no controlling terminal.
    ///
    /// This is the general answer to "is a person at the other end of this?",
    /// and `context.rs` asks it before it asks anything about names. On
    /// 2026-09-05 nine of the thirteen alerts on the badge were the user's own
    /// Claude sessions scored `service`, because they run as `systemd --user ->
    /// herdr -> bash -> claude` and `herdr` — a session host written recently
    /// enough that no list has heard of it — was in neither the interactive nor
    /// the service name list, so the walk fell through to `systemd`. Adding
    /// `herdr` to a list would have fixed that one host and nothing else; the
    /// kernel had already recorded the answer for every host there will ever
    /// be. Measured live that day: `claude` 11536 tty_nr 34821 (pts/5), `herdr`
    /// 0, `quickshell` 0.
    ///
    /// Tetragon's process record carries neither field, hence /proc.
    pub tty: Option<u32>,
}

/// Fields 6 and 7 of /proc/<pid>/stat — the session id and the controlling
/// terminal — in ONE read, because they are on the same line and the second
/// one was free.
///
/// The comm field can contain spaces and parentheses, so the fields after it
/// are found from the LAST ')' rather than by splitting the whole line.
pub fn read_session(pid: u32) -> (Option<u32>, Option<u32>) {
    if pid == 0 {
        return (None, None);
    }
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) else {
        return (None, None);
    };
    let Some(close) = stat.rfind(')') else {
        return (None, None);
    };
    // After ')': state, ppid, pgrp, session, tty_nr.
    let mut fields = stat[close + 1..].split_whitespace().skip(3);
    let sid = fields.next().and_then(|f| f.parse().ok());
    // tty_nr is printed signed; a negative value is not a device, it is "none".
    let tty = fields
        .next()
        .and_then(|f| f.parse::<i32>().ok())
        .map(|t| t.max(0) as u32);
    (sid, tty)
}

/// What `observe` uses. In a test build it reads nothing: the fixture pids
/// belong to whatever happens to be running on the machine under test, so a
/// real /proc read would make `context.rs` and `ai_cli.rs` pass or fail
/// depending on whether some unrelated process holds pid 41250 and a pty.
/// Tests state the kernel's answer with [`ProcTable::set_session`].
#[cfg(not(test))]
fn observed_session(pid: u32) -> (Option<u32>, Option<u32>) {
    read_session(pid)
}

#[cfg(test)]
fn observed_session(_pid: u32) -> (Option<u32>, Option<u32>) {
    (None, None)
}

impl ProcInfo {
    pub fn comm(&self) -> &str {
        crate::util::basename(&self.exe)
    }
}

pub struct ProcTable {
    map: HashMap<String, ProcInfo>,
    pub max_depth: usize,
    pub prune_secs: u64,
}

impl ProcTable {
    pub fn new(max_depth: usize, prune_secs: u64) -> ProcTable {
        ProcTable {
            map: HashMap::new(),
            max_depth,
            prune_secs,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Record whatever a `process` block told us. Every event carries one, so
    /// this is how the table stays populated even for processes that started
    /// before the daemon did (Tetragon backfills them from procfs).
    pub fn observe(&mut self, p: &Process) -> Option<String> {
        let exec_id = p.exec_id.clone()?;
        let (sid, tty) = observed_session(p.pid.unwrap_or(0));
        let info = ProcInfo {
            exec_id: exec_id.clone(),
            pid: p.pid.unwrap_or(0),
            uid: p.uid.unwrap_or(0),
            exe: p.exe().to_string(),
            args: p.args().to_string(),
            cwd: p.cwd.clone().unwrap_or_default(),
            start_time: p.start_time.clone().unwrap_or_default(),
            parent_exec_id: p.parent_exec_id.clone().filter(|s| !s.is_empty()),
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: p.in_container(),
            caps: p.dangerous_caps().iter().map(|c| c.to_string()).collect(),
            user_ns_host: p.user_ns_is_host(),
            sid,
            tty,
        };
        match self.map.get_mut(&exec_id) {
            Some(existing) => {
                // Never let a sparse `parent` block blank out a full record.
                if !info.exe.is_empty() {
                    // A re-reported binary invalidates any resolution note we
                    // had for the previous one.
                    if existing.exe != info.exe {
                        existing.exe_note = None;
                    }
                    existing.exe = info.exe;
                }
                if !info.args.is_empty() {
                    existing.args = info.args;
                }
                if !info.cwd.is_empty() {
                    existing.cwd = info.cwd;
                }
                if info.parent_exec_id.is_some() {
                    existing.parent_exec_id = info.parent_exec_id;
                }
                if existing.pid == 0 {
                    existing.pid = info.pid;
                }
                // A sparse `parent` block carries no `ns`; never let it blank
                // out an answer a full block already gave.
                if info.in_container.is_some() {
                    existing.in_container = info.in_container;
                }
            }
            None => {
                self.map.insert(exec_id.clone(), info);
            }
        }
        Some(exec_id)
    }

    pub fn on_exec(&mut self, ev: &ExecEvent) -> Option<String> {
        for a in &ev.ancestors {
            self.observe(a);
        }
        if let Some(p) = &ev.parent {
            self.observe(p);
        }
        let id = ev.process.as_ref().and_then(|p| self.observe(p))?;
        self.resolve_fd_binary(&id, None);
        Some(id)
    }

    /// Fix up a `/proc/self/fd/<n>` binary in place, from the hook's exec'd-file
    /// argument when there is one, otherwise the parent's argument 0. A no-op
    /// for every normal process.
    pub fn resolve_fd_binary(&mut self, exec_id: &str, binprm: Option<&str>) {
        let Some(me) = self.map.get(exec_id) else {
            return;
        };
        if !crate::util::is_proc_self_fd(&me.exe) {
            return;
        }
        let reported = me.exe.clone();
        let parent_args = me
            .parent_exec_id
            .clone()
            .and_then(|p| self.map.get(&p))
            .map(|p| p.args.clone());
        let (exe, note) =
            crate::util::resolve_exec_binary(&reported, binprm, parent_args.as_deref());
        if let Some(me) = self.map.get_mut(exec_id) {
            me.exe = exe;
            me.exe_note = note;
        }
    }

    /// Returns the exec_id that exited, if we could identify it.
    pub fn on_exit(&mut self, ev: &ExitEvent, now: u64) -> Option<String> {
        if let Some(p) = &ev.parent {
            self.observe(p);
        }
        let id = ev.process.as_ref().and_then(|p| self.observe(p))?;
        if let Some(e) = self.map.get_mut(&id) {
            e.exited_at = Some(now);
            e.exit_signal = ev.signal.clone();
        }
        Some(id)
    }

    pub fn get(&self, exec_id: &str) -> Option<&ProcInfo> {
        self.map.get(exec_id)
    }

    /// The most recently started process with this pid.
    ///
    /// Alerts on disk carry pids, not exec_ids (the exec_id is deliberately not
    /// serialised), so this is how `bundle.md` puts args and cwd back on an
    /// ancestry the alert recorded as pid + exe only. Pids are reused, hence
    /// "most recently started" rather than "the one".
    pub fn find_by_pid(&self, pid: u32) -> Option<&ProcInfo> {
        self.map
            .values()
            .filter(|p| p.pid == pid)
            .max_by(|a, b| a.start_time.cmp(&b.start_time))
    }

    /// Nearest ancestor first, self excluded, capped at `max_depth`. Cycles
    /// (which a reused exec_id could create) terminate on the visited set.
    pub fn ancestry(&self, exec_id: &str) -> Vec<&ProcInfo> {
        let mut out = Vec::new();
        let mut seen = vec![exec_id.to_string()];
        let mut cur = self.map.get(exec_id).and_then(|p| p.parent_exec_id.clone());
        while let Some(id) = cur {
            if out.len() >= self.max_depth || seen.contains(&id) {
                break;
            }
            seen.push(id.clone());
            match self.map.get(&id) {
                Some(info) => {
                    out.push(info);
                    cur = info.parent_exec_id.clone();
                }
                None => break,
            }
        }
        out
    }

    /// `npm -> sh -> node`, oldest first, self last. This is the line the alert
    /// summary and the evidence list both use.
    pub fn ancestry_line(&self, exec_id: &str) -> String {
        let mut parts: Vec<&str> = self
            .ancestry(exec_id)
            .into_iter()
            .map(|p| p.comm())
            .collect();
        parts.reverse();
        if let Some(me) = self.map.get(exec_id) {
            parts.push(me.comm());
        }
        parts.join(" -> ")
    }

    /// Does any ancestor (or the process itself) have a basename in `names`?
    pub fn chain_has(&self, exec_id: &str, names: &[&str]) -> Option<ProcInfo> {
        if let Some(me) = self.map.get(exec_id) {
            if names.contains(&me.comm()) {
                return Some(me.clone());
            }
        }
        self.ancestry(exec_id)
            .into_iter()
            .find(|p| names.contains(&p.comm()))
            .cloned()
    }

    /// Test-only: state what the kernel said about an already-observed process.
    ///
    /// In production `sid` and `tty` come from /proc at exec time. A test that
    /// wants a specific chain shape cannot get one that way — the pids in the
    /// fixtures either do not exist on the machine running the test or, worse,
    /// belong to some unrelated process that DOES have a pty, which would make
    /// every context test pass or fail depending on what else is running.
    #[cfg(test)]
    pub fn set_session(&mut self, exec_id: &str, sid: Option<u32>, tty: Option<u32>) {
        if let Some(p) = self.map.get_mut(exec_id) {
            p.sid = sid;
            p.tty = tty;
        }
    }

    /// State the sensor's namespace answer, for the same reason `set_session`
    /// exists: a fixture pid's real /proc entry belongs to whatever happens to
    /// be running on the machine under test, so the container tests have to
    /// state the kernel's answer rather than read one.
    #[cfg(test)]
    pub fn set_container(&mut self, exec_id: &str, in_container: Option<bool>) {
        if let Some(p) = self.map.get_mut(exec_id) {
            p.in_container = in_container;
        }
    }

    pub fn prune(&mut self, now: u64) {
        let cutoff = self.prune_secs;
        self.map
            .retain(|_, v| v.exited_at.map(|t| now.saturating_sub(t) < cutoff).unwrap_or(true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::RawEvent;

    fn feed() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        let text =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sample.log"))
                .unwrap();
        for line in text.lines() {
            let Some(ev) = RawEvent::parse(line) else { continue };
            if let Some(e) = &ev.process_exec {
                t.on_exec(e);
            } else if let Some(e) = &ev.process_exit {
                t.on_exit(e, 1_000);
            } else if let Some(h) = ev.hook() {
                if let Some(p) = &h.ev.process {
                    t.observe(p);
                }
                if let Some(p) = &h.ev.parent {
                    t.observe(p);
                }
            }
        }
        t
    }

    const NODE: &str = "bWFyczoxMjM0NTY3ODkwMTIzOjQxMjMz";
    /// The `sh` the postinstall script runs in, and the process the sample
    /// log's reverse-shell policy kills — the connect is made by the shell,
    /// because that is what `moat-shell-reverse-shell-connect` matches on.
    const SH: &str = "bWFyczoxMjM0NTY3MDAwMDAwOjQxMjMw";

    #[test]
    fn chain_is_built_from_parent_exec_ids() {
        let t = feed();
        let chain: Vec<String> = t.ancestry(NODE).iter().map(|p| p.comm().to_string()).collect();
        assert_eq!(chain, vec!["sh", "npm", "fish"]);
        assert_eq!(t.ancestry_line(NODE), "fish -> npm -> sh -> node");
    }

    #[test]
    fn chain_has_finds_a_package_manager() {
        let t = feed();
        let hit = t.chain_has(NODE, &["npm", "pnpm", "yarn"]).unwrap();
        assert_eq!(hit.pid, 41201);
        assert!(t.chain_has(NODE, &["cargo"]).is_none());
    }

    #[test]
    fn a_pid_lookup_finds_the_newest_process_with_that_pid() {
        let t = feed();
        assert_eq!(t.find_by_pid(41233).unwrap().exec_id, NODE);
        assert!(t.find_by_pid(999_999).is_none());

        // A recycled pid resolves to the later start time.
        let mut t2 = ProcTable::new(8, 60);
        for (id, start) in [("old", "2026-09-03T10:00:00.000000000Z"), ("new", "2026-09-03T18:00:00.000000000Z")] {
            t2.observe(&Process {
                exec_id: Some(id.into()),
                pid: Some(42),
                binary: Some(format!("/bin/{}", id)),
                start_time: Some(start.into()),
                ..Default::default()
            });
        }
        assert_eq!(t2.find_by_pid(42).unwrap().exec_id, "new");
    }

    #[test]
    fn depth_is_capped() {
        let mut t = ProcTable::new(3, 60);
        for i in 0..10u32 {
            let p = Process {
                exec_id: Some(format!("e{}", i)),
                pid: Some(i),
                binary: Some(format!("/bin/p{}", i)),
                parent_exec_id: if i == 0 { None } else { Some(format!("e{}", i - 1)) },
                ..Default::default()
            };
            t.observe(&p);
        }
        assert_eq!(t.ancestry("e9").len(), 3);
    }

    #[test]
    fn a_cycle_terminates() {
        let mut t = ProcTable::new(8, 60);
        for (id, parent) in [("a", "b"), ("b", "a")] {
            t.observe(&Process {
                exec_id: Some(id.into()),
                binary: Some(format!("/bin/{}", id)),
                parent_exec_id: Some(parent.into()),
                ..Default::default()
            });
        }
        assert!(t.ancestry("a").len() <= 2);
    }

    #[test]
    fn exit_signal_is_kept_then_pruned() {
        let mut t = feed();
        assert_eq!(t.get(SH).unwrap().exit_signal.as_deref(), Some("SIGKILL"));
        t.prune(1_030);
        assert!(t.get(SH).is_some(), "still inside the 60 s window");
        t.prune(1_100);
        assert!(t.get(SH).is_none(), "pruned after the window");
    }

    #[test]
    fn a_proc_self_fd_binary_is_resolved_from_the_parent_arguments() {
        let mut t = ProcTable::new(8, 60);
        t.observe(&Process {
            exec_id: Some("e-sh".into()),
            pid: Some(100),
            binary: Some("/usr/bin/sh".into()),
            arguments: Some("/tmp/.x9k --quiet".into()),
            ..Default::default()
        });
        let ev = ExecEvent {
            process: Some(Process {
                exec_id: Some("e-fd".into()),
                pid: Some(101),
                binary: Some("/proc/self/fd/9".into()),
                parent_exec_id: Some("e-sh".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        t.on_exec(&ev);
        let p = t.get("e-fd").unwrap();
        assert_eq!(p.exe, "/tmp/.x9k");
        assert!(p.exe_note.as_ref().unwrap().contains("/proc/self/fd/9"));

        // A hook that carries the exec'd file wins over the parent guess.
        t.observe(&Process {
            exec_id: Some("e-fd".into()),
            binary: Some("/proc/self/fd/9".into()),
            parent_exec_id: Some("e-sh".into()),
            ..Default::default()
        });
        t.resolve_fd_binary("e-fd", Some("/home/dan/proj/payload"));
        assert_eq!(t.get("e-fd").unwrap().exe, "/home/dan/proj/payload");
    }

    /// One read of /proc/<pid>/stat yields both fields. Asked of our own
    /// process, because that is the only pid a test can be sure about.
    #[test]
    fn the_session_id_and_the_controlling_terminal_come_from_one_read() {
        let me = std::process::id();
        let (sid, tty) = read_session(me);
        assert!(sid.is_some(), "our own /proc/<pid>/stat must be readable");
        assert!(tty.is_some(), "and it carries tty_nr on the same line");
        // pid 0 is not a process, and a pid nothing owns reads as "unknown"
        // rather than as "no terminal" -- the distinction context.rs relies on.
        assert_eq!(read_session(0), (None, None));
        assert_eq!(read_session(4_294_967_295), (None, None));
    }

    #[test]
    fn a_sparse_parent_block_does_not_blank_a_full_record() {
        let mut t = feed();
        let before = t.get(NODE).unwrap().clone();
        t.observe(&Process {
            exec_id: Some(NODE.into()),
            pid: Some(41233),
            ..Default::default()
        });
        assert_eq!(t.get(NODE).unwrap().exe, before.exe);
        assert_eq!(t.get(NODE).unwrap().cwd, before.cwd);
    }
}
