//! Telling "read my own /proc entry" apart from "read someone else's".
//!
//! `/proc/<pid>/environ` is a credential store: it holds whatever the process
//! was launched with, which on a developer box means `GITHUB_TOKEN`,
//! `AWS_SECRET_ACCESS_KEY`, `ANTHROPIC_API_KEY` and database URLs with the
//! password inline. Reading another process's copy is theft.
//!
//! Reading your *own* is unremarkable and extremely common — starship, zoxide,
//! mise, pgrep and every systemd generator do it at startup. The kernel cannot
//! make this distinction for us in a selector, because the only handle a
//! selector has on the target is the path, and comparing the path's pid against
//! the opener's pid is not something Tetragon's matchArgs can express. So the
//! kernel does the cheap cut (`Postfix /environ`) and this does the exact one.

/// The pid a `/proc/<pid>/…` path refers to, if the path has that shape.
///
/// `/proc/self/…` and `/proc/thread-self/…` never reach here: Tetragon reports
/// the resolved `d_path`, which has already become the numeric pid.
pub fn proc_target_pid(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("/proc/")?;
    let (first, _) = rest.split_once('/')?;
    first.parse().ok()
}

/// The thread-group leader of `pid`, read from procfs. A thread reading its own
/// process's environment is still a self-read, and threaded runtimes (the JVM,
/// Node's libuv pool, Chrome) do it under a tid that is not the tgid.
///
/// Best effort by design: the target may already be gone, in which case the
/// caller falls back to a plain pid comparison rather than inventing an answer.
fn thread_group_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Tgid:") {
            return v.trim().parse().ok();
        }
    }
    None
}

/// Is this event a process reading its own `/proc` entry?
///
/// `false` for a path that is not `/proc/<pid>/…` at all: that is not a
/// self-read, it is something this rule should not have matched, and the caller
/// decides what to do about it.
pub fn is_self_read(path: &str, actor_pid: u32) -> bool {
    let Some(target) = proc_target_pid(path) else {
        return false;
    };
    if target == actor_pid {
        return true;
    }
    // Same process, different thread.
    thread_group_of(target) == Some(actor_pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pid_is_read_out_of_a_proc_path() {
        assert_eq!(proc_target_pid("/proc/1234/environ"), Some(1234));
        assert_eq!(proc_target_pid("/proc/1/environ"), Some(1));
        // Not /proc, or not the /proc/<pid>/ shape.
        assert_eq!(proc_target_pid("/home/dan/environ"), None);
        assert_eq!(proc_target_pid("/proc/environ"), None);
        assert_eq!(proc_target_pid("/proc/sys/kernel/environ"), None);
        // d_path has already resolved these, but be explicit about it.
        assert_eq!(proc_target_pid("/proc/self/environ"), None);
    }

    #[test]
    fn own_environ_is_a_self_read_and_anothers_is_not() {
        assert!(is_self_read("/proc/4242/environ", 4242));
        assert!(!is_self_read("/proc/4242/environ", 99));
        // A path this rule should never have matched is not a "self read".
        assert!(!is_self_read("/home/dan/environ", 4242));
    }

    #[test]
    fn a_thread_reading_its_own_processs_environ_is_a_self_read() {
        // A thread we own and hold alive for the duration, rather than whatever
        // threads the test harness happens to be running: those come and go, and
        // a tid that exits between reading /proc/<pid>/task and checking it
        // makes the assertion race.
        let me = std::process::id();
        let (tx, rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            tx.send(unsafe { libc::gettid() } as u32).unwrap();
            // Stay alive until the assertions are done.
            let _ = done_rx.recv();
        });
        let tid = rx.recv().unwrap();
        assert_ne!(tid, me, "a spawned thread has its own tid");
        assert!(
            is_self_read(&format!("/proc/{}/environ", tid), me),
            "tid {} belongs to pid {}, so reading its environ is a self-read",
            tid,
            me
        );
        let _ = done_tx.send(());
        t.join().unwrap();

        // The main thread's tid is the pid itself.
        assert!(is_self_read(&format!("/proc/{}/environ", me), me));
        // pid 1 is in nobody else's thread group.
        assert_ne!(me, 1);
        assert!(!is_self_read("/proc/1/environ", me));
    }
}
