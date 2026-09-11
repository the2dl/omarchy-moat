//! Small helpers: atomic writes, ownership/mode fixing, time formatting,
//! /proc lookups and hashing. Nothing here needs root; every privileged step is
//! best-effort and silently skipped when we are not root (dev mode).

use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// RFC3339 with milliseconds and a `Z` suffix, as the contract's `ts` field.
/// Seconds between two RFC3339 stamps, 0 if either is unparseable.
///
/// Used for the triage settle window, where "unparseable means zero" is the
/// cautious answer: an alert whose timestamp cannot be read is treated as old
/// enough to look at rather than being deferred forever.
pub fn secs_between(then: &str, now: &str) -> u64 {
    let (Ok(a), Ok(b)) = (
        chrono::DateTime::parse_from_rfc3339(then),
        chrono::DateTime::parse_from_rfc3339(now),
    ) else {
        return u64::MAX;
    };
    (b - a).num_seconds().max(0) as u64
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Parse a Tetragon RFC3339 nanosecond timestamp into unix nanoseconds.
pub fn rfc3339_to_nanos(s: &str) -> Option<i128> {
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    Some(dt.timestamp() as i128 * 1_000_000_000 + dt.timestamp_subsec_nanos() as i128)
}

/// Re-render a Tetragon nanosecond timestamp as the contract's millisecond form.
pub fn normalize_ts(s: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(s) {
        Ok(dt) => dt
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string(),
        Err(_) => s.to_string(),
    }
}

/// Unix seconds as the contract's millisecond RFC3339 form. The inverse of
/// reading a `ts` back out of an alert.
pub fn rfc3339_of(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(now_rfc3339)
}

pub fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// When this boot started, in epoch seconds, from `/proc/stat`'s `btime`.
/// 0 when it cannot be read.
///
/// The point of comparison for a gap in the record: a heartbeat written BEFORE
/// this value belongs to a previous boot, so the wall-clock distance between
/// the two spans a shutdown and is not time anything went unobserved.
pub fn boot_time() -> u64 {
    let Ok(stat) = std::fs::read_to_string("/proc/stat") else {
        return 0;
    };
    stat.lines()
        .find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())
        .unwrap_or(0)
}

/// Seconds this machine has been AWAKE since boot -- `CLOCK_MONOTONIC`, which
/// does not advance across a suspend. 0 when the clock cannot be read.
///
/// `CLOCK_BOOTTIME` would include suspended time and `SystemTime` includes
/// both suspend and shutdown; this is the only one of the three that measures
/// "time during which code could have run". That is the quantity a gap in
/// moat's record is actually about. It is system-wide and survives a process
/// restart, resetting only on boot, which is what makes it comparable across
/// the very restart being explained.
pub fn awake_secs() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, fully initialised timespec we own.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    ts.tv_sec.max(0) as u64
}

/// A handle to a PROCESS, not to a number.
///
/// A pid is a name the kernel reuses. Between deciding to kill one and sending
/// the signal, moat reads `/proc`, walks a descendant tree and loops over up to
/// eight targets -- and every one of those steps is a moment in which a pid can
/// be freed and handed to something else. `verify_pid` closes the window it can
/// see (the alert's process, checked once) and cannot close the rest: the
/// descendants are never verified at all, and the target it did verify is
/// signalled later, by number.
///
/// `pidfd_open` resolves the number ONCE and pins what it found. Afterwards the
/// fd refers to that process even if the pid is recycled, and
/// `pidfd_send_signal` on a dead one fails with ESRCH instead of landing on a
/// stranger. So the order that matters is: open the fd, THEN verify, THEN
/// signal through the fd -- opening first is what makes the verification mean
/// anything at the moment the signal is sent, rather than only when it was run.
pub struct PidFd {
    fd: libc::c_int,
    pub pid: u32,
}

/// Why a pid could not be pinned. The distinction is not academic: `Gone` means
/// there is nothing to kill and sparing it is correct, while `Unsupported` and
/// `Exhausted` mean a live process was NOT signalled. Collapsing all three into
/// `None` is how "enforce mode killed nothing" came to be logged as "it exited
/// before it could be pinned" -- a sentence that is false in exactly the cases
/// where something went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinFailure {
    /// ESRCH: the process is already gone.
    Gone,
    /// ENOSYS: kernel older than 5.3. No pidfd at all, for any process.
    Unsupported,
    /// EMFILE/ENFILE: out of descriptors. Transient, and likeliest on exactly
    /// the wide process tree that a kill most needs to cover.
    Exhausted,
    Other(i32),
}

impl std::fmt::Display for PinFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinFailure::Gone => write!(f, "it exited before it could be pinned"),
            PinFailure::Unsupported => write!(
                f,
                "this kernel has no pidfd_open (pre-5.3), so no process can be pinned"
            ),
            PinFailure::Exhausted => write!(
                f,
                "out of file descriptors, so it could not be pinned (raise LimitNOFILE)"
            ),
            PinFailure::Other(e) => write!(
                f,
                "pidfd_open failed: {}",
                std::io::Error::from_raw_os_error(*e)
            ),
        }
    }
}

impl PidFd {
    /// `Err` carries *why*, because the caller's correct response differs:
    /// a process that is `Gone` needs nothing, and one that could not be pinned
    /// for any other reason is still running and still unsignalled.
    pub fn try_open(pid: u32) -> Result<PidFd, PinFailure> {
        // SAFETY: a syscall with scalar arguments; no pointers are passed.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(match e {
                libc::ESRCH => PinFailure::Gone,
                libc::ENOSYS => PinFailure::Unsupported,
                libc::EMFILE | libc::ENFILE => PinFailure::Exhausted,
                other => PinFailure::Other(other),
            });
        }
        Ok(PidFd {
            fd: fd as libc::c_int,
            pid,
        })
    }

    /// `None` when the pid could not be pinned, for any reason. Prefer
    /// [`PidFd::try_open`] anywhere the reason changes what should happen --
    /// which is everywhere that goes on to kill something.
    pub fn open(pid: u32) -> Option<PidFd> {
        PidFd::try_open(pid).ok()
    }

    /// SIGKILL the pinned process. `Err` carries the errno text; ESRCH here
    /// means the process died between opening and signalling, which is the
    /// case that used to be a stranger's pid.
    pub fn kill(&self) -> Result<(), String> {
        self.signal(libc::SIGKILL)
    }

    /// Any signal, to the pinned process. The tree kill sends SIGSTOP to the
    /// whole set before killing any of it, and that stop must land on the same
    /// processes the kill will -- two passes by pid number are two chances to
    /// stop a stranger and kill another.
    pub fn signal(&self, sig: libc::c_int) -> Result<(), String> {
        // SAFETY: `self.fd` is a live pidfd we own; the siginfo pointer is
        // NULL, which the kernel documents as "as if from kill(2)".
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().to_string())
        }
    }
}

impl Drop for PidFd {
    fn drop(&mut self) {
        // SAFETY: we own this descriptor and it is dropped exactly once.
        unsafe { libc::close(self.fd) };
    }
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Look a group up by name. Returns `None` when the group does not exist.
pub fn gid_of_group(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // getgrnam is not thread safe in theory; we only call it from setup paths.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    if gr.is_null() {
        None
    } else {
        Some(unsafe { (*gr).gr_gid })
    }
}

/// chown to root:<group> and chmod. Best effort: skipped entirely when not root
/// or when the group does not exist, so dev mode never fails on it.
pub fn secure_path(path: &Path, group: &str, mode: u32) -> std::io::Result<()> {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    if !is_root() {
        return Ok(());
    }
    if let Some(gid) = gid_of_group(group) {
        let c = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        unsafe {
            libc::chown(c.as_ptr(), 0, gid);
        }
    }
    Ok(())
}

/// Write `content` to `path` via a sibling temp file + rename, so a reader never
/// sees a half-written file. Returns `Ok(false)` when the content was already
/// byte-identical (which keeps `render-policies` idempotent, mtime included).
pub fn atomic_write(path: &Path, content: &[u8], mode: u32) -> std::io::Result<bool> {
    if let Ok(existing) = fs::read(path) {
        if existing == content {
            return Ok(false);
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = tmp_sibling(path);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)?;
    Ok(true)
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "out".into());
    let dir = path.parent().unwrap_or(Path::new("."));
    dir.join(format!(".{}.{}.tmp", name, std::process::id()))
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

/// Strict hex decode: even length, hex digits only. `None` rather than a
/// partial result, because every caller is checking a key or a signature.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn to_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Accepts the standard and URL-safe alphabets, with or without padding.
pub fn from_base64(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for ch in s.trim().bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => continue,
            b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A binary executed with `fexecve` (or from a memfd / an already-open fd) is
/// reported by Tetragon as `/proc/self/fd/<n>`: the kernel has no name for it
/// beyond the descriptor. Seen in the wild on the first live run.
pub const PROC_SELF_FD: &str = "/proc/self/fd/";

pub fn is_proc_self_fd(exe: &str) -> bool {
    exe.starts_with(PROC_SELF_FD)
}

/// Recover the real path of a `/proc/self/fd/<n>` binary.
///
/// Order of preference:
///
/// 1. the path the hook itself carried (the `linux_binprm` argument of
///    `bprm_check_security` is the file being executed, and it is resolved);
/// 2. the parent's argument 0, when it is an absolute path — the usual shape is
///    a launcher that was handed the program it then `fexecve`s.
///
/// Returns `(exe, note)`. When nothing can be recovered the reported path is
/// kept and the note says so, because an alert naming `/proc/self/fd/9` with no
/// explanation is worse than useless.
pub fn resolve_exec_binary(
    reported: &str,
    binprm: Option<&str>,
    parent_args: Option<&str>,
) -> (String, Option<String>) {
    if !is_proc_self_fd(reported) {
        return (reported.to_string(), None);
    }
    if let Some(p) = binprm.filter(|p| p.starts_with('/') && !is_proc_self_fd(p)) {
        return (
            p.to_string(),
            Some(format!(
                "binary reported as {} (executed from a file descriptor); resolved to {} from the \
                 hook's exec'd-file argument",
                reported, p
            )),
        );
    }
    if let Some(a0) = parent_args
        .and_then(|a| a.split_whitespace().next())
        .filter(|a| a.starts_with('/') && !is_proc_self_fd(a))
    {
        return (
            a0.to_string(),
            Some(format!(
                "binary reported as {} (executed from a file descriptor); resolved to {} from the \
                 parent's argument 0",
                reported, a0
            )),
        );
    }
    (
        reported.to_string(),
        Some(format!(
            "binary reported as {} (executed from a file descriptor): the kernel had no path for \
             it and neither the hook nor the parent's arguments named one, so the exe below is \
             the descriptor, not a file you can inspect",
            reported
        )),
    )
}

/// True when `path` sits under one of the directories a quarantine or a
/// "new executable" rule is allowed to touch.
pub fn under_any(path: &str, roots: &[String]) -> bool {
    let p = Path::new(path);
    roots.iter().any(|r| {
        let r = r.trim_end_matches('/');
        p.starts_with(r) && path.len() > r.len()
    })
}

/// Human users, per CONTRACT §2: uid >= 1000, home under /home or /var/home,
/// login shell not a nologin/false stub. Returned sorted and de-duplicated.
pub fn human_homes(passwd_path: &Path) -> Vec<String> {
    let mut homes: Vec<String> = Vec::new();
    let Ok(text) = fs::read_to_string(passwd_path) else {
        return homes;
    };
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        // 65534 is `nobody` on Arch; it satisfies uid >= 1000 but is not human.
        if !(1000..65534).contains(&uid) {
            continue;
        }
        let home = f[5].trim_end_matches('/').to_string();
        if !(home.starts_with("/home/") || home.starts_with("/var/home/")) {
            continue;
        }
        let shell = basename(f[6]);
        if shell.is_empty() || shell == "nologin" || shell == "false" || shell == "sync" {
            continue;
        }
        if !homes.contains(&home) {
            homes.push(home);
        }
    }
    homes.sort();
    homes
}

/// `/proc/<pid>` start time as unix nanoseconds, used to prove that the pid an
/// alert names is still the same process before we signal it.
pub fn proc_start_nanos(pid: u32) -> Option<i128> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // field 22 (1-based) is starttime in clock ticks since boot; comm may
    // contain spaces and parens, so split after the final ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ticks: u64 = fields.get(19)?.parse().ok()?;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    if hz == 0 {
        return None;
    }
    let btime = boot_time_secs()?;
    Some((btime as i128) * 1_000_000_000 + (ticks as i128 * 1_000_000_000) / hz as i128)
}

fn boot_time_secs() -> Option<u64> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    for line in stat.lines() {
        if let Some(v) = line.strip_prefix("btime ") {
            return v.trim().parse().ok();
        }
    }
    None
}

pub fn proc_exe(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

/// All descendants of `pid` (excluding `pid`), from `/proc/*/stat` ppids.
pub fn proc_descendants(pid: u32) -> Vec<u32> {
    let mut children: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(p) = name.parse::<u32>() else { continue };
        let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", p)) else {
            continue;
        };
        let Some(idx) = stat.rfind(')') else { continue };
        let fields: Vec<&str> = stat[idx + 1..].split_whitespace().collect();
        let Some(ppid) = fields.get(1).and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        children.entry(ppid).or_default().push(p);
    }
    let mut out = Vec::new();
    let mut queue = vec![pid];
    while let Some(p) = queue.pop() {
        if let Some(kids) = children.get(&p) {
            for k in kids {
                if !out.contains(k) && *k != pid {
                    out.push(*k);
                    queue.push(*k);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_homes_filters_system_users() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("passwd");
        fs::write(
            &p,
            "root:x:0:0::/root:/usr/bin/bash\n\
             bin:x:1:1::/:/usr/bin/nologin\n\
             dan:x:1000:1000::/home/dan:/usr/bin/fish\n\
             build:x:1001:1001::/var/lib/build:/usr/bin/bash\n\
             kiosk:x:1002:1002::/home/kiosk:/usr/bin/nologin\n\
             ada:x:1003:1003::/var/home/ada:/bin/zsh\n\
             nobody:x:65534:65534::/:/usr/bin/nologin\n",
        )
        .unwrap();
        assert_eq!(human_homes(&p), vec!["/home/dan", "/var/home/ada"]);
    }

    #[test]
    fn atomic_write_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a/b/c.txt");
        assert!(atomic_write(&p, b"hello", 0o644).unwrap());
        assert!(!atomic_write(&p, b"hello", 0o644).unwrap());
        assert!(atomic_write(&p, b"world", 0o644).unwrap());
        assert_eq!(fs::read_to_string(&p).unwrap(), "world");
    }

    #[test]
    fn under_any_needs_a_real_child() {
        let roots = vec!["/home/dan".to_string(), "/tmp".to_string()];
        assert!(under_any("/home/dan/x", &roots));
        assert!(under_any("/tmp/y", &roots));
        assert!(!under_any("/home/dan", &roots));
        assert!(!under_any("/etc/passwd", &roots));
    }

    #[test]
    fn proc_self_fd_binaries_are_resolved_and_noted() {
        // Nothing to do for a normal path.
        let (exe, note) = resolve_exec_binary("/usr/bin/node", None, None);
        assert_eq!(exe, "/usr/bin/node");
        assert!(note.is_none());

        // The hook's own exec'd-file argument wins.
        let (exe, note) = resolve_exec_binary(
            "/proc/self/fd/9",
            Some("/home/dan/proj/node_modules/.bin/evil"),
            Some("/usr/bin/other"),
        );
        assert_eq!(exe, "/home/dan/proj/node_modules/.bin/evil");
        assert!(note.unwrap().contains("/proc/self/fd/9"));

        // Otherwise the parent's argument 0.
        let (exe, note) = resolve_exec_binary("/proc/self/fd/9", None, Some("/tmp/.x9k --quiet"));
        assert_eq!(exe, "/tmp/.x9k");
        assert!(note.unwrap().contains("parent's argument 0"));

        // Nothing usable: keep the descriptor, say so.
        let (exe, note) = resolve_exec_binary("/proc/self/fd/9", None, Some("-c ls"));
        assert_eq!(exe, "/proc/self/fd/9");
        assert!(note.unwrap().contains("no path for it"));
    }

    #[test]
    fn timestamps_normalize_to_millis() {
        assert_eq!(
            normalize_ts("2026-09-03T16:21:07.123456789Z"),
            "2026-09-03T16:21:07.123Z"
        );
    }

    #[test]
    fn unix_seconds_render_as_the_contracts_timestamp() {
        assert_eq!(rfc3339_of(1_800_000_000), "2027-01-15T08:00:00.000Z");
        assert_eq!(rfc3339_to_nanos(&rfc3339_of(1_700_000_000)).unwrap(), 1_700_000_000i128 * 1_000_000_000);
    }
}

/// Btrfs subvolume roots, as `(exported prefix, real mountpoint)` pairs.
///
/// A Tetragon `dentry` argument has no `vfsmount` attached, so the kernel can
/// only resolve it as far as its *filesystem* root -- not the mount namespace
/// root. On the default Omarchy layout (`/` on subvol `@`, `/home` on `@home`,
/// `/var/log` on `@log`) that means the exported path carries the subvolume
/// name as its first component:
///
/// ```text
///   /home/dan/.bash_history      is exported as  /@home/dan/.bash_history
///   /var/tmp/x/.bash_history     is exported as  /@/var/tmp/x/.bash_history
/// ```
///
/// Both were measured on this machine on 2026-09-04. A `path` argument carries
/// the mount and needs none of this, which is why every other rule sees clean
/// paths -- only rules matching a bare dentry are affected.
///
/// Pairs are returned longest-prefix-first so `/@home` is tried before `/@`.
pub fn subvol_roots(mounts_path: &Path) -> Vec<(String, String)> {
    match fs::read_to_string(mounts_path) {
        Ok(text) => parse_subvol_roots(&text),
        Err(_) => Vec::new(),
    }
}

/// The parse, split out from the read so it can be tested without a file.
///
/// The tests used to write a fixture named after the process id and delete it
/// again -- which meant the three of them shared one path and raced, because
/// cargo runs them in parallel threads of the SAME process. That made the
/// package's `check()` fail about one run in three: a build gate that fails at
/// random is worse than no gate, because the first thing anyone learns is to
/// run it again.
pub fn parse_subvol_roots(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[2] != "btrfs" {
            continue;
        }
        let Some(sub) = f[3].split(',').find_map(|o| o.strip_prefix("subvol=")) else {
            continue;
        };
        // `subvol=/@home` -> exported prefix `/@home`. A nested subvolume
        // (`subvol=/@/var/lib/x`) exports under its own name the same way.
        let sub = sub.trim_end_matches('/');
        if sub.is_empty() || sub == "/" {
            continue;
        }
        let mount = f[1].trim_end_matches('/');
        let mount = if mount.is_empty() { "/" } else { mount };
        let pair = (sub.to_string(), mount.to_string());
        if !out.contains(&pair) {
            out.push(pair);
        }
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.0.len()));
    out
}

/// Rewrite a dentry-derived path into a real absolute path.
///
/// A no-op for anything that does not begin with a known subvolume prefix, so
/// it is safe to apply to every path: on ext4, and on every `path`-typed
/// argument, the input is already absolute and comes back unchanged.
///
/// Paths on a filesystem with no subvolume at all (a tmpfs such as `/tmp`)
/// cannot be recovered -- the export says `/x/.bash_history` for
/// `/tmp/x/.bash_history` and nothing in the event names the mount. Those are
/// returned as-is, which leaves them looking like paths at the root that do not
/// exist. That is the honest answer, and a caller asking "is this under a real
/// home" correctly gets `false`.
pub fn dentry_abs(path: &str, subvols: &[(String, String)]) -> String {
    if !path.starts_with("/@") {
        return path.to_string();
    }
    for (prefix, mount) in subvols {
        let rest = match path.strip_prefix(prefix.as_str()) {
            // Match whole components only: `/@home` must not match `/@homely`.
            Some(r) if r.is_empty() || r.starts_with('/') => r,
            _ => continue,
        };
        let joined = format!("{}/{}", mount.trim_end_matches('/'), rest.trim_start_matches('/'));
        let joined = joined.trim_end_matches('/').to_string();
        return if joined.is_empty() { "/".into() } else { joined };
    }
    path.to_string()
}

#[cfg(test)]
mod subvol_tests {
    use super::*;

    /// The real /proc/self/mounts from this machine, trimmed. Parsed from a
    /// string: no shared temp file, so the tests cannot race each other.
    fn mounts() -> Vec<(String, String)> {
        parse_subvol_roots(
            "/dev/nvme0n1p2 / btrfs rw,relatime,ssd,subvol=/@ 0 0\n\
             /dev/nvme0n1p2 /home btrfs rw,relatime,ssd,subvol=/@home 0 0\n\
             /dev/nvme0n1p2 /var/log btrfs rw,relatime,ssd,subvol=/@log 0 0\n\
             tmpfs /tmp tmpfs rw,nosuid,nodev,usrquota 0 0\n",
        )
    }

    #[test]
    fn a_dentry_path_becomes_the_path_the_user_would_recognise() {
        let s = mounts();
        // Both measured from live events on 2026-09-04.
        assert_eq!(
            dentry_abs("/@home/dan/.bash_history", &s),
            "/home/dan/.bash_history"
        );
        assert_eq!(
            dentry_abs("/@/var/tmp/probe/.bash_history", &s),
            "/var/tmp/probe/.bash_history"
        );
        assert_eq!(dentry_abs("/@log/journal/x", &s), "/var/log/journal/x");
    }

    #[test]
    fn longest_prefix_wins_and_only_whole_components_match() {
        let s = mounts();
        // `/@` is also a prefix of `/@home/...`; taking it would give
        // `/home/...` -> `//home/dan` and a home test that never matches.
        assert_eq!(dentry_abs("/@home/dan/x", &s), "/home/dan/x");
        // Not a subvolume, just a directory whose name starts the same way.
        assert_eq!(dentry_abs("/@homely/x", &s), "/@homely/x");
    }

    #[test]
    fn anything_already_absolute_is_returned_untouched() {
        let s = mounts();
        // Every `path`-typed argument, and every path on ext4. This is what
        // makes it safe to run over all of them.
        assert_eq!(dentry_abs("/home/dan/.bash_history", &s), "/home/dan/.bash_history");
        assert_eq!(dentry_abs("/var/lib/moat/alerts.jsonl", &s), "/var/lib/moat/alerts.jsonl");
        // A tmpfs dentry cannot be recovered and must not be invented.
        assert_eq!(dentry_abs("/scratch/home/.bash_history", &s), "/scratch/home/.bash_history");
        // No btrfs at all: the map is empty and nothing is rewritten.
        assert_eq!(dentry_abs("/@home/dan/x", &[]), "/@home/dan/x");
    }
}

/// Open a file that is under suspicion, for staging as evidence.
///
/// Returns the open descriptor **and the path the kernel says it really refers
/// to**, so a caller can re-run its own rules against what it is actually
/// holding rather than against the string it was given.
///
/// Both matter, and neither is paranoia:
///
/// * `O_NOFOLLOW` refuses a symlink at the final component. Without it,
///   `std::fs::copy` follows the link, and every staging path in this daemon
///   validated the *string* first and then followed it -- so a file the
///   attacker named `/tmp/bait`, pointing at `/etc/shadow`, passed the
///   credential check as `/tmp/bait` and was then read by root and written into
///   an incident directory the `moat` group can read. That is a root file-read
///   primitive handed to any group member, which on this threat model is the
///   attacker.
/// * `/proc/self/fd/<n>` closes the other half. `O_NOFOLLOW` only guards the
///   LAST component, so a symlinked parent directory (`~/.aws` -> `/etc`) walks
///   past it. Reading the descriptor's own path asks the kernel where it ended
///   up, after the fact and with the file already held open -- so there is no
///   window in which the answer can change between the check and the read.
/// * `O_NONBLOCK` so a FIFO cannot hang the daemon at `open`; the regular-file
///   test then rejects it, along with devices and directories.
pub fn open_suspect(path: &Path) -> Result<(fs::File, String), String> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            // ELOOP is the interesting one: it means the thing we were asked to
            // stage was a symlink, and saying so plainly is better than "could
            // not open".
            if e.raw_os_error() == Some(libc::ELOOP) {
                "refused: it is a symbolic link, and staging follows nothing".to_string()
            } else {
                format!("open: {}", e)
            }
        })?;

    let meta = f.metadata().map_err(|e| format!("stat: {}", e))?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }

    let real = fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd()))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string());
    Ok((f, real))
}

/// The uid a live process runs as, from `/proc/<pid>/status`.
pub fn proc_uid(pid: u32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // real, effective, saved, fs — the real uid is the first.
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// The cgroup path of a live process. `system.slice` is systemd's home for the
/// machine's own services, which is how moatd, tetragon, sshd and dbus are told
/// apart from a user's programs without matching on names.
pub fn proc_cgroup(pid: u32) -> Option<String> {
    let text = fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    Some(text.lines().next()?.to_string())
}

/// What the KERNEL will match when this path is executed, when that is not the
/// path itself. `None` means the path IS the binary the kernel loads.
///
/// `matchBinaries` compares the binary the kernel loaded, and for a `#!` script
/// that is the INTERPRETER: `/proc/<pid>/exe` of a running shell script reads
/// `/usr/bin/bash`, never the script. Tetragon's userspace process cache still
/// reports the script path, so the two disagree -- which is how, on 2026-09-07,
/// `moatctl exclusions` accepted `/usr/bin/ssh-copy-id` (a `#!/bin/sh` script),
/// recorded it, re-rendered and reloaded the policy, verified the re-arm, and
/// changed nothing at all: the kernel went on matching bash and refusing the
/// read, while moatd suppressed the alert because the name it was given was one
/// its own selectors exclude. Allowed in the panel, still denied on disk, and
/// no alert left to say why.
///
/// So this is the question to ask before writing an exclusion, and when
/// explaining a selector that contradicts itself.
pub fn interpreter_of(path: &str) -> Option<String> {
    use std::io::Read;
    let mut buf = [0u8; 256];
    let mut f = std::fs::File::open(path).ok()?;
    let n = f.read(&mut buf).ok()?;
    let head = &buf[..n];
    // The one case where the path is what the kernel matches.
    if head.starts_with(b"\x7fELF") {
        return None;
    }
    if head.starts_with(b"#!") {
        let line = head[2..].split(|b| *b == b'\n').next()?;
        let text = String::from_utf8_lossy(line);
        if let Some(interp) = text.split_whitespace().next() {
            if interp.starts_with('/') {
                return Some(interp.to_string());
            }
        }
    }
    // Executable, not ELF, no usable shebang: still not what the kernel loads.
    Some("the interpreter that runs it".to_string())
}

/// What the KERNEL will match when this path is executed, when the path is a
/// SYMLINK. `None` means the path IS the name the kernel reports.
///
/// The third member of the family, after `interpreter_of` (a script runs as its
/// interpreter) and `is_interpreter_path` (naming an interpreter grants every
/// program it runs). Same question, third way to get it wrong: `matchBinaries`
/// compares `d_path(current->mm->exe_file)`, which is the RESOLVED path, so an
/// allowlist entry naming a symlink never matches anything.
///
/// It fails silently and in the dangerous direction. A dead entry in a `NotIn`
/// kill list reads exactly like a live one and denies what it meant to permit.
/// On 2026-09-09 `/usr/lib/systemd/systemd-udevd` -> `/usr/bin/udevadm` in
/// `rootkit-kernel-module-load` SIGKILLed two udev workers loading an in-tree
/// Logitech HID driver (`systemd-udevd[1070]: Worker [14202] terminated by
/// signal 9`), leaving the device with no driver. The entry had never once
/// matched, and nothing said so.
///
/// Only answerable for a path that exists here: a symlink on the target machine
/// is not one this process can see if the package is not installed. `None` for
/// an absent path means "cannot tell", not "safe" — see `dead_matchbinaries`.
pub fn resolved_binary(path: &str) -> Option<String> {
    let real = std::fs::canonicalize(path).ok()?;
    let real = real.to_string_lossy();
    (real != path).then(|| real.to_string())
}

/// Is this path an interpreter — a binary whose identity is borrowed from
/// whatever it was handed?
///
/// `interpreter_of` answers the other direction: given a *script*, what does
/// the kernel load. This answers "is naming this as the actor a grant to every
/// program it runs", which is the question `moatctl allow` and
/// `engine::exclude_binary` have to refuse on. They are not the same test:
/// `/usr/bin/python3.14` is a real ELF, so `interpreter_of` correctly returns
/// `None` for it, and allowing it is still "any python program on this machine
/// may read your cloud credentials" (2026-09-07, gcloud).
///
/// Matched on the file NAME, not on content: an interpreter is only recognisable
/// by what it is, and the list is the set that actually ships on an Omarchy box
/// and turns up as `exe` in this daemon's own records. A version suffix is
/// stripped first, because the alert said `python3.14`, not `python`.
pub fn is_interpreter_path(path: &str) -> bool {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    // python3.14 -> python3 -> python; node22 -> node; ruby3.3 -> ruby.
    let stem: String = name
        .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .to_string();
    matches!(
        stem.as_str(),
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "ksh"
            | "ash"
            | "busybox"
            | "python"
            | "perl"
            | "ruby"
            | "node"
            | "deno"
            | "bun"
            | "lua"
            | "luajit"
            | "php"
            | "tclsh"
            | "wish"
            | "awk"
            | "gawk"
            | "mawk"
            | "env"
            | "java"
            | "Rscript"
            | "osascript"
            | "pwsh"
    )
}

#[cfg(test)]
mod pidfd_tests {
    use super::*;

    /// The property the whole thing rests on: a handle to a process that has
    /// gone signals NOTHING, rather than whatever now wears its number.
    ///
    /// This is what a bare `libc::kill(pid)` could not promise. Verifying a pid
    /// and then signalling it later by number is two different questions asked
    /// at two different moments, and moat asked them with a `/proc` walk and a
    /// loop over eight targets in between.
    #[test]
    fn a_handle_to_a_dead_process_signals_nothing() {
        // Control first: a live process, killed through its handle, really
        // does die. Without this, the refusal below could just mean `kill`
        // never works here.
        let mut alive = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let h = PidFd::open(alive.id()).expect("a running process can be pinned");
        assert!(h.kill().is_ok(), "a live process is killable through its handle");
        let status = alive.wait().expect("reap");
        assert!(!status.success(), "and it actually died: {status:?}");
        drop(h);

        // Now the case that matters. Pin a process, let it exit, and reap it so
        // the pid is genuinely free for reuse.
        let mut doomed = std::process::Command::new("true").spawn().expect("spawn true");
        let pid = doomed.id();
        let handle = PidFd::open(pid).expect("pinned while it was alive");
        doomed.wait().expect("reap");

        let err = handle
            .kill()
            .expect_err("a handle to a reaped process must not signal anything");
        assert!(
            err.contains("No such process") || err.contains("ESRCH") || err.contains("os error 3"),
            "and it must fail because the PROCESS is gone, not for some other \
             reason: {err}"
        );
    }

    /// The distinguishing property, against a pid that really has been reused.
    ///
    /// The test above does NOT prove pidfd is better than `libc::kill`: a
    /// reaped pid gives ESRCH either way, so it passes with the handle swapped
    /// back for a bare kill. It caught nothing, which is the failure mode this
    /// repo keeps finding in its own tests.
    ///
    /// The only case that separates them is a pid that has been recycled, and
    /// that can be built: inside a fresh PID namespace we are root, pids start
    /// at 1, and `/proc/sys/kernel/ns_last_pid` sets the next one. So: pin a
    /// process, let it die, force its number to be handed to a NEW process, and
    /// signal through the old handle. The handle must refuse. A bare
    /// `kill(pid)` at that moment kills a stranger -- which is exactly what
    /// moat's tree kill did, holding numbers across a `/proc` walk and two
    /// signal passes.
    ///
    /// Runs itself again inside the namespace. Skipped, loudly, where
    /// unprivileged user namespaces are unavailable.
    #[test]
    fn a_recycled_pid_is_not_signalled_through_an_old_handle() {
        const MARK: &str = "MOAT_PIDFD_RECYCLE_INNER";
        if std::env::var(MARK).is_ok() {
            recycle_check();
            return;
        }

        // Probe first, so "unshare cannot run here" is never confused with
        // "the check failed".
        let probe = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--pid", "--fork", "--mount-proc"])
            .arg("/bin/true")
            .output();
        match probe {
            Ok(o) if o.status.success() => {}
            _ => {
                eprintln!(
                    "SKIPPED a_recycled_pid_is_not_signalled_through_an_old_handle: \
                     unprivileged user+pid namespaces are not available here, so a pid \
                     cannot be recycled on purpose"
                );
                return;
            }
        }

        let exe = std::env::current_exe().expect("test binary");
        let out = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--pid", "--fork", "--mount-proc"])
            .arg(&exe)
            .args([
                "--exact",
                "util::pidfd_tests::a_recycled_pid_is_not_signalled_through_an_old_handle",
                "--nocapture",
            ])
            .env(MARK, "1")
            .output()
            .expect("re-run inside the namespace");
        assert!(
            out.status.success(),
            "the in-namespace check failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The body of the test above, running as root in a fresh PID namespace.
    fn recycle_check() {
        // Pin a process, then let it die and be reaped so its number is free.
        let mut doomed = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn /bin/true");
        let pid = doomed.id();
        let handle = PidFd::open(pid).expect("pinned while alive");
        doomed.wait().expect("reap");

        // Hand that exact number to something else.
        let mut victim = None;
        for _ in 0..8 {
            if std::fs::write("/proc/sys/kernel/ns_last_pid", (pid - 1).to_string()).is_err() {
                eprintln!("SKIPPED: ns_last_pid is not writable even in this namespace");
                return;
            }
            let c = std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .expect("spawn /bin/sleep");
            if c.id() == pid {
                victim = Some(c);
                break;
            }
            let mut c = c;
            let _ = c.kill();
            let _ = c.wait();
        }
        let Some(mut victim) = victim else {
            panic!("could not get the pid reused, so this test proved nothing");
        };
        assert_eq!(victim.id(), pid, "the number really is the same");

        // The whole point: the old handle must not reach the new process.
        let err = handle
            .kill()
            .expect_err("an old handle must not signal whatever now wears that pid");
        assert!(
            err.contains("No such process") || err.contains("os error 3"),
            "refused because the process is gone: {err}"
        );
        assert!(
            victim.try_wait().expect("poll").is_none(),
            "and the innocent process holding that pid is still running"
        );

        let _ = victim.kill();
        let _ = victim.wait();
    }

    /// Handles are file descriptors, and a process tree is not bounded.
    ///
    /// `cmd_kill` pins every descendant before signalling it, and
    /// `proc_descendants` returns the whole tree. Opening one handle per
    /// descendant AT ONCE meant a tree wider than RLIMIT_NOFILE ran out of
    /// descriptors -- so the widest trees, which is what a fork bomb and a
    /// build both look like, were the ones a kill silently missed.
    ///
    /// The ceiling on this machine is 524,288, far too high to reach politely,
    /// so the check runs in a CHILD with the limit lowered. Lowering it in this
    /// process would apply to every other test in the binary, which cargo runs
    /// as threads beside this one.
    #[test]
    fn descriptors_run_out_and_the_failure_is_visible() {
        const MARK: &str = "MOAT_PIDFD_NOFILE_INNER";
        const LIMIT: u64 = 96;

        if std::env::var(MARK).is_ok() {
            let me = std::process::id();
            let mut held: Vec<PidFd> = Vec::new();
            for _ in 0..LIMIT * 2 {
                match PidFd::open(me) {
                    Some(h) => held.push(h),
                    None => break,
                }
            }
            // The refusal is a `None` -- exactly what a `filter_map` throws
            // away without a word. That is why `cmd_kill` batches and reports.
            assert!(
                held.len() < (LIMIT * 2) as usize,
                "the kernel handed out {} descriptors under a limit of {LIMIT}",
                held.len()
            );
            assert!(PidFd::open(me).is_none(), "exhausted, and it says so");
            // And it must say WHICH failure. Reported as `Gone`, this would
            // read as "the process exited" about a process that is running --
            // which is precisely how a partial kill of a wide tree came to be
            // logged as a clean one.
            assert_eq!(
                PidFd::try_open(me).err(),
                Some(PinFailure::Exhausted),
                "descriptor exhaustion must not be reported as a dead process"
            );
            drop(held);
            assert!(
                PidFd::open(me).is_some(),
                "and the descriptors really were released on drop"
            );
            return;
        }

        use std::os::unix::process::CommandExt;
        let exe = std::env::current_exe().expect("test binary");
        let mut cmd = std::process::Command::new(&exe);
        cmd.args([
            "--exact",
            "util::pidfd_tests::descriptors_run_out_and_the_failure_is_visible",
            "--nocapture",
        ])
        .env(MARK, "1");
        // SAFETY: `setrlimit` is async-signal-safe and touches only this
        // about-to-exec child.
        unsafe {
            cmd.pre_exec(|| {
                let rl = libc::rlimit {
                    rlim_cur: LIMIT,
                    rlim_max: LIMIT,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = cmd.output().expect("run the child");
        assert!(
            out.status.success(),
            "the low-descriptor check failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A pid that was never running cannot be pinned, and that is not an error
    /// the caller should mistake for "pinned nothing".
    #[test]
    fn an_absent_pid_cannot_be_pinned() {
        // Well past /proc/sys/kernel/pid_max on any machine. The kernel calls
        // this EINVAL, not ESRCH -- the number is not a pid at all rather than
        // a pid with nothing behind it -- so it stays `Other` and, crucially,
        // does not claim a process exited.
        let why = PidFd::try_open(u32::MAX - 1).err().expect("cannot be pinned");
        assert!(matches!(why, PinFailure::Other(_)), "got {:?}", why);
        assert!(!why.to_string().contains("exited"));
    }

    /// The `Gone` case, against a process that really did exit: this is the one
    /// failure where sparing the pid is the correct answer, so it has to be
    /// distinguishable from the ones where it is not.
    #[test]
    fn a_reaped_child_reports_gone() {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn /bin/true");
        let pid = child.id();
        child.wait().expect("reap");
        // Reaped, so the pid is free and holds no zombie. A pid this fresh
        // being recycled inside these few microseconds would be a surprise;
        // if it ever is, the open succeeds and this asserts nothing false.
        if let Err(why) = PidFd::try_open(pid) {
            assert_eq!(why, PinFailure::Gone, "a reaped child is Gone, not {:?}", why);
            assert!(why.to_string().contains("exited"));
        }
    }

    /// Every reason a pin can fail must describe itself, because these strings
    /// are what a person reads when a kill did not happen. Only `Gone` may
    /// claim the process exited.
    #[test]
    fn each_pin_failure_says_what_actually_happened() {
        assert!(PinFailure::Gone.to_string().contains("exited"));

        for f in [
            PinFailure::Unsupported,
            PinFailure::Exhausted,
            PinFailure::Other(libc::EPERM),
        ] {
            let s = f.to_string();
            assert!(
                !s.contains("exited"),
                "{:?} renders as {:?}, which claims a live process is dead",
                f,
                s
            );
            assert!(!s.is_empty());
        }
        assert!(PinFailure::Unsupported.to_string().contains("5.3"));
        assert!(PinFailure::Exhausted.to_string().contains("LimitNOFILE"));
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    /// The 2026-09-09 shutdown alert, as arithmetic.
    ///
    /// `moat-x-was-not-running` called a 4416-second hole "nothing was seen by
    /// anything" when 73 of those minutes the machine was powered off. These
    /// three clocks are what tells those apart, so each has to be the clock it
    /// claims to be -- a silent 0 from either would make every gap read as
    /// fully blind again.
    #[test]
    fn the_three_clocks_are_ordered_the_way_the_gap_maths_needs() {
        let boot = boot_time();
        let awake = awake_secs();
        let wall = unix_secs();

        assert!(boot > 0, "/proc/stat btime must be readable");
        assert!(awake > 0, "CLOCK_MONOTONIC must be readable");
        assert!(
            boot < wall,
            "the machine booted at {boot}, which is not before now ({wall})"
        );
        // Uptime including suspend is wall-minus-boot; awake time cannot
        // exceed it, and equals it on a machine that never slept.
        let since_boot = wall - boot;
        assert!(
            awake <= since_boot + 2,
            "awake {awake}s exceeds time since boot {since_boot}s -- \
             CLOCK_MONOTONIC is not measuring what this thinks it is"
        );
    }

    /// A monotonic clock that does not advance cannot measure a gap.
    #[test]
    fn awake_time_advances() {
        let a = awake_secs();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(awake_secs() > a, "CLOCK_MONOTONIC did not advance over 1.1s");
    }
}

#[cfg(test)]
mod interpreter_tests {
    use super::*;

    /// The 2026-09-07 gcloud lesson, in both directions.
    ///
    /// `interpreter_of` cannot answer this one: `/usr/bin/python3.14` is a real
    /// ELF, so it is legitimately "what the kernel loads" — and an allowlist
    /// entry naming it is still a grant to every python program on the machine.
    #[test]
    fn an_interpreter_is_recognised_even_though_it_is_a_real_binary() {
        for p in [
            "/usr/bin/python3.14",
            "/usr/bin/python3",
            "/bin/sh",
            "/usr/bin/bash",
            "/home/dan/.local/share/mise/installs/node/26.5.0/bin/node",
            "/usr/bin/env",
        ] {
            assert!(is_interpreter_path(p), "{} is an interpreter", p);
        }
    }

    /// A program that only *runs* things is not the same as one that is named
    /// after one. These are ordinary binaries and allowing one grants only it.
    #[test]
    fn an_ordinary_binary_is_not_treated_as_an_interpreter() {
        for p in [
            "/usr/bin/cat",
            "/usr/bin/restic",
            "/usr/bin/ssh",
            "/usr/bin/nodemon",
            "/usr/bin/pythonize",
            "",
        ] {
            assert!(!is_interpreter_path(p), "{} is not an interpreter", p);
        }
    }

    #[test]
    fn a_real_binary_is_what_the_kernel_matches() {
        assert_eq!(interpreter_of("/usr/bin/cat"), None, "an ELF binary is itself");
    }

    #[test]
    fn a_shebang_script_names_its_interpreter() {
        // ssh-copy-id is the case this was written for; skip where it is absent.
        if std::path::Path::new("/usr/bin/ssh-copy-id").exists() {
            let i = interpreter_of("/usr/bin/ssh-copy-id").expect("a script is not its own binary");
            assert!(i.starts_with('/'), "{}", i);
            assert!(i.contains("sh"), "{}", i);
        }
    }

    #[test]
    fn a_path_that_cannot_be_read_is_not_claimed_to_be_a_script() {
        assert_eq!(interpreter_of("/nonexistent/moat/probe"), None);
    }
}

/// Is this process inside a container, i.e. a different mount namespace to ours?
///
/// moatd runs in the host's namespaces, so "not ours" means "not this machine's
/// filesystem". That is the whole question a container check has to answer, and
/// asking the kernel is the only honest way to ask it: a path is
/// namespace-relative, an ancestry walk truncates (measured at depth 8, which
/// is short of `runc` for an npm postinstall), and an exe path that does not
/// exist on the host only tells you it is missing NOW.
///
/// `proc` is a parameter so this is testable without a container.
///
/// Unknown means NOT a container. A process that has already exited cannot be
/// read, and defaulting to "container" there would let anything quiet itself by
/// dying fast -- the same trade `socket_is_gone_not_hidden` makes, in the same
/// direction.
pub fn in_container_at(proc: &std::path::Path, pid: u32) -> bool {
    let Ok(ours) = std::fs::read_link(proc.join("self").join("ns").join("mnt")) else {
        return false;
    };
    match std::fs::read_link(proc.join(pid.to_string()).join("ns").join("mnt")) {
        Ok(theirs) => theirs != ours,
        Err(_) => false,
    }
}

/// [`in_container_at`] against the real `/proc`.
pub fn in_container(pid: u32) -> bool {
    in_container_at(std::path::Path::new("/proc"), pid)
}

#[cfg(test)]
mod container_tests {
    use super::in_container_at;
    use std::os::unix::fs::symlink;

    /// A fake /proc where `self` and `pid` point at named namespaces.
    fn proc_with(dir: &std::path::Path, ours: &str, theirs: &str) -> std::path::PathBuf {
        for (who, ns) in [("self", ours), ("42", theirs)] {
            let d = dir.join(who).join("ns");
            std::fs::create_dir_all(&d).unwrap();
            symlink(ns, d.join("mnt")).unwrap();
        }
        dir.to_path_buf()
    }

    #[test]
    fn a_process_in_our_own_mount_namespace_is_not_a_container() {
        let d = tempfile::tempdir().unwrap();
        let p = proc_with(d.path(), "mnt:[4026531840]", "mnt:[4026531840]");
        assert!(!in_container_at(&p, 42));
    }

    #[test]
    fn a_different_mount_namespace_is_a_container() {
        let d = tempfile::tempdir().unwrap();
        let p = proc_with(d.path(), "mnt:[4026531840]", "mnt:[4026532999]");
        assert!(in_container_at(&p, 42));
    }

    #[test]
    fn a_process_that_has_already_gone_is_not_a_container() {
        // Unknown must mean "not a container", or anything could quieten itself
        // by exiting fast enough to lose the race.
        let d = tempfile::tempdir().unwrap();
        let p = proc_with(d.path(), "mnt:[4026531840]", "mnt:[4026532999]");
        assert!(!in_container_at(&p, 999), "no such pid");
    }
}

/// Binaries that only ever appear between the host and a container's processes.
///
/// Deliberately short and deliberately specific. Every name here is a container
/// RUNTIME -- the thing that made the namespace -- and not a program that merely
/// tends to run in one. `node` and `python` are the obvious wrong answers: they
/// are ancestors of half this machine either way.
const CONTAINER_RUNTIMES: &[&str] = &[
    "runc",
    "crun",
    "containerd-shim",
    "containerd-shim-runc-v1",
    "containerd-shim-runc-v2",
    "conmon",
    "dockerd",
    "containerd",
    "podman",
];

/// Did this run in a container, judged from its ancestry?
///
/// The FALLBACK, and only that. `process.ns.mnt.is_host` from the sensor is the
/// real answer, because it is what the kernel says and it cannot be spoofed by
/// naming a binary `runc`. But Tetragon puts `ns` on `process_exec` events only,
/// and moatd learns it only if it saw that exec -- which for short-lived
/// processes inside a container it frequently does not (`cgroup-rate` throttles
/// exec under exactly the bursts a compose stack produces). Measured on
/// 2026-09-08: of 1802 rows, 354 carried the sensor's answer and 1448 carried
/// nothing, and `is_host: false` was never once reported.
///
/// So: believe the sensor when it speaks; ask the ancestry when it does not.
///
/// The trade is stated plainly because it is a real one. An attacker who can
/// name a process `runc` in the alert's parent chain can reach this fallback and
/// be quietened -- but only down to the TIMELINE, never out of the record, never
/// past enforcement (the kernel decides that, and it uses the namespace itself),
/// and never for a package install. Weigh that against the alternative measured
/// today, which is that the switch does nothing at all for containers.
pub fn ancestry_looks_containerised(ancestry: &[String]) -> bool {
    ancestry
        .iter()
        .any(|exe| CONTAINER_RUNTIMES.contains(&basename(exe)))
}

#[cfg(test)]
mod ancestry_container_tests {
    use super::ancestry_looks_containerised as looks;

    fn chain(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_ancestry_of_a_real_container_process_is_recognised() {
        // Verbatim from the pg_isready rows on 2026-09-08, which the sensor
        // reported nothing at all about.
        assert!(looks(&chain(&[
            "/usr/lib/systemd/systemd",
            "/usr/bin/containerd",
            "/usr/bin/containerd-shim-runc-v2",
            "/usr/bin/containerd-shim-runc-v2",
        ])));
        // And the docker build shape.
        assert!(looks(&chain(&[
            "/usr/lib/systemd/systemd",
            "/usr/bin/dockerd",
            "/usr/bin/runc",
            "/bin/sh",
            "/usr/bin/apt-get",
        ])));
    }

    #[test]
    fn an_ordinary_host_chain_is_not() {
        // The one that matters most: moat's own sandbox and a normal build must
        // never be mistaken for a container by this path.
        assert!(!looks(&chain(&[
            "/usr/lib/systemd/systemd",
            "/usr/bin/herdr",
            "/usr/bin/bash",
            "/usr/bin/makepkg",
        ])));
        assert!(!looks(&chain(&[
            "/usr/bin/bash",
            "/usr/bin/cargo",
            "/usr/bin/node",
            "/usr/bin/python3",
        ])));
        assert!(!looks(&[]));
    }

    #[test]
    fn a_runtime_is_matched_on_its_basename_not_a_substring() {
        // `/usr/bin/runc` yes; a project called runc-tools no.
        assert!(looks(&chain(&["/usr/local/sbin/runc"])), "container-side path");
        assert!(!looks(&chain(&["/home/dan/src/runc-tools/target/debug/helper"])));
        assert!(!looks(&chain(&["/usr/bin/podman-compose-wrapper"])));
    }
}

/// `12 s`, `4 min`, `2 h 10 min` -- for an evidence line, where "12 s before
/// this connection" reads and "12 seconds" is fine but "7391 s" is not.
pub fn human_secs(secs: u64) -> String {
    if secs < 60 {
        return format!("{} s", secs);
    }
    if secs < 3_600 {
        return format!("{} min", secs / 60);
    }
    let h = secs / 3_600;
    let m = (secs % 3_600) / 60;
    if m == 0 {
        format!("{} h", h)
    } else {
        format!("{} h {} min", h, m)
    }
}
