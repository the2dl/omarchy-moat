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
