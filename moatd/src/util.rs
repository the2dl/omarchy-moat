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
    out.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
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
        if let Some(interp) = text.trim().split_whitespace().next() {
            if interp.starts_with('/') {
                return Some(interp.to_string());
            }
        }
    }
    // Executable, not ELF, no usable shebang: still not what the kernel loads.
    Some("the interpreter that runs it".to_string())
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
