//! Decoy files that exist for no reason, so that reading one is the alert.
//!
//! Every other file rule in `policies/` has the same shape: watch a real
//! credential, then subtract the programs that legitimately read it. That
//! subtraction is where the false positives live -- `cred-ssh-private-key-read`
//! carries fourteen `NotPostfix` entries and still needs an allowlist, because
//! ssh keys have readers.
//!
//! A canary has none. It is not referenced by any config, no program knows its
//! name, and it holds nothing real. So the rule is the path and nothing else,
//! and a hit means something walked the filesystem looking for secrets. That is
//! the one detection here that needs no tuning and cannot be quietened by
//! adding a binary to a list.
//!
//! Three decisions worth keeping:
//!
//! **The names differ per machine.** A fixed set would be a fingerprint: read
//! one file, learn the names of all the others, step around them everywhere.
//! Names are drawn per machine from a table of plausible shapes and recorded in
//! the manifest, which is the only place they exist.
//!
//! **The `/etc` decoys are world-readable on purpose.** A canary only root can
//! read cannot catch the thing worth catching -- an unprivileged process
//! enumerating `/etc` for a way up. A world-readable secrets file in `/etc` is
//! itself the classic local-escalation finding, which is exactly why it is
//! convincing bait and exactly why it must be reachable before the escalation,
//! not after. `/root` is the mirror image: 0600, unreadable until something
//! already succeeded, so a hit there means the escalation has happened.
//!
//! **Nothing is ever overwritten, and nothing without our marker is ever
//! removed.** A canary that clobbers a real `/etc/rsync.secrets` would be moat
//! destroying the machine it protects. Candidate names are skipped when taken,
//! and removal re-reads the file and refuses anything that is not ours.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Present in every canary, and the only thing that authorises removal.
///
/// It also answers the question a person asks when they find one of these:
/// files appearing in `/etc` with no package behind them is exactly the shape
/// of an intrusion, so a decoy that cannot explain itself is a decoy that gets
/// reported as malware -- by its own owner.
pub const MARKER: &str = "moat-canary";

/// The line the marker rides in on. Every format below takes `#` comments.
const MARKER_LINE: &str = "# moat-canary: a decoy. Nothing reads this file. If a program does, Moat says so.\n# Remove it with `sudo moatctl canary off`, never by hand -- moat is watching this exact path.\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// System secrets an unprivileged process reads while looking for a way up.
    Etc,
    /// Only readable once something is already root.
    Root,
    /// The exfiltration target.
    Home,
    /// Staging ground.
    Tmp,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Etc => "etc",
            Kind::Root => "root",
            Kind::Home => "home",
            Kind::Tmp => "tmp",
        }
    }

    /// What a read of this one means, in the alert.
    pub fn meaning(&self) -> &'static str {
        match self {
            Kind::Etc => "something searched /etc for credentials",
            Kind::Root => "something already running as root searched for credentials",
            Kind::Home => "something searched your home directory for credentials",
            Kind::Tmp => "something searched the temp directories for credentials",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    pub path: String,
    pub kind: Kind,
    /// Unix seconds. Only for `moatctl canary`, so a person can see these were
    /// planted at install and not by whatever they are currently chasing.
    pub planted: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub canaries: Vec<Canary>,
}

impl Manifest {
    pub fn paths(&self) -> Vec<String> {
        self.canaries.iter().map(|c| c.path.clone()).collect()
    }

    pub fn load(path: &Path) -> Manifest {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Manifest::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    /// 0600 root:root: the manifest is the only list of which files are decoys,
    /// so anything that can read it can step around every one of them.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {}", parent.display(), e))?;
        }
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, format!("{}\n", body)).map_err(|e| format!("{}: {}", path.display(), e))?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }
}

// ---------------------------------------------------------------- randomness

/// Bytes from the kernel. No `rand` dependency for a handful of choices, and
/// `/dev/urandom` is the right source anyway: these names are the only thing
/// stopping an attacker from knowing where the decoys are.
fn rand_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    // A predictable fallback is worse than none: without randomness the names
    // are the same on every machine, which is the fingerprint this exists to
    // avoid. Callers treat an empty vec as "cannot plant".
    Vec::new()
}

fn pick<T>(items: &[T], byte: u8) -> &T {
    &items[(byte as usize) % items.len()]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ------------------------------------------------------------- name tables

/// Shapes that look like a secret somebody left behind. Each is a real file
/// name in common use, which is what makes it worth reading -- and none is
/// shipped by a package on Arch, so the odds of a collision are low and a
/// collision is handled anyway.
const ETC_NAMES: &[&str] = &[
    "rsync.secrets",
    "backup.secrets",
    "ansible-vault-pass",
    "duplicity.conf",
    "borgmatic-passphrase",
    ".htpasswd",
    "mysql-backup.cnf",
    "pgbackup.conf",
    "restic-password",
    "smb-credentials",
];

const ROOT_NAMES: &[&str] = &[
    ".pgpass",
    ".my.cnf",
    ".netrc",
    "backup-key.txt",
    ".rclone.conf",
];

const HOME_NAMES: &[&str] = &[
    ".env.production",
    ".env.prod.local",
    "wallet.dat",
    "credentials.csv",
    ".netrc",
    "vault-recovery.txt",
    ".pypirc",
];

const TMP_NAMES: &[&str] = &[
    "db-dump.sql",
    "prod-backup.env",
    "creds.txt",
    "session-keys.json",
];

// ---------------------------------------------------------------- contents

/// Plausible contents. These have to read as the real thing for as long as it
/// takes to be worth opening -- which is already too late, because the alert
/// fires on the open and not on anything in here.
fn body(kind: Kind, name: &str, secret: &str) -> String {
    let fake_user = "svc-backup";
    match (kind, name) {
        (_, n) if n.ends_with(".secrets") || n == ".htpasswd" => {
            format!("{}{}:{}\n", MARKER_LINE, fake_user, secret)
        }
        (_, ".pgpass") => format!("{}*:*:*:postgres:{}\n", MARKER_LINE, secret),
        (_, ".netrc") => format!(
            "{}machine backup.internal login {} password {}\n",
            MARKER_LINE, fake_user, secret
        ),
        (_, ".my.cnf") | (_, "mysql-backup.cnf") => format!(
            "{}[client]\nuser={}\npassword={}\n",
            MARKER_LINE, fake_user, secret
        ),
        (_, ".pypirc") => format!(
            "{}[pypi]\nusername = __token__\npassword = pypi-{}\n",
            MARKER_LINE, secret
        ),
        (_, n) if n.starts_with(".env") || n.ends_with(".env") => format!(
            "{}DATABASE_URL=postgres://{}:{}@db.internal:5432/prod\nAWS_SECRET_ACCESS_KEY={}\n",
            MARKER_LINE, fake_user, secret, secret
        ),
        (_, "session-keys.json") | (_, "credentials.csv") => format!(
            "{}{{\"user\":\"{}\",\"token\":\"{}\"}}\n",
            MARKER_LINE, fake_user, secret
        ),
        _ => format!("{}{}\n", MARKER_LINE, secret),
    }
}

/// 0644 in `/etc` is not an oversight -- see the module docs. Everywhere else
/// the decoy is only meant to be reachable by whoever already owns the
/// directory it sits in.
fn mode(kind: Kind) -> u32 {
    match kind {
        Kind::Etc => 0o644,
        Kind::Root => 0o600,
        Kind::Home | Kind::Tmp => 0o600,
    }
}

// ------------------------------------------------------------------ planting

/// Choose paths that do not exist yet. `homes` comes from the same
/// `human_homes` the renderer uses, so the decoys land in the same homes the
/// credential rules already watch.
pub fn plan(homes: &[String], per_kind: usize) -> Vec<(Kind, PathBuf)> {
    let mut out: Vec<(Kind, PathBuf)> = Vec::new();
    let want = |kind: Kind, dir: &Path, names: &[&str], n: usize, out: &mut Vec<(Kind, PathBuf)>| {
        let r = rand_bytes(n.max(1) * 4);
        if r.is_empty() {
            return;
        }
        let mut used: Vec<String> = Vec::new();
        for i in 0..n {
            // Four tries for a free name, then give up on this slot rather than
            // loop: a directory where every candidate is taken is a directory
            // that does not need a decoy invented for it.
            for t in 0..4 {
                let idx = (i * 4 + t) % r.len();
                let name = pick(names, r[idx]);
                if used.iter().any(|u| u == name) {
                    continue;
                }
                let p = dir.join(name);
                if p.exists() {
                    continue;
                }
                used.push((*name).to_string());
                out.push((kind, p));
                break;
            }
        }
    };

    want(Kind::Etc, Path::new("/etc"), ETC_NAMES, per_kind, &mut out);
    want(Kind::Root, Path::new("/root"), ROOT_NAMES, 1, &mut out);
    for home in homes {
        want(Kind::Home, Path::new(home), HOME_NAMES, per_kind, &mut out);
    }
    want(Kind::Tmp, Path::new("/tmp"), TMP_NAMES, 1, &mut out);
    want(Kind::Tmp, Path::new("/var/tmp"), TMP_NAMES, 1, &mut out);
    out
}

/// Write one decoy. Refuses an existing path: a canary that overwrites a real
/// file is moat damaging the machine it is supposed to be protecting.
pub fn plant(kind: Kind, path: &Path, now: u64) -> Result<Canary, String> {
    if path.exists() {
        return Err(format!("{} exists; refusing to overwrite it", path.display()));
    }
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("secret");
    let secret = hex(&rand_bytes(20));
    if secret.is_empty() {
        return Err("no randomness available; refusing to plant a predictable decoy".into());
    }
    std::fs::write(path, body(kind, name, &secret))
        .map_err(|e| format!("{}: {}", path.display(), e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode(kind)))
        .map_err(|e| format!("chmod {}: {}", path.display(), e))?;
    // A decoy in a user's home owned by root is not a decoy, it is a puzzle --
    // and the attacker we care about runs as that user, so it has to be
    // readable by them or it catches nothing.
    if matches!(kind, Kind::Home | Kind::Tmp) {
        if let Some(dir) = path.parent() {
            if let Ok(md) = std::fs::metadata(dir) {
                use std::os::unix::fs::MetadataExt;
                let _ = chown(path, md.uid(), md.gid());
            }
        }
    }
    Ok(Canary {
        path: path.display().to_string(),
        kind,
        planted: now,
    })
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let rc = unsafe { libc::chown(c.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

/// Remove a decoy, but only if it is still one.
///
/// The marker is the whole authorisation. Between planting and removal a user
/// may have put something real at that path -- `moatctl canary off` must never
/// be the command that deletes it.
pub fn remove(path: &Path) -> Result<bool, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        // Already gone, or unreadable: either way there is nothing of ours to
        // take away, and reporting that as an error would make `canary off`
        // fail for the person tidying up after it.
        return Ok(false);
    };
    if !text.contains(MARKER) {
        return Err(format!(
            "{} is not a moat canary any more; leaving it alone",
            path.display()
        ));
    }
    std::fs::remove_file(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    Ok(true)
}

/// Which recorded canaries are no longer on disk.
///
/// Deleting one is not an attack -- a `/tmp` sweep does it on a timer -- but a
/// rule matching a path that does not exist detects nothing, and the gap is
/// invisible: the policy still loads, still reports armed, and can never fire.
pub fn missing(m: &Manifest) -> Vec<String> {
    m.canaries
        .iter()
        .filter(|c| !Path::new(&c.path).exists())
        .map(|c| c.path.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_planted_canary_carries_the_marker_and_the_right_mode() {
        let d = tmpdir();
        let p = d.path().join("rsync.secrets");
        let c = plant(Kind::Etc, &p, 100).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains(MARKER), "a decoy that cannot explain itself gets reported as malware by its owner");
        assert_eq!(c.kind, Kind::Etc);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "an /etc decoy only root can read cannot catch a process looking for a way up");
    }

    #[test]
    fn a_root_decoy_is_unreadable_until_something_already_won() {
        let d = tmpdir();
        let p = d.path().join(".pgpass");
        plant(Kind::Root, &p, 100).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// The one that matters most: moat must never destroy a real file.
    #[test]
    fn planting_never_overwrites_an_existing_file() {
        let d = tmpdir();
        let p = d.path().join(".netrc");
        std::fs::write(&p, "machine real.example login me password hunter2\n").unwrap();
        let err = plant(Kind::Home, &p, 100).unwrap_err();
        assert!(err.contains("refusing to overwrite"), "{}", err);
        assert!(
            std::fs::read_to_string(&p).unwrap().contains("hunter2"),
            "the real file has to survive untouched"
        );
    }

    #[test]
    fn removal_refuses_anything_that_is_not_ours_any_more() {
        let d = tmpdir();
        let p = d.path().join("creds.txt");
        plant(Kind::Tmp, &p, 100).unwrap();
        assert!(remove(&p).unwrap(), "our own decoy comes out");

        // The user replaced it with something real between plant and remove.
        std::fs::write(&p, "a real secret now\n").unwrap();
        let err = remove(&p).unwrap_err();
        assert!(err.contains("not a moat canary"), "{}", err);
        assert!(p.exists(), "`canary off` must never be the command that deletes a real file");

        // And a path already gone is not an error, or tidying up would fail.
        std::fs::remove_file(&p).unwrap();
        assert!(!remove(&p).unwrap());
    }

    #[test]
    fn a_plan_never_names_a_path_that_already_exists() {
        let d = tmpdir();
        // Fill every home candidate, so every slot must be skipped.
        for n in HOME_NAMES {
            std::fs::write(d.path().join(n), "real\n").unwrap();
        }
        let picked = plan(&[d.path().display().to_string()], 3);
        assert!(
            !picked.iter().any(|(k, _)| *k == Kind::Home),
            "with every name taken there is nothing safe to plant"
        );
    }

    #[test]
    fn two_machines_do_not_get_the_same_names() {
        let a = tmpdir();
        let b = tmpdir();
        // 5 slots each from a 7-name table: identical picks are possible but
        // vanishingly unlikely, and a fixed table would produce them every time.
        let mut same = 0;
        for _ in 0..8 {
            let pa = plan(&[a.path().display().to_string()], 3);
            let pb = plan(&[b.path().display().to_string()], 3);
            let na: Vec<_> = pa.iter().filter(|(k, _)| *k == Kind::Home)
                .map(|(_, p)| p.file_name().unwrap().to_owned()).collect();
            let nb: Vec<_> = pb.iter().filter(|(k, _)| *k == Kind::Home)
                .map(|(_, p)| p.file_name().unwrap().to_owned()).collect();
            if na == nb {
                same += 1;
            }
        }
        assert!(same < 8, "the names must not be a fingerprint shared by every install");
    }

    #[test]
    fn the_manifest_round_trips_and_lists_its_paths() {
        let d = tmpdir();
        let f = d.path().join("canaries.json");
        let m = Manifest {
            canaries: vec![Canary { path: "/etc/rsync.secrets".into(), kind: Kind::Etc, planted: 7 }],
        };
        m.save(&f).unwrap();
        let back = Manifest::load(&f);
        assert_eq!(back.paths(), vec!["/etc/rsync.secrets".to_string()]);
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "anything that can read the manifest can step around every decoy");
    }

    #[test]
    fn a_deleted_canary_is_reported_missing_because_the_rule_still_looks_armed() {
        let d = tmpdir();
        let p = d.path().join("creds.txt");
        plant(Kind::Tmp, &p, 1).unwrap();
        let m = Manifest {
            canaries: vec![Canary { path: p.display().to_string(), kind: Kind::Tmp, planted: 1 }],
        };
        assert!(missing(&m).is_empty());
        std::fs::remove_file(&p).unwrap();
        assert_eq!(missing(&m), vec![p.display().to_string()]);
    }
}
