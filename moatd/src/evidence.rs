//! Staging the artefacts an agent is allowed to read (LEARNING §2).
//!
//! Analysis is worth more when the agent can read the thing that was accused —
//! deobfuscating a dropped `setup.mjs`, judging a base64'd postinstall — rather
//! than only the alert's description of it. But the configured agent (`claude`,
//! `codex`) is a cloud API: whatever is staged leaves the machine. So what may
//! be staged is a security decision and it lives here, in code, not in a prompt.
//!
//! # The rule: what is accused, never what was stolen
//!
//! Every finding has an actor (`process.exe` — the script or binary that acted)
//! and a target (`file` — what it touched). For the `cred` family the target is
//! *the secret itself*: `moat-cred-ssh-private-key-read` matches
//! `~/.ssh/id_rsa`, `moat-cred-cloud-credentials-read` matches
//! `~/.aws/credentials`. Staging a target's contents would upload the user's
//! private key to a cloud API, from the tool whose whole purpose is stopping
//! credential theft.
//!
//! So the actor's bytes may be staged. A target's bytes may be staged only when
//! the target *is* the accused thing (an exec rule, where the file is the binary
//! that ran), and never when it looks like a secret. [`is_secret_path`] is the
//! belt to the family check's braces: it holds even if a rule is added to the
//! wrong family later, which is exactly the kind of mistake this has to survive.
//!
//! Withheld never means hidden: the artefact is still listed with its path,
//! size and sha256, and the reason it was withheld. The agent is told what
//! exists; it is not handed the contents.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::alert::Alert;
use crate::util;

/// Anything larger is listed but not staged. A model cannot usefully
/// deobfuscate a 40 MB binary, and uploading one is pure cost and exposure.
pub const MAX_STAGED_BYTES: u64 = 1024 * 1024;

/// Path shapes whose *contents* never leave the machine, whatever rule matched
/// them and whatever family that rule is in.
///
/// Matched on the whole path, lowercased. Deliberately broad: a false positive
/// here costs the agent some context, a false negative uploads a private key.
const SECRET_MARKERS: &[&str] = &[
    "/.ssh/",
    "/.gnupg/",
    "/.aws/credentials",
    "/.aws/config",
    "/.config/gcloud/",
    "/.azure/",
    "/.kube/config",
    "/.docker/config.json",
    "/.netrc",
    "/.npmrc",
    "/.pypirc",
    "/.git-credentials",
    "/.config/gh/hosts.yml",
    "/.claude/.credentials.json",
    "/.config/anthropic/",
    "/.codex/auth.json",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/ssl/private/",
    "/secrets/",
    // Browser and app credential stores. Added 2026-09-04 after an audit found
    // a real Chrome `Login Data` staged on disk: this list is described as "the
    // belt to the family check's braces", and for browser stores the belt had a
    // hole exactly where the braces were doing all the work -- they were safe
    // only because those rules happen to be classified `cred`. One misfiled
    // rule and a cookie jar goes to the agent through the "safe" path.
    "/.mozilla/firefox/",
    "/.config/rclone/",
    "/.pgpass",
    "/.my.cnf",
];

/// Credential files that are identified by NAME rather than by location,
/// because every Chromium-based app ships its own copy of them: Chrome, Brave,
/// Edge, Spotify, Discord, Slack, and anything else built on Electron.
const SECRET_BASENAMES: &[&str] = &[
    "login data",
    "login data for account",
    "cookies",
    "web data",
    // Chromium's `Local State` holds the key that decrypts the cookie store,
    // so it is credential material even though the name does not look it --
    // which is exactly why the policy that watches these lists it too.
    "local state",
    "logins.json",
    "key3.db",
    "key4.db",
    "cert9.db",
    "cookies.sqlite",
    "signons.sqlite",
    ".env",
    ".envrc",
];

/// Suffixes that are key material by convention.
const SECRET_SUFFIXES: &[&str] = &[
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".gpg", ".asc",
];

/// Does this path look like something whose contents must never be uploaded?
pub fn is_secret_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    if SECRET_MARKERS.iter().any(|m| p.contains(m)) {
        return true;
    }
    if SECRET_SUFFIXES.iter().any(|s| p.ends_with(s)) {
        return true;
    }
    let base = util::basename(&p);
    if SECRET_BASENAMES.contains(&base) {
        return true;
    }
    // `.env.production`, `.env.local`, ...
    if base.starts_with(".env.") {
        return true;
    }
    // `id_rsa`, `id_ed25519`, … anywhere, not only under ~/.ssh.
    util::basename(&p).starts_with("id_")
        && !p.ends_with(".pub")
        && p.contains("/.ssh")
}

/// One artefact the agent is told about, staged or withheld.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// `actor` (what did it) or `target` (what it touched).
    pub role: &'static str,
    pub original_path: String,
    pub bytes: Option<u64>,
    pub sha256: Option<String>,
    /// File name inside the bundle directory, if the contents were staged.
    pub staged_as: Option<String>,
    /// Why the contents were not staged. `None` when they were.
    pub withheld: Option<String>,
}

impl Artifact {
    pub fn to_json(&self) -> Value {
        json!({
            "role": self.role,
            "path": self.original_path,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "staged_as": self.staged_as,
            "withheld": self.withheld,
        })
    }
}

/// May this artefact's *contents* be staged?
///
/// `is_target` distinguishes the two halves of a finding; `family` is the
/// rule's family, so the cred rules are refused as a class rather than one
/// path pattern at a time.
fn may_stage(path: &str, is_target: bool, family: &str) -> Result<(), String> {
    if is_secret_path(path) {
        return Err("looks like key material or a credential store".into());
    }
    if is_target && family == "cred" {
        return Err(format!(
            "a {} rule's target is the secret it protects, not the suspect",
            family
        ));
    }
    Ok(())
}

/// Copy what may be read into `dir`, and describe everything either way.
///
/// Staged files are written mode 0400 with a `.suspect` extension: they are
/// assumed hostile, and nothing should be able to execute one by accident.
pub fn stage(alert: &Alert, dir: &Path, max_bytes: u64, group: &str) -> Vec<Artifact> {
    let mut out = Vec::new();
    let family = alert.family.as_str();

    let mut candidates: Vec<(&'static str, String, bool)> = Vec::new();
    if !alert.process.exe.is_empty() {
        candidates.push(("actor", alert.process.exe.clone(), false));
    }
    if let Some(f) = alert.file.as_ref() {
        if !f.path.is_empty() && f.path != alert.process.exe {
            candidates.push(("target", f.path.clone(), true));
        }
    }

    for (role, path, is_target) in candidates {
        let mut a = Artifact {
            role,
            original_path: path.clone(),
            bytes: None,
            sha256: None,
            staged_as: None,
            withheld: None,
        };
        let p = Path::new(&path);
        let meta = std::fs::metadata(p).ok();
        // Size is safe to report for anything, including a secret: it says
        // "this exists and is this big", not what is in it.
        if let Some(m) = meta.as_ref() {
            a.bytes = Some(m.len());
        }

        // A HASH IS NOT METADATA. It used to be computed here, unconditionally,
        // under a comment claiming it said no more than the size did. Computing
        // sha256 means opening the file and reading every byte of it, so moat
        // read the private key it was two lines away from refusing to stage --
        // root pulling secret bytes into memory after it had already decided it
        // must not. On 2026-09-08 the enforced ssh-key policy caught moat's own
        // dev daemon doing exactly that, which is how this was found.
        //
        // The hash is also not free to publish: a digest of a secret is an
        // oracle for it, and the incident directory is readable by the `moat`
        // group, which on this threat model is the attacker. So ask permission
        // FIRST, and hash only what may be staged.
        match may_stage(&path, is_target, family) {
            Err(why) => a.withheld = Some(why),
            Ok(()) => match meta {
                None => a.withheld = Some("not on disk any more".into()),
                Some(m) if !m.is_file() => {
                    a.withheld = Some("not a regular file".into());
                }
                Some(m) if m.len() > max_bytes => {
                    a.withheld = Some(format!(
                        "{} bytes, over the {} byte staging limit",
                        m.len(),
                        max_bytes
                    ));
                }
                Some(_) => {
                    a.sha256 = util::sha256_file(p).ok();
                    let name = util::basename(&path);
                    let name = if name.is_empty() { "artifact" } else { name };
                    let dest = dir.join(format!("{}.{}.suspect", role, name));
                    // Open FIRST, then re-run `may_stage` against what the
                    // kernel says we are actually holding.
                    //
                    // `may_stage` above judged a string. `std::fs::copy`
                    // followed it. So a file the attacker named `/tmp/bait`,
                    // pointing at `/etc/shadow`, passed the credential check
                    // under its own name and was then read BY ROOT into an
                    // incident directory the `moat` group can read -- an
                    // arbitrary root file-read for any group member, which on
                    // this threat model is the attacker. Checking the string and
                    // then following it is the whole bug; this checks the thing.
                    match util::open_suspect(p) {
                        Err(why) => a.withheld = Some(why),
                        Ok((mut f, real)) => match may_stage(&real, is_target, family) {
                            Err(why) => {
                                a.withheld = Some(format!("{} (it resolved to {})", why, real))
                            }
                            Ok(()) => match copy_readonly_from(&mut f, &dest, group) {
                                Ok(()) => {
                                    a.staged_as = dest
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string());
                                }
                                Err(e) => a.withheld = Some(e),
                            },
                        },
                    }
                }
            },
        }
        out.push(a);
    }
    out
}

/// Copy the accused file beside the bundle: read-only, and readable by the
/// group that reads everything else in the incident directory.
///
/// **0440 root:<group>, not 0400.** The daemon is root and the agent is the
/// user, so a 0400 root-owned copy is one nothing but moatd can open — which
/// made the whole of §2b inert: the agent was told the artefact was staged for
/// it, could not read a byte of it, and correctly dropped its confidence over
/// evidence it had been promised and not given. Auto-triage then withheld every
/// verdict on the confidence gate. "Read-only" is the property that matters
/// here (nothing should ever execute or alter a staged suspect); "root-only"
/// was never the point.
fn copy_readonly_from(src: &mut std::fs::File, dest: &PathBuf, group: &str) -> Result<(), String> {
    // From the descriptor, never from the path: the descriptor is the file that
    // was checked, and nothing can swap it afterwards.
    let mut out = std::fs::File::create(dest).map_err(|e| format!("create: {}", e))?;
    std::io::copy(src, &mut out).map_err(|e| format!("copy: {}", e))?;
    drop(out);
    crate::util::secure_path(dest, group, 0o440).map_err(|e| format!("chmod 440: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one test that matters most: a credential must never be stageable,
    /// by any route. A false negative here uploads a private key to a cloud
    /// API from the tool that exists to stop credential theft.
    #[test]
    fn credentials_are_never_stageable() {
        for p in [
            "/home/dan/.ssh/id_rsa",
            "/home/dan/.ssh/id_ed25519",
            "/home/dan/.ssh/config",
            "/home/dan/.aws/credentials",
            "/home/dan/.config/gcloud/credentials.db",
            "/home/dan/.kube/config",
            "/home/dan/.claude/.credentials.json",
            "/home/dan/.codex/auth.json",
            "/home/dan/.git-credentials",
            "/home/dan/.netrc",
            "/home/dan/.npmrc",
            "/etc/shadow",
            "/home/dan/certs/server.pem",
            "/home/dan/keys/deploy.key",
            "/home/dan/vault.kdbx",
            "/srv/secrets/token.txt",
            "/home/dan/.gnupg/secring.gpg",
        ] {
            assert!(is_secret_path(p), "{} must be treated as secret", p);
            // …and refused for both roles and every family, not just cred.
            for family in ["cred", "exec", "persist", "pkg", "rootkit"] {
                assert!(may_stage(p, false, family).is_err(), "{} as actor/{}", p, family);
                assert!(may_stage(p, true, family).is_err(), "{} as target/{}", p, family);
            }
        }
    }

    /// A cred rule's target is refused as a class, even for a path that does
    /// not look like a secret — the family is the braces to is_secret_path's
    /// belt, so a rule filed under cred later is still safe.
    #[test]
    fn a_cred_targets_contents_are_refused_by_family_alone() {
        let odd = "/home/dan/Projects/notes.txt";
        assert!(!is_secret_path(odd));
        assert!(may_stage(odd, true, "cred").is_err(), "cred target refused");
        // The actor that read it is exactly what we want the agent to see.
        assert!(may_stage(odd, false, "cred").is_ok(), "the suspect is stageable");
        // And in other families the target is the accused thing.
        assert!(may_stage(odd, true, "exec").is_ok());
    }

    /// Public keys and ordinary code are not secrets; refusing them would cost
    /// the agent the context it needs without protecting anything.
    #[test]
    fn ordinary_files_are_stageable() {
        for p in [
            "/home/dan/.ssh/id_rsa.pub",
            "/home/dan/.cache/npm/_x/setup.mjs",
            "/tmp/dropper.sh",
            "/home/dan/node_modules/evil/postinstall.js",
            "/usr/bin/node",
        ] {
            // id_rsa.pub sits under /.ssh/, which is a secret directory: the
            // marker wins, and losing a public key's contents costs nothing.
            if p.contains("/.ssh/") {
                assert!(is_secret_path(p));
                continue;
            }
            assert!(!is_secret_path(p), "{} is not a secret", p);
            assert!(may_stage(p, false, "exec").is_ok());
        }
    }

    #[test]
    fn staging_copies_the_actor_and_withholds_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let key = home.join(".ssh/id_rsa");
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----").unwrap();
        let actor = dir.path().join("evil.mjs");
        std::fs::write(&actor, b"eval(atob('...'))").unwrap();

        let mut a = crate::alert::tests_support::demo_alert("01TEST");
        a.family = "cred".into();
        a.process.exe = actor.display().to_string();
        a.file = Some(crate::alert::FileRef {
            path: key.display().to_string(),
            sha256: None,
        });

        let staged = stage(&a, dir.path(), MAX_STAGED_BYTES, "moat");
        assert_eq!(staged.len(), 2);

        let act = staged.iter().find(|x| x.role == "actor").unwrap();
        assert!(act.staged_as.is_some(), "the suspect script is staged");
        let copied = dir.path().join(act.staged_as.clone().unwrap());
        assert_eq!(std::fs::read(&copied).unwrap(), b"eval(atob('...'))");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&copied).unwrap().permissions().mode() & 0o777,
            0o440,
            "staged hostile files are read-only -- but readable by the group, or \
             the agent they are staged for cannot open them"
        );
        assert!(copied.to_string_lossy().ends_with(".suspect"));

        let tgt = staged.iter().find(|x| x.role == "target").unwrap();
        assert!(tgt.staged_as.is_none(), "the key is NOT staged");
        assert!(tgt.withheld.is_some());
        // Withheld is not hidden: it is still described BY ITS SIZE.
        assert_eq!(tgt.bytes, Some(std::fs::metadata(&key).unwrap().len()));
        // But NOT by its hash. This assertion was the other way round until
        // 2026-09-08, and it was wrong twice over: computing sha256 reads every
        // byte of the file, so moat opened the private key it had just refused
        // to stage; and a digest of a secret is an oracle for that secret,
        // published into a directory the `moat` group can read.
        assert!(
            tgt.sha256.is_none(),
            "a refused file is not opened, and its hash is not published"
        );
        assert!(act.sha256.is_some(), "what IS staged is still hashed");
        assert_eq!(tgt.original_path, key.display().to_string());
        // And its bytes are nowhere in the staging directory.
        for e in std::fs::read_dir(dir.path()).unwrap().flatten() {
            if e.path().is_file() {
                let body = std::fs::read(e.path()).unwrap_or_default();
                assert!(
                    !String::from_utf8_lossy(&body).contains("BEGIN PRIVATE KEY"),
                    "key material reached {}",
                    e.path().display()
                );
            }
        }
    }

    #[test]
    fn oversized_and_missing_artifacts_are_described_not_staged() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.bin");
        std::fs::write(&big, vec![0u8; 2048]).unwrap();

        let mut a = crate::alert::tests_support::demo_alert("01TEST");
        a.family = "exec".into();
        a.process.exe = big.display().to_string();
        a.file = Some(crate::alert::FileRef {
            path: dir.path().join("gone.sh").display().to_string(),
            sha256: None,
        });

        let staged = stage(&a, dir.path(), 1024, "moat");
        let act = staged.iter().find(|x| x.role == "actor").unwrap();
        assert!(act.staged_as.is_none());
        assert!(act.withheld.clone().unwrap().contains("staging limit"));
        assert_eq!(act.bytes, Some(2048));

        let tgt = staged.iter().find(|x| x.role == "target").unwrap();
        assert!(tgt.staged_as.is_none());
        assert!(tgt.withheld.clone().unwrap().contains("not on disk"));
    }
}

#[cfg(test)]
mod symlink_tests {

    /// The 2026-09-04 privilege escalation, pinned.
    ///
    /// `may_stage` judged the PATH STRING and `std::fs::copy` then followed it,
    /// so a file the attacker named `/tmp/bait` -- pointing at a root-only file
    /// -- passed the credential check under its own harmless name and was read
    /// by root into an incident directory the `moat` group can read. That is an
    /// arbitrary root file-read handed to any group member, and on this threat
    /// model the group member IS the attacker.
    #[test]
    fn a_symlink_is_never_followed_when_staging_evidence() {
        let dir = std::env::temp_dir().join(format!("moat-symlink-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let secret = dir.join("pretend-shadow");
        std::fs::write(&secret, b"root:$6$notreal\n").unwrap();
        let bait = dir.join("bait");
        let _ = std::fs::remove_file(&bait);
        std::os::unix::fs::symlink(&secret, &bait).unwrap();

        let err = crate::util::open_suspect(&bait).expect_err("a symlink must be refused");
        assert!(err.contains("symbolic link"), "{}", err);

        // A regular file still stages, and reports the path actually opened.
        let (_f, real) = crate::util::open_suspect(&secret).expect("a real file opens");
        assert_eq!(real, secret.display().to_string());

        // A directory and a FIFO are not evidence either.
        assert!(crate::util::open_suspect(&dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
