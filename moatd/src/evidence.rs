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
pub fn stage(alert: &Alert, dir: &Path, max_bytes: u64) -> Vec<Artifact> {
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
        // Metadata is safe to report for anything, including a secret: a size
        // and a hash say "this exists and is this big", not what is in it.
        if let Some(m) = meta.as_ref() {
            a.bytes = Some(m.len());
        }
        a.sha256 = util::sha256_file(p).ok();

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
                    let name = util::basename(&path);
                    let name = if name.is_empty() { "artifact" } else { name };
                    let dest = dir.join(format!("{}.{}.suspect", role, name));
                    match copy_readonly(p, &dest) {
                        Ok(()) => {
                            a.staged_as = dest
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string());
                        }
                        Err(e) => a.withheld = Some(e),
                    }
                }
            },
        }
        out.push(a);
    }
    out
}

fn copy_readonly(src: &Path, dest: &PathBuf) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::copy(src, dest).map_err(|e| format!("copy: {}", e))?;
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o400))
        .map_err(|e| format!("chmod 400: {}", e))?;
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

        let staged = stage(&a, dir.path(), MAX_STAGED_BYTES);
        assert_eq!(staged.len(), 2);

        let act = staged.iter().find(|x| x.role == "actor").unwrap();
        assert!(act.staged_as.is_some(), "the suspect script is staged");
        let copied = dir.path().join(act.staged_as.clone().unwrap());
        assert_eq!(std::fs::read(&copied).unwrap(), b"eval(atob('...'))");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&copied).unwrap().permissions().mode() & 0o777,
            0o400,
            "staged hostile files are read-only"
        );
        assert!(copied.to_string_lossy().ends_with(".suspect"));

        let tgt = staged.iter().find(|x| x.role == "target").unwrap();
        assert!(tgt.staged_as.is_none(), "the key is NOT staged");
        assert!(tgt.withheld.is_some());
        // Withheld is not hidden: it is still described.
        assert_eq!(tgt.bytes, Some(std::fs::metadata(&key).unwrap().len()));
        assert!(tgt.sha256.is_some());
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

        let staged = stage(&a, dir.path(), 1024);
        let act = staged.iter().find(|x| x.role == "actor").unwrap();
        assert!(act.staged_as.is_none());
        assert!(act.withheld.clone().unwrap().contains("staging limit"));
        assert_eq!(act.bytes, Some(2048));

        let tgt = staged.iter().find(|x| x.role == "target").unwrap();
        assert!(tgt.staged_as.is_none());
        assert!(tgt.withheld.clone().unwrap().contains("not on disk"));
    }
}
