//! `moat-x-new-exec-ioc`.
//!
//! Fills NOTES gap 6: `binary_properties` never carries a hash, so the sha256 of
//! an executed file has to be computed in userspace. We only hash executables
//! from the places a dropper writes to — `$HOME`, `/tmp`, `/var/tmp`,
//! `/dev/shm` — and only once per (path, mtime, size), because hashing every
//! exec on a build machine would be absurd.
//!
//! A hit against `feeds/hashes.txt` (operator-supplied; see docs/PACKAGE-FEED.md) is as
//! close to certainty as this system gets, hence `critical`.

use std::collections::HashMap;
use std::path::Path;

use crate::alert::{FileRef, IocRef};
use crate::config::Config;
use crate::event::ExecEvent;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::rules::{meta, RuleCtx, UserRule};

pub const ID: &str = "moat-x-new-exec-ioc";

/// Keyed by path; value is (mtime, size, sha256) so a rebuilt binary is rehashed.
type HashCache = HashMap<String, (i64, u64, String)>;

#[derive(Default)]
pub struct NewExecIoc {
    cache: HashCache,
}

impl NewExecIoc {
    /// Hash `path`, reusing the cache when the file has not changed.
    fn hash(&mut self, path: &str) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).ok()?;
        let key = (meta.mtime(), meta.size());
        if let Some((mt, sz, h)) = self.cache.get(path) {
            if (*mt, *sz) == key {
                return Some(h.clone());
            }
        }
        let h = crate::util::sha256_file(Path::new(path)).ok()?;
        // Bound the cache: a build box execs a lot of distinct paths.
        if self.cache.len() > 4096 {
            self.cache.clear();
        }
        self.cache.insert(path.to_string(), (key.0, key.1, h.clone()));
        Some(h)
    }

    fn watched_roots(ctx: &RuleCtx) -> Vec<String> {
        let mut roots: Vec<String> = ctx.homes.to_vec();
        roots.extend(["/tmp".to_string(), "/var/tmp".to_string(), "/dev/shm".to_string()]);
        roots
    }
}

impl UserRule for NewExecIoc {
    fn id(&self) -> &'static str {
        ID
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.new_exec_ioc
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            ID,
            "exec",
            "critical",
            "Executed file matches a known-malware hash",
            "The sha256 of this binary is in the local hash feed of samples seen in the wild. \
             That is not a heuristic: this exact file has been submitted as malware.",
            "Almost never. A false positive needs a hash collision with a sample someone \
             uploaded — far more likely is that a security tool or a malware sample you are \
             studying lives in one of the watched directories.",
            &["ssh-key", "github-token", "npm-token", "browser", "keyring"],
            &["kill", "quarantine", "ignore"],
            "exe",
        )
    }

    fn on_exec(&mut self, _ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        if ctx.feeds.hashes.is_empty() {
            return Vec::new();
        }
        let exe = match ctx.table.get(exec_id) {
            Some(p) if !p.exe.is_empty() => p.exe.clone(),
            _ => return Vec::new(),
        };
        if !crate::util::under_any(&exe, &Self::watched_roots(ctx)) {
            return Vec::new();
        }
        let Some(sha) = self.hash(&exe) else {
            return Vec::new();
        };
        if !ctx.feeds.hash_hit(&sha) {
            return Vec::new();
        }

        let Some(mut f) = ctx.finding(ID, self.meta(), exec_id) else {
            return Vec::new();
        };
        f.hook = "userland: sha256 of the executed file".into();
        f.file = Some(FileRef {
            path: exe.clone(),
            sha256: Some(sha.clone()),
        });
        f.ioc = Some(IocRef {
            source: "hash-feed".into(),
            matched: format!("sha256:{}", sha),
        });
        f.what_override = Some(format!(
            "{} is a known-malware binary: its sha256 is in the local hash feed.",
            exe
        ));
        f.extra_evidence = vec![format!(
            "feed: {} hashes loaded, last updated {}",
            ctx.feeds.meta.hashes,
            ctx.feeds.meta.updated.as_deref().unwrap_or("never")
        )];
        vec![f]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::Feeds;
    use crate::proctable::ProcTable;
    use crate::rules::testkit::{cfg, proc};

    fn feeds_with(dir: &Path, hash: &str) -> Feeds {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("hashes.txt"), format!("{}\n", hash)).unwrap();
        Feeds::load(dir)
    }

    fn run(rule: &mut NewExecIoc, t: &ProcTable, feeds: &Feeds, homes: &[String], id: &str) -> Vec<Finding> {
        let cfg = cfg();
        let ctx = RuleCtx {
            rarity: &crate::rarity::RarityStore::default(),
            cfg: &cfg,
            table: t,
            feeds,
            homes,
            now: 100,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
        };
        rule.on_exec(&ExecEvent::default(), id, &ctx)
    }

    #[test]
    fn a_dropped_binary_with_a_feed_hit_is_critical() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home/dan");
        std::fs::create_dir_all(&home).unwrap();
        let bin = home.join(".cache/x9k");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, b"malicious payload").unwrap();
        let sha = crate::util::sha256_file(&bin).unwrap();

        let feeds = feeds_with(&dir.path().join("feeds"), &sha);
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 41300, bin.to_str().unwrap(), "-q", None));

        let homes = vec![home.to_string_lossy().to_string()];
        let mut rule = NewExecIoc::default();
        let f = run(&mut rule, &t, &feeds, &homes, "e1");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "critical");
        assert_eq!(f[0].file.as_ref().unwrap().sha256.as_deref(), Some(sha.as_str()));
        assert!(f[0].ioc.as_ref().unwrap().matched.starts_with("sha256:"));

        // Second exec of the same file must not re-hash (cache hit) but must
        // still fire.
        assert_eq!(run(&mut rule, &t, &feeds, &homes, "e1").len(), 1);
        assert_eq!(rule.cache.len(), 1);
    }

    #[test]
    fn a_clean_binary_is_silent() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("clean");
        std::fs::write(&bin, b"fine").unwrap();
        let feeds = feeds_with(&dir.path().join("feeds"), "00ff");
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 1, bin.to_str().unwrap(), "", None));
        let homes = vec![dir.path().to_string_lossy().to_string()];
        assert!(run(&mut NewExecIoc::default(), &t, &feeds, &homes, "e1").is_empty());
    }

    #[test]
    fn binaries_outside_the_watched_roots_are_not_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let feeds = feeds_with(&dir.path().join("feeds"), "00ff");
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 1, "/usr/bin/ls", "", None));
        let homes = vec!["/home/dan".to_string()];
        let mut rule = NewExecIoc::default();
        assert!(run(&mut rule, &t, &feeds, &homes, "e1").is_empty());
        assert!(rule.cache.is_empty(), "/usr/bin must never be hashed");
    }

    #[test]
    fn an_empty_feed_short_circuits() {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 1, "/tmp/x", "", None));
        let f = run(
            &mut NewExecIoc::default(),
            &t,
            &Feeds::default(),
            &["/home/dan".to_string()],
            "e1",
        );
        assert!(f.is_empty());
    }

    #[test]
    fn a_rebuilt_file_is_rehashed() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("v");
        std::fs::write(&bin, b"one").unwrap();
        let mut rule = NewExecIoc::default();
        let h1 = rule.hash(bin.to_str().unwrap()).unwrap();
        std::fs::write(&bin, b"two different content").unwrap();
        let h2 = rule.hash(bin.to_str().unwrap()).unwrap();
        assert_ne!(h1, h2);
    }
}
