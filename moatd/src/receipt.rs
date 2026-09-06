//! Install receipts (LEARNING §3).
//!
//! Every alert moat raises is a negative. A receipt is the positive picture: for
//! each package-manager subtree (`rules/pkgtree.rs`), one line written when the
//! **root** exits, saying what the install actually did.
//!
//! ```text
//! npm install in ~/Projects/app (41 s, exit 0)
//!   postinstall scripts: 3 (esbuild, sharp, husky)
//!   wrote outside the project: ~/.npm/_cacache, ~/.cache/prisma
//!   network: registry.npmjs.org, github.com
//!   credential reads: none · persistence writes: .husky/pre-commit (alerted, low)
//!   binaries executed from the tree: 12 · from /tmp: 0
//! ```
//!
//! Receipts are **informational**: they are their own line kind in
//! `alerts.jsonl` (`{"v":1,"receipt":{…}}`), they never notify, they never
//! count towards the badge, and no allowlist or dedupe touches them. They are
//! also what the AI analysis reads when an alert comes out of an install.
//!
//! The tracker below accumulates one [`Acc`] per subtree root while the install
//! runs, and turns it into a [`Receipt`] on the root's `process_exit`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::proctable::ProcInfo;
use crate::rarity::dir_of;
use crate::util::{self, basename};

/// How many entries any one list in a receipt keeps. A pathological install
/// must not turn one line of `alerts.jsonl` into a megabyte.
pub const LIST_CAP: usize = 64;

/// Directories whose executables count as "from /tmp" (LEARNING §3).
pub const TMP_ROOTS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

/// One persistence write the install performed, and whether it was loud.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceWrite {
    pub path: String,
    /// False when an allowlist entry suppressed the alert: the write happened,
    /// the user had already said it was fine.
    pub alerted: bool,
    pub severity: String,
}

/// The shape LEARNING §9 pins. The plugin is built against exactly this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub id: String,
    pub root_exe: String,
    pub root_args: String,
    pub cwd: String,
    pub started: String,
    pub duration_s: u64,
    pub exit: i64,
    pub postinstall_scripts: Vec<String>,
    pub writes_outside_project: Vec<String>,
    pub network: Vec<String>,
    pub credential_reads: Vec<String>,
    pub persistence_writes: Vec<PersistenceWrite>,
    pub execs_from_tree: u64,
    pub execs_from_tmp: u64,
}

/// One line of `alerts.jsonl`. `AlertStore::load` ignores it (it parses as
/// neither a full alert nor an update), which is why receipts can share the file
/// without a reader ever mistaking one for an alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptLine {
    pub v: u32,
    pub receipt: Receipt,
}

impl Receipt {
    pub fn line(&self) -> ReceiptLine {
        ReceiptLine {
            v: crate::alert::ALERT_V,
            receipt: self.clone(),
        }
    }

    /// The `npm install in …` block of LEARNING §3, for `moatctl receipts`.
    pub fn render(&self) -> String {
        let mut out = format!(
            "{} {} in {} ({} s, exit {})",
            basename(&self.root_exe),
            first_word(&self.root_args),
            if self.cwd.is_empty() { "(unknown cwd)" } else { &self.cwd },
            self.duration_s,
            self.exit
        );
        out.push_str(&format!(
            "\n  postinstall scripts: {}{}",
            self.postinstall_scripts.len(),
            list_suffix(&self.postinstall_scripts)
        ));
        out.push_str(&format!(
            "\n  wrote outside the project: {}",
            or_none(&self.writes_outside_project)
        ));
        out.push_str(&format!("\n  network: {}", or_none(&self.network)));
        let persist: Vec<String> = self
            .persistence_writes
            .iter()
            .map(|p| {
                format!(
                    "{} ({}, {})",
                    p.path,
                    if p.alerted { "alerted" } else { "suppressed" },
                    p.severity
                )
            })
            .collect();
        out.push_str(&format!(
            "\n  credential reads: {} · persistence writes: {}",
            or_none(&self.credential_reads),
            or_none(&persist)
        ));
        out.push_str(&format!(
            "\n  binaries executed from the tree: {} · from /tmp: {}",
            self.execs_from_tree, self.execs_from_tmp
        ));
        out
    }
}

fn first_word(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
}

fn or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join(", ")
    }
}

fn list_suffix(v: &[String]) -> String {
    if v.is_empty() {
        String::new()
    } else {
        format!(" ({})", v.join(", "))
    }
}

/// What we know about one running install.
#[derive(Debug, Clone)]
pub struct Acc {
    pub root_exec_id: String,
    pub root_exe: String,
    pub root_args: String,
    pub cwd: String,
    pub started: String,
    started_unix: u64,
    /// Wall clock at which the accumulator was created, for pruning installs
    /// whose exit we never saw.
    opened: u64,
    pub scripts: Vec<String>,
    pub writes_outside_project: Vec<String>,
    pub network: Vec<String>,
    pub credential_reads: Vec<String>,
    pub persistence_writes: Vec<PersistenceWrite>,
    pub execs_from_tree: u64,
    pub execs_from_tmp: u64,
}

impl Acc {
    fn new(root: &ProcInfo, now: u64) -> Acc {
        let started_unix = util::rfc3339_to_nanos(&root.start_time)
            .map(|n| (n / 1_000_000_000) as u64)
            .unwrap_or(now);
        Acc {
            root_exec_id: root.exec_id.clone(),
            root_exe: root.exe.clone(),
            root_args: root.args.clone(),
            cwd: root.cwd.clone(),
            started: util::normalize_ts(&root.start_time),
            started_unix,
            opened: now,
            scripts: Vec::new(),
            writes_outside_project: Vec::new(),
            network: Vec::new(),
            credential_reads: Vec::new(),
            persistence_writes: Vec::new(),
            execs_from_tree: 0,
            execs_from_tmp: 0,
        }
    }
}

fn push_capped(v: &mut Vec<String>, s: String) {
    if s.is_empty() || v.len() >= LIST_CAP || v.contains(&s) {
        return;
    }
    v.push(s);
}

/// `…/node_modules/@scope/pkg/scripts/install.js` -> `@scope/pkg`;
/// `…/node_modules/sharp/install.js` -> `sharp`.
///
/// The **last** `node_modules` segment wins, because nested dependency trees
/// (`a/node_modules/b`) are the package that actually ran.
pub fn node_package_of(path: &str) -> Option<String> {
    let idx = path.rfind("/node_modules/")?;
    let rest = &path[idx + "/node_modules/".len()..];
    let mut it = rest.split('/');
    let first = it.next().filter(|s| !s.is_empty())?;
    if first.starts_with('@') {
        let second = it.next().filter(|s| !s.is_empty())?;
        return Some(format!("{}/{}", first, second));
    }
    // `.bin`, `.package-lock.json`, `.pnpm` and friends are npm's own
    // bookkeeping, not packages. A binary under `node_modules/.bin/` is counted
    // as an exec from the tree instead.
    if first.starts_with('.') {
        return None;
    }
    Some(first.to_string())
}

/// Interpreters whose first path-looking argument is the script they run.
const SCRIPT_INTERPRETERS: &[&str] = &[
    "node", "nodejs", "python", "python2", "python3", "perl", "ruby", "sh", "bash", "zsh", "dash",
    "ksh", "fish",
];

/// What this exec contributes to `postinstall_scripts`: the package it came out
/// of, or the script path an interpreter was handed. `None` for a plain binary,
/// which is counted in `execs_from_tree` / `execs_from_tmp` instead.
pub fn script_hint(exe: &str, args: &str) -> Option<String> {
    if let Some(p) = node_package_of(exe) {
        return Some(p);
    }
    for tok in args.split_whitespace() {
        let tok = tok.trim_matches(['"', '\'']);
        if let Some(p) = node_package_of(tok) {
            return Some(p);
        }
    }
    if SCRIPT_INTERPRETERS.contains(&basename(exe)) {
        for tok in args.split_whitespace() {
            let tok = tok.trim_matches(['"', '\'']);
            if tok.starts_with('-') {
                continue;
            }
            // A script, not a subcommand: it has to look like a file.
            if tok.contains('/') || tok.rsplit('.').next().map(is_script_ext).unwrap_or(false) {
                return Some(tok.to_string());
            }
            break;
        }
    }
    None
}

fn is_script_ext(ext: &str) -> bool {
    matches!(ext, "js" | "cjs" | "mjs" | "py" | "sh" | "rb" | "pl" | "ts")
}

pub fn under(path: &str, dir: &str) -> bool {
    if dir.is_empty() {
        return false;
    }
    let dir = dir.trim_end_matches('/');
    path.len() > dir.len() + 1 && path.starts_with(dir) && path.as_bytes()[dir.len()] == b'/'
}

pub fn in_tmp(path: &str) -> bool {
    TMP_ROOTS.iter().any(|r| path.starts_with(r))
}

/// One accumulator per live subtree root.
#[derive(Debug, Default)]
pub struct Tracker {
    open: HashMap<String, Acc>,
    /// Receipts written since start, for `status`.
    pub written: u64,
}

impl Tracker {
    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Make sure the root has an accumulator. Called on every exec inside a
    /// subtree, because the daemon may have started mid-install.
    pub fn ensure(&mut self, root: &ProcInfo, now: u64) {
        if let Some(a) = self.open.get_mut(&root.exec_id) {
            // A later event can carry the argv the first sighting lacked.
            if a.root_args.is_empty() && !root.args.is_empty() {
                a.root_args = root.args.clone();
            }
            if a.cwd.is_empty() && !root.cwd.is_empty() {
                a.cwd = root.cwd.clone();
            }
            return;
        }
        self.open.insert(root.exec_id.clone(), Acc::new(root, now));
    }

    /// One `process_exec` somewhere under `root`.
    pub fn note_exec(&mut self, root_exec_id: &str, child: &ProcInfo) {
        let Some(a) = self.open.get_mut(root_exec_id) else {
            return;
        };
        if let Some(s) = script_hint(&child.exe, &child.args) {
            push_capped(&mut a.scripts, s);
        }
        if in_tmp(&child.exe) {
            a.execs_from_tmp += 1;
        } else if under(&child.exe, &a.cwd) {
            a.execs_from_tree += 1;
        }
    }

    /// One finding attributed to this subtree. Suppressed findings count too:
    /// the write still happened, and the receipt is a record of what the install
    /// did, not of what moat shouted about.
    #[allow(clippy::too_many_arguments)]
    pub fn note_finding(
        &mut self,
        root_exec_id: &str,
        family: &str,
        access: Option<&str>,
        file: Option<&str>,
        net: Option<&str>,
        severity: &str,
        alerted: bool,
    ) {
        let Some(a) = self.open.get_mut(root_exec_id) else {
            return;
        };
        if let Some(dst) = net {
            push_capped(&mut a.network, dst.to_string());
        }
        let Some(path) = file else { return };
        let writing = access.map(is_write).unwrap_or(family == "persist");
        match family {
            "cred" if !writing => push_capped(&mut a.credential_reads, path.to_string()),
            "persist"
                if a.persistence_writes.len() < LIST_CAP
                    && !a.persistence_writes.iter().any(|p| p.path == path) =>
            {
                a.persistence_writes.push(PersistenceWrite {
                    path: path.to_string(),
                    alerted,
                    severity: severity.to_string(),
                });
            }
            _ => {}
        }
        // "Outside the project" is the interesting half: an install writing
        // inside its own worktree is what installs do.
        if writing && (family == "persist" || family == "cred") && !under(path, &a.cwd) {
            push_capped(&mut a.writes_outside_project, dir_of(path));
        }
    }

    /// The root exited: turn the accumulator into a receipt. `root` is used to
    /// build one on the spot when the daemon started mid-install.
    pub fn finish(&mut self, root: &ProcInfo, status: Option<u32>, now: u64) -> Receipt {
        let a = self
            .open
            .remove(&root.exec_id)
            .unwrap_or_else(|| Acc::new(root, now));
        Receipt {
            id: ulid::Ulid::new().to_string(),
            root_exe: a.root_exe,
            root_args: a.root_args,
            cwd: a.cwd,
            started: a.started,
            duration_s: now.saturating_sub(a.started_unix),
            exit: status.map(|s| s as i64).unwrap_or(0),
            postinstall_scripts: a.scripts,
            writes_outside_project: a.writes_outside_project,
            network: a.network,
            credential_reads: a.credential_reads,
            persistence_writes: a.persistence_writes,
            execs_from_tree: a.execs_from_tree,
            execs_from_tmp: a.execs_from_tmp,
        }
    }

    /// Drop installs whose exit we never saw (the daemon was restarted, the log
    /// rotated, the export dropped the exit line). Unbounded growth here would
    /// be a slow leak on a build machine.
    pub fn prune(&mut self, now: u64, max_age_secs: u64) -> usize {
        let before = self.open.len();
        self.open
            .retain(|_, a| now.saturating_sub(a.opened) < max_age_secs);
        before - self.open.len()
    }
}

fn is_write(access: &str) -> bool {
    access.contains("write") || access.contains("append")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Started at unix second 1000, so a `finish` at 1041 is a 41 s install.
    fn proc(id: &str, pid: u32, exe: &str, args: &str, cwd: &str) -> ProcInfo {
        ProcInfo {
            exec_id: id.into(),
            pid,
            uid: 1000,
            exe: exe.into(),
            args: args.into(),
            cwd: cwd.into(),
            start_time: util::rfc3339_of(1_000),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            sid: None,
            tty: None,
        }
    }

    #[test]
    fn a_node_modules_path_names_its_package_scope_included() {
        assert_eq!(
            node_package_of("/home/dan/app/node_modules/sharp/install.js").as_deref(),
            Some("sharp")
        );
        assert_eq!(
            node_package_of("/home/dan/app/node_modules/@esbuild/linux-x64/install.js").as_deref(),
            Some("@esbuild/linux-x64")
        );
        // Nested trees: the innermost package is the one that ran.
        assert_eq!(
            node_package_of("/a/node_modules/outer/node_modules/inner/x.js").as_deref(),
            Some("inner")
        );
        assert_eq!(node_package_of("/usr/bin/node"), None);
    }

    #[test]
    fn a_script_hint_prefers_the_package_then_the_script_path() {
        assert_eq!(
            script_hint("/usr/bin/node", "/home/dan/app/node_modules/husky/lib/install.js")
                .as_deref(),
            Some("husky")
        );
        assert_eq!(
            script_hint("/usr/bin/python3", "setup.py build").as_deref(),
            Some("setup.py")
        );
        assert_eq!(
            script_hint("/usr/bin/sh", "/home/dan/app/scripts/post.sh").as_deref(),
            Some("/home/dan/app/scripts/post.sh")
        );
        // `-c` is code, not a file, and a bare binary contributes nothing.
        assert_eq!(script_hint("/usr/bin/sh", "-c 'echo hi'"), None);
        assert_eq!(script_hint("/usr/bin/cc", "-c foo.c"), None);
    }

    #[test]
    fn under_needs_a_real_child_and_tmp_is_recognised() {
        assert!(under("/home/dan/app/node_modules/.bin/x", "/home/dan/app"));
        assert!(!under("/home/dan/apple/x", "/home/dan/app"));
        assert!(!under("/home/dan/app", "/home/dan/app"));
        assert!(!under("/x", ""));
        assert!(in_tmp("/tmp/.x9k"));
        assert!(in_tmp("/dev/shm/payload"));
        assert!(!in_tmp("/home/dan/tmp/x"));
    }

    /// The whole §3 flow: one install, several children, some findings, exit.
    #[test]
    fn a_finished_install_produces_the_shape_the_plugin_parses() {
        let mut t = Tracker::default();
        let root = proc(
            "e-npm",
            41201,
            "/usr/bin/npm",
            "install",
            "/home/dan/Projects/app",
        );
        t.ensure(&root, 1_000);
        assert_eq!(t.len(), 1);

        t.note_exec(
            "e-npm",
            &proc(
                "e-a",
                41230,
                "/usr/bin/node",
                "/home/dan/Projects/app/node_modules/esbuild/install.js",
                "/home/dan/Projects/app",
            ),
        );
        t.note_exec(
            "e-npm",
            &proc(
                "e-b",
                41231,
                "/usr/bin/node",
                "/home/dan/Projects/app/node_modules/husky/lib/bin.js install",
                "/home/dan/Projects/app",
            ),
        );
        // `node_modules/.bin/` is npm's own shim directory, not a package: this
        // one counts as a binary executed from the tree, not as a script.
        t.note_exec(
            "e-npm",
            &proc(
                "e-d",
                41233,
                "/home/dan/Projects/app/node_modules/.bin/tsc",
                "--noEmit",
                "/home/dan/Projects/app",
            ),
        );
        t.note_exec("e-npm", &proc("e-c", 41232, "/tmp/.x9k", "", ""));

        t.note_finding("e-npm", "net", None, None, Some("registry.npmjs.org"), "medium", true);
        t.note_finding("e-npm", "net", None, None, Some("registry.npmjs.org"), "medium", true);
        t.note_finding(
            "e-npm",
            "cred",
            Some("read"),
            Some("/home/dan/.aws/credentials"),
            None,
            "critical",
            true,
        );
        t.note_finding(
            "e-npm",
            "persist",
            Some("write"),
            Some("/home/dan/Projects/app/.husky/pre-commit"),
            None,
            "low",
            true,
        );
        t.note_finding(
            "e-npm",
            "persist",
            Some("write"),
            Some("/home/dan/.config/systemd/user/evil.service"),
            None,
            "critical",
            false,
        );

        let r = t.finish(&root, Some(0), 1_041);
        assert_eq!(r.duration_s, 41);
        assert!(t.is_empty(), "the accumulator is consumed by the receipt");
        assert_eq!(r.root_exe, "/usr/bin/npm");
        assert_eq!(r.cwd, "/home/dan/Projects/app");
        assert_eq!(r.exit, 0);
        assert_eq!(r.postinstall_scripts, vec!["esbuild", "husky"]);
        assert_eq!(r.network, vec!["registry.npmjs.org"], "deduped");
        assert_eq!(r.credential_reads, vec!["/home/dan/.aws/credentials"]);
        assert_eq!(r.persistence_writes.len(), 2);
        assert_eq!(r.persistence_writes[0].severity, "low");
        assert!(!r.persistence_writes[1].alerted, "suppressed is recorded as such");
        // The project's own .husky write is not "outside the project".
        assert_eq!(
            r.writes_outside_project,
            vec!["/home/dan/.config/systemd/user"]
        );
        assert_eq!(r.execs_from_tree, 1, "node_modules/.bin/tsc");
        assert_eq!(r.execs_from_tmp, 1);
        assert!(!r.id.is_empty());

        // The line shape LEARNING §9 pins.
        let line = serde_json::to_string(&r.line()).unwrap();
        assert!(line.starts_with("{\"v\":1,\"receipt\":{"));
        for k in [
            "\"id\"", "\"root_exe\"", "\"root_args\"", "\"cwd\"", "\"started\"",
            "\"duration_s\"", "\"exit\"", "\"postinstall_scripts\"",
            "\"writes_outside_project\"", "\"network\"", "\"credential_reads\"",
            "\"persistence_writes\"", "\"execs_from_tree\"", "\"execs_from_tmp\"",
        ] {
            assert!(line.contains(k), "receipt line has no {}", k);
        }
        // And it is not an alert: the alert reader must skip it.
        assert!(crate::alert::parse_record(&line).is_none());
    }

    #[test]
    fn a_receipt_renders_the_block_from_the_doc() {
        let mut t = Tracker::default();
        let root = proc("e", 1, "/usr/bin/npm", "install", "/home/dan/app");
        t.ensure(&root, 1_000);
        let r = t.finish(&root, Some(0), 1_041);
        let text = r.render();
        assert!(text.starts_with("npm install in /home/dan/app (41 s, exit 0)"), "{}", text);
        assert!(text.contains("postinstall scripts: 0"));
        assert!(text.contains("credential reads: none · persistence writes: none"));
        assert!(text.contains("binaries executed from the tree: 0 · from /tmp: 0"));
    }

    #[test]
    fn an_install_whose_exit_we_never_see_is_pruned() {
        let mut t = Tracker::default();
        t.ensure(&proc("e", 1, "/usr/bin/npm", "install", "/x"), 1_000);
        assert_eq!(t.prune(1_100, 3_600), 0);
        assert_eq!(t.prune(10_000, 3_600), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn a_root_that_exits_without_ever_being_seen_still_gets_a_receipt() {
        let mut t = Tracker::default();
        let root = proc("e", 1, "/usr/bin/cargo", "build", "/home/dan/app");
        let r = t.finish(&root, Some(101), 1_005);
        assert_eq!(r.root_exe, "/usr/bin/cargo");
        assert_eq!(r.duration_s, 5);
        assert_eq!(r.exit, 101);
    }

    #[test]
    fn every_list_is_capped() {
        let mut t = Tracker::default();
        let root = proc("e", 1, "/usr/bin/npm", "install", "/home/dan/app");
        t.ensure(&root, 1_000);
        for i in 0..(LIST_CAP * 2) {
            t.note_finding("e", "net", None, None, Some(&format!("10.0.0.{}", i)), "low", true);
        }
        let r = t.finish(&root, Some(0), 1_001);
        assert_eq!(r.network.len(), LIST_CAP);
    }
}
