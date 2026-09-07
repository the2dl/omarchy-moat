//! `moat-ransom-file-churn`.
//!
//! Ransomware behaviour, judged by shape rather than by name. Two shapes:
//!
//! 1. **Read, then destroy, the same file -- across many files.** An actor
//!    opens a document for reading and then unlinks it, renames it away, or
//!    empties it with `O_TRUNC`; and does that to N distinct files inside a
//!    window. Builds delete files they never read (`cargo clean`, `rm -rf
//!    node_modules`); backups read files they never delete; an editor writes a
//!    temp file and renames *that* over the original, so the path it read is
//!    never the path it destroys. Encryption reads the plaintext and destroys
//!    it, whether by writing `x.locked` and unlinking `x`, by rewriting `x` in
//!    place and renaming it, or by truncating and overwriting it.
//! 2. **Homogenisation.** N distinct files renamed to ONE shared new extension
//!    in the window (`report.pdf` -> `report.pdf.locked`, `cat.jpg` ->
//!    `cat.jpg.locked`). Deliberately NOT a list of known ransomware suffixes,
//!    which is worthless against anything written this year: the tell is that
//!    files of many kinds became files of one kind, or that a suffix was
//!    appended to every name.
//!
//! Fed by the kernel policy of the same name (`policies/ransom-file-churn.yaml`),
//! which posts read-opens, unlinks, renames and truncates under the document
//! directories of every human home and nothing else. The policy is `signal`
//! and carries no `rateLimit` -- `rateLimit` suppresses events and never counts
//! them (NOTES gap 5), which is the reason `mass_read` exists and the reason
//! this rule does. Because the rule owns the policy id, `engine::rule_owns`
//! stops the kernel's per-event record from becoming a finding: a hundred
//! unlinks are input to this rule, not a hundred timeline rows.
//!
//! State is a per-actor, per-path machine. The actor is the process, except
//! that the children of a shell are folded into that shell: a loop of `openssl
//! enc … && rm` is one thing doing the encrypting, not two hundred short-lived
//! processes that each did one harmless step. Same structure as `mass_read`:
//! bounded map, sliding window, fire once, then reset.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::config::Config;
use crate::event::HookHit;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::proctable::{ProcInfo, ProcTable};
use crate::rules::{meta, RuleCtx, UserRule, LOGIN_SHELLS};
use crate::util::basename;

pub const ID: &str = "moat-ransom-file-churn";

/// The read half, as an LSM hook name or its kprobe twin (NOTES §3).
const READ_HOOKS: &[&str] = &["security_file_post_open", "file_post_open"];
const UNLINK_HOOK: &str = "security_path_unlink";
const RENAME_HOOK: &str = "security_path_rename";
const TRUNCATE_HOOK: &str = "security_path_truncate";

/// MAY_READ, from NOTES §3.
const MAY_READ: i64 = 4;

/// Path fragments that mark a build or cache tree. The kernel policy scopes by
/// directory prefix, and Prefix cannot say "not under a node_modules anywhere
/// below ~/Documents" (NOTES gap 2: no middle wildcard), so a project checked
/// out under a document directory still posts its build churn. Cut here: an
/// `npm update` reads a package's `package.json` and then removes the package,
/// which is shape 1 to the letter, eight packages at a time. Ransomware that
/// encrypts a `node_modules` also encrypts everything around it, so nothing
/// worth catching lives only in these.
///
/// Mirrors `telemetry.quiet_creates_under`, for the same reason it exists.
const BUILD_TREES: &[&str] = &[
    "/node_modules/",
    "/.cache/",
    "/.npm/",
    "/target/",
    "/.git/",
    "/__pycache__/",
    "/.venv/",
    "/site-packages/",
    "/.cargo/registry/",
    "/dist/",
    "/build/",
];

/// Reads remembered per actor. A thumbnailer over a big photo folder reads
/// thousands of files and destroys none; it must not grow the map without
/// bound, and the oldest reads are the ones least likely to pair with a later
/// destruction anyway.
const MAX_READS_PER_ACTOR: usize = 4096;
/// Distinct destroyed paths remembered per actor inside the window.
const MAX_DESTROYED_PER_ACTOR: usize = 4096;
/// Actors tracked before the map is pruned (same figure as `mass_read`).
const MAX_ACTORS: usize = 512;

/// What was done to a file that stops it being what it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Destroy {
    Unlinked,
    Renamed,
    Truncated,
}

impl Destroy {
    fn word(self) -> &'static str {
        match self {
            Destroy::Unlinked => "deleted",
            Destroy::Renamed => "renamed",
            Destroy::Truncated => "emptied",
        }
    }
}

#[derive(Clone, Debug)]
struct Destroyed {
    at: u64,
    path: String,
    kind: Destroy,
    /// Renames only: where the file went.
    new_path: Option<String>,
    /// Did this actor read the file inside the window before destroying it?
    read_first: bool,
    /// Which process did it (the comm), for the evidence line of a folded actor.
    by: String,
}

impl Destroyed {
    /// `name_actor` adds who did it, for a folded actor whose members differ.
    fn describe(&self, name_actor: bool) -> String {
        let by = if name_actor { format!(" by {}", self.by) } else { String::new() };
        match (&self.kind, &self.new_path) {
            (Destroy::Renamed, Some(n)) => format!("{} -> {}{}", self.path, n, by),
            _ => format!("{} ({}{})", self.path, self.kind.word(), by),
        }
    }
}

#[derive(Default)]
struct Actor {
    /// Recent read-opens, oldest first: `(when, path)`.
    reads: VecDeque<(u64, String)>,
    /// Distinct paths destroyed inside the window, oldest first.
    destroyed: VecDeque<Destroyed>,
    /// Comms of every process that contributed, for a folded actor.
    members: BTreeSet<String>,
    /// unix seconds of the last event, for pruning.
    last: u64,
}

impl Actor {
    fn prune(&mut self, now: u64, window: u64) {
        while let Some((t, _)) = self.reads.front() {
            if now.saturating_sub(*t) >= window {
                self.reads.pop_front();
            } else {
                break;
            }
        }
        while let Some(d) = self.destroyed.front() {
            if now.saturating_sub(d.at) >= window {
                self.destroyed.pop_front();
            } else {
                break;
            }
        }
    }

    fn note_read(&mut self, now: u64, path: String) {
        if self.reads.iter().any(|(_, p)| p == &path) {
            return;
        }
        if self.reads.len() >= MAX_READS_PER_ACTOR {
            self.reads.pop_front();
        }
        self.reads.push_back((now, path));
    }

    fn read_recently(&self, path: &str) -> bool {
        self.reads.iter().any(|(_, p)| p == path)
    }

    fn note_destroyed(&mut self, d: Destroyed) {
        // Distinct paths: the same file renamed twice, or truncated and then
        // unlinked, is one file.
        if self.destroyed.iter().any(|x| x.path == d.path) {
            return;
        }
        if self.destroyed.len() >= MAX_DESTROYED_PER_ACTOR {
            self.destroyed.pop_front();
        }
        self.destroyed.push_back(d);
    }
}

/// Which of the two shapes fired, with the files that made it.
enum Shape {
    ReadThenDestroy(Vec<Destroyed>),
    Homogenised { ext: String, files: Vec<Destroyed> },
}

#[derive(Default)]
pub struct RansomChurn {
    actors: HashMap<String, Actor>,
}

impl UserRule for RansomChurn {
    fn id(&self) -> &'static str {
        ID
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.ransom_file_churn
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            ID,
            "ransom",
            "critical",
            "Files read and then destroyed, many at a time",
            "One program read a document and then deleted, renamed away or emptied that same \
             document, and did it to many different files inside a minute. That is what \
             encrypting a directory looks like from the kernel: the plaintext is read, the \
             ciphertext is written somewhere, and the original is made to go away. Builds \
             delete files they never read and backups read files they never delete; doing \
             both to the same file, over and over, is the one shape they do not share. The \
             other shape reported here is many different files renamed to one new extension \
             -- files of many kinds becoming files of one kind.",
            "Rarely. A script you wrote to reorganise photos by moving them across \
             filesystems (a copy and then a delete of each), a batch tool rewriting images or \
             notes in place (jpegoptim, exiftool -overwrite_original_in_place, prettier \
             --write on a folder of markdown), or you renaming a folder of files to a new \
             suffix by hand. mv, rsync, tar and the sync and backup clients are excluded in \
             the kernel, and terminal editors that rename the original to `file~` on save \
             (vim, nvim, emacs) are excluded too. It watches your document directories only \
             -- Documents, Desktop, Pictures, Videos, Music, Downloads -- so a sweep that \
             never reaches them is not seen here.",
            &[],
            &["kill", "ignore"],
            "exe",
        )
    }

    fn on_hook(&mut self, h: &HookHit, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        // Only the policy of the same name feeds this. The rule owns that id,
        // so the engine hands every one of its events here and raises none of
        // them itself.
        if h.policy_name() != ID || exec_id.is_empty() {
            return Vec::new();
        }
        let Some(me) = ctx.table.get(exec_id) else {
            return Vec::new();
        };
        let hook = h.hook_name();
        let window = ctx.cfg.thresholds.ransom_churn_window_secs;
        let threshold = ctx.cfg.thresholds.ransom_churn_files;
        let now = ctx.now;

        // Keep the map from growing without bound on a busy machine.
        if self.actors.len() > MAX_ACTORS {
            self.actors
                .retain(|_, a| now.saturating_sub(a.last) < window);
        }

        let (key, folded_under) = actor_key(ctx.table, me);
        let by = me.comm().to_string();
        let actor = self.actors.entry(key).or_default();
        actor.last = now;
        actor.prune(now, window);
        actor.members.insert(by.clone());

        if READ_HOOKS.contains(&hook.as_str()) {
            // A mask, when present, must include MAY_READ (`file_post_open`
            // reports acc_mode; a write-open is not a read).
            if let Some(mask) = h.int_arg() {
                if mask & MAY_READ == 0 {
                    return Vec::new();
                }
            }
            let Some(path) = h.file_path() else {
                return Vec::new();
            };
            if in_build_tree(&path) {
                return Vec::new();
            }
            actor.note_read(now, path);
            return Vec::new();
        }

        // The destroy half. Unlink and rename report the PARENT directory as a
        // mount-aware `path` and the file itself as a bare `dentry`; a dentry
        // resolves no further than its own filesystem root (`/@home/dan/…` on
        // btrfs, see util::dentry_abs), so the full name is the parent joined
        // with the dentry's basename, which no subvolume prefix can touch.
        let (path, kind, new_path) = match hook.as_str() {
            UNLINK_HOOK => match (path_at(h, 0), path_at(h, 1)) {
                (Some(dir), Some(dentry)) => (join(dir, dentry), Destroy::Unlinked, None),
                _ => return Vec::new(),
            },
            RENAME_HOOK => match (path_at(h, 0), path_at(h, 1)) {
                (Some(dir), Some(dentry)) => {
                    // new_dir / new_dentry are indexes 2 and 3 of
                    // security_path_rename. Reported for evidence and for the
                    // homogenisation shape; absent (an older policy rendering,
                    // a truncated event) the rename still counts as a
                    // destruction of the old path.
                    let new = match (path_at(h, 2), path_at(h, 3)) {
                        (Some(d), Some(n)) => Some(join(d, n)),
                        _ => None,
                    };
                    (join(dir, dentry), Destroy::Renamed, new)
                }
                _ => return Vec::new(),
            },
            TRUNCATE_HOOK => match path_at(h, 0) {
                Some(p) => (p, Destroy::Truncated, None),
                None => return Vec::new(),
            },
            _ => return Vec::new(),
        };
        if in_build_tree(&path) {
            return Vec::new();
        }
        let read_first = actor.read_recently(&path);
        actor.note_destroyed(Destroyed {
            at: now,
            path,
            kind,
            new_path,
            read_first,
            by,
        });

        let Some(shape) = evaluate(actor, threshold) else {
            return Vec::new();
        };
        // Fired: reset so the next alert needs another full burst (the alert
        // deduper would otherwise fold every subsequent event into a count).
        // Reads are kept: they are context, not the thing counted.
        let members: Vec<String> = actor.members.iter().cloned().collect();
        actor.destroyed.clear();
        actor.members.clear();
        // A fold is only worth naming when more than one program took part;
        // `sh -c "node install.js"` is node, and the alert should say node.
        let folded_under = folded_under.filter(|_| members.len() > 1);

        let Some(mut f) = ctx.finding(ID, self.meta(), exec_id) else {
            return Vec::new();
        };
        let actor_words = match &folded_under {
            Some(shell) => format!(
                "the children of {} (pid {}: {})",
                shell.comm(),
                shell.pid,
                members.join(", ")
            ),
            None => f.proc.comm().to_string(),
        };
        let (files, ext) = match &shape {
            Shape::ReadThenDestroy(files) => (files, None),
            Shape::Homogenised { ext, files } => (files, Some(ext.clone())),
        };
        let first = files.iter().map(|d| d.at).min().unwrap_or(now);
        let span = now.saturating_sub(first).max(1);
        let sample: Vec<String> = files
            .iter()
            .take(5)
            .map(|d| d.describe(folded_under.is_some()))
            .collect();

        match &shape {
            Shape::ReadThenDestroy(files) => {
                f.hook = format!(
                    "userland: {} distinct files read and then destroyed in {} s",
                    files.len(),
                    span
                );
                f.what_override = Some(format!(
                    "{} read {} different files under your documents and then deleted, renamed \
                     away or emptied each of them, all inside {} seconds.",
                    actor_words,
                    files.len(),
                    span
                ));
            }
            Shape::Homogenised { ext, files } => {
                // Weaker than read-then-destroy: a person renaming a folder
                // of files to `.bak` by hand is this shape too. High, and
                // the badge, but not the top of the ladder.
                f.meta.severity = "high".into();
                f.hook = format!(
                    "userland: {} distinct files renamed to .{} in {} s",
                    files.len(),
                    ext,
                    span
                );
                f.what_override = Some(format!(
                    "{} renamed {} different files to the same new extension .{} inside {} \
                     seconds.",
                    actor_words,
                    files.len(),
                    ext,
                    span
                ));
            }
        }
        f.extra_evidence = vec![
            format!(
                "threshold: {} distinct files inside {} s (the {}th is the trigger)",
                threshold, window, threshold
            ),
            format!("first files: {}", sample.join(", ")),
        ];
        if let Shape::ReadThenDestroy(_) = &shape {
            f.extra_evidence.push(
                "each of these was opened for reading by the same actor inside the window \
                 before it was destroyed; a delete without a read, or a read without a \
                 delete, is never counted"
                    .to_string(),
            );
        }
        if let Some(ext) = shared_extension(files) {
            f.extra_evidence
                .push(format!("every rename in the burst ended in the same new extension: .{}", ext));
        } else if let Some(ext) = ext {
            f.extra_evidence.push(format!("shared new extension: .{}", ext));
        }
        if let Some(shell) = &folded_under {
            f.extra_evidence.push(format!(
                "counted across the children of {} (pid {}), because a shell loop that \
                 encrypts with one program and deletes with another is one actor",
                shell.comm(),
                shell.pid
            ));
        }
        vec![f]
    }
}

/// The process whose file activity is accumulated together: the process
/// itself, or its parent when that parent is a shell. Returns the key and, when
/// folded, the shell.
fn actor_key(table: &ProcTable, me: &ProcInfo) -> (String, Option<ProcInfo>) {
    if let Some(parent) = me
        .parent_exec_id
        .as_deref()
        .and_then(|id| table.get(id))
    {
        if LOGIN_SHELLS.contains(&parent.comm()) {
            return (parent.exec_id.clone(), Some(parent.clone()));
        }
    }
    (me.exec_id.clone(), None)
}

/// Which shape, if any, the window now satisfies. Read-then-destroy wins when
/// both do: it is the stronger claim.
fn evaluate(actor: &Actor, threshold: usize) -> Option<Shape> {
    let read_first: Vec<Destroyed> = actor
        .destroyed
        .iter()
        .filter(|d| d.read_first)
        .cloned()
        .collect();
    // `<`, not `<=`: N means N, as `mass_read` says at length.
    if read_first.len() >= threshold {
        return Some(Shape::ReadThenDestroy(read_first));
    }

    // Homogenisation: group renames by the extension they were renamed TO.
    let mut by_ext: BTreeMap<String, Vec<&Destroyed>> = BTreeMap::new();
    for d in actor.destroyed.iter().filter(|d| d.kind == Destroy::Renamed) {
        let Some(new) = d.new_path.as_deref() else {
            continue;
        };
        if let Some(ext) = extension(new) {
            by_ext.entry(ext).or_default().push(d);
        }
    }
    let (ext, group) = by_ext.into_iter().max_by_key(|(_, g)| g.len())?;
    if group.len() < threshold {
        return None;
    }
    // The variety test. Files of several kinds became files of one kind, or a
    // suffix was appended to every name. Without it, a browser finishing eight
    // photo downloads (`x.jpg.crdownload` -> `x.jpg`) and an editor's
    // temp-then-rename save (`.f.rs.tmp` -> `f.rs`) would both read as
    // homogenisation, and neither is: their sources were already one kind, and
    // the names got shorter, not longer.
    let old_kinds: BTreeSet<Option<String>> = group.iter().map(|d| extension(&d.path)).collect();
    let appended = group
        .iter()
        .filter(|d| {
            let new = d.new_path.as_deref().map(basename).unwrap_or("");
            let old = basename(&d.path);
            new.len() > old.len() && new.starts_with(old)
        })
        .count();
    if old_kinds.len() < 2 && appended < threshold {
        return None;
    }
    Some(Shape::Homogenised {
        ext,
        files: group.into_iter().cloned().collect(),
    })
}

/// The extension every rename in `files` ended in, when there is exactly one.
fn shared_extension(files: &[Destroyed]) -> Option<String> {
    let mut exts: BTreeSet<String> = BTreeSet::new();
    let mut renames = 0;
    for d in files {
        if d.kind != Destroy::Renamed {
            continue;
        }
        renames += 1;
        exts.insert(extension(d.new_path.as_deref()?)?);
    }
    if renames >= 2 && exts.len() == 1 {
        exts.into_iter().next()
    } else {
        None
    }
}

/// `report.pdf.locked` -> `locked`; `.bashrc` and `Makefile` -> none.
fn extension(path: &str) -> Option<String> {
    let base = basename(path);
    let (stem, ext) = base.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() || ext.len() > 16 || ext.contains(char::is_whitespace) {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

fn in_build_tree(path: &str) -> bool {
    BUILD_TREES.iter().any(|frag| path.contains(frag))
}

/// The `i`th argument as a path, whichever of Tetragon's path-shaped
/// encodings it arrived in. `path` and `dentry` are both exported as
/// `path_arg` (v1.7.1 `pkg/sensors/tracing/args_linux.go`); `file` as
/// `file_arg`.
fn path_at(h: &HookHit, i: usize) -> Option<String> {
    let a = h.ev.args.get(i)?;
    for key in ["path_arg", "file_arg"] {
        if let Some(p) = a.get(key).and_then(|v| v.get("path")).and_then(|p| p.as_str()) {
            return Some(p.to_string());
        }
    }
    None
}

/// Parent directory + the basename of a dentry path.
fn join(dir: String, dentry: String) -> String {
    let name = basename(&dentry);
    if dir.ends_with('/') {
        format!("{}{}", dir, name)
    } else {
        format!("{}/{}", dir, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HookEvent, HookKind};
    use crate::feeds::Feeds;
    use crate::rules::testkit::{cfg, proc};

    fn read(path: &str) -> HookEvent {
        HookEvent {
            function_name: Some("security_file_post_open".into()),
            policy_name: Some(ID.into()),
            args: vec![
                serde_json::json!({"file_arg":{"path":path,"permission":"-rw-r--r--"}}),
                serde_json::json!({"int_arg":4}),
            ],
            ..Default::default()
        }
    }

    /// The kernel reports the parent as a `path` and the file as a `dentry`;
    /// on this btrfs machine the dentry carries the subvolume root
    /// (`/@home/…`) rather than the mount, exactly as measured for
    /// `util::dentry_abs` on 2026-09-04.
    fn unlink(path: &str) -> HookEvent {
        let (dir, name) = path.rsplit_once('/').unwrap();
        HookEvent {
            function_name: Some(UNLINK_HOOK.into()),
            policy_name: Some(ID.into()),
            args: vec![
                serde_json::json!({"path_arg":{"path":dir}}),
                serde_json::json!({"path_arg":{"path":format!("/@home{}/{}", &dir["/home".len()..], name)}}),
            ],
            ..Default::default()
        }
    }

    fn rename(old: &str, new: &str) -> HookEvent {
        let (odir, oname) = old.rsplit_once('/').unwrap();
        let (ndir, nname) = new.rsplit_once('/').unwrap();
        HookEvent {
            function_name: Some(RENAME_HOOK.into()),
            policy_name: Some(ID.into()),
            args: vec![
                serde_json::json!({"path_arg":{"path":odir}}),
                serde_json::json!({"path_arg":{"path":format!("/@home{}/{}", &odir["/home".len()..], oname)}}),
                serde_json::json!({"path_arg":{"path":ndir}}),
                serde_json::json!({"path_arg":{"path":format!("/@home{}/{}", &ndir["/home".len()..], nname)}}),
            ],
            ..Default::default()
        }
    }

    fn truncate(path: &str) -> HookEvent {
        HookEvent {
            function_name: Some(TRUNCATE_HOOK.into()),
            policy_name: Some(ID.into()),
            args: vec![serde_json::json!({"path_arg":{"path":path}})],
            ..Default::default()
        }
    }

    /// `alacritty -> fish -> sh -c … -> node`, plus a few stand-alone tools.
    fn table() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-term", 41100, "/usr/bin/alacritty", "", None));
        t.observe(&proc("e-fish", 41101, "/usr/bin/fish", "", Some("e-term")));
        t.observe(&proc("e-npm", 41201, "/usr/bin/npm", "install", Some("e-fish")));
        t.observe(&proc("e-sh", 41202, "/usr/bin/sh", "-c node install.js", Some("e-npm")));
        t.observe(&proc("e-node", 41250, "/usr/bin/node", "install.js", Some("e-sh")));
        t.observe(&proc("e-git", 41300, "/usr/bin/git", "checkout main", Some("e-fish")));
        t.observe(&proc("e-restic", 41301, "/usr/bin/restic", "backup /home/dan", None));
        t.observe(&proc("e-code", 41302, "/usr/lib/code/code", "", Some("e-term")));
        t.observe(&proc("e-chromium", 41303, "/usr/lib/chromium/chromium", "", Some("e-term")));
        // A shell loop: `for f in *; do openssl enc … "$f" > "$f.enc"; rm "$f"; done`
        t.observe(&proc("e-loop", 41400, "/usr/bin/bash", "-c for f in *; …", Some("e-fish")));
        for i in 0..20 {
            t.observe(&proc(
                &format!("e-ossl-{}", i),
                41500 + i,
                "/usr/bin/openssl",
                "enc -aes-256-cbc",
                Some("e-loop"),
            ));
            t.observe(&proc(&format!("e-rm-{}", i), 41600 + i, "/usr/bin/rm", "--", Some("e-loop")));
            t.observe(&proc(&format!("e-mv-{}", i), 41700 + i, "/usr/bin/mv", "--", Some("e-loop")));
        }
        t
    }

    fn fire(rule: &mut RansomChurn, t: &ProcTable, c: &Config, e: &HookEvent, exec_id: &str, now: u64) -> Vec<Finding> {
        let feeds = Feeds::default();
        let homes = vec!["/home/dan".to_string()];
        let ctx = RuleCtx {
            rarity: &crate::rarity::RarityStore::default(),
            cfg: c,
            table: t,
            feeds: &feeds,
            homes: &homes,
            now,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
        };
        rule.on_hook(&HookHit { kind: HookKind::Kprobe, ev: e }, exec_id, &ctx)
    }

    fn doc(i: usize) -> String {
        let exts = ["pdf", "docx", "jpg", "xlsx", "md"];
        format!("/home/dan/Documents/report-{}.{}", i, exts[i % exts.len()])
    }

    #[test]
    fn a_process_that_reads_then_deletes_many_documents_fires_once_and_is_critical() {
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        let mut out = Vec::new();
        // Encrypt-to-a-new-file-then-unlink: read x, write x.locked, rm x.
        for i in 0..12 {
            assert!(fire(&mut rule, &t, &c, &read(&doc(i)), "e-node", 100 + i as u64).is_empty());
            out.extend(fire(&mut rule, &t, &c, &unlink(&doc(i)), "e-node", 100 + i as u64));
        }
        assert_eq!(out.len(), 1, "fires on the 8th read-then-destroyed file, then resets");
        let f = &out[0];
        assert_eq!(f.meta.severity, "critical");
        assert_eq!(f.meta.family, "ransom");
        assert!(f.what_override.as_ref().unwrap().contains("node read 8 different files"), "{:?}", f.what_override);
        assert!(f.extra_evidence[1].contains("/home/dan/Documents/report-0.pdf (deleted)"), "{:?}", f.extra_evidence);
        assert!(f.hook.contains("8 distinct files read and then destroyed"));
    }

    #[test]
    fn in_place_encryption_that_renames_the_file_afterwards_is_the_same_sweep() {
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        let mut out = Vec::new();
        for i in 0..8 {
            let p = doc(i);
            fire(&mut rule, &t, &c, &read(&p), "e-node", 200);
            // Rewritten through O_TRUNC, then given the family's suffix.
            out.extend(fire(&mut rule, &t, &c, &truncate(&p), "e-node", 200));
            out.extend(fire(&mut rule, &t, &c, &rename(&p, &format!("{}.locked", p)), "e-node", 201));
        }
        // The 8th truncate of a just-read file fires it. The rename of the same
        // path is not a second file, and after the reset it is one file, not
        // eight, so nothing fires twice.
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.meta.severity, "critical");
        assert!(f.extra_evidence[1].contains("(emptied)"), "{:?}", f.extra_evidence);
    }

    #[test]
    fn a_build_deleting_files_it_never_read_is_not_a_sweep() {
        // `cargo clean`, `rm -rf node_modules`, `make clean`: hundreds of
        // unlinks, not one preceded by a read of the same path.
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        for i in 0..200 {
            let p = format!("/home/dan/Documents/proj/out/obj-{}.o", i);
            assert!(fire(&mut rule, &t, &c, &unlink(&p), "e-node", 300).is_empty());
        }
        // And truncating files it did not read (a fresh `> log` on each) is
        // not one either.
        for i in 0..50 {
            let p = format!("/home/dan/Documents/proj/out/log-{}.txt", i);
            assert!(fire(&mut rule, &t, &c, &truncate(&p), "e-node", 300).is_empty());
        }
    }

    #[test]
    fn a_backup_reading_everything_and_deleting_nothing_is_not_a_sweep() {
        // restic is excluded in the kernel as well; this proves the rule
        // itself needs the destroy half even when the read half is a flood.
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        for i in 0..5000 {
            let p = format!("/home/dan/Pictures/2026/img-{}.jpg", i);
            assert!(fire(&mut rule, &t, &c, &read(&p), "e-restic", 400).is_empty());
        }
        // Memory stays bounded however long it reads.
        assert!(rule.actors["e-restic"].reads.len() <= MAX_READS_PER_ACTOR);
    }

    #[test]
    fn git_checkout_switching_branches_is_not_a_sweep() {
        // A checkout reads the index and objects, unlinks worktree files it
        // did not read, writes new ones fresh (a create, so no truncate), and
        // renames `index.lock` over `index`. Nothing here is a path that was
        // both read and destroyed. (`.git/` is also a build tree and git is
        // excluded in the kernel; the test drives the shape past both.)
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        for i in 0..40 {
            fire(&mut rule, &t, &c, &read(&format!("/home/dan/Documents/thesis/objects/{:02x}/blob", i)), "e-git", 500);
        }
        for i in 0..40 {
            let p = format!("/home/dan/Documents/thesis/chapter-{}.tex", i);
            assert!(fire(&mut rule, &t, &c, &unlink(&p), "e-git", 500).is_empty());
        }
        for _ in 0..40 {
            assert!(fire(&mut rule, &t, &c, &rename("/home/dan/Documents/thesis/index.lock", "/home/dan/Documents/thesis/index"), "e-git", 500).is_empty());
        }
    }

    #[test]
    fn an_editor_atomic_save_loop_is_not_a_sweep() {
        // Save-all in an editor that writes a temp file and renames it over
        // the original: the path it READ (`f.rs`) is the rename's NEW name,
        // never its old one, and the new extensions vary with the files.
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        for i in 0..20 {
            let p = doc(i);
            let tmp = format!("/home/dan/Documents/.report-{}.tmp", i);
            fire(&mut rule, &t, &c, &read(&p), "e-code", 600);
            assert!(fire(&mut rule, &t, &c, &rename(&tmp, &p), "e-code", 600).is_empty(), "save #{}", i);
        }
        // The same twenty files all being `.md` notes -- homogenous source,
        // homogenous target, names not lengthened -- is still not a sweep.
        for i in 0..20 {
            let p = format!("/home/dan/Documents/notes/n-{}.md", i);
            let tmp = format!("/home/dan/Documents/notes/.n-{}.md.tmp", i);
            fire(&mut rule, &t, &c, &read(&p), "e-code", 601);
            assert!(fire(&mut rule, &t, &c, &rename(&tmp, &p), "e-code", 601).is_empty(), "note #{}", i);
        }
    }

    #[test]
    fn a_browser_finishing_a_batch_of_downloads_is_not_homogenisation() {
        // Twenty `x.jpg.crdownload` -> `x.jpg`: every new name is one kind,
        // but so was every old name, and the names got shorter. Nothing was
        // read first either.
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        for i in 0..20 {
            let fin = format!("/home/dan/Downloads/photo-{}.jpg", i);
            let tmp = format!("{}.crdownload", fin);
            assert!(fire(&mut rule, &t, &c, &rename(&tmp, &fin), "e-chromium", 700).is_empty(), "download #{}", i);
        }
    }

    #[test]
    fn homogenising_many_files_to_one_new_extension_fires_without_a_read() {
        // Files of five kinds all become `.locked`. No read is needed: the
        // encryption may have happened through an fd this rule never saw.
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        let mut out = Vec::new();
        for i in 0..10 {
            let p = doc(i);
            out.extend(fire(&mut rule, &t, &c, &rename(&p, &format!("{}.locked", p)), "e-node", 800 + i as u64));
        }
        assert_eq!(out.len(), 1, "fires on the 8th distinct file renamed to .locked");
        let f = &out[0];
        assert_eq!(f.meta.severity, "high", "weaker than read-then-destroy");
        assert!(f.what_override.as_ref().unwrap().contains("to the same new extension .locked"), "{:?}", f.what_override);
        assert!(f.extra_evidence.iter().any(|e| e.contains("ended in the same new extension: .locked")), "{:?}", f.extra_evidence);
        assert!(f.extra_evidence[1].contains("report-0.pdf -> /home/dan/Documents/report-0.pdf.locked"), "{:?}", f.extra_evidence);

        // Files of ONE kind given the same suffix is the appended shape and
        // fires too: `cat.jpg` -> `cat.jpg.enc`, a whole photo folder.
        let mut rule = RansomChurn::default();
        let mut out = Vec::new();
        for i in 0..8 {
            let p = format!("/home/dan/Pictures/cat-{}.jpg", i);
            out.extend(fire(&mut rule, &t, &c, &rename(&p, &format!("{}.enc", p)), "e-node", 900));
        }
        assert_eq!(out.len(), 1);

        // But files of one kind REPLACED with another extension, names not
        // lengthened -- `mv *.jpeg *.jpg` -- is a person tidying, not a sweep.
        let mut rule = RansomChurn::default();
        for i in 0..20 {
            let p = format!("/home/dan/Pictures/cat-{}.jpeg", i);
            assert!(fire(&mut rule, &t, &c, &rename(&p, &format!("/home/dan/Pictures/cat-{}.jpg", i)), "e-node", 950).is_empty());
        }
    }

    #[test]
    fn a_shell_loop_of_openssl_and_rm_is_one_actor() {
        // Each iteration is two fresh processes; per-process they each did one
        // harmless thing. Folded into the shell that spawned them they read
        // and then deleted eight files.
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        let mut out = Vec::new();
        for i in 0..8 {
            let p = doc(i);
            assert!(fire(&mut rule, &t, &c, &read(&p), &format!("e-ossl-{}", i), 1000 + i as u64).is_empty());
            out.extend(fire(&mut rule, &t, &c, &unlink(&p), &format!("e-rm-{}", i), 1000 + i as u64));
        }
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.meta.severity, "critical");
        assert!(f.what_override.as_ref().unwrap().contains("the children of bash (pid 41400: openssl, rm)"), "{:?}", f.what_override);
        assert!(f.extra_evidence.iter().any(|e| e.contains("counted across the children of bash")), "{:?}", f.extra_evidence);
        assert!(f.extra_evidence[1].contains("report-0.pdf (deleted by rm)"), "{:?}", f.extra_evidence);
        // The finding is pinned on the process that tripped it, with the
        // shell in its ancestry.
        assert_eq!(f.proc.comm(), "rm");

        // The same fold catches `for f in *; do mv "$f" "$f.locked"; done`.
        let mut rule = RansomChurn::default();
        let mut out = Vec::new();
        for i in 0..8 {
            let p = doc(i);
            out.extend(fire(&mut rule, &t, &c, &rename(&p, &format!("{}.locked", p)), &format!("e-mv-{}", i), 1100));
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].meta.severity, "high");
    }

    #[test]
    fn build_trees_under_a_document_directory_are_ignored() {
        // `npm update` in ~/Documents/proj: reads each package's
        // package.json and then removes the package -- shape 1 exactly, and
        // the kernel cannot exclude a node_modules that sits under Documents.
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        for i in 0..30 {
            let p = format!("/home/dan/Documents/proj/node_modules/pkg-{}/package.json", i);
            fire(&mut rule, &t, &c, &read(&p), "e-node", 1200);
            assert!(fire(&mut rule, &t, &c, &unlink(&p), "e-node", 1200).is_empty());
        }
        for i in 0..30 {
            let p = format!("/home/dan/Documents/proj/target/debug/deps/lib-{}.rlib", i);
            fire(&mut rule, &t, &c, &read(&p), "e-node", 1200);
            assert!(fire(&mut rule, &t, &c, &rename(&p, &format!("{}.locked", p)), "e-node", 1200).is_empty());
        }
    }

    #[test]
    fn only_its_own_policy_feeds_this_rule() {
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        for i in 0..20 {
            let mut r = read(&doc(i));
            r.policy_name = Some("moat-cred-project-token-read".into());
            let mut u = unlink(&doc(i));
            u.policy_name = Some("moat-rootkit-evidence-tamper".into());
            assert!(fire(&mut rule, &t, &c, &r, "e-node", 1300).is_empty());
            assert!(fire(&mut rule, &t, &c, &u, "e-node", 1300).is_empty());
        }
        assert!(rule.actors.is_empty());
    }

    #[test]
    fn events_spread_past_the_window_never_accumulate() {
        let t = table();
        let mut c = cfg();
        c.thresholds.ransom_churn_window_secs = 10;
        let mut rule = RansomChurn::default();
        for i in 0..40u64 {
            let p = doc(i as usize);
            // One file every 11 s: the window never holds two.
            fire(&mut rule, &t, &c, &read(&p), "e-node", 2000 + i * 11);
            assert!(fire(&mut rule, &t, &c, &unlink(&p), "e-node", 2000 + i * 11).is_empty());
        }
        // A read that is older than the window does not make a later delete a
        // read-then-destroy.
        let mut rule = RansomChurn::default();
        for i in 0..20 {
            fire(&mut rule, &t, &c, &read(&doc(i)), "e-node", 3000);
        }
        for i in 0..20 {
            assert!(fire(&mut rule, &t, &c, &unlink(&doc(i)), "e-node", 3011).is_empty());
        }
    }

    #[test]
    fn a_write_open_is_not_a_read() {
        // `file_post_open` reports acc_mode; a write-open of a file this
        // actor then deletes is "write then delete", not "read then delete".
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        for i in 0..20 {
            let p = doc(i);
            let mut w = read(&p);
            w.args[1] = serde_json::json!({"int_arg":2});
            fire(&mut rule, &t, &c, &w, "e-node", 4000);
            assert!(fire(&mut rule, &t, &c, &unlink(&p), "e-node", 4000).is_empty());
        }
    }

    #[test]
    fn the_dentry_path_is_joined_onto_the_mount_aware_parent() {
        // The parent arrives as `/home/dan/Documents`, the file as
        // `/@home/dan/Documents/x.pdf`: the finding must say /home, never /@home.
        let t = table();
        let c = cfg();
        let mut rule = RansomChurn::default();
        let mut out = Vec::new();
        for i in 0..8 {
            fire(&mut rule, &t, &c, &read(&doc(i)), "e-node", 5000);
            out.extend(fire(&mut rule, &t, &c, &unlink(&doc(i)), "e-node", 5000));
        }
        assert_eq!(out.len(), 1);
        assert!(!out[0].extra_evidence[1].contains("/@home"), "{:?}", out[0].extra_evidence);
        assert!(out[0].extra_evidence[1].contains("/home/dan/Documents/report-0.pdf"));

        assert_eq!(extension("/a/report.pdf.locked").as_deref(), Some("locked"));
        assert_eq!(extension("/a/.bashrc"), None);
        assert_eq!(extension("/a/Makefile"), None);
        assert_eq!(extension("/a/x."), None);
        assert_eq!(join("/home/dan/Documents".into(), "/@home/dan/Documents/x.pdf".into()), "/home/dan/Documents/x.pdf");
    }
}
