//! Selectable telemetry classes.
//!
//! An alert is a claim; telemetry is the record you go back to when the claim
//! was never made. moat has always had the second kind — Tetragon exports every
//! `PROCESS_EXEC`/`PROCESS_EXIT` on the machine — but it went into
//! `/var/log/moat/tetragon.log`, 0600 root:root, rotated away inside half an
//! hour. Full telemetry nobody could query. This module turns it into named,
//! switchable classes that land in a group-readable file `moat-ship` can send
//! somewhere it survives.
//!
//! # The four classes
//!
//! | class     | source                          | default | measured on this box |
//! |-----------|---------------------------------|---------|----------------------|
//! | `alerts`  | `alerts.jsonl`                  | **on**  | a handful a day      |
//! | `process` | exec/exit, already exported     | off     | ~42 ev/s, ~122 KB/s  |
//! | `network` | `moat-telemetry-network-connect`| off     | ~0.2 conn/s          |
//! | `file`    | `moat-telemetry-file-*`         | off     | ~1.2 ev/s scoped     |
//!
//! # Two rules that shape everything here
//!
//! **Telemetry never enters the detection path.** A broad file policy that was
//! evaluated against every rule would burn moatd's CPU on events that can never
//! raise an alert. Every policy this module owns is named `moat-telemetry-*`,
//! and [`is_telemetry_policy`] is checked in `engine::handle_line` *before*
//! `policy_finding` and `run_rules_hook` — the event updates the process table
//! (ancestry is the whole value of the record) and then leaves.
//!
//! **The `file` class is keyed on the file, not on the operation.** "Every
//! write" is the volume trap: measured on this machine, writes under `$HOME`
//! run at 24.5/s and one `npm install` of 171 packages produced 2769 of them in
//! three seconds. What a real EDR keeps is what the file could *become* —
//! something executable-shaped, or something in a place where anything at all
//! is interesting. The kernel filter is a suffix list and a location list; the
//! ladder that follows is in [`FileVerdict`]:
//!
//! * a **create** of an executable-shaped file — interesting;
//! * a **modify of one that already existed** — more interesting. On
//!   2026-09-04 a simulated npm package took a command over a WebSocket and
//!   rewrote its own `node_modules/express/index.js`, so the payload would
//!   survive every future `require`. Nothing raised a word. An installed script
//!   being rewritten after install is close to unambiguous;
//! * a **chmod +x** — often a better signal than the write before it, and
//!   nearly free;
//! * anything else — noise, not recorded.
//!
//! Creates inside a build tree are the bulk of the volume and almost none of
//! the value, so [`TelemetryConfig::quiet_creates_under`] drops *creates* under
//! `node_modules/`, `target/`, `.cache/` and friends. It never drops a modify:
//! that would delete the one case above.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::config::TelemetryConfig;
use crate::event::{ExecEvent, ExitEvent, HookHit};
use crate::proctable::{ProcInfo, ProcTable};

/// Every class name `moat.toml` and `moat-ship` accept.
pub const CLASSES: &[&str] = &["alerts", "process", "network", "file"];

/// Policies in this family are telemetry: recorded, never evaluated.
pub const POLICY_PREFIX: &str = "moat-telemetry-";

/// Record version, carried on every line so a collector can migrate.
pub const V: u32 = 1;

pub fn is_telemetry_policy(name: &str) -> bool {
    name.starts_with(POLICY_PREFIX)
}

/// Template file names each class owns, relative to `paths.templates_dir`.
///
/// `render` only writes the ones whose class is on, which is what makes a class
/// switchable: a policy that is not rendered is not in `tracing-policy-dir` and
/// is not in the export allowlist, so the kernel never attaches it and nothing
/// is written to disk for it.
pub fn templates_for(class: &str) -> &'static [&'static str] {
    match class {
        "network" => &["telemetry-network-connect.yaml"],
        "file" => &[
            "telemetry-file-exec-shape.yaml",
            "telemetry-file-became-executable.yaml",
        ],
        // `alerts` and `process` need no kernel policy: alerts.jsonl already
        // exists, and exec/exit cannot be filtered in-kernel anyway (NOTES §10)
        // so they are exported whatever we do. Both are shipping decisions.
        _ => &[],
    }
}

/// Every telemetry template, on or off. `render` uses this to know which files
/// in `templates_dir` are class-gated at all.
pub fn all_templates() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = CLASSES.iter().flat_map(|c| templates_for(c)).copied().collect();
    v.sort_unstable();
    v
}

/// Which class a template belongs to, or `None` for an always-on policy.
pub fn class_of_template(file_name: &str) -> Option<&'static str> {
    CLASSES
        .iter()
        .find(|c| templates_for(c).contains(&file_name))
        .copied()
}

// --------------------------------------------------------------- file verdict

/// The ladder of §"The `file` class". Ordered by how much it is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileVerdict {
    /// A file that did not exist a moment ago.
    Create,
    /// A file that did: the payload-persistence case.
    Modify,
    /// The mode gained an execute bit.
    ChmodX,
}

impl FileVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileVerdict::Create => "create",
            FileVerdict::Modify => "modify",
            FileVerdict::ChmodX => "chmod_x",
        }
    }
}

/// What made the path interesting to the kernel filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileShape {
    /// Suffix is one of the script extensions.
    Script,
    /// First bytes are `\x7fELF`. Only ever decided in userspace: the kernel
    /// cannot read file contents in a selector.
    Elf,
    /// Location alone is the reason (`/usr/bin/`, a unit directory, …).
    Location,
    Other,
}

impl FileShape {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileShape::Script => "script",
            FileShape::Elf => "elf",
            FileShape::Location => "location",
            FileShape::Other => "other",
        }
    }
}

/// `\x7fELF`, read from the file the kernel just named. Four bytes, on a path
/// that already passed the kernel's suffix/location filter, so this is a few
/// hundred reads a day and not a scan.
pub fn looks_like_elf(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

/// Create or modify, from the file's birth time.
///
/// `statx` `STATX_BTIME` is what separates "npm just unpacked this" from
/// "something rewrote a file that shipped three weeks ago", and it is the only
/// way to tell them apart from a single open event — the kernel's open hook
/// does not report `O_CREAT` in a form a selector or the export can carry.
///
/// A filesystem with no birth time (or a clock skew) answers `Modify`, which is
/// the cautious direction: a create mislabelled as a modify is one extra
/// record, a modify mislabelled as a create is the record you needed. A
/// `create_window_secs` of 0 therefore means "call everything a modify".
pub fn verdict_for(path: &Path, now: u64, create_window_secs: u64) -> FileVerdict {
    let Ok(meta) = std::fs::metadata(path) else {
        // Written and already gone: a dropper cleaning up after itself is much
        // more likely to be new than to be an edit of something installed.
        return FileVerdict::Create;
    };
    let Ok(born) = meta.created() else {
        return FileVerdict::Modify;
    };
    let Ok(age) = born.elapsed() else {
        return FileVerdict::Modify;
    };
    let _ = now;
    if age.as_secs() < create_window_secs {
        FileVerdict::Create
    } else {
        FileVerdict::Modify
    }
}

/// Is this a *create* the config says to stay quiet about?
///
/// Only creates. A modify under `node_modules/` is the whole point of the
/// class, so the same substring must never suppress one.
pub fn is_quiet_create(cfg: &TelemetryConfig, verdict: FileVerdict, path: &str) -> bool {
    verdict == FileVerdict::Create
        && cfg
            .quiet_creates_under
            .iter()
            .any(|frag| !frag.is_empty() && path.contains(frag.as_str()))
}

// --------------------------------------------------------------- projections

/// One telemetry line, ready for `telemetry.jsonl`.
#[derive(Debug, Clone)]
pub struct Record {
    pub class: &'static str,
    pub value: Value,
}

impl Record {
    pub fn to_line(&self) -> String {
        serde_json::to_string(&self.value).unwrap_or_default()
    }
}

fn base(class: &'static str, kind: &str, ts: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("v".into(), json!(V));
    m.insert("class".into(), json!(class));
    m.insert("kind".into(), json!(kind));
    m.insert("ts".into(), json!(ts));
    m
}

/// `process` class, exec half.
///
/// The export's own exec record duplicates the entire parent block inline on
/// every child — about half of its ~2.9 KB. Shipping `parent_exec_id` and
/// joining at the far end is the same graph for roughly half the bytes, so
/// that is the default; `inline_parent = true` restores the self-contained
/// form for collectors that cannot join.
pub fn exec_record(cfg: &TelemetryConfig, ev: &ExecEvent, ts: &str) -> Option<Record> {
    let p = ev.process.as_ref()?;
    let mut m = base("process", "exec", ts);
    m.insert("exec_id".into(), json!(p.exec_id));
    m.insert("parent_exec_id".into(), json!(p.parent_exec_id));
    m.insert("pid".into(), json!(p.pid));
    m.insert("uid".into(), json!(p.uid));
    m.insert("auid".into(), json!(p.auid));
    m.insert("exe".into(), json!(p.exe()));
    m.insert("args".into(), json!(p.args()));
    m.insert("cwd".into(), json!(p.cwd));
    m.insert("start_time".into(), json!(p.start_time));
    if cfg.inline_parent {
        if let Some(par) = ev.parent.as_ref() {
            m.insert(
                "parent".into(),
                json!({"exec_id": par.exec_id, "pid": par.pid, "exe": par.exe(), "args": par.args()}),
            );
        }
    }
    Some(Record {
        class: "process",
        value: Value::Object(m),
    })
}

/// `process` class, exit half. Tiny by design: the collector already has the
/// exec record this `exec_id` refers to.
pub fn exit_record(ev: &ExitEvent, ts: &str) -> Option<Record> {
    let p = ev.process.as_ref()?;
    let mut m = base("process", "exit", ts);
    m.insert("exec_id".into(), json!(p.exec_id));
    m.insert("pid".into(), json!(p.pid));
    m.insert("status".into(), json!(ev.status));
    m.insert("signal".into(), json!(ev.signal));
    Some(Record {
        class: "process",
        value: Value::Object(m),
    })
}

/// `network` class. Connect rates are orders of magnitude below exec rates
/// (measured here: 0.2/s against 42/s), which is what makes a *broad* policy
/// affordable where a broad file policy is not.
pub fn network_record(
    hook: &HookHit,
    table: &ProcTable,
    exec_id: &str,
    ts: &str,
) -> Option<Record> {
    let (ip, port) = hook.dest()?;
    let mut m = base("network", "connect", ts);
    m.insert("dst_ip".into(), json!(ip));
    m.insert("dst_port".into(), json!(port));
    m.insert("hook".into(), json!(hook.hook_name()));
    add_actor(&mut m, table, exec_id);
    Some(Record {
        class: "network",
        value: Value::Object(m),
    })
}

/// `file` class. `verdict`, `shape` and `pkg_root` are the three things the
/// kernel could not decide and moatd can.
#[allow(clippy::too_many_arguments)]
pub fn file_record(
    path: &str,
    verdict: FileVerdict,
    shape: FileShape,
    bytes: Option<u64>,
    sha256: Option<String>,
    body: Option<String>,
    table: &ProcTable,
    exec_id: &str,
    ts: &str,
) -> Record {
    let kind = if verdict == FileVerdict::ChmodX {
        "file_chmod"
    } else {
        "file_write"
    };
    let mut m = base("file", kind, ts);
    m.insert("path".into(), json!(path));
    m.insert("verdict".into(), json!(verdict.as_str()));
    m.insert("shape".into(), json!(shape.as_str()));
    m.insert("bytes".into(), json!(bytes));
    m.insert("sha256".into(), json!(sha256));
    if let Some(b) = body {
        m.insert("body".into(), json!(b));
    }
    add_actor(&mut m, table, exec_id);
    Record {
        class: "file",
        value: Value::Object(m),
    }
}

/// The actor block every non-process record carries: who did it, and whether
/// they were inside a package install. `pkg_root` is ancestry the kernel cannot
/// see (NOTES gap 1) and it is what separates "npm unpacked this" from
/// "something rewrote it afterwards".
fn add_actor(m: &mut Map<String, Value>, table: &ProcTable, exec_id: &str) {
    let me: Option<&ProcInfo> = table.get(exec_id);
    let (pid, uid, exe, args, cwd, parent) = match me {
        Some(p) => (
            json!(p.pid),
            json!(p.uid),
            json!(p.exe),
            json!(p.args),
            json!(p.cwd),
            json!(p.parent_exec_id),
        ),
        None => (
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ),
    };
    m.insert("exec_id".into(), json!(exec_id));
    m.insert("parent_exec_id".into(), parent);
    m.insert("pid".into(), pid);
    m.insert("uid".into(), uid);
    m.insert("exe".into(), exe);
    m.insert("args".into(), args);
    m.insert("cwd".into(), cwd);
    let root = crate::rules::pkgtree::pkg_root_for(table, exec_id).map(|r| r.exe.clone());
    m.insert("pkg_root".into(), json!(root));
}

// ------------------------------------------------------------------- the file

/// `telemetry.jsonl` — append only, rotated by rename, 0640 root:&lt;group&gt;.
///
/// Separate from `alerts.jsonl` on purpose. Alerts are a small, permanent,
/// user-facing record that the panel reads and the digest counts; telemetry is
/// high volume and disposable, and mixing them would push a week of alerts out
/// of the store in an afternoon.
pub struct TelemetryStore {
    path: std::path::PathBuf,
    rotated: std::path::PathBuf,
    max_bytes: u64,
    group: String,
    file: Option<std::fs::File>,
    size: u64,
    pub written: u64,
}

impl TelemetryStore {
    pub fn open(
        path: &Path,
        rotated: &Path,
        max_bytes: u64,
        group: &str,
    ) -> std::io::Result<TelemetryStore> {
        let mut s = TelemetryStore {
            path: path.to_path_buf(),
            rotated: rotated.to_path_buf(),
            max_bytes: max_bytes.max(1 << 20),
            group: group.to_string(),
            file: None,
            size: 0,
            written: 0,
        };
        s.reopen()?;
        Ok(s)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn reopen(&mut self) -> std::io::Result<()> {
        if let Some(p) = self.path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size = f.metadata().map(|m| m.len()).unwrap_or(0);
        let _ = crate::util::secure_path(&self.path, &self.group, 0o640);
        self.file = Some(f);
        Ok(())
    }

    pub fn append(&mut self, rec: &Record) -> std::io::Result<()> {
        use std::io::Write;
        if self.file.is_none() {
            self.reopen()?;
        }
        let line = rec.to_line();
        let f = self.file.as_mut().expect("reopened above");
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        self.size += line.len() as u64 + 1;
        self.written += 1;
        if self.size >= self.max_bytes {
            self.file = None;
            std::fs::rename(&self.path, &self.rotated)?;
            self.reopen()?;
        }
        Ok(())
    }

    /// Telemetry is written per event, so it is flushed on a timer rather than
    /// per line: 42 exec events a second is 42 `write(2)`s, and fsyncing each
    /// one would put the sensor's own I/O on the critical path.
    pub fn flush(&mut self) {
        use std::io::Write;
        if let Some(f) = self.file.as_mut() {
            let _ = f.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TelemetryConfig;

    fn cfg() -> TelemetryConfig {
        TelemetryConfig::default()
    }


    #[test]
    fn only_the_telemetry_prefix_is_telemetry() {
        assert!(is_telemetry_policy("moat-telemetry-network-connect"));
        assert!(is_telemetry_policy("moat-telemetry-file-exec-shape"));
        assert!(!is_telemetry_policy("moat-cred-ssh-private-key-read"));
        assert!(!is_telemetry_policy("moat-net-suspicious-port-egress"));
        // A policy that merely *mentions* telemetry is not one.
        assert!(!is_telemetry_policy("moat-x-telemetry-lag"));
    }

    #[test]
    fn every_class_is_known_and_maps_to_its_templates() {
        assert_eq!(CLASSES, &["alerts", "process", "network", "file"]);
        assert!(templates_for("alerts").is_empty());
        assert!(templates_for("process").is_empty());
        assert_eq!(templates_for("network").len(), 1);
        assert_eq!(templates_for("file").len(), 2);
        for t in all_templates() {
            assert!(class_of_template(t).is_some(), "{} has no class", t);
        }
        assert_eq!(class_of_template("cred-ssh-private-key-read.yaml"), None);
    }

    /// The rule that keeps the class affordable, and the exception that keeps
    /// it useful.
    #[test]
    fn quiet_creates_never_silences_a_modify() {
        let c = cfg();
        let p = "/home/dan/app/node_modules/express/index.js";
        assert!(
            is_quiet_create(&c, FileVerdict::Create, p),
            "an install unpacking node_modules is the volume, not the signal"
        );
        assert!(
            !is_quiet_create(&c, FileVerdict::Modify, p),
            "a package rewriting its own entry point after install is exactly \
             what this class exists for"
        );
        assert!(!is_quiet_create(&c, FileVerdict::ChmodX, p));
        // Outside the quiet list a create is kept.
        assert!(!is_quiet_create(&c, FileVerdict::Create, "/home/dan/bin/x.sh"));
    }

    #[test]
    fn birth_time_separates_a_create_from_a_modify() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("new.sh");
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        let now = crate::util::unix_secs();
        assert_eq!(verdict_for(&p, now, 5), FileVerdict::Create);
        // With a zero-second window the same file reads as pre-existing, which
        // is how the "already installed" side of the ladder is exercised
        // without waiting for a file to age.
        assert_eq!(verdict_for(&p, now, 0), FileVerdict::Modify);
        // A file that is already gone is treated as a drop, not an edit.
        std::fs::remove_file(&p).unwrap();
        assert_eq!(verdict_for(&p, now, 0), FileVerdict::Create);
    }

    #[test]
    fn elf_magic_is_read_from_the_file_not_the_name() {
        let dir = tempfile::tempdir().unwrap();
        let elf = dir.path().join("noextension");
        std::fs::write(&elf, b"\x7fELF\x02\x01\x01\x00rest").unwrap();
        assert!(looks_like_elf(&elf));
        let script = dir.path().join("x.sh");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        assert!(!looks_like_elf(&script));
        assert!(!looks_like_elf(&dir.path().join("missing")));
    }

    #[test]
    fn exec_records_ship_the_parent_id_not_the_parent_block() {
        let ev: ExecEvent = serde_json::from_str(
            r#"{"process":{"exec_id":"e1","pid":41233,"uid":1000,"binary":"/usr/bin/node",
                 "arguments":"setup.mjs","cwd":"/home/dan/p","start_time":"2026-09-03T16:21:06.9Z",
                 "parent_exec_id":"e0"},
                "parent":{"exec_id":"e0","pid":41230,"binary":"/usr/bin/sh","arguments":"-c x"}}"#,
        )
        .unwrap();
        let mut c = cfg();
        let r = exec_record(&c, &ev, "2026-09-03T16:21:06.900Z").unwrap();
        assert_eq!(r.value["parent_exec_id"], "e0");
        assert!(r.value.get("parent").is_none(), "the parent block is a join, not a copy");
        let small = r.to_line().len();

        c.inline_parent = true;
        let r2 = exec_record(&c, &ev, "2026-09-03T16:21:06.900Z").unwrap();
        assert_eq!(r2.value["parent"]["exec_id"], "e0");
        assert!(r2.to_line().len() > small, "inlining costs bytes; that is the point");
    }

    #[test]
    fn exit_records_are_a_reference_and_a_result() {
        let ev: ExitEvent = serde_json::from_str(
            r#"{"process":{"exec_id":"e1","pid":41233},"signal":"SIGKILL"}"#,
        )
        .unwrap();
        let r = exit_record(&ev, "2026-09-03T16:21:07.000Z").unwrap();
        assert_eq!(r.value["exec_id"], "e1");
        assert_eq!(r.value["signal"], "SIGKILL");
        assert!(r.to_line().len() < 200, "an exit line must stay small");
    }

    #[test]
    fn a_file_record_carries_the_three_things_the_kernel_could_not_decide() {
        let table = ProcTable::new(8, 60);
        let r = file_record(
            "/home/dan/app/node_modules/express/index.js",
            FileVerdict::Modify,
            FileShape::Script,
            Some(120),
            Some("abc".into()),
            None,
            &table,
            "missing",
            "2026-09-04T10:00:00.000Z",
        );
        assert_eq!(r.value["verdict"], "modify");
        assert_eq!(r.value["shape"], "script");
        assert_eq!(r.value["kind"], "file_write");
        assert!(r.value.get("pkg_root").is_some());
        assert!(r.value.get("body").is_none(), "no body unless asked for");
    }

    #[test]
    fn the_store_rotates_and_stays_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut s = TelemetryStore::open(
            &dir.path().join("telemetry.jsonl"),
            &dir.path().join("telemetry.1.jsonl"),
            1 << 20,
            "moat",
        )
        .unwrap();
        let table = ProcTable::new(8, 60);
        for _ in 0..8000 {
            let r = file_record(
                "/home/dan/x/some/reasonably/long/path/index.js",
                FileVerdict::Create,
                FileShape::Script,
                Some(1),
                None,
                None,
                &table,
                "e",
                "2026-09-04T10:00:00.000Z",
            );
            s.append(&r).unwrap();
        }
        s.flush();
        assert!(dir.path().join("telemetry.1.jsonl").exists(), "must rotate");
        let mode = std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
}
