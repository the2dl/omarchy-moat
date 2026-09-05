//! `moat-x-exec-memfd` and `moat-x-exec-privileges-raised`.
//!
//! Two detections that cost nothing, because Tetragon has been handing moat
//! the answer since the first run and nothing read it.
//!
//! `process.binary_properties` is populated on exec events only (NOTES §4):
//!
//! ```text
//! file{inode{number,links},path}   present ONLY for memfd/shm/deleted binaries
//! setuid, setgid
//! privileges_changed[]            PRIVILEGES_RAISED_EXEC_FILE_CAP|_SETUID|_SETGID
//! ```
//!
//! `PROCESS_EXEC` is in the export allowlist unconditionally (`render.rs`), so
//! these arrive whatever policies are loaded: no new TracingPolicy, no kernel
//! attachment, no sensor restart, and nothing to pay for at runtime. The field
//! was already parsed into `event.rs::BinaryProperties` and used by no rule.
//!
//! ## Why these two are worth having and `exec-untrusted-tmpfs` is noisy
//!
//! `exec-untrusted-tmpfs` fires on every build: 300+ alerts came out of moat's
//! own test suite during one afternoon of `makepkg` runs. It is a chain step,
//! not a detection, and it is right that it stays low.
//!
//! These are the opposite shape. Executing a binary that has no name on disk
//! is a deliberate act with one purpose -- leaving nothing to scan, hash or
//! quarantine -- and ordinary software does not do it. Neither does ordinary
//! software gain privilege at exec outside a handful of known setuid helpers.
//! They are rare, so they can afford to be loud.

use crate::event::ExecEvent;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::rules::{meta, RuleCtx, UserRule};

pub const MEMFD_ID: &str = "moat-x-exec-memfd";
pub const PRIV_ID: &str = "moat-x-exec-privileges-raised";

/// A binary with no path on disk.
#[derive(Default)]
pub struct ExecMemfd;

impl UserRule for ExecMemfd {
    fn id(&self) -> &'static str {
        MEMFD_ID
    }

    fn enabled(&self, cfg: &crate::config::Config) -> bool {
        cfg.rules.exec_memfd
    }

    fn on_exec(&mut self, ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some(props) = ev.process.as_ref().and_then(|p| p.binary_properties.as_ref()) else {
            return Vec::new();
        };
        // The presence of `file` IS the signal: Tetragon populates it only for
        // a memfd, a /dev/shm image, or a binary unlinked before exec. We do
        // not have to recognise a path shape, which is the whole reason this
        // is reliable -- `/proc/self/fd/<n>` and `memfd:name (deleted)` are
        // both spellings of the same thing and neither is guaranteed.
        let Some(file) = props.file.as_ref() else {
            return Vec::new();
        };
        let m = self.meta();
        let Some(mut f) = ctx.finding(MEMFD_ID, m, exec_id) else {
            return Vec::new();
        };
        let named = file["path"].as_str().unwrap_or_default().to_string();
        f.extra_evidence = vec![
            if named.is_empty() {
                "the kernel had no path for this binary at all".to_string()
            } else {
                format!("the kernel's name for it was {}", named)
            },
            "a program that is never written to disk cannot be scanned, hashed or \
             quarantined -- which is the reason to run one this way"
                .to_string(),
        ];
        if file["inode"]["links"].as_u64() == Some(0) {
            f.extra_evidence
                .push("its inode has no remaining links: the file was unlinked before it ran".into());
        }
        vec![f]
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            MEMFD_ID,
            "exec",
            "high",
            "A program ran that was never written to disk",
            "The binary was executed from anonymous memory (memfd), shared memory, or a \
             file deleted before it ran, so there is nothing on disk to inspect. This is \
             the standard way to run an implant without leaving a file behind; almost \
             nothing legitimate does it.",
            "Rarely, and it is worth looking at every time. A few packers, some language \
             runtimes and container tooling load code this way.",
            &[],
            &["kill", "ignore"],
            "exe",
        )
    }
}

/// A process that gained privilege by executing something.
#[derive(Default)]
pub struct ExecPrivilegesRaised;

impl UserRule for ExecPrivilegesRaised {
    fn id(&self) -> &'static str {
        PRIV_ID
    }

    fn enabled(&self, cfg: &crate::config::Config) -> bool {
        cfg.rules.exec_privileges_raised
    }

    fn on_exec(&mut self, ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some(props) = ev.process.as_ref().and_then(|p| p.binary_properties.as_ref()) else {
            return Vec::new();
        };
        if props.privileges_changed.is_empty() {
            return Vec::new();
        }
        let m = self.meta();
        let Some(mut f) = ctx.finding(PRIV_ID, m, exec_id) else {
            return Vec::new();
        };
        f.extra_evidence = vec![
            format!("the kernel recorded: {}", props.privileges_changed.join(", ")),
            // The distinction that matters, and the one `priv-setuid-chmod`
            // misses: that rule watches a bit being SET, which every package
            // build does to its own staged files as the user who owns them.
            // This is the moment privilege is actually GAINED.
            "this is privilege actually being gained at exec, not a setuid bit being set on \
             a file"
                .to_string(),
        ];
        vec![f]
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            PRIV_ID,
            "priv",
            "medium",
            "A program gained privilege when it started",
            "The kernel raised this process's privileges as it executed: a setuid or \
             setgid binary, or one carrying file capabilities. That is how an ordinary \
             process becomes a privileged one.",
            "Every `sudo`, `su`, `passwd`, `ping`, `newgrp` and `pkexec` on the machine, \
             so constantly. It earns its place as a chain step, beside a credential read \
             or an outbound connection, rather than on its own.",
            &[],
            &["ignore"],
            "exe",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::event::ExecEvent;
    use crate::feeds::Feeds;
    use crate::proctable::ProcTable;
    use crate::rules::testkit::proc;

    /// Builds the exec event from JSON rather than by hand, so the test is
    /// pinned to the SHAPE Tetragon actually sends -- `binary_properties` is
    /// an untyped `Value` on our side, and a struct literal would happily
    /// encode a shape the sensor never produces.
    fn exec(props: &str) -> ExecEvent {
        let json = format!(
            r#"{{"process":{{"exec_id":"e1","pid":41,"uid":1000,
               "binary":"/usr/bin/whatever","start_time":"2026-09-05T18:00:00.000Z"
               {}}}}}"#,
            props
        );
        serde_json::from_str(&json).expect("valid exec event")
    }

    fn table() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 41, "/usr/bin/whatever", "", None));
        t
    }

    fn run(rule: &mut dyn UserRule, ev: &ExecEvent) -> Vec<Finding> {
        let cfg = Config::default();
        let t = table();
        let feeds = Feeds::default();
        let rarity = crate::rarity::RarityStore::default();
        let ctx = RuleCtx {
            rarity: &rarity,
            cfg: &cfg,
            table: &t,
            feeds: &feeds,
            homes: &[],
            now: 100,
            mode: "monitor",
        };
        rule.on_exec(ev, "e1", &ctx)
    }

    /// The whole point: `file` is present ONLY for memfd/shm/deleted binaries,
    /// so its presence is the detection. No path shape is matched.
    #[test]
    fn a_binary_with_no_name_on_disk_is_reported() {
        let ev = exec(r#","binary_properties":{"file":{"inode":{"number":7,"links":0}}}"#);
        let out = run(&mut ExecMemfd, &ev);
        assert_eq!(out.len(), 1, "a memfd exec must be reported");
        assert_eq!(out[0].meta.severity, "high");
        assert!(
            out[0].extra_evidence.iter().any(|e| e.contains("no remaining links")),
            "an unlinked inode is worth saying out loud: {:?}",
            out[0].extra_evidence
        );
    }

    /// The expensive half of any new detection is what it does on the other
    /// 99.99% of execs. Tetragon omits `binary_properties` entirely for an
    /// ordinary binary, and omits `file` when only setuid is set.
    #[test]
    fn an_ordinary_exec_is_silent() {
        assert!(run(&mut ExecMemfd, &exec("")).is_empty(), "no binary_properties at all");
        assert!(
            run(&mut ExecMemfd, &exec(r#","binary_properties":{"setuid":0}"#)).is_empty(),
            "setuid without `file` is not a memfd"
        );
        assert!(
            run(&mut ExecPrivilegesRaised, &exec("")).is_empty(),
            "no binary_properties at all"
        );
        assert!(
            run(
                &mut ExecPrivilegesRaised,
                &exec(r#","binary_properties":{"privileges_changed":[]}"#)
            )
            .is_empty(),
            "an empty list is not a privilege change"
        );
    }

    #[test]
    fn a_privilege_raising_exec_names_what_the_kernel_said() {
        let ev = exec(
            r#","binary_properties":{"privileges_changed":["PRIVILEGES_RAISED_EXEC_FILE_SETUID"]}"#,
        );
        let out = run(&mut ExecPrivilegesRaised, &ev);
        assert_eq!(out.len(), 1);
        assert!(out[0].extra_evidence[0].contains("PRIVILEGES_RAISED_EXEC_FILE_SETUID"));
        // Medium, not high: every sudo on the machine trips this, so it is a
        // chain step. Raising it would make the badge useless within an hour.
        assert_eq!(out[0].meta.severity, "medium");
        assert_eq!(out[0].meta.family, "priv");
    }
}
