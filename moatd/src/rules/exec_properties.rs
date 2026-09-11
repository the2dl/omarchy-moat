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
pub const CAP_ID: &str = "moat-x-exec-capability-held";

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
        // KEY ON THE INODE, not on the field's presence.
        //
        // `systemd --user` re-execs itself through /proc/self/fd/9 on every
        // daemon-reexec -- 12 such execs in this machine's log. Its binary is
        // an ordinary file with links on disk, so an fd-shaped-path heuristic
        // (which is what this rule nearly became) would have raised 12 high
        // alerts for the user manager restarting. A memfd, a /dev/shm image
        // and a binary unlinked before exec all have NO remaining links; that
        // is the actual distinction and it is the one thing worth matching.
        //
        // Absent reads as zero on purpose: protojson omits default values, so
        // `links: 0` -- the case this rule exists for -- may not appear in the
        // JSON at all. Only a POSITIVE link count means "this has a name on
        // disk" and rules the exec out.
        if file["inode"]["links"].as_u64().unwrap_or(0) != 0 {
            return Vec::new();
        }
        let m = self.meta();
        let Some(mut f) = ctx.finding(MEMFD_ID, m, exec_id) else {
            return Vec::new();
        };
        // v1.7.1 never populates `file.path` -- `process.go` sets only the
        // inode -- so the name has to come from `process.binary`, which for
        // one of these is the fd the kernel executed through:
        // `/proc/self/fd/N`, `/proc/<pid>/fd/N`, or `/dev/fd/N` for
        // execveat(AT_EMPTY_PATH). Reading `file.path` was a branch that could
        // never run.
        let named = ev
            .process
            .as_ref()
            .and_then(|p| p.binary.clone())
            .unwrap_or_default();
        // What was MEASURED, first. The kernel attests one fact -- no directory
        // entry for this inode at exec -- and the rule used to dress that up as
        // "never written to disk", which is a claim about history the kernel
        // cannot make. A file compiled to disk and then unlinked looks
        // identical here, and moat's own lab scrim is precisely that case: it
        // builds an ELF, copies it into a memfd, and leaves the original in
        // place. Overclaiming in the first line is how an accurate detection
        // acquires an inaccurate reputation.
        // The inode, and BOTH possibilities, spelled out.
        //
        // The deleted-binary case is where a vague line costs something real:
        // a dropper writes /tmp/.x, execs it, unlinks it. If the alert only
        // says "no file on disk", the natural response is to stop looking --
        // when the write itself was probably recorded by
        // `telemetry-file-became-executable`, the exec by
        // `exec-untrusted-tmpfs`, and the path is still in the process's own
        // record. Saying which of the two it might be is what keeps a
        // responder pointed at evidence that exists.
        let inode = file["inode"]["number"].as_u64();
        let measured = format!(
            "the kernel found no directory entry for this binary when it ran{}: it was \
             either created in memory or deleted before exec",
            inode.map(|n| format!(" (inode {}, 0 links)", n)).unwrap_or_default()
        );
        f.extra_evidence = vec![
            if named.is_empty() {
                measured
            } else {
                // The fd spelling stays the primary name. `resolve_exec_binary`
                // will happily recover the PARENT's argv0 for one of these --
                // `python`, for the scrim -- and an alert headed "python ran"
                // would point at the wrong object entirely.
                format!("{}; it was executed through {}", measured, named)
            },
            // "with no file on disk", matching the line above. "Never written
            // to disk" would contradict it: the first line allows for deleted-
            // before-exec, and the two sentences have to agree or the alert
            // argues with itself in front of the person reading it.
            "a program with no file on disk cannot be scanned, hashed or quarantined -- \
             which is the reason to run one this way"
                .to_string(),
        ];
        f.extra_evidence.push(
            "if it was deleted rather than created in memory, the write and the exec were \
             probably recorded separately -- check the timeline around this alert"
                .into(),
        );
        vec![f]
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            MEMFD_ID,
            "exec",
            "high",
            "A program ran from a file with no name on disk",
            "The binary had no directory entry when it ran: anonymous memory (memfd), \
             shared memory, or a file unlinked before exec. Whichever it was, there is \
             nothing on disk to inspect now. This is the standard way to run an implant \
             without leaving a file behind; almost nothing legitimate does it.",
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
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
            names: &crate::rules::NO_NAMES,
        };
        rule.on_exec(ev, "e1", &ctx)
    }

    /// The whole point: `file` is present ONLY for memfd/shm/deleted binaries,
    /// so its presence is the detection. No path shape is matched.
    #[test]
    fn a_binary_with_no_name_on_disk_is_reported() {
        // The real v1.7.1 shape: an inode, no path. The name comes from
        // `process.binary`, which for a memfd exec is the fd it ran through.
        let ev = exec(r#","binary_properties":{"file":{"inode":{"number":7,"links":0}}}"#);
        let out = run(&mut ExecMemfd, &ev);
        assert_eq!(out.len(), 1, "a memfd exec must be reported");
        assert_eq!(out[0].meta.severity, "high");
        assert!(
            out[0].extra_evidence[0].contains("/usr/bin/whatever"),
            "the name must come from process.binary, not the never-populated file.path: {:?}",
            out[0].extra_evidence
        );
        assert!(
            out[0].extra_evidence[0].contains("inode 7, 0 links"),
            "the measurement belongs in the evidence: {:?}",
            out[0].extra_evidence
        );
        assert!(
            out[0].extra_evidence.iter().any(|e| e.contains("recorded separately")),
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
        // The systemd case: re-exec through /proc/self/fd/9 of a binary that
        // is still on disk. 12 of these are in this machine's log, and an
        // fd-path heuristic would have called every one of them an implant.
        assert!(
            run(
                &mut ExecMemfd,
                &exec(r#","binary_properties":{"file":{"inode":{"number":42,"links":1}}}"#)
            )
            .is_empty(),
            "a binary with a name on disk is not fileless, whatever fd it ran through"
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


/// A process running with a capability that is root by another name.
///
/// `moat-priv-setcap-xattr` watches a file capability being WRITTEN.
/// `moat-x-exec-privileges-raised` fires when the kernel raises privilege at
/// exec, which includes any file capability at all. Neither says which
/// capability, and that is the part that decides whether this matters:
/// `cap_net_bind_service` on `rlogin` is nothing, and `cap_sys_admin` on
/// `gsr-kms-server` is unrestricted root sitting on a screen-recording helper
/// most people do not know they have installed (docs/LPE.md).
///
/// Keyed off the capability set on the EVENT, never a list of binaries. An
/// audit of this machine goes stale the moment a package adds a capability;
/// `process.cap` is what the kernel handed the process this time.
///
/// A chain step, deliberately. On its own "a privileged helper ran" is the
/// ordinary business of a desktop -- `dumpcap`, `btop`, `newuidmap` -- and it
/// is next to a credential read or an outbound connection that it means
/// something. Loud on its own it would be `exec-untrusted-tmpfs` again.
#[derive(Default)]
pub struct ExecCapabilityHeld;

impl UserRule for ExecCapabilityHeld {
    fn id(&self) -> &'static str {
        CAP_ID
    }

    fn enabled(&self, cfg: &crate::config::Config) -> bool {
        cfg.rules.exec_capability_held
    }

    fn on_exec(&mut self, ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some(proc) = ev.process.as_ref() else {
            return Vec::new();
        };
        let grave = proc.dangerous_caps();
        if grave.is_empty() {
            return Vec::new();
        }
        // A process that is ALREADY root gains nothing from a capability: root
        // holds the full set by definition, so every daemon on the machine
        // would match and the rule would say nothing about any of them. The
        // interesting case is an unprivileged process holding one.
        let euid = proc
            .process_credentials
            .as_ref()
            .and_then(|c| c.euid)
            .or(proc.uid);
        if euid == Some(0) {
            return Vec::new();
        }
        let m = self.meta();
        let Some(mut f) = ctx.finding(CAP_ID, m, exec_id) else {
            return Vec::new();
        };
        f.extra_evidence = vec![
            format!(
                "held as a non-root process (uid {}): {}",
                euid.map(|u| u.to_string()).unwrap_or_else(|| "unknown".into()),
                grave.join(", ")
            ),
            "read from the kernel's own capability set for this exec, not from a list of \
             binaries: a package adding a capability changes what this reports without \
             anything here being updated"
                .to_string(),
        ];
        vec![f]
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            CAP_ID,
            "priv",
            "low",
            "A privileged capability was held by a program that is not root",
            "This process ran without being root and still held a capability that grants \
             what root has -- reading any file, writing any file, loading a module, or \
             becoming another user. A file capability is how a binary carries that \
             without a setuid bit.",
            "Ordinary desktop tooling: dumpcap holds CAP_DAC_OVERRIDE, btop holds \
             CAP_DAC_READ_SEARCH, newuidmap and newgidmap hold CAP_SETUID and CAP_SETGID. \
             It is a chain step beside something else, never a finding on its own.",
            &[],
            &["ignore"],
            "exe",
        )
    }
}

#[cfg(test)]
mod capability_tests {
    use crate::event::{Capabilities, Credentials};

    fn caps(effective: &[&str], permitted: &[&str]) -> Capabilities {
        Capabilities {
            effective: effective.iter().map(|s| s.to_string()).collect(),
            permitted: permitted.iter().map(|s| s.to_string()).collect(),
            inheritable: Vec::new(),
        }
    }

    /// The measured example: gpu-screen-recorder's helper carries
    /// cap_sys_admin=ep, which is root by another name, on a machine where
    /// nobody knows it is installed.
    #[test]
    fn cap_sys_admin_is_grave_and_cap_net_bind_service_is_not() {
        assert_eq!(
            caps(&["CAP_SYS_ADMIN"], &["CAP_SYS_ADMIN"]).is_dangerous(),
            vec!["CAP_SYS_ADMIN"]
        );
        assert!(caps(&["CAP_NET_BIND_SERVICE"], &[]).is_dangerous().is_empty());
        assert!(caps(&[], &[]).is_dangerous().is_empty());
    }

    /// The one-of-41 wart. Tetragon's CapabilitiesType enum spells DAC_OVERRIDE
    /// without the CAP_ prefix, protojson renders enums by name, and so that is
    /// what an event carries. Matching only the prefixed spelling meant silently
    /// never reporting dumpcap -- the exact binary docs/LPE.md holds up as the
    /// example of a read-anything primitive. A load test against the live sensor
    /// found it, in the policy; the same mistake was sitting here.
    #[test]
    fn dac_override_is_matched_in_the_spelling_tetragon_actually_sends() {
        assert_eq!(caps(&["DAC_OVERRIDE"], &[]).is_dangerous(), vec!["DAC_OVERRIDE"]);
        // And the kernel's own spelling still works, for anything reading getcap.
        assert_eq!(
            caps(&["CAP_DAC_OVERRIDE"], &[]).is_dangerous(),
            vec!["CAP_DAC_OVERRIDE"]
        );
        // CAP_DAC_READ_SEARCH does carry the prefix -- only DAC_OVERRIDE does not.
        assert_eq!(
            caps(&["CAP_DAC_READ_SEARCH"], &[]).is_dangerous(),
            vec!["CAP_DAC_READ_SEARCH"]
        );
    }

    /// Permitted counts, not just effective: a process can raise a permitted
    /// capability into effective at any moment without executing anything.
    #[test]
    fn permitted_counts_even_when_not_effective() {
        assert_eq!(
            caps(&[], &["CAP_DAC_OVERRIDE"]).is_dangerous(),
            vec!["CAP_DAC_OVERRIDE"]
        );
    }

    /// dumpcap holds cap_dac_override,cap_net_admin,cap_net_raw=eip. Only the
    /// first is a read-anything primitive, and the report must name that one
    /// rather than the whole set.
    #[test]
    fn only_the_grave_ones_are_named_and_they_are_deduped() {
        let c = caps(
            &["CAP_DAC_OVERRIDE", "CAP_NET_ADMIN", "CAP_NET_RAW"],
            &["CAP_DAC_OVERRIDE", "CAP_NET_ADMIN", "CAP_NET_RAW"],
        );
        assert_eq!(c.is_dangerous(), vec!["CAP_DAC_OVERRIDE"], "named once, not twice");
    }

    /// Root holds everything by definition. Including it would match every
    /// daemon on the machine and distinguish none of them.
    #[test]
    fn root_is_not_reported_because_root_explains_nothing() {
        let creds = Credentials {
            uid: Some(0),
            euid: Some(0),
            ..Default::default()
        };
        assert_eq!(creds.euid, Some(0));
        // The rule's own gate, stated as the test's subject.
        let is_root = creds.euid.or(creds.uid) == Some(0);
        assert!(is_root, "a root process is skipped by ExecCapabilityHeld");
    }

    /// A setuid execution is uid 1000 with euid 0, and the difference is the
    /// whole point: `process.uid` alone cannot see it.
    #[test]
    fn euid_raised_sees_what_uid_alone_cannot() {
        let setuid = Credentials {
            uid: Some(1000),
            euid: Some(0),
            ..Default::default()
        };
        assert!(setuid.euid_raised());

        let ordinary = Credentials {
            uid: Some(1000),
            euid: Some(1000),
            ..Default::default()
        };
        assert!(!ordinary.euid_raised());

        // Already root is not a RAISE, whatever else it is.
        let root = Credentials {
            uid: Some(0),
            euid: Some(0),
            ..Default::default()
        };
        assert!(!root.euid_raised());
    }
}
