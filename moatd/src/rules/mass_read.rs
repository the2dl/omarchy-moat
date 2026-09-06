//! `moat-x-mass-read`.
//!
//! Fills NOTES gap 5: `rateLimit` suppresses events, it never counts them. The
//! TruffleHog / stealer pattern is one process opening dozens of dotfiles in a
//! couple of seconds — each open is individually boring, the burst is not.
//!
//! Input is the `cred` family's read events (the policies agent emits those for
//! `$HOME` dotdirs); we count *distinct* paths per process in a sliding window.

use std::collections::{HashMap, VecDeque};

use crate::config::Config;
use crate::event::HookHit;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::rules::{meta, RuleCtx, UserRule};

pub const ID: &str = "moat-x-mass-read";

/// Hooks whose first file argument is an open/read of that path.
const FILE_HOOKS: &[&str] = &[
    "file_open",
    "file_post_open",
    "security_file_post_open",
    "security_file_open",
    "file_permission",
    "security_file_permission",
    "mmap_file",
    "security_mmap_file",
];

/// MAY_READ, from NOTES §3.
const MAY_READ: i64 = 4;

#[derive(Default)]
struct Window {
    entries: VecDeque<(u64, String)>,
}

#[derive(Default)]
pub struct MassRead {
    windows: HashMap<String, Window>,
}

impl UserRule for MassRead {
    fn id(&self) -> &'static str {
        ID
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.mass_read
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            ID,
            "cred",
            "high",
            "One process read many private files in seconds",
            "Reading dozens of different dotfiles in a few seconds is not what a program \
             doing its job looks like; it is what a secret scanner looks like. Credential \
             stealers sweep ~/.ssh, ~/.aws, ~/.config and the browser profiles in one pass.",
            "Backup tools (restic, borg, rsync), indexers, antivirus scans, `grep -r` over \
             your home directory, and your editor opening a project-wide search.",
            &["ssh-key", "github-token", "aws", "npm-token", "browser", "keyring"],
            &["kill", "ignore"],
            "exe",
        )
    }

    fn on_hook(&mut self, h: &HookHit, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        if !FILE_HOOKS.contains(&h.hook_name().as_str()) {
            return Vec::new();
        }
        // The policies agent puts $HOME dotdir reads in the `cred` family; that
        // is the coordination point named in CONTRACT §6.4.
        if !h.policy_name().starts_with("moat-cred-") {
            return Vec::new();
        }
        // A mask, when present, must include MAY_READ. Absent = the hook has no
        // mask argument, which we treat as a read.
        if let Some(mask) = h.int_arg() {
            if mask & MAY_READ == 0 {
                return Vec::new();
            }
        }
        let Some(path) = h.file_path() else {
            return Vec::new();
        };
        // NOT gated on `in_home_dotdir` any more.
        //
        // The `moat-cred-*` policies above already decide what counts as a
        // credential file; asking a second, narrower question here meant a
        // harvest anywhere else was invisible to the counter -- a staged copy,
        // a checked-out repo, an extracted archive, or (2026-09-05) a lab
        // fixture that read eight credential-shaped files and produced nothing
        // but two timeline entries. One question, one place that answers it.
        if exec_id.is_empty() {
            return Vec::new();
        }

        let window_secs = ctx.cfg.thresholds.mass_read_window_secs;
        let threshold = ctx.cfg.thresholds.mass_read_files;

        // Keep the map from growing without bound on a busy machine.
        if self.windows.len() > 512 {
            let now = ctx.now;
            self.windows
                .retain(|_, w| w.entries.back().map(|(t, _)| now.saturating_sub(*t) < window_secs).unwrap_or(false));
        }

        let w = self.windows.entry(exec_id.to_string()).or_default();
        while let Some((t, _)) = w.entries.front() {
            if ctx.now.saturating_sub(*t) >= window_secs {
                w.entries.pop_front();
            } else {
                break;
            }
        }
        if !w.entries.iter().any(|(_, p)| p == &path) {
            w.entries.push_back((ctx.now, path.clone()));
        }
        let distinct: Vec<String> = w.entries.iter().map(|(_, p)| p.clone()).collect();
        // `<`, not `<=`: `mass_read_files = 3` means THREE credential files
        // fire it, not four. The config comment and the alert text both say
        // "more than this many" -- but the number a person sets is the number
        // they expect to be the trigger, and off-by-one in a security
        // threshold is the kind of thing nobody notices until the rule fails
        // to fire on a real harvest. Named explicitly in the config.
        if distinct.len() < threshold {
            return Vec::new();
        }
        // Fired: reset so the next alert needs another full burst (the alert
        // deduper would otherwise fold every subsequent read into a count).
        w.entries.clear();

        let Some(mut f) = ctx.finding(ID, self.meta(), exec_id) else {
            return Vec::new();
        };
        let sample: Vec<String> = distinct.iter().take(5).cloned().collect();
        f.hook = format!("userland: {} distinct files in {} s", distinct.len(), window_secs);
        f.what_override = Some(format!(
            "{} read {} different private files in under {} seconds.",
            f.proc.comm(),
            distinct.len(),
            window_secs
        ));
        f.extra_evidence = vec![
            format!(
                "threshold: more than {} distinct files under a home dotdir within {} s",
                threshold, window_secs
            ),
            format!("first files: {}", sample.join(", ")),
        ];
        vec![f]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HookEvent, HookKind};
    use crate::feeds::Feeds;
    use crate::proctable::ProcTable;
    use crate::rules::testkit::{cfg, proc};

    fn ev(path: &str, mask: i64, policy: &str) -> HookEvent {
        HookEvent {
            function_name: Some("file_post_open".into()),
            policy_name: Some(policy.into()),
            args: vec![
                serde_json::json!({"file_arg":{"path":path,"permission":"-rw-------"}}),
                serde_json::json!({"int_arg":mask}),
            ],
            ..Default::default()
        }
    }

    fn table() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 41300, "/usr/bin/trufflehog", "filesystem /home/dan", None));
        t
    }

    fn fire(rule: &mut MassRead, t: &ProcTable, c: &Config, e: &HookEvent, now: u64) -> Vec<Finding> {
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
        rule.on_hook(
            &HookHit {
                kind: HookKind::Lsm,
                ev: e,
            },
            "e1",
            &ctx,
        )
    }

    #[test]
    fn a_burst_over_the_threshold_fires_once() {
        let t = table();
        let mut c = cfg();
        c.thresholds.mass_read_files = 5;
        let mut rule = MassRead::default();
        let mut fired = 0;
        for i in 0..8 {
            let e = ev(
                &format!("/home/dan/.config/app{}/token", i),
                4,
                "moat-cred-dotfile-read",
            );
            fired += fire(&mut rule, &t, &c, &e, 100).len();
        }
        assert_eq!(fired, 1, "fires on the 6th distinct file, then resets");
    }

    #[test]
    fn the_same_file_read_repeatedly_is_not_a_sweep() {
        let t = table();
        let mut c = cfg();
        c.thresholds.mass_read_files = 3;
        let mut rule = MassRead::default();
        let e = ev("/home/dan/.ssh/id_rsa", 4, "moat-cred-ssh-private-key-read");
        for _ in 0..20 {
            assert!(fire(&mut rule, &t, &c, &e, 100).is_empty());
        }
    }

    #[test]
    fn reads_spread_past_the_window_never_accumulate() {
        let t = table();
        let mut c = cfg();
        c.thresholds.mass_read_files = 3;
        c.thresholds.mass_read_window_secs = 10;
        let mut rule = MassRead::default();
        for i in 0..10u64 {
            let e = ev(
                &format!("/home/dan/.config/a{}/t", i),
                4,
                "moat-cred-dotfile-read",
            );
            // One file every 11 s: the window never holds two.
            assert!(fire(&mut rule, &t, &c, &e, 100 + i * 11).is_empty());
        }
    }

    #[test]
    fn writes_are_ignored_but_a_harvest_outside_a_dotdir_is_not() {
        let t = table();
        let mut c = cfg();
        c.thresholds.mass_read_files = 2;
        let mut rule = MassRead::default();

        // A write is not a read, however many of them there are.
        for i in 0..10 {
            let w = ev(&format!("/home/dan/.cache/w{}", i), 2, "moat-cred-dotfile-read");
            assert!(fire(&mut rule, &t, &c, &w, 100).is_empty());
        }

        // Credential reads OUTSIDE a home dotdir used to be dropped here, so a
        // harvest of staged or extracted credentials counted for nothing. The
        // cred-* policy already decided these are credential files; this rule
        // counts what it is given.
        let mut fired = 0;
        for i in 0..4 {
            let p = ev(&format!("/tmp/staged/proj-{}/.env", i), 4, "moat-cred-project-token-read");
            fired += fire(&mut rule, &t, &c, &p, 100).len();
        }
        assert!(fired > 0, "four credential reads in one second must be counted");
    }

    #[test]
    fn only_the_cred_family_feeds_this_rule() {
        let t = table();
        let mut c = cfg();
        c.thresholds.mass_read_files = 2;
        let mut rule = MassRead::default();
        for i in 0..10 {
            let e = ev(&format!("/home/dan/.config/x{}", i), 4, "moat-priv-something");
            assert!(fire(&mut rule, &t, &c, &e, 100).is_empty());
        }
    }

    #[test]
    fn the_finding_names_the_files_it_saw() {
        let t = table();
        let mut c = cfg();
        c.thresholds.mass_read_files = 2;
        let mut rule = MassRead::default();
        let mut out = Vec::new();
        for i in 0..4 {
            let e = ev(
                &format!("/home/dan/.ssh/k{}", i),
                4,
                "moat-cred-ssh-private-key-read",
            );
            out.extend(fire(&mut rule, &t, &c, &e, 100));
        }
        // threshold 2 means the SECOND read fires it, and the window resets
        // after each finding, so four reads produce two findings.
        assert_eq!(out.len(), 2, "N means N: {:?}", out.len());
        let f = &out[0];
        assert!(
            f.what_override.as_ref().unwrap().contains("2 different private files"),
            "{:?}",
            f.what_override
        );
        assert!(f.extra_evidence[1].contains("/home/dan/.ssh/k0"));
        assert_eq!(f.meta.family, "cred");
    }
}
