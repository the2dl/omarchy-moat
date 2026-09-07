//! `moat-ransom-snapshot-command`.
//!
//! Destroying the recovery points is the step ransomware has to take before
//! the encryption means anything -- the Linux shape of `vssadmin delete
//! shadows`. On this desktop that is `btrfs subvolume delete`, `snapper
//! delete`, `timeshift --delete`, and for the user-owned repositories `restic
//! forget` and `borg delete`.
//!
//! No kernel selector can see argv (NOTES gap 1; policies/README "moatd
//! covers" §1), and every exec is exported whatever policies are loaded, so
//! the argument test lives here at no sensor cost. The on-disk half -- `rm -rf`
//! of `~/.snapshots`, `/.snapshots`, `/timeshift` -- is the kernel policy
//! `moat-ransom-snapshot-destroy`, a plain detection with its own name.
//!
//! What keeps it quiet: the snapshot tools drive each other by design.
//! `timeshift` and `snapperd` shell out to `btrfs`, `borgmatic` runs `borg`,
//! and `snapper-cleanup.timer` runs `/usr/lib/snapper/systemd-helper` every
//! hour on this machine (verified 2026-09-06: `NUMBER_CLEANUP="yes"` in
//! `/etc/snapper/configs/root`). A destructive command with one of those as an
//! ancestor is the tool doing its job. And a retention run -- `restic forget
//! --keep-daily 7 --prune`, `borg prune --keep-weekly 4` -- keeps something by
//! construction, so it is told apart from `restic forget <id>` by the presence
//! of a `--keep` option rather than by who ran it.

use crate::config::Config;
use crate::event::ExecEvent;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::rules::{meta, RuleCtx, UserRule};
use crate::util::basename;

pub const ID: &str = "moat-ransom-snapshot-command";

/// Programs that delete snapshots and backups as part of running normally. A
/// destructive command whose ancestry contains one of these is that program
/// working, not somebody using it as a weapon.
///
/// `snapper` (the CLI) is deliberately absent: `snapper delete` typed or
/// scripted is exactly the exec this rule reports, and the daemon that acts on
/// it (`snapperd`) never execs anything.
const MANAGERS: &[&str] = &[
    "snapperd",
    "systemd-helper", // /usr/lib/snapper/systemd-helper, the cleanup timer
    "timeshift",
    "timeshift-gtk",
    "btrfs-assistant",
    "btrbk",
    "yabsnap",
    "borgmatic",
    "backrest",
    "autorestic",
    "resticprofile",
];

/// restic's (and rustic's) command words, so the command can be found past the
/// global options (`-r repo`, `--password-file f`, `-o k=v`, …) without a table
/// of which options take a value.
const RESTIC_COMMANDS: &[&str] = &[
    "backup", "cat", "check", "copy", "diff", "dump", "find", "forget", "generate", "init",
    "key", "list", "ls", "migrate", "mount", "prune", "rebuild-index", "recover", "repair",
    "restore", "rewrite", "self-update", "snapshots", "stats", "tag", "unlock", "version",
];

const BORG_COMMANDS: &[&str] = &[
    "benchmark", "break-lock", "check", "compact", "config", "create", "debug", "delete",
    "diff", "export-tar", "extract", "import-tar", "info", "init", "key", "list", "mount",
    "prune", "rcreate", "rdelete", "recreate", "rename", "rinfo", "rlist", "serve", "umount",
    "upgrade", "with-lock",
];

/// snapper's global options that take a value, which have to be stepped over to
/// find the command. Everything else that starts with `-` is a flag.
const SNAPPER_VALUE_OPTS: &[&str] = &[
    "-c", "--config", "-t", "--table-style", "-r", "--root", "--separator", "--machine-readable",
];

pub struct SnapshotCommand;

impl UserRule for SnapshotCommand {
    fn id(&self) -> &'static str {
        ID
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.ransom_snapshot_command
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            ID,
            "ransom",
            "critical",
            "A snapshot or backup was deleted by command",
            "Encryption only holds you to ransom once the copies are gone, so destroying the \
             recovery points comes first: the btrfs and snapper snapshots that would roll the \
             system back, the timeshift restore points, the restic and borg repositories you \
             back up to. Each of those has a one-line command that removes them, and a program \
             running as you can type it as easily as you can. This is that command being run \
             -- by whatever ran it.",
            "You, deleting a snapshot on purpose, or a backup script of your own that removes \
             specific snapshots by id. Retention runs stay quiet: `restic forget` with any \
             --keep option and `borg prune` are keeping something by construction, and the \
             snapshot tools themselves -- timeshift and snapperd calling `btrfs`, borgmatic \
             calling `borg`, snapper's hourly cleanup timer -- are recognised by ancestry. \
             Note what it cannot see: a deletion done through the btrfs ioctl directly, which \
             is how snapperd works, and which leaves no exec to read.",
            &[],
            &["kill", "ignore"],
            "parent",
        )
    }

    fn on_exec(&mut self, _ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some(me) = ctx.table.get(exec_id) else {
            return Vec::new();
        };
        let comm = basename(&me.exe);
        let Some(why) = destructive(comm, &me.args) else {
            return Vec::new();
        };
        // Ancestors only, never the process itself: `timeshift --delete` IS
        // the finding, and `btrfs subvolume delete` under timeshift is not.
        if let Some(mgr) = ctx
            .table
            .ancestry(exec_id)
            .into_iter()
            .find(|p| MANAGERS.contains(&p.comm()))
        {
            log::debug!(
                "{}: {} {} under {} is the snapshot tool at work",
                ID,
                comm,
                me.args,
                mgr.comm()
            );
            return Vec::new();
        }

        let Some(mut f) = ctx.finding(ID, self.meta(), exec_id) else {
            return Vec::new();
        };
        f.hook = "userland: exec of a command that deletes recovery points".into();
        f.what_override = Some(format!("{} ran `{} {}`: {}.", f.proc.comm(), comm, me.args.trim(), why));
        f.extra_evidence = vec![
            format!("command: {} {}", me.exe, me.args.trim()),
            "no snapshot manager (timeshift, snapperd, btrbk, borgmatic, …) is in this \
             process's ancestry, so this is not a tool tidying its own snapshots"
                .to_string(),
        ];
        vec![f]
    }
}

/// Why this exec destroys a recovery point, or `None` when it does not.
fn destructive(comm: &str, args: &str) -> Option<String> {
    let toks: Vec<&str> = args.split_whitespace().collect();
    match comm {
        "btrfs" => btrfs_subvolume_delete(&toks),
        "snapper" => snapper_delete(&toks),
        "timeshift" => toks
            .iter()
            .any(|t| *t == "--delete" || *t == "--delete-all")
            .then(|| "timeshift was asked to delete restore points".to_string()),
        "restic" | "rustic" => restic_forget(comm, &toks),
        "borg" => borg_delete(&toks),
        _ => None,
    }
}

/// `btrfs subvolume delete <path>`, with btrfs's unambiguous-prefix rule:
/// `btrfs sub del` and `btrfs su d` are the same command. `su` is the shortest
/// prefix that is only `subvolume`; `d` is the only subvolume verb starting
/// with d.
fn btrfs_subvolume_delete(toks: &[&str]) -> Option<String> {
    let mut words = toks.iter().filter(|t| !t.starts_with('-'));
    let group = words.next()?;
    let verb = words.next()?;
    let is_subvolume = group.len() >= 2 && "subvolume".starts_with(group);
    let is_delete = !verb.is_empty() && "delete".starts_with(verb);
    if is_subvolume && is_delete {
        let targets: Vec<&str> = words.copied().collect();
        return Some(format!(
            "that deletes the btrfs subvolume{} {}",
            if targets.len() == 1 { "" } else { "s" },
            targets.join(", ")
        ));
    }
    None
}

/// `snapper [-c cfg] delete|rm|remove <numbers>`. The command is the first word
/// after the global options; a description containing the word "rm" is not it.
fn snapper_delete(toks: &[&str]) -> Option<String> {
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i];
        if t.starts_with('-') {
            if SNAPPER_VALUE_OPTS.contains(&t) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        return match t {
            "delete" | "rm" | "remove" => Some(format!(
                "that deletes snapper snapshot{} {}",
                if toks.len().saturating_sub(i + 1) == 1 { "" } else { "s" },
                toks[i + 1..].join(" ")
            )),
            _ => None,
        };
    }
    None
}

/// `restic forget` with no `--keep-*`: not a retention policy but a deletion
/// of named snapshots (or, with `--unsafe-allow-remove-all`, of all of them).
/// `prune` on its own only removes data no snapshot references.
fn restic_forget(comm: &str, toks: &[&str]) -> Option<String> {
    let cmd = toks.iter().find(|t| RESTIC_COMMANDS.contains(t))?;
    if *cmd != "forget" {
        return None;
    }
    if toks.iter().any(|t| t.starts_with("--keep")) {
        return None;
    }
    if toks.iter().any(|t| *t == "--unsafe-allow-remove-all") {
        return Some(format!("{} was asked to forget EVERY snapshot in the repository", comm));
    }
    Some(format!(
        "{} forget without any --keep option deletes the named snapshots outright rather than \
         applying a retention policy",
        comm
    ))
}

/// `borg delete` removes an archive or the whole repository. `borg prune`
/// refuses to run without a `--keep`, so it is never a deletion of everything.
fn borg_delete(toks: &[&str]) -> Option<String> {
    let cmd = toks.iter().find(|t| BORG_COMMANDS.contains(t))?;
    match *cmd {
        "delete" | "rdelete" => Some("borg delete removes an archive, or the whole repository".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ExecEvent;
    use crate::feeds::Feeds;
    use crate::proctable::ProcTable;
    use crate::rules::testkit::{cfg, proc};

    fn run(t: &ProcTable, exec_id: &str) -> Vec<Finding> {
        let c = cfg();
        let feeds = Feeds::default();
        let ctx = RuleCtx {
            rarity: &crate::rarity::RarityStore::default(),
            cfg: &c,
            table: t,
            feeds: &feeds,
            homes: &[],
            now: 100,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
        };
        SnapshotCommand.on_exec(&ExecEvent::default(), exec_id, &ctx)
    }

    fn one(exe: &str, args: &str, parent: Option<(&str, &str)>) -> Vec<Finding> {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-fish", 4100, "/usr/bin/fish", "", None));
        let parent_id = match parent {
            Some((id, pexe)) => {
                t.observe(&proc(id, 4200, pexe, "", Some("e-fish")));
                id
            }
            None => "e-fish",
        };
        t.observe(&proc("e-cmd", 4300, exe, args, Some(parent_id)));
        run(&t, "e-cmd")
    }

    #[test]
    fn the_five_destructive_commands_fire_and_are_critical() {
        for (exe, args) in [
            ("/usr/bin/btrfs", "subvolume delete /.snapshots/42/snapshot"),
            ("/usr/bin/btrfs", "sub del /home/dan/.snapshots/3/snapshot"),
            ("/usr/bin/btrfs", "-q su d /a /b"),
            ("/usr/bin/snapper", "-c root delete 40-50"),
            ("/usr/bin/snapper", "--config home rm 7"),
            ("/usr/bin/timeshift", "--delete --snapshot 2026-09-01_00-00-01"),
            ("/usr/bin/timeshift", "--delete-all"),
            ("/usr/bin/restic", "-r /mnt/backup forget 3f2a9c1e"),
            ("/usr/bin/restic", "forget --unsafe-allow-remove-all"),
            ("/usr/bin/rustic", "forget latest"),
            ("/usr/bin/borg", "delete /mnt/backup::2026-09-01"),
            ("/usr/bin/borg", "rdelete /mnt/backup"),
        ] {
            let out = one(exe, args, None);
            assert_eq!(out.len(), 1, "{} {}", exe, args);
            let f = &out[0];
            assert_eq!(f.meta.severity, "critical");
            assert_eq!(f.meta.family, "ransom");
            assert!(f.what_override.as_ref().unwrap().contains(args.split(' ').next().unwrap()), "{:?}", f.what_override);
        }
        let f = &one("/usr/bin/restic", "forget --unsafe-allow-remove-all", None)[0];
        assert!(f.what_override.as_ref().unwrap().contains("EVERY snapshot"));
    }

    #[test]
    fn retention_runs_and_read_only_subcommands_are_quiet() {
        for (exe, args) in [
            // The user's own nightly hygiene: keeps something by construction.
            ("/usr/bin/restic", "-r /mnt/backup forget --keep-daily 7 --keep-weekly 4 --prune"),
            ("/usr/bin/restic", "forget --tag nightly --keep-last 10"),
            ("/usr/bin/restic", "prune"),
            ("/usr/bin/restic", "backup /home/dan"),
            ("/usr/bin/borg", "prune --keep-daily=7 /mnt/backup"),
            ("/usr/bin/borg", "create /mnt/backup::{now} /home/dan"),
            ("/usr/bin/borg", "compact /mnt/backup"),
            // Listing, creating, showing.
            ("/usr/bin/btrfs", "subvolume list /"),
            ("/usr/bin/btrfs", "subvolume snapshot -r / /.snapshots/x"),
            ("/usr/bin/btrfs", "filesystem usage /"),
            ("/usr/bin/snapper", "-c root list"),
            ("/usr/bin/snapper", "create -d rm old kernels"),
            ("/usr/bin/snapper", "cleanup number"),
            ("/usr/bin/timeshift", "--create --comments before-upgrade"),
            ("/usr/bin/timeshift", "--list"),
            // Something else entirely with a suggestive word in it.
            ("/usr/bin/rm", "-rf /home/dan/Documents/old"),
            ("/usr/bin/git", "branch --delete feature"),
        ] {
            assert!(one(exe, args, None).is_empty(), "{} {}", exe, args);
        }
    }

    #[test]
    fn a_snapshot_manager_driving_the_tool_is_the_tool_at_work() {
        // timeshift shells out to btrfs; borgmatic runs borg; the hourly
        // snapper-cleanup.timer runs systemd-helper. None of these is an alert.
        for (exe, args, parent) in [
            ("/usr/bin/btrfs", "subvolume delete /timeshift/snapshots/x/@", ("e-ts", "/usr/bin/timeshift")),
            ("/usr/bin/btrfs", "subvolume delete /.snapshots/9/snapshot", ("e-sd", "/usr/bin/snapperd")),
            ("/usr/bin/borg", "delete /mnt/backup::old", ("e-bm", "/usr/bin/borgmatic")),
            ("/usr/bin/snapper", "delete 1", ("e-helper", "/usr/lib/snapper/systemd-helper")),
        ] {
            assert!(one(exe, args, Some(parent)).is_empty(), "{} {} under {}", exe, args, parent.1);
        }
        // ...but the manager itself being told to delete IS the finding.
        assert_eq!(one("/usr/bin/timeshift", "--delete-all", None).len(), 1);
        // And an unrelated parent does not launder it.
        assert_eq!(one("/usr/bin/btrfs", "subvolume delete /.snapshots/9/snapshot", Some(("e-node", "/usr/bin/node"))).len(), 1);
    }

    #[test]
    fn the_finding_quotes_the_command_and_offers_the_parent_scope() {
        let out = one("/usr/bin/snapper", "-c root delete 40-50", Some(("e-node", "/usr/bin/node")));
        let f = &out[0];
        assert!(f.what_override.as_ref().unwrap().starts_with("snapper ran `snapper -c root delete 40-50`"), "{:?}", f.what_override);
        assert!(f.extra_evidence[0].contains("/usr/bin/snapper -c root delete 40-50"));
        assert_eq!(f.meta.fp_hint, "parent");
        assert!(f.ancestry_line.contains("node -> snapper"), "{}", f.ancestry_line);
    }
}
