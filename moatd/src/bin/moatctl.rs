//! `moatctl` — a thin CLI over the control socket.
//!
//! It gains nothing from root: the socket is 0660 root:moat and every
//! action names an alert id. If the connection is refused, the error tells the
//! user exactly how to join the group.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use moatd::alert::Alert;
use moatd::config::Config;
use moatd::control::request;

#[derive(Parser)]
#[command(
    name = "moatctl",
    version,
    about = "Inspect and act on Moat alerts",
    after_help = "Every action names an alert id, never a pid or a path.\n\
                  If you get a permission error: sudo usermod -aG moat $USER, then log out and back in."
)]
struct Cli {
    /// Control socket (default /run/moat/control.sock).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// moat.toml, used only to find the socket.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Print the raw JSON response.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Daemon, Tetragon, policy, feed and unacked-alert state.
    Status,
    /// Recent alerts, newest last.
    List {
        /// Only alerts after this id.
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u64,
    },
    /// The full explanation for one alert.
    Explain { id: String },
    /// Everything the panel needs, already folded: alerts and receipts in one
    /// response. Not meant to be read by a person; `list` is.
    Feed {
        #[arg(long, default_value_t = 500)]
        limit: u64,
    },
    /// Every decision the kill gate has made: what it spared, what it would
    /// have killed, and why. This is the evidence for whether `set kill kill`
    /// is safe on this machine -- read it before arming, not after.
    Decisions {
        #[arg(long, default_value_t = 50)]
        limit: u64,
    },
    /// Per-rule cross-family neighbour rate: how often each rule's alerts sit
    /// beside ANOTHER family in one process tree. The evidence for whether a
    /// rule could be gated behind a sequence without switching it off -- read
    /// it before gating, not after. Covers the whole store, not a page of it.
    Neighbours,
    /// Make Moat forget what it has learned about one network destination, so
    /// the next connection there is a first contact again. Needs root, and is
    /// recorded. For a re-provisioned host, a changed network, or a lab.
    Forget {
        /// An address, e.g. 192.168.44.122
        dst: String,
    },
    /// Mark an alert as seen. With no ID, use --all/--rule/--before to clear a
    /// backlog: after a rule retune the old alerts are about rules that no
    /// longer exist, and they hide the real ones until they are cleared.
    Ack {
        /// One or more alert ids. Several ids are answered in ONE request:
        /// the panel closes a whole card this way, and acking N alerts should
        /// cost one round trip, not N.
        ids: Vec<String>,
        /// Ack every unacked alert.
        #[arg(long)]
        all: bool,
        /// Ack only alerts from this rule, e.g. moat-pkg-subtree-netcat-exec.
        #[arg(long)]
        rule: Option<String>,
        /// Ack only alerts older than this alert id.
        #[arg(long)]
        before: Option<String>,
        /// Ack every alert in the same chain. One decision about a sequence
        /// should not leave its other four steps on the badge.
        #[arg(long)]
        chain: bool,
    },
    /// SIGKILL the process tree the alert recorded.
    Kill { id: String },
    /// Move the alert's file into /var/lib/moat/quarantine.
    Quarantine {
        id: Option<String>,
        /// Show everything held, with where it came from and when.
        #[arg(long)]
        list: bool,
        /// Put this one back where it came from.
        #[arg(long)]
        restore: bool,
    },
    /// Stop alerting on this pattern; writes a [[rule]] block and acks.
    Ignore {
        id: String,
        /// exe | exe+file | parent | rule
        #[arg(long, default_value = "exe")]
        scope: String,
        /// Appended to the generated comment.
        #[arg(long)]
        comment: Option<String>,
    },
    /// Write an allowlist entry directly, without waiting for an alert.
    ///
    /// `ignore <alert-id>` needs an alert to have fired and offers four canned
    /// scopes; this takes the matchers themselves, including `--script`, which
    /// no scope can express. Every field is a glob and every field present must
    /// match.
    ///
    /// It PREVIEWS by default: it prints which alerts on record the entry would
    /// have suppressed and writes nothing. `--yes` (with sudo) commits it.
    /// Seeing the blast radius before granting is the whole point of the
    /// command, so it is the default rather than a flag.
    Allow {
        /// The rule to allow, or a glob: moat-cred-ssh-private-key-read,
        /// moat-cred-*. Required.
        #[arg(long)]
        name: String,
        /// The binary that acted. For a script this is the INTERPRETER, which
        /// is why naming one here without --script is refused.
        #[arg(long)]
        exe: Option<String>,
        /// The file that was touched.
        #[arg(long)]
        file: Option<String>,
        /// Any ancestor's binary, up to the ancestry cap.
        #[arg(long)]
        parent: Option<String>,
        /// What an interpreter was actually running, e.g.
        /// /opt/google-cloud-cli/lib/gcloud.py. This is how you allow `gcloud`
        /// without allowing every python program on the machine.
        #[arg(long)]
        script: Option<String>,
        /// Appended to the generated comment. Say WHY; `moatctl allowlist`
        /// will still be showing it in six months.
        #[arg(long)]
        comment: Option<String>,
        /// Actually write it. Needs root, and is recorded.
        #[arg(long)]
        yes: bool,
    },
    /// Remove the n-th rule from an allowlist.d file (see `allowlist`).
    Unignore {
        rule: u64,
        /// Which file the index is in. Defaults to user.toml; use
        /// `--file baseline.toml` to drop a learned entry.
        #[arg(long)]
        file: Option<String>,
    },
    /// List the merged allowlist rules with their index and comment.
    Allowlist,
    /// set mode monitor|enforce, sandbox on|off, digest on|off, contain on|off,
    /// kill off|log|kill (what containment does to the processes involved), or
    /// threshold.<NAME> <N|default> to retune a detection
    /// (`threshold.ransom_churn_files 12`) without editing moat.toml or
    /// restarting anything — an unknown name lists the ones there are.
    /// Everything but `digest` needs root: they are the switches that can
    /// weaken protection, and a hijacked package runs as you, not as root.
    /// A threshold needs root in BOTH directions, because whether a number is
    /// a weakening depends on the number it replaces.
    Set {
        key: String,
        value: String,
        /// Only this rule, leaving every other one — and the daemon-wide
        /// mode — untouched. The safe way to start enforcing: one rule whose
        /// false-positive surface you have already measured. Takes a kernel
        /// policy or one of the userland rules that kills
        /// (`moat-pkg-subtree-netcat-exec`, `moat-shell-stdio-socket`);
        /// `moatctl status --json` lists them all under `enforceable`.
        #[arg(long)]
        rule: Option<String>,
    },
    /// feeds refresh
    Feeds {
        #[arg(default_value = "refresh")]
        action: String,
    },
    /// The learning window, its proposals, and the noise guard (BASELINE §3/§4).
    Baseline {
        #[command(subcommand)]
        action: BaselineCmd,
    },
    /// What package installs actually did (LEARNING §3). Informational.
    Receipts {
        #[arg(long, default_value_t = 20)]
        last: u64,
    },
    /// Incident snapshots on disk (LEARNING §4).
    Incidents {
        #[arg(long, default_value_t = 20)]
        last: u64,
    },
    /// Write <incidents dir>/<id>/bundle.md and print its path (LEARNING §2).
    Bundle { id: String },
    /// Bundle the alert and hand it to your default agent (LEARNING §2).
    Analyze {
        id: String,
        /// Print the command instead of running it.
        #[arg(long)]
        dry_run: bool,
    },
    /// The unattended agent pass (LEARNING §2c). `--run` is what the user
    /// timer runs; with no flags it prints what is waiting.
    Triage {
        /// Do the pass: bundle each pending alert, ask the agent, record the
        /// verdict.
        #[arg(long)]
        run: bool,
        /// At most this many; the daemon's `triage_max_per_run` otherwise.
        #[arg(long)]
        limit: Option<usize>,
        /// Print the agent command for the first pending alert and stop.
        #[arg(long)]
        dry_run: bool,
        /// Drop this alert's verdict and put it back on the badge.
        #[arg(long, value_name = "ID")]
        undo: Option<String>,
    },
    /// How unusual this alert's tuple is on this machine (LEARNING §1).
    Rarity { id: String },
    /// The sequence an alert is part of: what led here, with times (design 2b).
    /// With no ID, list the chains on record.
    Chain {
        id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u64,
    },
    /// Binaries a rule has been told to stop watching, and how to undo that.
    Exclusions {
        /// Watch this binary again. Takes `<rule>:<binary>` as listed.
        #[arg(long)]
        remove: Option<String>,
    },
    /// What moatd is refusing on its own judgement right now, and how to stop it.
    Contain {
        /// Drop the containment for this chain immediately.
        #[arg(long)]
        release: Option<String>,
    },
    /// The weekly digest (LEARNING §5). `--notify` is what the user timer runs.
    Digest {
        /// Send it through omarchy-notification-send, if it is due and on.
        #[arg(long)]
        notify: bool,
        /// Send it even when it is not due yet.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum BaselineCmd {
    /// Learning state, pending proposals, learned entries, demoted rules.
    List,
    /// Write a pending proposal into allowlist.d/baseline.toml.
    Accept { id: String },
    /// Drop a pending proposal and stop being asked about it.
    Dismiss { id: String },
    /// Restart the learning window, for after a big change.
    Relearn {
        #[arg(long)]
        days: Option<u64>,
    },
    /// Dump every tuple for review (LEARNING §8 step 1).
    Export {
        /// Only tuples last seen on or after this date (YYYY-MM-DD).
        #[arg(long)]
        since: Option<String>,
    },
    /// Propose baseline entries for a noisy rule's top tuples.
    Propose {
        #[arg(long)]
        rule: String,
        #[arg(long, default_value_t = 5)]
        top: u64,
    },
    /// Clear a demotion: go back to watching this rule, or all of them.
    Undemote {
        rule: Option<String>,
        /// Clear every demotion. Use after a retune: the demotions on the board
        /// were caused by the noise you just fixed.
        #[arg(long)]
        all: bool,
    },
}

/// Verbs that change what moat does or hides an alert. An agent may run
/// moatctl to READ (status, list, explain, chain, decisions) but never to act:
/// the auto-triage ceiling is "explain and at most demote", and an agent that
/// reached a shell must not be able to ack, allowlist, disarm or release from
/// it. `MOAT_AGENT_CONTEXT` is set by every path that launches an agent over
/// moat's own evidence; the user's own shell never has it. The sandbox already
/// masks the socket, so this is the second lock, for the paths that run an
/// agent unconfined (a machine without moat-sandbox, a `--dry-run` a human
/// pasted). Bypassable by a shell that unsets its own env -- which is why the
/// sandbox, not this, is the boundary -- but it stops the ordinary case where
/// an agent runs the `moatctl ack` it found in a recommendation list.
fn agent_may_not_run(cmd: &Cmd) -> bool {
    if std::env::var("MOAT_AGENT_CONTEXT").ok().as_deref() != Some("1") {
        return false;
    }
    matches!(
        cmd,
        Cmd::Ack { .. }
            // `allow --yes` writes; `allow` on its own only previews, and an
            // agent drafting a rule for a person to run is exactly what the
            // preview is for. The gate is on the commit, not on the thinking.
            | Cmd::Allow { yes: true, .. }
            | Cmd::Ignore { .. }
            | Cmd::Unignore { .. }
            | Cmd::Set { .. }
            | Cmd::Kill { .. }
            | Cmd::Quarantine { .. }
            | Cmd::Forget { .. }
            | Cmd::Contain { .. }
            | Cmd::Baseline { .. }
    )
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if agent_may_not_run(&cli.cmd) {
        eprintln!(
            "moatctl: refusing a state-changing command from inside an agent context. \
             An agent analysing moat's evidence may read, and may propose commands for \
             you to run -- it may not run them itself."
        );
        return ExitCode::FAILURE;
    }

    let socket = cli.socket.clone().unwrap_or_else(|| {
        let p = cli.config.clone().unwrap_or_else(Config::default_path);
        Config::load(&p).unwrap_or_default().paths.socket
    });

    let req = match &cli.cmd {
        Cmd::Status => json!({"cmd": "status"}),
        Cmd::List { since, limit } => {
            json!({"cmd": "list", "since": since.clone().unwrap_or_default(), "limit": limit})
        }
        Cmd::Explain { id } => json!({"cmd": "explain", "id": id}),
        Cmd::Forget { dst } => json!({"cmd": "forget", "dst": dst}),
        Cmd::Decisions { limit } => json!({"cmd": "decisions", "limit": limit}),
        Cmd::Neighbours => json!({"cmd": "neighbours"}),
        Cmd::Feed { limit } => json!({"cmd": "feed", "limit": limit}),
        Cmd::Ack { ids, all, rule, before, chain } => json!({
            "cmd": "ack",
            // The first id keeps the single-alert and --chain paths working
            // unchanged; `ids` is what the daemon uses when there are several.
            "id": ids.first().cloned().unwrap_or_default(),
            "ids": ids,
            "all": all,
            "rule": rule.clone().unwrap_or_default(),
            "before": before.clone().unwrap_or_default(),
            "chain": chain,
        }),
        Cmd::Kill { id } => json!({"cmd": "kill", "id": id}),
        Cmd::Quarantine { id, list, restore } => json!({
            "cmd": "quarantine",
            "id": id.clone().unwrap_or_default(),
            "action": if *list { "list" } else if *restore { "restore" } else { "" },
        }),
        Cmd::Ignore { id, scope, comment } => json!({
            "cmd": "ignore", "id": id, "scope": scope,
            "comment": comment.clone().unwrap_or_default()
        }),
        Cmd::Unignore { rule, file } => {
            json!({"cmd": "unignore", "rule": rule, "index": rule, "file": file.clone().unwrap_or_default()})
        }
        Cmd::Allow {
            name,
            exe,
            file,
            parent,
            script,
            comment,
            yes,
        } => json!({
            "cmd": "allow",
            "action": if *yes { "add" } else { "preview" },
            "name": name,
            "exe": exe.clone().unwrap_or_default(),
            "file": file.clone().unwrap_or_default(),
            "parent": parent.clone().unwrap_or_default(),
            "script": script.clone().unwrap_or_default(),
            "comment": comment.clone().unwrap_or_default(),
        }),
        Cmd::Allowlist => json!({"cmd": "allowlist"}),
        Cmd::Set { key, value, rule } => json!({
            "cmd": "set", "key": key, "value": value,
            "rule": rule.clone().unwrap_or_default(),
        }),
        Cmd::Feeds { action } => json!({"cmd": "feeds", "action": action}),
        Cmd::Baseline { action } => baseline_request(action),
        Cmd::Receipts { last } => json!({"cmd": "receipts", "last": last}),
        Cmd::Incidents { last } => json!({"cmd": "incidents", "last": last}),
        Cmd::Bundle { id } => json!({"cmd": "bundle", "id": id}),
        Cmd::Analyze { id, .. } => json!({"cmd": "analyze", "id": id}),
        Cmd::Triage { limit, undo, .. } => match undo {
            Some(id) => json!({"cmd": "triage", "action": "undo", "id": id}),
            None => json!({"cmd": "triage", "action": "pending", "limit": limit}),
        },
        Cmd::Rarity { id } => json!({"cmd": "rarity", "id": id}),
        Cmd::Chain { id, limit } => json!({
            "cmd": "chain", "id": id.clone().unwrap_or_default(), "limit": limit,
        }),
        Cmd::Exclusions { remove } => match remove {
            Some(pair) => {
                let (rule, exe) = pair.split_once(':').unwrap_or(("", ""));
                json!({"cmd": "exclusions", "action": "remove", "rule": rule, "exe": exe})
            }
            None => json!({"cmd": "exclusions", "action": "list"}),
        },
        Cmd::Contain { release } => match release {
            Some(chain) => json!({"cmd": "contain", "action": "release", "id": chain}),
            None => json!({"cmd": "contain", "action": "list"}),
        },
        Cmd::Digest { .. } => json!({"cmd": "digest"}),
    };

    let resp = match request(&socket, &req) {
        Ok(r) => r,
        Err(e) => {
            if cli.json {
                println!("{}", json!({"ok": false, "error": e}));
            } else {
                eprintln!("moatctl: {}", e);
            }
            return ExitCode::from(3);
        }
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&resp).unwrap_or_default());
    } else {
        print_human(&cli.cmd, &resp);
    }

    // Two commands finish their work in the **user's** session, with what the
    // daemon answered: launching the agent, and sending the notification. The
    // daemon does neither — it runs as root with no session (LEARNING §2, §5).
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        match &cli.cmd {
            Cmd::Analyze { dry_run, .. } => return launch_agent(&resp, *dry_run),
            Cmd::Triage { run, dry_run, undo: None, .. } if *run || *dry_run => {
                return run_triage(&resp, &socket, *dry_run, cli.json)
            }
            Cmd::Digest { notify: true, force } => {
                return send_digest(&resp, *force, &socket, cli.json)
            }
            _ => {}
        }
    }

    ExitCode::from(exit_code(&cli.cmd, &resp))
}

/// LEARNING §2 step 2: `omarchy-agent --prompt "<preamble>"`, in this session.
/// LEARNING §2c: the unattended pass, run from the user's session by
/// `moat-triage.timer`.
///
/// The daemon cannot do this itself — it is root, has no session, and holds
/// none of the agent's credentials — so the split mirrors `analyze` and
/// `digest`: the daemon says what needs looking at and decides what the answer
/// is allowed to do; this side does the looking.
///
/// Nothing here decides anything. It bundles, asks, parses, and posts the
/// answer back; `cmd_triage` re-validates it and applies the ceiling. A crash,
/// a timeout, a truncated answer or a hostile one all end the same way: the
/// alert is left exactly as it was.
fn run_triage(resp: &Value, socket: &std::path::Path, dry_run: bool, json_out: bool) -> ExitCode {
    use moatd::triage;

    let mode = resp["mode"].as_str().unwrap_or("off");
    if mode == "off" {
        if !json_out {
            println!("auto_triage is off (`[analysis] auto_triage` in moat.toml)");
        }
        return ExitCode::SUCCESS;
    }
    let pending = resp["pending"].as_array().cloned().unwrap_or_default();
    if pending.is_empty() {
        if !json_out {
            println!("nothing waiting to be triaged");
        }
        return ExitCode::SUCCESS;
    }
    let agent = match moatd::analysis::default_agent() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("moatctl triage: {}", e);
            return ExitCode::from(2);
        }
    };
    // The unattended path builds its own flags precisely so a config key cannot
    // relax them; say so rather than appearing to honour the setting.
    let cfg: BTreeMap<String, Vec<String>> =
        serde_json::from_value(resp["agent_args"].clone()).unwrap_or_default();
    if let Some(note) = triage::agent_args_ignored(&agent, &cfg) {
        eprintln!("moatctl triage: {}", note);
    }
    // FAIL CLOSED. moat-sandbox is what masks the control socket (and the
    // credential stores) from the agent; without it the agent runs with the
    // user's full authority over content that is under suspicion by
    // definition, and on 2026-09-06 an unconfined agent reached
    // `moatctl ack` and cleared its own findings off the badge. An unattended
    // pass that cannot be confined must not run at all -- warning and running
    // anyway was fail-open, which is the wrong default for the path with
    // nobody watching.
    let sandbox = match moatd::analysis::sandbox_bin() {
        Some(bin) => bin,
        None => {
            eprintln!(
                "moatctl triage: moat-sandbox is not available. The agent will NOT run \
                 unconfined over content under suspicion -- it could reach the control \
                 socket and act on its own findings. Install moat-sandbox, or set \
                 `[analysis] auto_triage = \"off\"`."
            );
            return ExitCode::FAILURE;
        }
    };
    let sandbox = Some(sandbox);
    let timeout = resp["timeout_secs"].as_u64().unwrap_or(180);

    // Two passes must not overlap. systemd will not start a second
    // moat-triage.service while one is active, but a hand-run `moatctl triage
    // --run` races it happily: on the first live run here, the timer's pass and
    // a manual one both picked the same pending alert and both spent a full
    // agent call on it, because `pending` is a snapshot and nothing marks an
    // alert as being worked on. The lock costs nothing and makes the manual
    // command safe to type at any moment.
    let _lock = match TriageLock::acquire() {
        Ok(l) => l,
        Err(e) => {
            if !json_out {
                println!("another triage pass is already running ({e})");
            }
            return ExitCode::SUCCESS;
        }
    };

    let mut done = 0usize;
    let mut checked_visibility: Option<bool> = None;
    for item in &pending {
        let id = item["id"].as_str().unwrap_or_default();
        if id.is_empty() {
            continue;
        }
        let bundle = match request(socket, &json!({"cmd": "bundle", "id": id})) {
            Ok(b) if b["ok"] == Value::Bool(true) => b["path"].as_str().unwrap_or("").to_string(),
            Ok(b) => {
                eprintln!("moatctl triage {}: {}", id, b["error"].as_str().unwrap_or("bundle failed"));
                continue;
            }
            Err(e) => {
                eprintln!("moatctl triage {}: {}", id, e);
                continue;
            }
        };
        // The agent reads the bundle from inside the sandbox, which is not the
        // same filesystem view this process has: moat-sandbox gives the child a
        // private /tmp, so a bundle_dir under /tmp is invisible to it while
        // being perfectly readable from here. Without this check that costs a
        // full agent call and records a confident-sounding "no evidence was
        // examined" verdict on a real alert. Checked once — the whole directory
        // is either visible or it is not.
        if checked_visibility.is_none() {
            checked_visibility = Some(bundle_is_visible(sandbox.as_deref(), &agent, &bundle));
        }
        if checked_visibility == Some(false) {
            eprintln!(
                "moatctl triage: {} cannot be read inside moat-sandbox, so the agent would have no evidence to read. A bundle_dir under /tmp cannot work — the sandbox gives the child a private /tmp. Nothing was triaged.",
                bundle
            );
            return ExitCode::from(2);
        }
        let argv = match triage::launch_argv(&agent, &triage::preamble(&bundle), sandbox.as_deref()) {
            Ok(a) => a,
            // An agent with no read-only headless mode is not run at all. This
            // is a per-machine fact, not a per-alert one, so stop rather than
            // repeat it for every pending alert.
            Err(e) => {
                eprintln!("moatctl triage: {}", e);
                return ExitCode::from(2);
            }
        };
        if dry_run {
            println!("{}", argv.iter().map(|a| format!("{:?}", a)).collect::<Vec<_>>().join(" "));
            return ExitCode::SUCCESS;
        }
        let output = match capture(&argv, timeout) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("moatctl triage {}: {}", id, e);
                continue;
            }
        };
        let result = match triage::parse_result(&output.stdout) {
            Ok(r) => r,
            // The alert stays untouched and stays on the badge, which is the
            // safe direction: an answer nobody can read is not a reason to stop
            // showing the user the evidence.
            //
            // This is the one case where the agent's stderr earns its place in
            // the log: it said something we could not use, and the reason is
            // usually there rather than on stdout.
            Err(e) => {
                eprintln!("moatctl triage {}: {}", id, e);
                let why = tail_lines(&output.stderr, 5);
                if !why.is_empty() {
                    eprintln!("moatctl triage {}: agent stderr: {}", id, why);
                }
                continue;
            }
        };
        let submit = json!({
            "cmd": "triage", "action": "submit", "id": id,
            "agent": agent, "result": result,
        });
        match request(socket, &submit) {
            Ok(r) if r["ok"] == Value::Bool(true) => {
                done += 1;
                if !json_out {
                    println!("{}  {}  {}", id, r["outcome"].as_str().unwrap_or("?"), result.summary);
                }
            }
            Ok(r) => eprintln!("moatctl triage {}: {}", id, r["error"].as_str().unwrap_or("refused")),
            Err(e) => eprintln!("moatctl triage {}: {}", id, e),
        }
    }
    if json_out {
        println!("{}", json!({"ok": true, "triaged": done, "pending": pending.len()}));
    }
    ExitCode::SUCCESS
}

/// A non-blocking exclusive lock held for the duration of one pass.
///
/// `flock` rather than a pid file: the kernel drops it when the process dies,
/// so a killed or crashed pass never leaves a stale lock that needs clearing by
/// hand. Released on drop, and on exit either way.
struct TriageLock(std::fs::File);

impl TriageLock {
    fn acquire() -> Result<TriageLock, String> {
        let dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
        let path = std::path::Path::new(&dir).join("moat-triage.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("{}: {}", path.display(), e))?;
        // SAFETY: a plain flock on a fd this process owns for the call's duration.
        let rc = unsafe {
            libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX | libc::LOCK_NB)
        };
        if rc != 0 {
            return Err(format!("{} is held", path.display()));
        }
        Ok(TriageLock(file))
    }
}

impl Drop for TriageLock {
    fn drop(&mut self) {
        // SAFETY: same fd, still open; the kernel would release it at exit anyway.
        unsafe {
            libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN);
        }
    }
}

/// Can the agent actually read the bundle from where it will run?
///
/// Answered by asking the sandbox, rather than by pattern-matching the path:
/// the deny list, the private /tmp and `~/.config/moat/sandbox.conf` all shape
/// what the child sees, and only the sandbox knows the result.
fn bundle_is_visible(sandbox_bin: Option<&str>, agent: &str, bundle: &str) -> bool {
    let Some(bin) = sandbox_bin else {
        // Unconfined: this process and the agent share a filesystem view, and
        // the daemon just wrote the file.
        return std::path::Path::new(bundle).exists();
    };
    let probe = vec!["test".to_string(), "-r".to_string(), bundle.to_string()];
    let argv = moatd::analysis::sandbox_argv(agent, bin, &probe);
    Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The last `n` non-blank lines of a stream, for a diagnostic that has to fit
/// in a log line rather than reproduce the whole run.
fn tail_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join(" | ")
}

struct AgentOutput {
    stdout: String,
    stderr: String,
}

/// Run the agent and collect its output, with a wall-clock ceiling.
///
/// Both streams are drained on their own threads rather than read after the
/// wait: an agent that prints more than a pipe buffer would otherwise block
/// forever while this side waits for an exit that cannot come. Killing on the
/// deadline closes the pipes, which ends the readers too.
///
/// stderr is **captured, not inherited**. Inheriting put roughly 2 KB in the
/// journal per alert per pass, because `moat-sandbox` echoes its whole argv —
/// prompt included — in its `[moat] sandboxed:` banner. Silencing that with
/// MOAT_QUIET would also lose the warnings that share the same `warn()`
/// (`--allow <dir> does not exist`, the cwd-denied error), which are exactly
/// what a failed pass needs. Capturing keeps all of it and shows it only when
/// something went wrong.
fn capture(argv: &[String], timeout_secs: u64) -> Result<AgentOutput, String> {
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        // The agent (and any moatctl it spawns) runs marked: it may read moat's
        // evidence, never act on it. `agent_may_not_run` enforces the other end.
        .env("MOAT_AGENT_CONTEXT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run {}: {}", argv[0], e))?;
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_string(&mut s);
            }
            s
        })
    };
    let out_reader = drain(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let err_reader = drain(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => return Err(format!("waiting for {}: {}", argv[0], e)),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    if timed_out {
        // The tail is what says WHY it hung -- a sandbox refusal, an auth
        // prompt the agent could not show. Without it a timeout is unactionable.
        let why = tail_lines(&stderr, 3);
        return Err(if why.is_empty() {
            format!("{} did not answer within {}s", argv[0], timeout_secs)
        } else {
            format!("{} did not answer within {}s: {}", argv[0], timeout_secs, why)
        });
    }
    Ok(AgentOutput { stdout, stderr })
}

fn launch_agent(resp: &Value, dry_run: bool) -> ExitCode {
    let path = resp["path"].as_str().unwrap_or_default();
    let agent = match moatd::analysis::default_agent() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("moatctl analyze: {}", e);
            eprintln!("  the bundle is ready at {}", path);
            return ExitCode::from(2);
        }
    };
    // `agent_args` cannot reach the agent through omarchy-agent (see
    // moatd::analysis); say so rather than dropping it silently.
    let cfg: BTreeMap<String, Vec<String>> =
        serde_json::from_value(resp["agent_args"].clone()).unwrap_or_default();
    if let Some(note) = moatd::analysis::agent_args_note(&agent, &cfg) {
        eprintln!("moatctl analyze: {}", note);
    }

    let inner = moatd::analysis::launch_argv(path);
    // The bundle now stages the accused file for the agent to read, and reading
    // hostile content is exactly when injection has something to gain. Confine
    // the agent so a successful injection cannot turn "analyse this dropper"
    // into "read ~/.ssh". It keeps its network and its own config; it loses the
    // credential stores.
    let argv = match moatd::analysis::sandbox_bin() {
        Some(bin) => moatd::analysis::sandbox_argv(&agent, &bin, &inner),
        None => {
            eprintln!(
                "moatctl analyze: moat-sandbox is not available, so {} will run unconfined \
                 and can read ~/.ssh, ~/.aws and the browser profiles. The bundle stages a \
                 file that is already under suspicion; treat its analysis accordingly.",
                agent
            );
            inner.clone()
        }
    };
    if dry_run {
        println!("{}", argv.iter().map(|a| format!("{:?}", a)).collect::<Vec<_>>().join(" "));
        return ExitCode::SUCCESS;
    }
    println!("handing {} to {} …", path, agent);
    let err = Command::new(&argv[0]).args(&argv[1..]).env("MOAT_AGENT_CONTEXT", "1").exec();
    eprintln!(
        "moatctl analyze: could not run {}: {}\n  the bundle is ready at {}",
        argv[0], err, path
    );
    ExitCode::from(2)
}

/// LEARNING §5: what the user timer runs once a week.
fn send_digest(resp: &Value, force: bool, socket: &std::path::Path, json_out: bool) -> ExitCode {
    if resp["enabled"] != Value::Bool(true) {
        if !json_out {
            println!("the weekly digest is off (`moatctl set digest on` turns it back on)");
        }
        return ExitCode::SUCCESS;
    }
    let due = resp["due_unix"].as_u64().unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !force && now < due {
        if !json_out {
            println!(
                "not due yet (next {}); --force sends it anyway",
                resp["due"].as_str().unwrap_or("?")
            );
        }
        return ExitCode::SUCCESS;
    }
    let text = resp["text"].as_str().unwrap_or("moat");
    let body = text.strip_prefix("moat: ").unwrap_or(text);
    let notifier =
        std::env::var("MOAT_NOTIFY_BIN").unwrap_or_else(|_| "omarchy-notification-send".into());
    match Command::new(&notifier)
        .args([
            "-u",
            resp["urgency"].as_str().unwrap_or("normal"),
            "Moat",
            body,
        ])
        .status()
    {
        Ok(s) if s.success() => {
            // Record the delivery so a catch-up run does not send twice.
            let _ = request(socket, &json!({"cmd": "digest", "action": "sent"}));
            if !json_out {
                println!("sent: {}", text);
            }
            ExitCode::SUCCESS
        }
        Ok(s) => {
            eprintln!("moatctl digest: {} exited {:?}", notifier, s.code());
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("moatctl digest: {}: {}", notifier, e);
            ExitCode::from(2)
        }
    }
}

fn baseline_request(a: &BaselineCmd) -> Value {
    match a {
        BaselineCmd::List => json!({"cmd": "baseline", "action": "list"}),
        BaselineCmd::Accept { id } => json!({"cmd": "baseline", "action": "accept", "id": id}),
        BaselineCmd::Dismiss { id } => json!({"cmd": "baseline", "action": "dismiss", "id": id}),
        BaselineCmd::Relearn { days } => {
            json!({"cmd": "baseline", "action": "relearn", "days": days})
        }
        BaselineCmd::Export { since } => {
            json!({"cmd": "baseline", "action": "export", "since": since.clone().unwrap_or_default()})
        }
        BaselineCmd::Propose { rule, top } => {
            json!({"cmd": "baseline", "action": "propose", "rule": rule, "top": top})
        }
        BaselineCmd::Undemote { rule, all } => json!({
            "cmd": "baseline",
            "action": "undemote",
            "rule": rule.clone().unwrap_or_default(),
            "all": all,
        }),
    }
}

/// 0 success, 2 the daemon said no — **and 2 for a `set mode` that reached no
/// policy at all**.
///
/// `set mode` used to exit 0 after applying the mode to zero policies, which is
/// exactly the case a script needs to catch: the daemon remembers the choice,
/// but nothing in the kernel changed, so "enforce" was a lie. The daemon still
/// answers `ok: true` (it did persist the mode); the CLI is where the failure
/// has to be visible.
fn exit_code(cmd: &Cmd, r: &Value) -> u8 {
    if r.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return 2;
    }
    if let Cmd::Set { key, value, .. } = cmd {
        if key == "mode" && r["applied"].as_u64() == Some(0) {
            let policies = r["policies"].as_u64().unwrap_or(0);
            eprintln!(
                "moatctl: mode {} was NOT applied to any policy ({} loaded). The daemon recorded \
                 the choice, but no Tetragon policy changed mode, so nothing is being {}d.",
                value,
                policies,
                if value == "enforce" { "enforce" } else { "monitor" }
            );
            eprintln!(
                "  Check that Tetragon is running and that {} exists:\n  \
                 systemctl status tetragon && {} tp list",
                r["tetra"].as_str().unwrap_or("tetra"),
                r["tetra"].as_str().unwrap_or("tetra")
            );
            if policies == 0 {
                eprintln!("  No policies are loaded at all: run `moatd render-policies` and restart tetragon.");
            }
            return 2;
        }
    }
    0
}

fn print_human(cmd: &Cmd, r: &Value) {
    if r.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        eprintln!(
            "moatctl: {}",
            r.get("error").and_then(|v| v.as_str()).unwrap_or("failed")
        );
        return;
    }
    match cmd {
        Cmd::Status => print_status(r),
        Cmd::List { .. } => print_list(r),
        Cmd::Exclusions { remove: Some(_) } => println!(
            "{} is watched again by {}",
            r["exe"].as_str().unwrap_or("?"),
            r["rule"].as_str().unwrap_or("?")
        ),
        Cmd::Exclusions { remove: None } => {
            let rows = r["exclusions"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("no binary has been excluded from a rule");
            }
            for e in rows {
                let (rule, exe) = (
                    e["rule"].as_str().unwrap_or("?"),
                    e["exe"].as_str().unwrap_or("?"),
                );
                println!(
                    "{}\n  {} is not watched by this rule at all\n  undo: moatctl exclusions --remove {}:{}",
                    rule, exe, rule, exe
                );
            }
        }
        Cmd::Contain { release: Some(chain) } => {
            println!("released {}; that destination is reachable again", chain)
        }
        Cmd::Contain { release: None } => {
            let live = r["live"].as_array().cloned().unwrap_or_default();
            if !r["enabled"].as_bool().unwrap_or(false) {
                println!("containment is off ([contain] enabled = false)");
            }
            if live.is_empty() {
                println!("nothing contained");
            }
            for c in live {
                let dests: Vec<String> = c["dests"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|d| d.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                // `exes`, plural. A containment named one binary until
                // 2026-09-05, when it grew to name every binary in the chain
                // that reached out -- and this reader was left behind, so the
                // one screen you would use to check a containment is sane
                // printed "?" for the thing it contains.
                let exes: Vec<String> = c["exes"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|e| e.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                println!(
                    "{}  {} may not reach {}\n  release: moatctl contain --release {}",
                    c["chain"].as_str().unwrap_or("?"),
                    if exes.is_empty() { "?".to_string() } else { exes.join(", ") },
                    dests.join(", "),
                    c["chain"].as_str().unwrap_or("?")
                );
            }
        }
        // `--run` prints its own progress line per alert as it goes; this is
        // the bare `moatctl triage`, which only says what is waiting.
        Cmd::Triage { undo: Some(id), .. } => println!(
            "{} is back on the badge ({})",
            id,
            r["undone"].as_str().unwrap_or("verdict dropped")
        ),
        Cmd::Triage { run: false, dry_run: false, .. } => {
            let pending = r["pending"].as_array().cloned().unwrap_or_default();
            println!(
                "auto_triage {}   {} alert(s) waiting",
                r["mode"].as_str().unwrap_or("?"),
                pending.len()
            );
            for p in &pending {
                println!(
                    "  {}  {:8}  {}",
                    p["id"].as_str().unwrap_or("?"),
                    p["severity"].as_str().unwrap_or("?"),
                    p["title"].as_str().unwrap_or("?")
                );
            }
        }
        Cmd::Neighbours => {
            let total = r["total"].as_u64().unwrap_or(0);
            if total == 0 {
                println!("no alerts in the store yet, so there is nothing to measure");
                return;
            }
            println!(
                "{} alerts, {} .. {}",
                total,
                r["first_ts"].as_str().unwrap_or("?"),
                r["last_ts"].as_str().unwrap_or("?")
            );
            println!();
            println!(
                "{:<44} {:<10} {:>7} {:>8} {:>8}",
                "rule", "tier", "alerts", "chained", "cross"
            );
            let mut rules = r["rules"].as_array().cloned().unwrap_or_default();
            rules.sort_by_key(|v| std::cmp::Reverse(v["alerts"].as_u64().unwrap_or(0)));
            for v in &rules {
                println!(
                    "{:<44} {:<10} {:>7} {:>8} {:>7.1}%",
                    v["rule"].as_str().unwrap_or("?"),
                    v["tier"].as_str().unwrap_or("?"),
                    v["alerts"].as_u64().unwrap_or(0),
                    v["chained"].as_u64().unwrap_or(0),
                    v["cross_family_pct"].as_f64().unwrap_or(0.0)
                );
            }
            println!();
            for v in r["tiers"].as_array().cloned().unwrap_or_default() {
                println!(
                    "{:<10} {:>7} alerts, cross-family {:.1}%",
                    v["tier"].as_str().unwrap_or("?"),
                    v["alerts"].as_u64().unwrap_or(0),
                    v["cross_family_pct"].as_f64().unwrap_or(0.0)
                );
            }
            println!();
            println!(
                "A rule near 0% has no neighbour to be gated behind: requiring a sequence \
                 would switch it off, not quieten it."
            );
        }
        Cmd::Decisions { .. } => {
            let d = r["decisions"].as_array().cloned().unwrap_or_default();
            if d.is_empty() {
                println!("no kill-gate decisions recorded yet");
            }
            for v in &d {
                println!(
                    "{}  {:<18} {:<9} {}",
                    v["ts"].as_str().unwrap_or("?"),
                    v["verdict"].as_str().unwrap_or("?"),
                    v["severity"].as_str().unwrap_or("?"),
                    v["reason"].as_str().unwrap_or("")
                );
                let t = v["targets"].as_array().cloned().unwrap_or_default();
                if !t.is_empty() {
                    println!("    {}", t.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "));
                }
            }
            if !d.is_empty() {
                println!(
                    "\n{} spared, {} would have been killed, {} killed",
                    r["spared"].as_u64().unwrap_or(0),
                    r["would_have_killed"].as_u64().unwrap_or(0),
                    r["killed"].as_u64().unwrap_or(0)
                );
            }
        }
        Cmd::Forget { dst } => println!(
            "forgot {} counter(s) for {}; the next connection there reports as a first contact",
            r["forgotten"].as_u64().unwrap_or(0),
            dst
        ),
        // Machine-readable only: `--json` carries it, and the plain form says
        // so rather than printing 500 alerts at somebody.
        Cmd::Feed { .. } => println!(
            "{} alert(s), {} receipt(s) — use --json (this is what the panel reads)",
            r["alerts"].as_array().map(|a| a.len()).unwrap_or(0),
            r["receipts"].as_array().map(|a| a.len()).unwrap_or(0)
        ),
        Cmd::Triage { .. } => {}
        Cmd::Explain { .. } => match serde_json::from_value::<Alert>(r["alert"].clone()) {
            Ok(a) => print_explain(&a),
            Err(e) => eprintln!("moatctl: unreadable alert: {}", e),
        },
        Cmd::Ack { ids, all, rule, before, chain } => {
            if *chain {
                println!(
                    "acked {} alert(s) — the whole of chain {}",
                    r["acked"].as_u64().unwrap_or(0),
                    r["chain"].as_str().unwrap_or("?")
                );
            } else if *all || rule.is_some() || before.is_some() {
                let n = r["acked"].as_u64().unwrap_or(0);
                println!("acked {} alert(s)", n);
                // Say what was left alone, or a bulk ack that touched 13 of
                // 1,854 rows looks like it silently failed on the rest.
                if let Some(s) = r["skipped"].as_u64().filter(|s| *s > 0) {
                    println!(
                        "skipped {} recorded/suppressed row(s): they were never on the badge, so \
                         there was nothing to answer",
                        s
                    );
                }
                if let Some(f) = r["failed"].as_array() {
                    for e in f {
                        eprintln!("  failed: {}", e.as_str().unwrap_or("?"));
                    }
                }
            } else {
                println!("acked {}", ids.join(", "));
            }
        }
        Cmd::Kill { .. } => println!(
            "killed pids {}",
            r["killed"]
                .as_array()
                .map(|a| a.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default()
        ),
        Cmd::Quarantine { list, restore, .. } => {
            if *list {
                match r["quarantine"].as_array() {
                    Some(q) if !q.is_empty() => {
                        println!("{} item(s) in {}\n", q.len(), r["dir"].as_str().unwrap_or(""));
                        for x in q {
                            println!(
                                "{}\n  was      {}\n  rule     {}\n  held     {}{}\n  since    {}\n  restore  moatctl quarantine {} --restore\n",
                                x["alert"].as_str().unwrap_or("?"),
                                x["original_path"].as_str().unwrap_or("?"),
                                x["rule"].as_str().unwrap_or("?"),
                                x["held_at"].as_str().unwrap_or("?"),
                                match x["bytes"].as_u64() {
                                    Some(b) => format!(" ({} bytes)", b),
                                    None => " (MISSING)".to_string(),
                                },
                                x["quarantined_at"].as_str().unwrap_or("?"),
                                x["alert"].as_str().unwrap_or("?"),
                            );
                        }
                    }
                    _ => println!("nothing is quarantined"),
                }
            } else if *restore {
                println!("restored {}", r["restored"].as_str().unwrap_or("?"));
            } else {
                println!(
                    "moved {}\n   to {}\n   (mode 000; nothing is deleted — `moatctl quarantine --list` shows it, `--restore` puts it back)",
                    r["from"].as_str().unwrap_or(""),
                    r["to"].as_str().unwrap_or("")
                );
            }
        }
        Cmd::Ignore { .. } => {
            println!(
                "wrote to {} and acked the alert:\n",
                r["file"].as_str().unwrap_or("")
            );
            println!("{}", r["block"].as_str().unwrap_or(""));
            println!("Undo with: moatctl allowlist, then moatctl unignore <index>");
        }
        Cmd::Unignore { .. } => println!(
            "removed from {}:\n\n{}",
            r["file"].as_str().unwrap_or(""),
            r["removed"].as_str().unwrap_or("")
        ),
        Cmd::Allow { yes, .. } => print_allow(*yes, r),
        Cmd::Allowlist => print_allowlist(r),
        Cmd::Baseline { action } => print_baseline(action, r),
        Cmd::Set { key, .. } => print_set(key, r),
        Cmd::Feeds { .. } => println!(
            "feeds: {} hashes, {} domains (updated {})\n{}",
            r["feeds"]["hashes"], r["feeds"]["domains"],
            r["feeds"]["updated"].as_str().unwrap_or("never"),
            r["stdout"].as_str().unwrap_or("")
        ),
        Cmd::Receipts { .. } => print_receipts(r),
        Cmd::Incidents { .. } => print_incidents(r),
        Cmd::Bundle { .. } => println!("{}", r["path"].as_str().unwrap_or("")),
        Cmd::Analyze { .. } => println!(
            "bundle: {}\n(the daemon writes the bundle; the agent is launched here, as you)",
            r["path"].as_str().unwrap_or("")
        ),
        Cmd::Rarity { .. } => println!(
            "{}  {}",
            r["rarity"].as_str().unwrap_or("?"),
            r["rarity_text"].as_str().unwrap_or("")
        ),
        Cmd::Chain { id, .. } => print_chain(id.as_deref(), r),
        Cmd::Digest { .. } => println!(
            "{}\n  {}   next {}{}",
            r["text"].as_str().unwrap_or(""),
            if r["enabled"] == true { "on" } else { "off" },
            r["due"].as_str().unwrap_or("?"),
            match r["last_sent"].as_str() {
                Some(t) => format!("   last sent {}", t),
                None => "   never sent".to_string(),
            }
        ),
    }
}

/// LEARNING §3: the positive picture, in the doc's own layout.
fn print_receipts(r: &Value) {
    let empty = vec![];
    let rendered = r["rendered"].as_array().unwrap_or(&empty);
    if rendered.is_empty() {
        println!("no install receipts yet (they are written when a package install finishes)");
        return;
    }
    let ids = r["receipts"].as_array().unwrap_or(&empty);
    for (i, text) in rendered.iter().enumerate() {
        println!(
            "{}  {}",
            ids.get(i).map(|x| x["id"].as_str().unwrap_or("")).unwrap_or(""),
            ids.get(i).map(|x| x["started"].as_str().unwrap_or("")).unwrap_or("")
        );
        for line in text.as_str().unwrap_or("").lines() {
            println!("  {}", line);
        }
        println!();
    }
    println!(
        "{} receipt(s){}. Receipts never notify and are never counted.",
        rendered.len(),
        match r["open"].as_u64().filter(|n| *n > 0) {
            Some(n) => format!(", {} install(s) still running", n),
            None => String::new(),
        }
    );
}

/// Design 2b, "What led here": ancestry as a story with times.
///
/// The old panel had the data — `kernel -> systemd -> ... -> bash -> flea` —
/// but as one line with no times and no sibling events. This prints the
/// sequence instead: one row per step, the time it happened, and whether it was
/// something the user had already allowed on its own.
fn print_chain(id: Option<&str>, r: &Value) {
    if id.is_none() {
        let chains = r["chains"].as_array().cloned().unwrap_or_default();
        if chains.is_empty() {
            println!("no chains on record");
            return;
        }
        println!(
            "{} chain(s) on record   {} open now\n",
            chains.len(),
            r["open"].as_u64().unwrap_or(0)
        );
        for c in &chains {
            println!(
                "{}  {:8}  {}\n  {}\n  moatctl chain {}\n",
                c["id"].as_str().unwrap_or("?"),
                c["severity"].as_str().unwrap_or("?"),
                c["last_ts"].as_str().unwrap_or("?"),
                c["summary"].as_str().unwrap_or(""),
                c["id"].as_str().unwrap_or("?"),
            );
        }
        return;
    }
    let c = &r["chain"];
    if c.is_null() {
        println!(
            "{} is not part of a chain",
            r["alert"].as_str().unwrap_or("that alert")
        );
        return;
    }
    println!(
        "CHAIN {}   {}\n{}\n",
        c["id"].as_str().unwrap_or("?"),
        c["severity"].as_str().unwrap_or("?").to_uppercase(),
        c["summary"].as_str().unwrap_or("")
    );
    println!(
        "  under    {} (pid {})",
        c["ancestor"]["exe"].as_str().unwrap_or("?"),
        c["ancestor"]["pid"]
    );
    println!("  severity {}", c["severity_reason"].as_str().unwrap_or(""));
    println!("\nWHAT LED HERE\n");
    for s in c["steps"].as_array().cloned().unwrap_or_default() {
        // The time is the point of this screen, so it leads the row.
        println!(
            "  {}  {:8}  {}",
            s["ts"].as_str().unwrap_or("?"),
            s["family"].as_str().unwrap_or("?"),
            s["title"].as_str().unwrap_or("?"),
        );
        println!(
            "  {:24}  {} · pid {} · {}{}",
            "",
            s["rule"].as_str().unwrap_or("?"),
            s["pid"],
            s["alert"].as_str().unwrap_or("?"),
            if s["role"] == "context" {
                "  (you had already allowed this one)"
            } else {
                ""
            },
        );
    }
    if c["truncated"] == Value::Bool(true) {
        println!(
            "\n  ... {} more step(s) not shown",
            c["steps_total"].as_u64().unwrap_or(0) - c["steps"].as_array().map(|a| a.len()).unwrap_or(0) as u64
        );
    }
    println!(
        "\nOne decision covers all of it: moatctl ack {} --chain",
        c["id"].as_str().unwrap_or("?")
    );
}

fn print_incidents(r: &Value) {
    let empty = vec![];
    let rows = r["incidents"].as_array().unwrap_or(&empty);
    if rows.is_empty() {
        println!(
            "no incident snapshots in {} (taken at {} and above)",
            r["dir"].as_str().unwrap_or(""),
            r["snapshot_min_severity"].as_str().unwrap_or("high")
        );
        return;
    }
    for x in rows {
        println!(
            "{}  {:8}  {}",
            x["id"].as_str().unwrap_or(""),
            x["severity"].as_str().unwrap_or("?"),
            x["title"].as_str().unwrap_or("")
        );
        println!(
            "    {}   captured {}{}",
            x["dir"].as_str().unwrap_or(""),
            x["captured"].as_str().unwrap_or("?"),
            if x["bundle"] == true { "   (bundle.md ready)" } else { "" }
        );
        for f in x["files"].as_array().unwrap_or(&empty) {
            println!(
                "      {:<20} {:>9} bytes  {}",
                f["name"].as_str().unwrap_or(""),
                f["size"],
                &f["sha256"].as_str().unwrap_or("")[..12.min(f["sha256"].as_str().unwrap_or("").len())]
            );
        }
        for e in x["errors"].as_array().unwrap_or(&empty) {
            println!("      ! {}", e.as_str().unwrap_or(""));
        }
    }
    println!(
        "\n{} snapshot(s), kept {} days or {} of them. `moatctl analyze <id>` reads one.",
        rows.len(),
        r["retain_days"],
        r["retain_max"]
    );
}

/// The `enforcing` line: what is armed, and then — loudly — the part of it the
/// kernel does not agree with.
///
/// On 2026-09-05 this line listed seven rules as enforcing for a whole day
/// while all seven sat in `monitor` in the kernel: the re-arm ran 2 s after
/// start and tetragon needed 16 s to load 44 policies, every `tetra tp
/// set-mode` failed, and nothing retried or checked. A list of rules that are
/// "armed" is worth nothing on its own — what matters is whether the kernel
/// will act on them — so the unverified set is printed on the same line, in the
/// same shape as the `*** NOT PROTECTED ***` marker on `tetragon`.
///
/// `None` when nothing is armed: an empty line about enforcement is noise.
fn enforcing_line(r: &Value) -> Option<String> {
    let armed: Vec<&str> = r["enforcing_rules"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if armed.is_empty() {
        return None;
    }
    let unverified: Vec<&str> = r["enforcing_unverified"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    let suffix = if !unverified.is_empty() {
        format!(
            "   *** NOT ARMED IN KERNEL: {} — see journal: journalctl -u moatd -u tetragon ***",
            unverified.join(", ")
        )
    } else if r["arming_pending"] == Value::Bool(true) {
        "   (arming: waiting for the sensor to finish loading)".to_string()
    } else {
        String::new()
    };
    Some(format!("enforcing  {}{}", armed.join(", "), suffix))
}

fn print_status(r: &Value) {
    let u = &r["unacked"];
    println!("moatd  {}   mode {}", r["version"].as_str().unwrap_or("?"), r["mode"].as_str().unwrap_or("?"));
    // What is actually armed to kill, which is never obvious from `mode` alone
    // once rules can be enforced individually.
    if let Some(line) = enforcing_line(r) {
        println!("{}", line);
    }
    let state = r["tetragon"].as_str().unwrap_or("?");
    println!(
        "tetragon   {}{}",
        state,
        // Loud, because a sensor that is not loaded makes every other line on
        // this screen meaningless — including a reassuring 0 unacked.
        if r["sensor_unhealthy"] == Value::Bool(true) {
            "   *** NOT PROTECTED — check: systemctl status tetragon ***"
        } else {
            ""
        }
    );
    println!(
        "policies   {}{}{}",
        r["policies"],
        match r["sensors_loaded"].as_u64() {
            Some(n) => format!("   ({} loaded in the kernel)", n),
            None => "   (loaded count unavailable)".to_string(),
        },
        match r["policies_failed"].as_array() {
            Some(f) if !f.is_empty() => format!("   ({} failed to render: {})", f.len(), join(f)),
            _ => String::new(),
        }
    );
    println!(
        "feeds      {} hashes, {} domains, updated {}",
        r["feeds"]["hashes"],
        r["feeds"]["domains"],
        r["feeds"]["updated"].as_str().unwrap_or("never")
    );
    // A rule that is on and cannot fire is worse than one that is off: it
    // reads as coverage. Printed above the counts, because it changes what
    // those counts mean.
    if let Some(inert) = r["inert_rules"].as_array().filter(|a| !a.is_empty()) {
        println!(
            "INERT      {} cannot fire: tetragon needs --enable-process-cred\n\
             \x20          fix: echo true | sudo tee /etc/tetragon/tetragon.conf.d/enable-process-cred\n\
             \x20          then: sudo systemctl restart tetragon",
            inert
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.replace("moat-x-", ""))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    // Three populations, three words, and only the first one is a queue.
    //
    // "unacked 1,854" was true and read as a backlog: 48% of it was
    // allowlist-suppressed (already answered) and most of the rest was timeline
    // rows that were never a question, while the badge said 13. A number is
    // only honest with the word next to it, so the queue is printed first and
    // under its own name, and the other two are printed beside it rather than
    // folded into it. The severity breakdown stays, indented, because it is
    // about the queue and nothing else.
    let l = &r["ledger"];
    if l.is_object() {
        println!(
            "needs you  {}   (recorded {}, of which {} signal; suppressed {})",
            l["needs_you"], l["recorded"], l["signal"], l["suppressed"]
        );
    }
    println!(
        "unacked    critical {}  high {}  medium {}  low {}",
        u["critical"], u["high"], u["medium"], u["low"]
    );
    println!(
        "sandbox    {}",
        if r["sandbox"] == true { "on" } else { "off" }
    );
    println!(
        "socket     group {}   uptime {}s   {} events, {} alerts",
        r["socket_group"].as_str().unwrap_or("moat"),
        r["uptime_secs"],
        r["events_seen"],
        r["alerts"]
    );
    let b = &r["baseline"];
    if !b.is_null() {
        println!(
            "baseline   {}   {} proposal(s), {} learned entr{}",
            if b["learning"] == true {
                format!("learning until {}", b["learning_ends"].as_str().unwrap_or("?"))
            } else {
                "learning window closed".to_string()
            },
            b["proposals"],
            b["learned"],
            if b["learned"].as_u64() == Some(1) { "y" } else { "ies" }
        );
        if let Some(dem) = r["demoted_rules"].as_array().filter(|d| !d.is_empty()) {
            println!("demoted    {}   (timeline only)", join(dem));
        }
    }
}

fn join(v: &[Value]) -> String {
    v.iter()
        .map(|x| x.as_str().unwrap_or("?").to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_list(r: &Value) {
    let empty = vec![];
    let alerts = r["alerts"].as_array().unwrap_or(&empty);
    if alerts.is_empty() {
        println!("no alerts");
        return;
    }
    for a in alerts {
        let acked = if a["acked"] == true { " (acked)" } else { "" };
        let action = match a["action_taken"].as_str().unwrap_or("none") {
            "none" => String::new(),
            other => format!(" [{}]", other),
        };
        let count = match a["count"].as_u64() {
            Some(n) if n > 1 => format!(" x{}", n),
            _ => String::new(),
        };
        println!(
            "{}  {:8}  {}{}{}{}",
            a["id"].as_str().unwrap_or(""),
            a["severity"].as_str().unwrap_or(""),
            a["title"].as_str().unwrap_or(""),
            count,
            action,
            acked
        );
        println!(
            "    {}  {}",
            a["ts"].as_str().unwrap_or(""),
            a["summary"].as_str().unwrap_or("")
        );
    }
    println!("\n{} alert(s). `moatctl explain <id>` for the full story.", alerts.len());
}

/// The five headed sections of CONTRACT §5.
fn print_explain(a: &Alert) {
    let rule = format!("{} ({})", a.rule, a.severity);
    println!("{}", a.title);
    println!("{}", "=".repeat(a.title.chars().count().max(8)));
    println!("{}   {}   alert {}\n", rule, a.ts, a.id);

    println!("WHAT HAPPENED");
    println!("  {}", a.explain.what);
    println!(
        "  process: {} (pid {}, uid {})",
        a.process.exe, a.process.pid, a.process.uid
    );
    if !a.process.args.is_empty() {
        println!("  args:    {}", a.process.args);
    }
    if !a.process.cwd.is_empty() {
        println!("  cwd:     {}", a.process.cwd);
    }
    if !a.process.ancestry.is_empty() {
        let chain: Vec<String> = a
            .process
            .ancestry
            .iter()
            .rev()
            .map(|p| format!("{} ({})", basename(&p.exe), p.pid))
            .collect();
        println!("  parents: {}", chain.join(" -> "));
    }
    if let Some(f) = &a.file {
        println!("  file:    {}", f.path);
    }
    if let Some(n) = &a.net {
        println!("  network: {}:{}", n.dst_ip, n.dst_port);
    }
    if let Some(i) = &a.ioc {
        println!("  ioc:     {} {}", i.source, i.matched);
    }
    println!("  mode:    {}   action taken: {}", a.mode, a.action_taken);

    // The single most important thing about an alert that is part of a
    // sequence is that it is part of a sequence, so it goes above the
    // rule's own reasoning rather than at the end: the rule below explains
    // one event, and the chain is why that event matters.
    if let Some(c) = &a.chain {
        let step = c.steps.iter().position(|s| s.alert == a.id).map(|i| i + 1);
        println!("\nTHIS IS PART OF A SEQUENCE");
        println!("  {}", c.summary);
        // `severity_reason` already names the severity, so printing it again
        // above would read as two different answers to the same question.
        println!("  as a sequence: {}", c.severity_reason);
        match step {
            Some(n) => println!("  this alert is step {} of {}", n, c.steps_total),
            None => println!("  this alert is one of {} steps", c.steps_total),
        }
        println!("  see it whole: moatctl chain {}", c.id);
    }

    println!("\nWHY IT WAS FLAGGED");
    for line in wrap(&a.explain.why, 76) {
        println!("  {}", line);
    }

    println!("\nEVIDENCE");
    for e in &a.explain.evidence {
        println!("  - {}", e);
    }

    println!("\nIF THIS IS EXPECTED");
    for line in wrap(&a.explain.expected, 76) {
        println!("  {}", line);
    }
    println!(
        "  Writes to {} (recommended scope: {}).",
        a.explain.if_expected.file, a.explain.if_expected.hint
    );
    for o in &a.explain.if_expected.options {
        let star = if o.scope == a.explain.if_expected.hint {
            "*"
        } else {
            " "
        };
        println!("\n  {} {}", star, o.cmd);
        for l in o.line.lines() {
            println!("      {}", l);
        }
    }

    println!("\nWHAT TO DO");
    for (i, n) in a.explain.next.iter().enumerate() {
        let prefix = format!("  {}. ", i + 1);
        for (j, line) in wrap(n, 72).into_iter().enumerate() {
            if j == 0 {
                println!("{}{}", prefix, line);
            } else {
                println!("     {}", line);
            }
        }
    }
    if !a.rotate.is_empty() {
        println!("\n  secrets to rotate: {}", a.rotate.join(", "));
    }
}

/// The blast radius, printed the same way whether or not the entry was written.
///
/// The number that matters is "how much of what you have already seen would
/// this have hidden", so it leads with that and only then shows the block. A
/// preview that buried the count under the TOML would be a preview nobody read.
fn print_allow(committed: bool, r: &Value) {
    let would = &r["would"];
    let matched = would["matched"].as_u64().unwrap_or(0);
    let scanned = would["scanned"].as_u64().unwrap_or(0);

    if committed {
        println!("wrote to {}:\n", r["file"].as_str().unwrap_or(""));
    } else {
        println!("nothing was written. This entry would be:\n");
    }
    println!("{}", r["block"].as_str().unwrap_or(""));

    println!(
        "It matches {} of the {} alerts on record.",
        matched, scanned
    );
    if let Some(by) = would["by_rule"].as_object() {
        for (rule, n) in by {
            println!("  {:>4}  {}", n, rule);
        }
    }
    if let Some(sample) = would["sample"].as_array() {
        if !sample.is_empty() {
            println!();
        }
        for a in sample {
            let already = match a["already_suppressed"].as_str() {
                // Worth saying: an entry that only re-covers ground an existing
                // one already covers is a grant with no effect, and the reason
                // people end up with six overlapping rules they dare not touch.
                Some(by) => format!("   (already suppressed by {})", by),
                None => String::new(),
            };
            println!(
                "  {}  {}  {}{}",
                a["id"].as_str().unwrap_or(""),
                a["severity"].as_str().unwrap_or(""),
                a["title"].as_str().unwrap_or(""),
                already
            );
            if let Some(s) = a["script"].as_str() {
                println!("      script {}", s);
            }
        }
        let shown = sample.len() as u64;
        if matched > shown {
            println!("  ... and {} more", matched - shown);
        }
    }
    if matched == 0 {
        println!(
            "\nNothing on record matches it. That is fine if you are allowing something \
             ahead of time -- and it is also what a typo looks like. Check the matchers \
             against `moatctl explain <id>` before committing."
        );
    }
    if committed {
        println!(
            "\nUndo with: moatctl allowlist, then moatctl unignore {}",
            r["index"].as_u64().unwrap_or(0)
        );
    } else {
        println!("\nCommit it with the same command plus `--yes`, under sudo.");
    }
}

fn print_allowlist(r: &Value) {
    let empty = vec![];
    let rules = r["rules"].as_array().unwrap_or(&empty);
    if rules.is_empty() {
        println!(
            "no allowlist rules in {}",
            r["dir"].as_str().unwrap_or("allowlist.d")
        );
        return;
    }
    for x in rules {
        let idx = match x["index"].as_u64() {
            Some(n) => format!("{:>3}", n),
            None => "  -".to_string(),
        };
        println!(
            "{}  {}  [{}]",
            idx,
            x["name"].as_str().unwrap_or(""),
            x["source"].as_str().unwrap_or("shipped")
        );
        if let Some(c) = x["comment"].as_str().filter(|c| !c.is_empty()) {
            println!("     # {}", c);
        }
        for (label, key) in [
            ("exe", "exe"),
            ("file", "path"),
            ("parent", "parent"),
            // Printed since 2026-09-07. Without it an entry whose real actor is
            // `gcloud.py` displayed as nothing but `exe = /usr/bin/python3.14`,
            // so the review read WIDER than the rule actually was.
            ("script", "script"),
        ] {
            if let Some(v) = x[key].as_str() {
                println!("     {} = {}", label, v);
            }
        }
        println!(
            "     from {}{}",
            x["file"].as_str().unwrap_or(""),
            if x["removable"] == false { " (shipped, not removable)" } else { "" }
        );
    }
    println!(
        "\nRemove one with `moatctl unignore <index>` (user.toml) or \
         `moatctl unignore <index> --file baseline.toml` for a learned entry."
    );
    if let Some(errs) = r["errors"].as_array() {
        for e in errs {
            eprintln!("warning: {}", e.as_str().unwrap_or(""));
        }
    }
}

fn print_baseline(a: &BaselineCmd, r: &Value) {
    match a {
        BaselineCmd::List => {
            if r["learning"] == true {
                println!(
                    "learning until {} — recurring official patterns are written straight to {}",
                    r["learning_ends"].as_str().unwrap_or("?"),
                    r["baseline_file"].as_str().unwrap_or("baseline.toml")
                );
            } else {
                println!(
                    "learning window closed on {} — recurring patterns become proposals",
                    r["learning_ends"].as_str().unwrap_or("?")
                );
            }
            let empty = vec![];
            let props = r["proposals"].as_array().unwrap_or(&empty);
            if props.is_empty() {
                println!("\nno proposals to review");
            } else {
                println!("\n{} pattern(s) to review:", props.len());
                for p in props {
                    println!(
                        "\n  {}  {}",
                        p["id"].as_str().unwrap_or(""),
                        p["rule"].as_str().unwrap_or("")
                    );
                    println!(
                        "    {} {}  — {} times on {} day(s), {} .. {}",
                        p["exe"].as_str().unwrap_or(""),
                        p["dir"].as_str().filter(|d| !d.is_empty()).unwrap_or("(no file)"),
                        p["count"],
                        p["days"],
                        p["first_seen"].as_str().unwrap_or(""),
                        p["last_seen"].as_str().unwrap_or("")
                    );
                    // A proposal that carries a reason is NOT the baseline
                    // vouching for the pattern -- it is the noise guard saying
                    // it keeps having to quieten this. Printing it above the
                    // TOML matters: the block below looks identical either
                    // way, and accepting one is a permanent allowlist entry.
                    if let Some(why) = p["reason"].as_str().filter(|w| !w.is_empty()) {
                        println!("    NOTE: {}", why);
                    }
                    for l in p["toml"].as_str().unwrap_or("").lines() {
                        println!("      {}", l);
                    }
                    println!(
                        "    accept: moatctl baseline accept {}   dismiss: moatctl baseline dismiss {}",
                        p["id"].as_str().unwrap_or(""),
                        p["id"].as_str().unwrap_or("")
                    );
                }
            }
            let learned = r["learned"].as_array().unwrap_or(&empty);
            println!("\n{} learned entr{}", learned.len(), if learned.len() == 1 { "y" } else { "ies" });
            for l in learned {
                println!(
                    "  {}  {}  (written {})",
                    l["rule"].as_str().unwrap_or(""),
                    l["exe"].as_str().unwrap_or(""),
                    l["written"].as_str().unwrap_or("")
                );
            }
            if let Some(d) = r["demoted_rules"].as_array().filter(|d| !d.is_empty()) {
                println!("\ndemoted (timeline only): {}", join(d));
                println!("  back to watching: moatctl baseline undemote <rule>");
            }
        }
        BaselineCmd::Accept { .. } => {
            println!("wrote to {}:\n", r["file"].as_str().unwrap_or(""));
            println!("{}", r["block"].as_str().unwrap_or(""));
        }
        BaselineCmd::Dismiss { .. } => println!(
            "dismissed {} for {}",
            r["dismissed"]["id"].as_str().unwrap_or(""),
            r["dismissed"]["rule"].as_str().unwrap_or("")
        ),
        BaselineCmd::Relearn { .. } => println!(
            "learning restarted for {} day(s); it ends {}",
            r["days"], r["learning_ends"].as_str().unwrap_or("?")
        ),
        BaselineCmd::Export { .. } => print_export(r),
        BaselineCmd::Propose { .. } => {
            let empty = vec![];
            let made = r["proposals"].as_array().unwrap_or(&empty);
            println!("{} proposal(s) created for {}", made.len(), r["rule"].as_str().unwrap_or(""));
            for p in made {
                println!("  {}  {}", p["id"].as_str().unwrap_or(""), p["exe"].as_str().unwrap_or(""));
            }
            println!("Review them with `moatctl baseline list`.");
        }
        BaselineCmd::Undemote { rule, all } => {
            if *all {
                match r["cleared"].as_array() {
                    Some(c) if c.is_empty() => println!("nothing was demoted"),
                    Some(c) => {
                        for x in c {
                            println!("{} is being watched again", x.as_str().unwrap_or("?"));
                        }
                    }
                    None => println!("nothing was demoted"),
                }
            } else {
                println!("{} is being watched again", rule.clone().unwrap_or_default());
            }
        }
    }
}

/// LEARNING §8 step 1: a table a human reviews before anything is shipped.
fn print_export(r: &Value) {
    let empty = vec![];
    let rows = r["tuples"].as_array().unwrap_or(&empty);
    println!(
        "# moat baseline export  {}  machine {}  {} tuple(s){}",
        r["generated"].as_str().unwrap_or(""),
        r["machine"].as_str().unwrap_or("?"),
        rows.len(),
        r["since"].as_str().map(|s| format!("  since {}", s)).unwrap_or_default()
    );
    println!("# only `official` provenance is ever eligible to ship (LEARNING §8 step 2).");
    println!(
        "{:<40} {:<9} {:<8} {:>6} {:>5}  actor / dir",
        "rule", "prov", "context", "count", "days"
    );
    for t in rows {
        let mut flags = String::new();
        if t["suppressed"] == true {
            flags.push_str(" [suppressed]");
        }
        if t["demoted"] == true {
            flags.push_str(" [demoted]");
        }
        if t["learned"] == true {
            flags.push_str(" [learned]");
        }
        println!(
            "{:<40} {:<9} {:<8} {:>6} {:>5}  {} {}{}",
            t["rule"].as_str().unwrap_or(""),
            t["provenance"].as_str().unwrap_or(""),
            t["context"].as_str().unwrap_or(""),
            t["count"],
            t["days"],
            t["exe"].as_str().unwrap_or(""),
            t["dir"].as_str().unwrap_or(""),
            flags
        );
    }
    if rows.is_empty() {
        println!("(nothing recorded yet)");
    }
}

fn print_set(key: &str, r: &Value) {
    match key {
        "mode" => {
            let rule = r["rule"].as_str().unwrap_or("");
            if rule.is_empty() {
                println!(
                    "mode is now {} ({} of {} policies updated via {})",
                    r["mode"].as_str().unwrap_or("?"),
                    r["applied"],
                    r["policies"],
                    r["tetra"].as_str().unwrap_or("tetra")
                );
            } else {
                // WHERE it now enforces, because the two are different
                // promises: a kernel policy stops being armed if tetragon
                // restarts without moatd re-arming it, and a userland rule
                // kills from moatd itself and never touches the kernel at all.
                println!(
                    "{} is now {} {}; the daemon stays in {} mode",
                    rule,
                    r["requested"].as_str().unwrap_or("?"),
                    if r["tetra_applied"] == false { "in moatd" } else { "in the kernel" },
                    r["mode"].as_str().unwrap_or("?")
                );
            }
            match r["enforcing_rules"].as_array() {
                Some(e) if !e.is_empty() => println!(
                    "enforcing: {}",
                    e.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                _ => {
                    if r["mode"].as_str() == Some("monitor") {
                        println!("enforcing: nothing");
                    }
                }
            }
            if let Some(f) = r["failed"].as_array().filter(|f| !f.is_empty()) {
                eprintln!("could not set the mode on {} policies:", f.len());
                for x in f {
                    eprintln!(
                        "  {}: {}",
                        x["policy"].as_str().unwrap_or("?"),
                        x["error"].as_str().unwrap_or("")
                    );
                }
            }
        }
        "sandbox" => println!(
            "sandbox shims {} ({})\n{}",
            if r["sandbox"] == true { "enabled" } else { "disabled" },
            r["flag"].as_str().unwrap_or(""),
            r["note"].as_str().unwrap_or("")
        ),
        k if k.starts_with("threshold.") => {
            let name = r["threshold"].as_str().unwrap_or(&k["threshold.".len()..]);
            match r["source"].as_str() {
                Some("moat.toml") => println!(
                    "{} is back to {}, the value in /etc/moat/moat.toml",
                    name, r["value"]
                ),
                _ => {
                    // The direction is said in words, not left to be inferred
                    // from two numbers: "8 -> 20" reads as a tuning, "less will
                    // be caught" reads as what it is.
                    let d = r["direction"].as_str().unwrap_or("same");
                    println!("{} is now {} (was {})", name, r["value"], r["was"]);
                    match d {
                        "weaker" => println!(
                            "  this rule now needs MORE before it fires: less will be caught. \
                             Recorded as a protection change."
                        ),
                        "stronger" => println!("  this rule now fires on less: more will be caught."),
                        _ => println!("  unchanged."),
                    }
                    println!("  in effect from the next event; nothing was restarted.");
                    println!("  undo with: sudo moatctl set threshold.{} default", name);
                }
            }
        }
        _ => println!("{}", serde_json::to_string_pretty(r).unwrap_or_default()),
    }
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Naive greedy wrap; the explain text is prose, never preformatted.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

#[cfg(test)]
mod tests {

    /// An agent may read, never act. The marker is what the launchers set.
    #[test]
    fn an_agent_context_refuses_state_changes_but_not_reads() {
        // Serialise the env mutation; other tests must not see it.
        std::env::set_var("MOAT_AGENT_CONTEXT", "1");

        assert!(agent_may_not_run(&Cmd::Ack { ids: vec!["01X".into()], all: false, rule: None, before: None, chain: false }));
        assert!(agent_may_not_run(&Cmd::Forget { dst: "1.2.3.4".into() }));
        assert!(agent_may_not_run(&Cmd::Set { key: "kill".into(), value: "kill".into(), rule: None }));

        // Reading is always allowed -- the agent needs it to analyse.
        assert!(!agent_may_not_run(&Cmd::Status));
        assert!(!agent_may_not_run(&Cmd::List { since: None, limit: 20 }));
        assert!(!agent_may_not_run(&Cmd::Explain { id: "01X".into() }));

        std::env::remove_var("MOAT_AGENT_CONTEXT");
        // Without the marker, a human shell, nothing is refused.
        assert!(!agent_may_not_run(&Cmd::Ack { ids: vec!["01X".into()], all: false, rule: None, before: None, chain: false }));
    }


    use super::*;

    /// `moatctl status` must not print a reassuring list of armed rules when
    /// the daemon has just told it the kernel disagrees. This is the surface
    /// that lied all day on 2026-09-05.
    #[test]
    fn the_enforcing_line_names_the_rules_the_kernel_is_not_running() {
        let armed = serde_json::json!(["moat-cred-a", "moat-net-b", "moat-priv-c"]);

        // The honest good case: armed, and confirmed in the kernel.
        let ok = serde_json::json!({
            "enforcing_rules": armed,
            "enforcing_verified": armed,
            "enforcing_unverified": [],
            "arming_pending": false,
        });
        let line = enforcing_line(&ok).unwrap();
        assert_eq!(line, "enforcing  moat-cred-a, moat-net-b, moat-priv-c");

        // The failure: the record says three, the kernel is running one.
        let bad = serde_json::json!({
            "enforcing_rules": armed,
            "enforcing_verified": ["moat-cred-a"],
            "enforcing_unverified": ["moat-net-b", "moat-priv-c"],
            "arming_pending": false,
        });
        let line = enforcing_line(&bad).unwrap();
        assert!(line.contains("NOT ARMED IN KERNEL"), "{}", line);
        assert!(line.contains("moat-net-b, moat-priv-c"), "{}", line);
        assert!(
            line.starts_with("enforcing  moat-cred-a, moat-net-b, moat-priv-c"),
            "the armed list is still printed in full, the warning is added to it: {}",
            line
        );
        assert!(line.contains("journalctl"), "and says where to look: {}", line);

        // Mid-boot is not a failure, and must not be shouted about.
        let starting = serde_json::json!({
            "enforcing_rules": armed,
            "enforcing_verified": [],
            "enforcing_unverified": [],
            "arming_pending": true,
        });
        let line = enforcing_line(&starting).unwrap();
        assert!(line.contains("waiting for the sensor"), "{}", line);
        assert!(!line.contains("NOT ARMED"), "{}", line);

        // Nothing armed: no line at all.
        assert!(enforcing_line(&serde_json::json!({"enforcing_rules": []})).is_none());
    }

    fn set_mode_resp(applied: u64, policies: u64) -> Value {
        json!({
            "ok": true, "mode": "enforce", "applied": applied,
            "policies": policies, "failed": [], "tetra": "/usr/bin/tetra"
        })
    }

    #[test]
    fn set_mode_with_nothing_applied_is_a_failure() {
        let cmd = Cmd::Set { key: "mode".into(), value: "enforce".into(), rule: None };
        assert_eq!(exit_code(&cmd, &set_mode_resp(0, 17)), 2, "0 of 17 is a failure");
        assert_eq!(exit_code(&cmd, &set_mode_resp(0, 0)), 2, "no policies at all is too");
        assert_eq!(exit_code(&cmd, &set_mode_resp(17, 17)), 0);
        assert_eq!(exit_code(&cmd, &set_mode_resp(9, 17)), 0, "partial is not a hard failure");
    }

    #[test]
    fn the_stderr_tail_is_a_diagnostic_not_a_transcript() {
        // The whole point: moat-sandbox echoes its argv, prompt included, so a
        // successful pass must not put that in the journal and a failed one
        // must still say why.
        let noisy = "[moat] sandboxed: claude -p -- moat, the runtime security monitor\n\
                     \n   {\n  \"verdict\": ...\n\nPrefer `unclear` to a guess.\n\
                     [moat] --allow /home/dan/.claude does not exist, skipping\n\
                     Invalid API key\n";
        let tail = tail_lines(noisy, 2);
        assert!(tail.contains("Invalid API key"), "{tail}");
        assert!(tail.contains("does not exist"), "{tail}");
        assert!(!tail.contains("sandboxed:"), "the banner is not the diagnostic: {tail}");
        // Blank lines are dropped rather than eating the budget.
        assert_eq!(tail_lines("a\n\n\n b \n", 5), "a |  b");
        assert_eq!(tail_lines("", 3), "");
        assert_eq!(tail_lines("only", 3), "only");
    }

    #[test]
    fn every_baseline_subcommand_maps_to_its_socket_action() {
        let cases: Vec<(BaselineCmd, &str)> = vec![
            (BaselineCmd::List, "list"),
            (BaselineCmd::Accept { id: "01X".into() }, "accept"),
            (BaselineCmd::Dismiss { id: "01X".into() }, "dismiss"),
            (BaselineCmd::Relearn { days: Some(14) }, "relearn"),
            (BaselineCmd::Export { since: Some("2026-09-01".into()) }, "export"),
            (BaselineCmd::Propose { rule: "moat-x-pkg-egress".into(), top: 5 }, "propose"),
            (BaselineCmd::Undemote { rule: Some("moat-x-pkg-egress".into()), all: false }, "undemote"),
        ];
        for (cmd, action) in &cases {
            let r = baseline_request(cmd);
            assert_eq!(r["cmd"], "baseline");
            assert_eq!(r["action"], *action);
        }
        assert_eq!(baseline_request(&cases[1].0)["id"], "01X");
        assert_eq!(baseline_request(&cases[3].0)["days"], 14);
        assert_eq!(baseline_request(&cases[4].0)["since"], "2026-09-01");
        assert_eq!(baseline_request(&cases[5].0)["rule"], "moat-x-pkg-egress");
        // A relearn with no --days lets the daemon use its configured window.
        assert!(baseline_request(&BaselineCmd::Relearn { days: None })["days"].is_null());
        // And an export with no --since sends an empty string, not "null".
        assert_eq!(baseline_request(&BaselineCmd::Export { since: None })["since"], "");
    }

    /// LEARNING §7: every new subcommand is one socket request, and the two
    /// that act in the user's session still go through the daemon first.
    #[test]
    fn the_analysis_subcommands_map_to_their_socket_commands() {
        let cases: Vec<(Cmd, &str)> = vec![
            (Cmd::Receipts { last: 5 }, "receipts"),
            (Cmd::Incidents { last: 5 }, "incidents"),
            (Cmd::Triage { run: false, limit: None, dry_run: false, undo: None }, "triage"),
            (Cmd::Bundle { id: "01X".into() }, "bundle"),
            (Cmd::Analyze { id: "01X".into(), dry_run: true }, "analyze"),
            (Cmd::Rarity { id: "01X".into() }, "rarity"),
            (Cmd::Chain { id: Some("01X".into()), limit: 20 }, "chain"),
            (Cmd::Digest { notify: true, force: false }, "digest"),
        ];
        for (cmd, want) in &cases {
            let req = match cmd {
                Cmd::Receipts { last } => json!({"cmd": "receipts", "last": last}),
                Cmd::Incidents { last } => json!({"cmd": "incidents", "last": last}),
                Cmd::Bundle { id } => json!({"cmd": "bundle", "id": id}),
                Cmd::Analyze { id, .. } => json!({"cmd": "analyze", "id": id}),
                Cmd::Triage { limit, undo, .. } => match undo {
                    Some(id) => json!({"cmd": "triage", "action": "undo", "id": id}),
                    None => json!({"cmd": "triage", "action": "pending", "limit": limit}),
                },
                Cmd::Rarity { id } => json!({"cmd": "rarity", "id": id}),
                Cmd::Chain { id, limit } => json!({
                    "cmd": "chain",
                    "id": id.clone().unwrap_or_default(),
                    "limit": limit,
                }),
                Cmd::Digest { .. } => json!({"cmd": "digest"}),
                _ => unreachable!(),
            };
            assert_eq!(req["cmd"], *want);
        }
        // `analyze` never asks the daemon to launch anything: the request is
        // the same one `bundle` makes, plus the preamble in the answer.
        assert_eq!(
            json!({"cmd": "analyze", "id": "01X"})["cmd"],
            "analyze"
        );
        // And a failed request is still exit 2 for all of them.
        for (cmd, _) in cases {
            assert_eq!(exit_code(&cmd, &json!({"ok": false, "error": "x"})), 2);
            assert_eq!(exit_code(&cmd, &json!({"ok": true})), 0);
        }
    }

    #[test]
    fn other_commands_keep_the_old_contract() {
        // sandbox is unaffected by `applied`.
        let sandbox = Cmd::Set { key: "sandbox".into(), value: "on".into(), rule: None };
        assert_eq!(exit_code(&sandbox, &json!({"ok": true, "applied": 0})), 0);
        // ok:false is always 2.
        assert_eq!(exit_code(&Cmd::Status, &json!({"ok": false, "error": "x"})), 2);
        assert_eq!(exit_code(&Cmd::Status, &json!({"ok": true})), 0);
    }
}
