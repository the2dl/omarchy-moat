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
    /// Mark an alert as seen.
    /// Mark an alert as seen. With no ID, use --all/--rule/--before to clear a
    /// backlog: after a rule retune the old alerts are about rules that no
    /// longer exist, and they hide the real ones until they are cleared.
    Ack {
        id: Option<String>,
        /// Ack every unacked alert.
        #[arg(long)]
        all: bool,
        /// Ack only alerts from this rule, e.g. moat-pkg-subtree-netcat-exec.
        #[arg(long)]
        rule: Option<String>,
        /// Ack only alerts older than this alert id.
        #[arg(long)]
        before: Option<String>,
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
    /// set mode monitor|enforce, or set sandbox on|off.
    Set {
        key: String,
        value: String,
        /// Only this policy, leaving every other one — and the daemon-wide
        /// mode — untouched. The safe way to start enforcing: one rule whose
        /// false-positive surface you have already measured.
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
    /// How unusual this alert's tuple is on this machine (LEARNING §1).
    Rarity { id: String },
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

fn main() -> ExitCode {
    let cli = Cli::parse();
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
        Cmd::Ack { id, all, rule, before } => json!({
            "cmd": "ack",
            "id": id.clone().unwrap_or_default(),
            "all": all,
            "rule": rule.clone().unwrap_or_default(),
            "before": before.clone().unwrap_or_default(),
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
        Cmd::Rarity { id } => json!({"cmd": "rarity", "id": id}),
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
            Cmd::Digest { notify: true, force } => {
                return send_digest(&resp, *force, &socket, cli.json)
            }
            _ => {}
        }
    }

    ExitCode::from(exit_code(&cli.cmd, &resp))
}

/// LEARNING §2 step 2: `omarchy-agent --prompt "<preamble>"`, in this session.
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

    let argv = moatd::analysis::launch_argv(path);
    if dry_run {
        println!("{} --prompt {:?}", argv[0], argv[2]);
        return ExitCode::SUCCESS;
    }
    println!("handing {} to {} …", path, agent);
    let err = Command::new(&argv[0]).args(&argv[1..]).exec();
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
        Cmd::Explain { .. } => match serde_json::from_value::<Alert>(r["alert"].clone()) {
            Ok(a) => print_explain(&a),
            Err(e) => eprintln!("moatctl: unreadable alert: {}", e),
        },
        Cmd::Ack { id, all, rule, before } => {
            if *all || rule.is_some() || before.is_some() {
                let n = r["acked"].as_u64().unwrap_or(0);
                println!("acked {} alert(s)", n);
                if let Some(f) = r["failed"].as_array() {
                    for e in f {
                        eprintln!("  failed: {}", e.as_str().unwrap_or("?"));
                    }
                }
            } else {
                println!("acked {}", id.clone().unwrap_or_default());
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

fn print_status(r: &Value) {
    let u = &r["unacked"];
    println!("moatd  {}   mode {}", r["version"].as_str().unwrap_or("?"), r["mode"].as_str().unwrap_or("?"));
    // What is actually armed to kill, which is never obvious from `mode` alone
    // once rules can be enforced individually.
    if let Some(e) = r["enforcing_rules"].as_array().filter(|e| !e.is_empty()) {
        println!(
            "enforcing  {}",
            e.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")
        );
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
        for (label, key) in [("exe", "exe"), ("file", "path"), ("parent", "parent")] {
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
                println!(
                    "{} is now {} in the kernel; the daemon stays in {} mode",
                    rule,
                    r["requested"].as_str().unwrap_or("?"),
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
    use super::*;

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
            (Cmd::Bundle { id: "01X".into() }, "bundle"),
            (Cmd::Analyze { id: "01X".into(), dry_run: true }, "analyze"),
            (Cmd::Rarity { id: "01X".into() }, "rarity"),
            (Cmd::Digest { notify: true, force: false }, "digest"),
        ];
        for (cmd, want) in &cases {
            let req = match cmd {
                Cmd::Receipts { last } => json!({"cmd": "receipts", "last": last}),
                Cmd::Incidents { last } => json!({"cmd": "incidents", "last": last}),
                Cmd::Bundle { id } => json!({"cmd": "bundle", "id": id}),
                Cmd::Analyze { id, .. } => json!({"cmd": "analyze", "id": id}),
                Cmd::Rarity { id } => json!({"cmd": "rarity", "id": id}),
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
