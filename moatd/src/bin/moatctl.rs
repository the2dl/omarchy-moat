//! `moatctl` — a thin CLI over the control socket.
//!
//! It gains nothing from root: the socket is 0660 root:moat and every
//! action names an alert id. If the connection is refused, the error tells the
//! user exactly how to join the group.

use std::path::PathBuf;
use std::process::ExitCode;

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
    Ack { id: String },
    /// SIGKILL the process tree the alert recorded.
    Kill { id: String },
    /// Move the alert's file into /var/lib/moat/quarantine.
    Quarantine { id: String },
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
    /// Remove the n-th rule from allowlist.d/user.toml (see `allowlist`).
    Unignore { rule: u64 },
    /// List the merged allowlist rules with their index and comment.
    Allowlist,
    /// set mode monitor|enforce, or set sandbox on|off.
    Set { key: String, value: String },
    /// feeds refresh
    Feeds {
        #[arg(default_value = "refresh")]
        action: String,
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
        Cmd::Ack { id } => json!({"cmd": "ack", "id": id}),
        Cmd::Kill { id } => json!({"cmd": "kill", "id": id}),
        Cmd::Quarantine { id } => json!({"cmd": "quarantine", "id": id}),
        Cmd::Ignore { id, scope, comment } => json!({
            "cmd": "ignore", "id": id, "scope": scope,
            "comment": comment.clone().unwrap_or_default()
        }),
        Cmd::Unignore { rule } => json!({"cmd": "unignore", "rule": rule}),
        Cmd::Allowlist => json!({"cmd": "allowlist"}),
        Cmd::Set { key, value } => json!({"cmd": "set", "key": key, "value": value}),
        Cmd::Feeds { action } => json!({"cmd": "feeds", "action": action}),
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

    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
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
        Cmd::Ack { id } => println!("acked {}", id),
        Cmd::Kill { .. } => println!(
            "killed pids {}",
            r["killed"]
                .as_array()
                .map(|a| a.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default()
        ),
        Cmd::Quarantine { .. } => println!(
            "moved {}\n   to {}\n   (mode 000; meta.json alongside it records how to restore)",
            r["from"].as_str().unwrap_or(""),
            r["to"].as_str().unwrap_or("")
        ),
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
        Cmd::Set { key, .. } => print_set(key, r),
        Cmd::Feeds { .. } => println!(
            "feeds: {} hashes, {} domains (updated {})\n{}",
            r["feeds"]["hashes"], r["feeds"]["domains"],
            r["feeds"]["updated"].as_str().unwrap_or("never"),
            r["stdout"].as_str().unwrap_or("")
        ),
    }
}

fn print_status(r: &Value) {
    let u = &r["unacked"];
    println!("moatd  {}   mode {}", r["version"].as_str().unwrap_or("?"), r["mode"].as_str().unwrap_or("?"));
    println!("tetragon   {}", r["tetragon"].as_str().unwrap_or("?"));
    println!(
        "policies   {}{}",
        r["policies"],
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
        println!("{}  {}", idx, x["name"].as_str().unwrap_or(""));
        if let Some(c) = x["comment"].as_str().filter(|c| !c.is_empty()) {
            println!("     # {}", c);
        }
        for (label, key) in [("exe", "exe"), ("file", "path"), ("parent", "parent")] {
            if let Some(v) = x[key].as_str() {
                println!("     {} = {}", label, v);
            }
        }
        println!("     from {}", x["file"].as_str().unwrap_or(""));
    }
    println!(
        "\nRemove one with `moatctl unignore <index>` (indexed rules live in {}).",
        r["user_file"].as_str().unwrap_or("user.toml")
    );
    if let Some(errs) = r["errors"].as_array() {
        for e in errs {
            eprintln!("warning: {}", e.as_str().unwrap_or(""));
        }
    }
}

fn print_set(key: &str, r: &Value) {
    match key {
        "mode" => {
            println!(
                "mode is now {} ({} of {} policies updated via {})",
                r["mode"].as_str().unwrap_or("?"),
                r["applied"],
                r["policies"],
                r["tetra"].as_str().unwrap_or("tetra")
            );
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
