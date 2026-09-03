//! `sentineld` — the daemon and the policy renderer.
//!
//! Two subcommands:
//!
//! * `render-policies` — runs as tetragon.service's `ExecStartPre`; expands
//!   `{{HOME}}` and regenerates the export-allowlist.
//! * `run` — tails the export, serves the control socket.
//!
//! Every path is overridable, which is what makes dev mode possible:
//!
//! ```text
//! sentineld run --log ./testdata/sample.log --state-dir /tmp/x \
//!               --socket /tmp/x/sock --policies-dir ./testdata/policies
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::{Args, Parser, Subcommand};

use sentineld::config::Config;
use sentineld::engine::{self, Daemon, RunOptions};
use sentineld::render::{render, RenderOptions};
use sentineld::{control, util};

#[derive(Parser)]
#[command(
    name = "sentineld",
    version,
    about = "omarchy-sentinel daemon: turns Tetragon events into explainable alerts"
)]
struct Cli {
    /// Config file (default /etc/sentinel/sentinel.toml, or $SENTINEL_CONFIG).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// -v for debug, -vv for trace.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Expand {{HOME}} in the policy templates and write the export allowlist.
    RenderPolicies(RenderArgs),
    /// Tail the Tetragon export and serve the control socket.
    Run(RunArgs),
    /// Print the effective configuration and exit.
    Config,
}

#[derive(Args)]
struct RenderArgs {
    /// Templates carrying {{HOME}}.
    #[arg(long)]
    templates_dir: Option<PathBuf>,
    /// Where rendered policies go (Tetragon's tracing-policy-dir).
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// Generated Tetragon conf.d fragment. `--export-allowlist ''` skips it.
    #[arg(long)]
    export_allowlist: Option<PathBuf>,
    /// Where to look for human users.
    #[arg(long)]
    passwd: Option<PathBuf>,
    /// Use these homes instead of scanning passwd (repeatable; for testing).
    #[arg(long = "home")]
    homes: Vec<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Default)]
struct RunArgs {
    /// Tetragon JSON export to tail.
    #[arg(long)]
    log: Option<PathBuf>,
    /// alerts.jsonl, state.json, quarantine/, feeds/ live here.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Control socket path.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Rendered policies (for annotations).
    #[arg(long)]
    policies_dir: Option<PathBuf>,
    #[arg(long)]
    allowlist_dir: Option<PathBuf>,
    #[arg(long)]
    sandbox_flag: Option<PathBuf>,
    #[arg(long)]
    tetra: Option<PathBuf>,
    #[arg(long)]
    passwd: Option<PathBuf>,
    /// Group that owns the socket and the alert log.
    #[arg(long)]
    group: Option<String>,
    /// Starting mode; state.json wins if it has one.
    #[arg(long)]
    mode: Option<String>,
    /// Read the log from the beginning instead of tailing from the end.
    #[arg(long)]
    from_start: bool,
    /// Process what is there and exit (implies --from-start). For dev-run.
    #[arg(long)]
    once: bool,
    /// Do not bind the control socket.
    #[arg(long)]
    no_socket: bool,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    let cfg_path = cli.config.clone().unwrap_or_else(Config::default_path);
    let cfg = match Config::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sentineld: {}", e);
            return std::process::ExitCode::from(2);
        }
    };

    match cli.cmd.unwrap_or(Cmd::Run(RunArgs::default())) {
        Cmd::RenderPolicies(a) => cmd_render(cfg, a),
        Cmd::Run(a) => cmd_run(cfg, cfg_path, a),
        Cmd::Config => {
            println!("{}", toml::to_string_pretty(&cfg).unwrap_or_default());
            std::process::ExitCode::SUCCESS
        }
    }
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_timestamp_secs()
        .init();
}

fn cmd_render(cfg: Config, a: RenderArgs) -> std::process::ExitCode {
    let templates = a.templates_dir.unwrap_or(cfg.paths.templates_dir);
    let out = a.out_dir.unwrap_or(cfg.paths.policies_dir);
    let allowlist = match a.export_allowlist {
        Some(p) if p.as_os_str().is_empty() => None,
        Some(p) => Some(p),
        None => Some(cfg.paths.export_allowlist),
    };
    let passwd = a.passwd.unwrap_or(cfg.paths.passwd);
    let opts = RenderOptions {
        templates_dir: &templates,
        out_dir: &out,
        export_allowlist: allowlist.as_deref(),
        passwd: &passwd,
        homes: (!a.homes.is_empty()).then_some(a.homes.clone()),
    };
    let report = match render(&opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sentineld render-policies: {}", e);
            return std::process::ExitCode::from(1);
        }
    };
    if a.json {
        println!(
            "{}",
            serde_json::json!({
                "rendered": report.rendered,
                "failed": report.failed.iter().map(|(n, e)| serde_json::json!({"template": n, "error": e})).collect::<Vec<_>>(),
                "files_changed": report.files_changed,
                "removed": report.removed.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "allowlist_changed": report.allowlist_changed,
                "out_dir": out.display().to_string(),
            })
        );
    } else {
        println!(
            "rendered {} policies into {} ({} changed{})",
            report.rendered.len(),
            out.display(),
            report.files_changed,
            if report.allowlist_changed {
                ", export-allowlist updated"
            } else {
                ""
            }
        );
        for (name, e) in &report.failed {
            eprintln!("  FAILED {}: {}", name, e);
        }
        for p in &report.removed {
            println!("  removed stale {}", p.display());
        }
    }
    // A partial render is still worth loading, so this is not fatal; the failed
    // names show up in `status.policies_failed` once the daemon is up.
    std::process::ExitCode::SUCCESS
}

fn cmd_run(mut cfg: Config, cfg_path: PathBuf, a: RunArgs) -> std::process::ExitCode {
    if let Some(p) = a.log {
        cfg.paths.tetragon_log = p;
    }
    if let Some(p) = a.state_dir {
        cfg.paths.state_dir = p;
    }
    if let Some(p) = a.socket {
        cfg.paths.socket = p;
    }
    if let Some(p) = a.policies_dir {
        cfg.paths.policies_dir = p;
    }
    if let Some(p) = a.allowlist_dir {
        cfg.paths.allowlist_dir = p;
    }
    if let Some(p) = a.sandbox_flag {
        cfg.paths.sandbox_flag = p;
    }
    if let Some(p) = a.tetra {
        cfg.paths.tetra = p;
    }
    if let Some(p) = a.passwd {
        cfg.paths.passwd = p;
    }
    if let Some(g) = a.group {
        cfg.group = g;
    }
    if let Some(m) = a.mode {
        cfg.mode = m;
    }
    if let Some(p) = cfg.paths.socket.parent() {
        cfg.paths.runtime_dir = p.to_path_buf();
    }

    for dir in [&cfg.paths.state_dir, &cfg.paths.runtime_dir] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("sentineld: {}: {}", dir.display(), e);
            return std::process::ExitCode::from(1);
        }
        let _ = util::secure_path(dir, &cfg.group, 0o750);
    }
    if let Err(e) = std::fs::create_dir_all(cfg.paths.feeds()) {
        log::warn!("{}: {}", cfg.paths.feeds().display(), e);
    }

    engine::install_signal_handlers();

    let socket = cfg.paths.socket.clone();
    let group = cfg.group.clone();
    let daemon = match Daemon::new(cfg, &cfg_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("sentineld: {}", e);
            return std::process::ExitCode::from(1);
        }
    };
    log::info!(
        "sentineld {} starting: {} policies, {} allowlist rules, {} feed hashes, mode {}",
        sentineld::VERSION,
        daemon.policies.len(),
        daemon.allowlist.len(),
        daemon.feeds.meta.hashes,
        daemon.mode
    );
    if !daemon.policies.failed.is_empty() {
        log::warn!("policies that did not parse: {:?}", daemon.policies.failed);
    }

    let shared = Arc::new(Mutex::new(daemon));
    if !a.no_socket {
        if let Err(e) = control::serve(Arc::clone(&shared), &socket, &group) {
            eprintln!("sentineld: {}: {}", socket.display(), e);
            return std::process::ExitCode::from(1);
        }
    }
    shared.lock().expect("daemon lock").write_state();

    engine::run(
        Arc::clone(&shared),
        RunOptions {
            from_start: a.from_start || a.once,
            once: a.once,
            ..Default::default()
        },
    );

    if !a.no_socket {
        let _ = std::fs::remove_file(&socket);
    }
    std::process::ExitCode::SUCCESS
}
