//! `moat-ship` — send the record somewhere it survives.
//!
//! Runs as a systemd unit in group `moat` with **no capabilities at all**.
//! `alerts.jsonl` and `telemetry.jsonl` are 0640 root:moat, so reading them
//! needs group membership and nothing more; the outbound socket needs nothing
//! either. That is the whole reason this is a separate binary rather than a
//! thread in moatd: moatd runs as root with the kernel sensor attached, and an
//! HTTPS client there would put a TLS stack, a retry loop and a
//! remote-controlled blocking point inside the process that owns detection.
//! `moat-feeds` is the same argument in the other direction.
//!
//! Subcommands:
//!
//! * `run` — the service. Polls, ships, heartbeats, backs off.
//! * `once` — one pass and exit. For a timer, and for testing.
//! * `check` — validate the config and the destination, send nothing.
//! * `status` — what the cursor says. Never prints a secret.
//!
//! `--dry-run` on `run`/`once` prints the exact bytes a collector would
//! receive, with the token still unresolved, and does not advance the cursor.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use moatd::config::Config;
use moatd::ship::{
    self, describe_https, DryRunTransport, HttpsTransport, ShipConfig, Shipper, Source,
    SyslogTransport, Transport,
};
use moatd::util;

#[derive(Parser)]
#[command(
    name = "moat-ship",
    version,
    about = "Ship moat alerts and telemetry to an HTTPS collector or syslog"
)]
struct Cli {
    /// ship.toml (default /etc/moat/ship.toml, or $MOAT_SHIP_CONFIG).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// moat.toml, for the state directory and the human homes used by redaction.
    #[arg(long, global = true)]
    moat_config: Option<PathBuf>,
    /// Where cursor.json lives. Defaults to <state_dir>/ship.
    #[arg(long, global = true)]
    cursor_dir: Option<PathBuf>,
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Poll and ship until stopped. This is what the unit runs.
    Run {
        /// Print what would be sent instead of sending it. The cursor does not
        /// move, so a dry run costs nothing and repeats.
        #[arg(long)]
        dry_run: bool,
        /// Stop after this many passes (testing).
        #[arg(long)]
        max_passes: Option<u64>,
    },
    /// One pass and exit.
    Once {
        #[arg(long)]
        dry_run: bool,
    },
    /// Validate the configuration; send nothing.
    Check,
    /// What has been shipped, dropped and withheld.
    Status {
        #[arg(long)]
        json: bool,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }))
    .format_timestamp_secs()
    .init();

    let cfg_path = cli.config.clone().unwrap_or_else(ShipConfig::default_path);
    let ship_cfg = match ShipConfig::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("moat-ship: {}", e);
            return std::process::ExitCode::from(2);
        }
    };
    let moat_cfg_path = cli.moat_config.clone().unwrap_or_else(Config::default_path);
    let moat_cfg = Config::load(&moat_cfg_path).unwrap_or_default();

    let cursor_dir = cli
        .cursor_dir
        .clone()
        .unwrap_or_else(|| moat_cfg.paths.state_dir.join("ship"));
    let cursor_path = cursor_dir.join("cursor.json");

    match cli.cmd.unwrap_or(Cmd::Run {
        dry_run: false,
        max_passes: None,
    }) {
        Cmd::Check => cmd_check(&ship_cfg, &cfg_path),
        Cmd::Status { json } => cmd_status(&ship_cfg, &cursor_path, json),
        Cmd::Once { dry_run } => {
            run_passes(ship_cfg, &cfg_path, &moat_cfg, cursor_path, dry_run, Some(1))
        }
        Cmd::Run {
            dry_run,
            max_passes,
        } => run_passes(
            ship_cfg,
            &cfg_path,
            &moat_cfg,
            cursor_path,
            dry_run,
            max_passes,
        ),
    }
}

/// Sources in `CLASSES` order. `alerts` is `alerts.jsonl`; everything else
/// comes out of the one `telemetry.jsonl` moatd writes, so the shipper never
/// needs to read `/var/log/moat/tetragon.log` — which is 0600 root:root, and
/// which a privilege-free shipper must not need and must not be given.
fn sources(cfg: &Config) -> Vec<Source> {
    let mut v = vec![Source {
        class: "alerts".into(),
        path: cfg.paths.alerts(),
        rotated: cfg.paths.alerts_rotated(),
    }];
    for class in ["process", "network", "file"] {
        v.push(Source {
            class: class.into(),
            path: cfg.paths.telemetry(),
            rotated: cfg.paths.telemetry_rotated(),
        });
    }
    v
}

/// Deduplicate the telemetry sources: they are all the same file, and reading
/// it once per class would ship every record three times.
///
/// The class on a telemetry record is a field inside the line, not the file it
/// came from, so the shipper reads `telemetry.jsonl` under a single source and
/// `Shipper::class_filter` decides per record which ones survive.
fn effective_sources(cfg: &Config, ship_cfg: &ShipConfig) -> Vec<Source> {
    let mut out = Vec::new();
    let mut telemetry_added = false;
    for s in sources(cfg) {
        if !ship_cfg.classes.iter().any(|c| c == &s.class) {
            continue;
        }
        if s.class == "alerts" {
            out.push(s);
            continue;
        }
        if !telemetry_added {
            telemetry_added = true;
            // One source for the file, named by the first enabled class; the
            // per-record class filter does the rest.
            out.push(s);
        }
    }
    out
}

fn cmd_check(cfg: &ShipConfig, cfg_path: &std::path::Path) -> std::process::ExitCode {
    println!("config:    {}", cfg_path.display());
    println!("enabled:   {}", cfg.enabled);
    println!("transport: {}", cfg.transport);
    println!("classes:   {}", cfg.classes.join(", "));
    println!("heartbeat: every {}s", cfg.heartbeat_secs);
    match cfg.transport.as_str() {
        "https" => print!("{}", describe_https(&cfg.https)),
        "syslog" => println!(
            "syslog:    {} facility {} app {} max {} bytes (SUMMARY projection)",
            cfg.syslog.target, cfg.syslog.facility, cfg.syslog.app_name, cfg.syslog.max_len
        ),
        _ => {}
    }
    println!(
        "redaction: home={} secret_paths={} extra={}",
        cfg.redact.home,
        cfg.redact.secret_paths,
        cfg.redact.extra.len()
    );
    let problems = cfg.problems(cfg_path);
    if problems.is_empty() {
        println!("\nOK");
        std::process::ExitCode::SUCCESS
    } else {
        println!();
        for p in &problems {
            println!("PROBLEM: {}", p);
        }
        std::process::ExitCode::from(1)
    }
}

fn cmd_status(
    cfg: &ShipConfig,
    cursor_path: &std::path::Path,
    json: bool,
) -> std::process::ExitCode {
    let c = ship::Cursor::load(cursor_path);
    if json {
        // Deliberately built by hand rather than serialising the config: there
        // is no field of ShipConfig that holds a secret which could slip in,
        // and this keeps it that way for the next field somebody adds.
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "cursor": cursor_path.display().to_string(),
                "enabled": cfg.enabled,
                "transport": cfg.transport,
                "classes": cfg.classes,
                "shipped": c.shipped,
                "dropped": c.dropped,
                "withheld": c.withheld,
                "last_ok": c.last_ok,
                "last_error": c.last_error,
                "sources": c.sources.iter().map(|(k, v)| {
                    serde_json::json!({"class": k, "offset": v.offset, "inode": v.inode})
                }).collect::<Vec<_>>(),
            })
        );
    } else {
        println!("cursor:    {}", cursor_path.display());
        println!("transport: {} ({})", cfg.transport, if cfg.enabled { "enabled" } else { "disabled" });
        println!("shipped:   {}", c.shipped);
        println!("dropped:   {}", c.dropped);
        println!("withheld:  {} (staged evidence refused)", c.withheld);
        println!("last ok:   {}", if c.last_ok.is_empty() { "never" } else { &c.last_ok });
        if !c.last_error.is_empty() {
            println!("last error:{}", c.last_error);
        }
        for (class, s) in &c.sources {
            println!("  {:<8} offset {} inode {}", class, s.offset, s.inode);
        }
    }
    std::process::ExitCode::SUCCESS
}

fn run_passes(
    ship_cfg: ShipConfig,
    cfg_path: &std::path::Path,
    moat_cfg: &Config,
    cursor_path: PathBuf,
    dry_run: bool,
    max_passes: Option<u64>,
) -> std::process::ExitCode {
    let problems = ship_cfg.problems(cfg_path);
    for p in &problems {
        log::error!("{}", p);
    }
    if !problems.is_empty() && !dry_run {
        // Refuse rather than ship badly. A collector token in a world-readable
        // file or a plain-http endpoint is not something to warn about and
        // then do anyway.
        return std::process::ExitCode::from(1);
    }
    if !ship_cfg.enabled && !dry_run {
        log::info!(
            "shipping is disabled ({}: enabled = false); nothing to do",
            cfg_path.display()
        );
        return std::process::ExitCode::SUCCESS;
    }

    let host = if ship_cfg.host.is_empty() {
        ship::hostname()
    } else {
        ship_cfg.host.clone()
    };
    let homes = util::human_homes(&moat_cfg.paths.passwd);

    // The token is resolved exactly once, here, and reaches exactly two
    // places: the transport's header map, and the scrubber's deny list.
    let token = match ship_cfg.token() {
        Ok(t) => t,
        Err(e) => {
            log::error!("token: {}", e);
            return std::process::ExitCode::from(1);
        }
    };
    let mut secrets: Vec<String> = ship_cfg.redact.extra.clone();
    if !token.is_empty() {
        secrets.push(token.clone());
    }
    let scrub = ship::Scrubber::new(secrets);

    let poll = std::time::Duration::from_secs(ship_cfg.poll_secs.max(1));
    let srcs = effective_sources(moat_cfg, &ship_cfg);
    if srcs.is_empty() {
        log::warn!("no classes enabled for shipping; nothing to do");
        return std::process::ExitCode::SUCCESS;
    }
    let wanted: Vec<String> = ship_cfg.classes.clone();
    let quarantine = moat_cfg.paths.quarantine();

    let mut tx: Box<dyn Transport> = if dry_run {
        Box::new(DryRunTransport {
            sent: Vec::new(),
            print: true,
            syslog: if ship_cfg.transport == "syslog" {
                Some((ship_cfg.syslog.clone(), host.clone()))
            } else {
                None
            },
        })
    } else {
        match ship_cfg.transport.as_str() {
            "https" => Box::new(HttpsTransport::new(&ship_cfg.https, &token, scrub.clone())),
            "syslog" => Box::new(SyslogTransport::new(&ship_cfg.syslog, &host)),
            _ => {
                log::info!("transport = none; nothing to do");
                return std::process::ExitCode::SUCCESS;
            }
        }
    };
    // `token` has done its job. Nothing below this line may read it.
    drop(token);

    let mut shipper = Shipper::new(
        ship_cfg,
        host,
        cursor_path,
        srcs,
        &homes,
        &moat_cfg.analysis.bundle_dir,
        &quarantine,
        scrub,
    );
    shipper.class_filter = wanted;
    // A dry run must be repeatable: it previews the backlog, it does not eat it.
    shipper.persist = !dry_run;

    log::info!(
        "moat-ship {} -> {} (classes {:?})",
        moatd::VERSION,
        tx.name(),
        shipper.cfg.classes
    );

    install_signal_handlers();
    let mut passes = 0u64;
    loop {
        if STOP.load(std::sync::atomic::Ordering::SeqCst) {
            log::info!("stopping");
            break;
        }
        let n = shipper.pass(tx.as_mut(), util::unix_secs());
        if n > 0 {
            log::debug!("shipped {} records", n);
        }
        passes += 1;
        if max_passes.is_some_and(|m| passes >= m) {
            break;
        }
        // Sleep in slices so SIGTERM is answered promptly.
        //
        // `thread::sleep` retries on EINTR, so a signal during it does not cut
        // it short: the handler set STOP and the process went on sleeping for
        // the rest of `poll_secs`. With the 5 s TimeoutStopSec this machine
        // defaults to and a 10 s poll, that made a clean stop IMPOSSIBLE --
        // every restart ended `State 'stop-sigterm' timed out. Killing.` and
        // `Failed with result 'timeout'`, which is what a shipper looks like
        // when it is losing data even though this one is not (the cursor only
        // advances past acknowledged batches, so a SIGKILL re-sends at worst
        // one batch).
        //
        // Raising the timeout would have hidden it. A daemon should answer a
        // stop request at the speed of the request, not of its poll interval.
        let slice = std::time::Duration::from_millis(250);
        let mut slept = std::time::Duration::ZERO;
        while slept < poll {
            if STOP.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let step = slice.min(poll - slept);
            std::thread::sleep(step);
            slept += step;
        }
    }
    let s = shipper.stats();
    log::info!(
        "moat-ship exiting: {} shipped, {} dropped, {} withheld, {} still buffered",
        s.shipped,
        s.dropped,
        s.withheld,
        s.backlog
    );
    std::process::ExitCode::SUCCESS
}

static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}
