//! `moatd` — the daemon and the policy renderer.
//!
//! Subcommands:
//!
//! * `render-policies` — runs as tetragon.service's `ExecStartPre`; expands
//!   `{{HOME}}` and regenerates the export-allowlist.
//! * `wait-sensor` — runs as tetragon.service's `ExecStartPost`; blocks until
//!   the rendered policies are actually pinned in the kernel, so
//!   `After=tetragon.service` orders against a LOADED sensor rather than a
//!   forked one (NOTES §7.1).
//! * `run` — tails the export, serves the control socket.
//! * `config`, `telemetry` — report, and apply a telemetry profile.
//!
//! Every path is overridable, which is what makes dev mode possible:
//!
//! ```text
//! moatd run --log ./testdata/sample.log --state-dir /tmp/x \
//!               --socket /tmp/x/sock --policies-dir ./testdata/policies
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::{Args, Parser, Subcommand};

use moatd::config::Config;
use moatd::engine::{self, Daemon, RunOptions};
use moatd::render::{render, RenderOptions};
use moatd::{control, util};

#[derive(Parser)]
#[command(
    name = "moatd",
    version,
    about = "omarchy-moat daemon: turns Tetragon events into explainable alerts"
)]
struct Cli {
    /// Config file (default /etc/moat/moat.toml, or $MOAT_CONFIG).
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
    /// Show or apply the selectable telemetry classes.
    Telemetry(TelemetryArgs),
    /// Block until Tetragon has actually loaded the rendered policies.
    WaitSensor(WaitSensorArgs),
}

#[derive(Args)]
struct WaitSensorArgs {
    /// Seconds to wait before giving up.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// Rendered policies to count against (default `[paths] policies_dir`).
    #[arg(long)]
    policies_dir: Option<PathBuf>,
}

#[derive(Args)]
struct TelemetryArgs {
    /// Validate, render, restart the sensor in the documented order, and then
    /// VERIFY that it came back. Without this the command only reports.
    #[arg(long)]
    apply: bool,
    /// Skip the systemctl restarts (render and validate only). Useful when the
    /// sensor is going to be restarted by something else, and in a container.
    #[arg(long)]
    no_restart: bool,
    /// Seconds to wait for the sensor to come back healthy after the restart.
    #[arg(long, default_value_t = 60)]
    verify_timeout: u64,
    #[arg(long)]
    json: bool,
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
    /// Incident snapshots and bundles (LEARNING §2, §4). Defaults to
    /// `[analysis] bundle_dir`; dev mode points it at a scratch directory.
    #[arg(long)]
    incidents_dir: Option<PathBuf>,
    #[arg(long)]
    sandbox_flag: Option<PathBuf>,
    #[arg(long)]
    tetra: Option<PathBuf>,
    #[arg(long)]
    passwd: Option<PathBuf>,
    /// Local pacman database, for provenance (BASELINE §1).
    #[arg(long)]
    pacman_local: Option<PathBuf>,
    /// `pacman` binary, called once per pacman transaction for `-Sl`.
    #[arg(long)]
    pacman: Option<PathBuf>,
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
            eprintln!("moatd: {}", e);
            return std::process::ExitCode::from(2);
        }
    };

    match cli.cmd.unwrap_or(Cmd::Run(RunArgs::default())) {
        Cmd::RenderPolicies(a) => cmd_render(cfg, a),
        Cmd::Run(a) => cmd_run(cfg, cfg_path, a),
        Cmd::Telemetry(a) => cmd_telemetry(cfg, cfg_path, a),
        Cmd::WaitSensor(a) => cmd_wait_sensor(cfg, a),
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
    // Read before anything moves out of `cfg.paths`.
    let exclusions = moatd::engine::read_exclusions(&cfg.paths.state_file());
    let canary_manifest = cfg.paths.canaries();
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
        telemetry: cfg.telemetry.clone(),
        canaries: moatd::canary::Manifest::load(&canary_manifest).paths(),
        names_enabled: cfg.names.enabled,
        // Read from state.json, because `render-policies` runs as ExecStartPre
        // in its own process: an exclusion the user granted has to survive a
        // restart, or the program they allowed starts dying again after the
        // next reboot with nothing to explain why.
        exclusions,
        // Reserved containment slot names. `render-policies` runs as
        // ExecStartPre, so this is where they actually reach the file
        // tetragon reads at startup.
        contain_slots: cfg.contain.max,
    };
    let report = match render(&opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("moatd render-policies: {}", e);
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
                "skipped": report.skipped.iter().map(|(n, w)| serde_json::json!({"template": n, "reason": w})).collect::<Vec<_>>(),
                "telemetry_classes": report.telemetry_classes,
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
        for (name, why) in &report.skipped {
            println!("  skipped {}: {}", name, why);
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
    if let Some(p) = a.incidents_dir {
        cfg.analysis.bundle_dir = p;
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
    if let Some(p) = a.pacman_local {
        cfg.paths.pacman_local = p;
    }
    if let Some(p) = a.pacman {
        cfg.paths.pacman = p;
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
            eprintln!("moatd: {}: {}", dir.display(), e);
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
            eprintln!("moatd: {}", e);
            return std::process::ExitCode::from(1);
        }
    };
    log::info!(
        "moatd {} starting: {} policies, {} allowlist rules, {} feed hashes, mode {}",
        moatd::VERSION,
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
            eprintln!("moatd: {}: {}", socket.display(), e);
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

// ---------------------------------------------------------------- telemetry

/// `moatd telemetry [--apply]`.
///
/// **A Tetragon restart is the dangerous operation in this whole project.** On
/// 2026-09-03 a bad policy load left the sensor dead for 25 minutes while every
/// surface — systemd, the gRPC socket, the export log's mtime — still read
/// "running". Switching a telemetry class on or off writes new policy files and
/// restarts Tetragon to load them, which is exactly that operation. So this
/// command:
///
/// 1. refuses a configuration that cannot be applied safely (an unscoped file
///    class is the one that matters);
/// 2. renders the policies and re-runs `policies/check.py` over what it wrote,
///    so a template that Tetragon would reject at startup is caught here
///    instead of at 3am;
/// 3. restarts **tetragon first, then moatd** — moatd is `PartOf=` tetragon, so
///    the other order leaves moatd tailing a log nothing is writing;
/// 4. **verifies the sensor came back**, by counting the policies the kernel
///    has actually pinned under `/sys/fs/bpf/tetragon`, and says so loudly if
///    it did not. Assuming a restart worked is precisely the mistake that cost
///    25 minutes of blindness.
fn cmd_telemetry(cfg: Config, cfg_path: PathBuf, a: TelemetryArgs) -> std::process::ExitCode {
    use moatd::telemetry;

    let classes = cfg.telemetry.classes();
    let problems = cfg.telemetry.problems();

    if !a.json {
        println!("config:  {}", cfg_path.display());
        println!("classes: {}", classes.join(", "));
        for c in telemetry::CLASSES {
            let on = cfg.telemetry.enabled(c);
            let policies = telemetry::templates_for(c);
            println!(
                "  {:<8} {:<3} {}",
                c,
                if on { "on" } else { "off" },
                if policies.is_empty() {
                    "no kernel policy (already exported; a shipping decision)".to_string()
                } else {
                    policies.join(", ")
                }
            );
        }
        if cfg.telemetry.file {
            println!(
                "  file scope:    {} prefixes, {} suffixes, {} quiet-create fragments",
                cfg.telemetry.file_scope.len(),
                cfg.telemetry.file_suffixes.len(),
                cfg.telemetry.quiet_creates_under.len()
            );
            if cfg.telemetry.capture_body {
                println!(
                    "  capture_body:  ON, <= {} bytes. Script bodies leave this machine. \
                     Credential paths are never read.",
                    cfg.telemetry.capture_body_max_bytes
                );
            }
        }
    }
    for p in &problems {
        eprintln!("PROBLEM: {}", p);
    }
    if !problems.is_empty() {
        return std::process::ExitCode::from(1);
    }
    if !a.apply {
        if !a.json {
            println!("\n(reporting only; add --apply to render and reload the sensor)");
        } else {
            println!(
                "{}",
                serde_json::json!({"ok": true, "applied": false, "classes": classes})
            );
        }
        return std::process::ExitCode::SUCCESS;
    }

    // ---- 1. render -------------------------------------------------------
    let out = cfg.paths.policies_dir.clone();
    let opts = RenderOptions {
        templates_dir: &cfg.paths.templates_dir,
        out_dir: &out,
        export_allowlist: Some(&cfg.paths.export_allowlist),
        passwd: &cfg.paths.passwd,
        homes: None,
        telemetry: cfg.telemetry.clone(),
        canaries: moatd::canary::Manifest::load(&cfg.paths.canaries()).paths(),
        names_enabled: cfg.names.enabled,
        exclusions: moatd::engine::read_exclusions(&cfg.paths.state_file()),
        contain_slots: cfg.contain.max,
    };
    let report = match render(&opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("moatd telemetry: render failed, nothing was changed: {}", e);
            return std::process::ExitCode::from(1);
        }
    };
    if !report.failed.is_empty() {
        for (n, e) in &report.failed {
            eprintln!("PROBLEM: template {} did not render: {}", n, e);
        }
        eprintln!(
            "moatd telemetry: refusing to restart the sensor with {} broken template(s)",
            report.failed.len()
        );
        return std::process::ExitCode::from(1);
    }
    println!(
        "rendered {} policies into {} ({} changed)",
        report.rendered.len(),
        out.display(),
        report.files_changed
    );
    for (n, why) in &report.skipped {
        println!("  skipped {}: {}", n, why);
    }

    // ---- 2. validate what we just wrote ----------------------------------
    match run_policy_check(&cfg, &out) {
        CheckOutcome::Ok(msg) => println!("check.py: {}", msg),
        CheckOutcome::Skipped(why) => eprintln!(
            "WARNING: policy validation was skipped ({}). The sensor is about to be \
             restarted with policies nothing has checked.",
            why
        ),
        CheckOutcome::Failed(out) => {
            eprintln!("{}", out);
            eprintln!(
                "moatd telemetry: policies/check.py rejected the rendered policies. \
                 NOT restarting the sensor — a bad policy load is a silent outage."
            );
            return std::process::ExitCode::from(1);
        }
    }

    if a.no_restart {
        println!(
            "\n--no-restart: policies are on disk but NOT loaded. Tetragon reads \
             tracing-policy-dir once at startup and has no hot-reload, so nothing has \
             changed in the kernel yet."
        );
        return std::process::ExitCode::SUCCESS;
    }

    // ---- 3. restart, in the documented order -----------------------------
    // Root, and say so BEFORE touching the sensor.
    //
    // Until 2026-09-05 this check lived in step 4, phrased as "cannot read
    // /sys/fs/bpf/tetragon (are you root?)" -- so a non-root caller got both
    // restarts issued and then a question about their privileges, and (worse)
    // a *root* caller got the same message and exit 1 the moment bpffs had not
    // been recreated yet, which is the normal state two seconds after a
    // tetragon restart. Both halves of the confusion are fixed here: the
    // privilege question is asked once, up front, where it can still prevent
    // something.
    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root {
        eprintln!(
            "moatd telemetry --apply needs root: it restarts tetragon.service and \
             moatd.service, and verifies the result by reading {}.\n  \
             sudo moatd telemetry --apply",
            cfg.paths.tetragon_bpf_dir.display()
        );
        return std::process::ExitCode::from(1);
    }
    // tetragon first: moatd is PartOf=tetragon.service and tails the log
    // tetragon writes, so restarting moatd first would just make it wait.
    for unit in ["tetragon.service", "moatd.service"] {
        print!("restarting {} ... ", unit);
        use std::io::Write;
        let _ = std::io::stdout().flush();
        match std::process::Command::new("systemctl")
            .args(["restart", unit])
            .status()
        {
            Ok(s) if s.success() => println!("ok"),
            Ok(s) => {
                println!("FAILED ({})", s);
                eprintln!(
                    "moatd telemetry: {} did not restart. Check `systemctl status {}` and \
                     `journalctl -u {}` — the sensor may be down.",
                    unit, unit, unit
                );
                return std::process::ExitCode::from(1);
            }
            Err(e) => {
                println!("FAILED ({})", e);
                return std::process::ExitCode::from(1);
            }
        }
    }

    // ---- 4. verify, rather than assume -----------------------------------
    let expected = report.rendered.len();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(a.verify_timeout);
    let mut last = None;
    loop {
        match count_pinned(&cfg.paths.tetragon_bpf_dir) {
            Some(n) if n >= expected => {
                println!(
                    "sensor verified: {}/{} policies pinned under {}",
                    n,
                    expected,
                    cfg.paths.tetragon_bpf_dir.display()
                );
                println!("telemetry classes now on: {}", classes.join(", "));
                report_arming(&cfg);
                return std::process::ExitCode::SUCCESS;
            }
            Some(n) => last = Some(n),
            // `None` here is "NOT YET", not "not root": the caller is root (we
            // checked before restarting anything) and tetragon recreates
            // /sys/fs/bpf/tetragon as it pins its first policy, so the
            // directory genuinely does not exist for the first second or two
            // after the restart this command just issued. Treating that as a
            // hard failure is what happened on 2026-09-05, under sudo: the
            // restart worked, the verification exited 1 anyway, and the
            // operator was asked whether they were root.
            None => {}
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    match last {
        Some(n) => eprintln!(
            "SENSOR NOT HEALTHY after {}s: {}/{} policies pinned under {}.\n\
             The machine may be unprotected right now. This is the 2026-09-03 failure mode:\n\
               journalctl -u tetragon -n 50\n\
               moatctl status\n\
             To roll back, put the previous [telemetry] block into {} and run \
             `moatd telemetry --apply` again.",
            a.verify_timeout,
            n,
            expected,
            cfg.paths.tetragon_bpf_dir.display(),
            cfg_path.display()
        ),
        None => eprintln!(
            "SENSOR NOT HEALTHY after {}s: {} never appeared, so tetragon has not pinned a \
             single one of {} policies.\n\
             The machine is unprotected right now:\n\
               journalctl -u tetragon -n 50\n\
               systemctl status tetragon\n\
             To roll back, put the previous [telemetry] block into {} and run \
             `moatd telemetry --apply` again.",
            a.verify_timeout,
            cfg.paths.tetragon_bpf_dir.display(),
            expected,
            cfg_path.display()
        ),
    }
    std::process::ExitCode::from(1)
}

/// Loading is not arming.
///
/// Pinned policies say the sensor read the files; they say nothing about
/// whether the rules the user armed are in `enforce`, which is a separate
/// thing moatd does afterwards and which failed silently for a whole day on
/// 2026-09-05. So the last thing `--apply` does is ask the daemon that just
/// restarted. Best-effort: the socket may not be back yet, and that is a
/// "check `moatctl status`", not a failure of the apply.
fn report_arming(cfg: &Config) {
    let req = serde_json::json!({"cmd": "status"});
    for attempt in 0..10 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        let Ok(r) = control::request(&cfg.paths.socket, &req) else {
            continue;
        };
        let unverified: Vec<&str> = r["enforcing_unverified"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if !unverified.is_empty() {
            eprintln!(
                "WARNING: {} armed policy/policies are NOT armed in the kernel: {}\n  \
                 moatd is retrying; check `moatctl status` and \
                 `journalctl -u moatd -u tetragon`.",
                unverified.len(),
                unverified.join(", ")
            );
            return;
        }
        if r["arming_pending"] == serde_json::Value::Bool(true) {
            println!("arming: moatd is still waiting for the sensor; check `moatctl status`");
            return;
        }
        match r["enforcing_rules"].as_array() {
            Some(e) if !e.is_empty() => println!(
                "enforcement verified: {} policy/policies armed in the kernel",
                e.len()
            ),
            _ => println!("enforcement: nothing is armed"),
        }
        return;
    }
    println!(
        "(could not reach {} to check arming; run `moatctl status`)",
        cfg.paths.socket.display()
    );
}

/// `moatd wait-sensor` — make systemd's "tetragon started" mean "the policies
/// are loaded".
///
/// tetragon.service is `Type=simple`, so systemd calls it started the instant
/// it forks. On 2026-09-05 that was 16 seconds and 44 policies before the
/// sensor could answer for any of them, and moatd — ordered `After=` it, and
/// therefore believing it — re-armed 2 s in and had all seven `tetra tp
/// set-mode` calls fail against names the kernel did not have yet.
///
/// Wired as `ExecStartPost=-` on tetragon.service, this closes that: a unit
/// with an `ExecStartPost` stays in `activating` until the command returns, so
/// `After=tetragon.service` finally orders against *loaded* rather than
/// *forked*. The `-` prefix is deliberate — a timeout here must not fail the
/// sensor unit and hand it to `Restart=always` in a loop; the ordering is the
/// point, the exit code is for a human running it by hand.
///
/// Exit: 0 loaded, 1 timed out, 2 could not read bpffs at all (not root).
fn cmd_wait_sensor(cfg: Config, a: WaitSensorArgs) -> std::process::ExitCode {
    let dir = a.policies_dir.unwrap_or_else(|| cfg.paths.policies_dir.clone());
    let expected = moatd::policy::PolicySet::load(&dir).len();
    let bpf = &cfg.paths.tetragon_bpf_dir;
    if expected == 0 {
        println!("wait-sensor: no policies in {}, nothing to wait for", dir.display());
        return std::process::ExitCode::SUCCESS;
    }

    let start = std::time::Instant::now();
    let deadline = start + std::time::Duration::from_secs(a.timeout);
    let mut reported = usize::MAX;
    let mut last = None;
    loop {
        let now = count_pinned(bpf);
        // Keep the best answer we ever got: a bpffs that appeared and then
        // vanished is a sensor that died, and saying "never appeared" there
        // would send the reader looking for a permissions problem instead.
        last = now.or(last);
        match now {
            Some(n) if n >= expected => {
                println!(
                    "sensor loaded: {}/{} policies pinned under {} after {}s",
                    n,
                    expected,
                    bpf.display(),
                    start.elapsed().as_secs()
                );
                return std::process::ExitCode::SUCCESS;
            }
            // Progress, not silence: 16 seconds of nothing on the console is
            // indistinguishable from a hang, and this runs on every boot.
            Some(n) if n != reported => {
                println!("waiting for the sensor: {}/{} policies pinned", n, expected);
                reported = n;
            }
            Some(_) => {}
            None => {
                // The directory does not exist YET on a cold start -- tetragon
                // creates it as it pins the first policy. "Cannot read it" is
                // only "are you root" once the deadline has passed.
                if reported == usize::MAX {
                    println!(
                        "waiting for the sensor: {} does not exist yet",
                        bpf.display()
                    );
                    reported = 0;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    match last {
        Some(n) => {
            eprintln!(
                "wait-sensor: TIMED OUT after {}s with {}/{} policies pinned under {}.\n\
                 The sensor is up but not fully loaded; anything armed will not be enforcing.\n  \
                 journalctl -u tetragon -n 50\n  moatctl status",
                a.timeout,
                n,
                expected,
                bpf.display()
            );
            std::process::ExitCode::from(1)
        }
        None => {
            eprintln!(
                "wait-sensor: {} never appeared in {}s.\n\
                 If you are not root, this command cannot see it at all -- run it with sudo.\n\
                 If you are root, tetragon has not pinned a single policy:\n  \
                 journalctl -u tetragon -n 50",
                bpf.display(),
                a.timeout
            );
            std::process::ExitCode::from(2)
        }
    }
}

/// Same count as `Daemon::sensors_loaded`, without needing a daemon.
fn count_pinned(dir: &std::path::Path) -> Option<usize> {
    let entries = std::fs::read_dir(dir).ok()?;
    Some(
        entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("moat-"))
            .count(),
    )
}

enum CheckOutcome {
    Ok(String),
    Skipped(String),
    Failed(String),
}

fn run_policy_check(cfg: &Config, rendered_dir: &std::path::Path) -> CheckOutcome {
    let script = &cfg.paths.policy_check;
    if !script.exists() {
        return CheckOutcome::Skipped(format!("{} is not installed", script.display()));
    }
    if !cfg.paths.python.exists() {
        return CheckOutcome::Skipped(format!("{} is not installed", cfg.paths.python.display()));
    }
    match std::process::Command::new(&cfg.paths.python)
        .arg(script)
        .arg(rendered_dir)
        .output()
    {
        Err(e) => CheckOutcome::Skipped(format!("{}: {}", script.display(), e)),
        Ok(o) if o.status.success() => CheckOutcome::Ok(format!(
            "{} policies validated in {}",
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .last()
                .unwrap_or("all")
                .trim(),
            rendered_dir.display()
        )),
        // Exit 2 is "cannot run" (no PyYAML), which is not the same as
        // "your policies are wrong" and must not read like it.
        Ok(o) if o.status.code() == Some(2) => CheckOutcome::Skipped(
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        ),
        Ok(o) => CheckOutcome::Failed(format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )),
    }
}
