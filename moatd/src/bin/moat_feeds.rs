//! `moat-feeds` — refreshes the malicious-package index, run every 15
//! minutes by a timer.
//!
//! Exit status is always 0: the timer must never fail hard (CONTRACT §6.7).
//! Problems are logged; `--json` prints a machine-readable summary for the
//! socket's `feeds refresh` command.

use std::path::PathBuf;

use clap::Parser;

use moatd::config::Config;
use moatd::feeds::{self, FeedsConfig};

#[derive(Parser)]
#[command(
    name = "moat-feeds",
    version,
    about = "Refresh the signed malicious-package index the scanners read"
)]
struct Cli {
    /// feeds.toml (default /etc/moat/feeds.toml, or $MOAT_FEEDS_CONFIG).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Where packages.txt, meta.json and state.json are written.
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// moat.toml, used only to find the default out-dir.
    #[arg(long)]
    moat_config: Option<PathBuf>,
    #[arg(long)]
    json: bool,
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
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

    let cfg_path = cli.config.unwrap_or_else(feeds::default_config_path);
    let cfg = match FeedsConfig::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("{}", e);
            if cli.json {
                println!("{}", serde_json::json!({"ok": false, "error": e}));
            }
            // Still exit 0: a broken config must not fail the timer.
            return std::process::ExitCode::SUCCESS;
        }
    };

    let legacy = cfg.legacy_keys_present();
    if !legacy.is_empty() {
        log::warn!(
            "{}: {} no longer does anything -- moat no longer fetches abuse.ch \
             (it required an Auth-Key, so most machines had no feed at all). \
             The malicious-package index is keyless; see docs/PACKAGE-FEED.md. \
             Compare your file against the shipped feeds.toml.pacnew.",
            cfg_path.display(),
            legacy.join(", ")
        );
    }

    let out_dir = match cli.out_dir {
        Some(p) => p,
        None => {
            let sc = cli.moat_config.unwrap_or_else(Config::default_path);
            Config::load(&sc).unwrap_or_default().paths.feeds()
        }
    };

    let sum = feeds::refresh(&cfg, &out_dir);
    if sum.skipped {
        log::info!(
            "feeds not refreshed: {}",
            sum.reason.clone().unwrap_or_default()
        );
    } else if sum.mode == "unchanged" {
        log::debug!("feed already at seq {}", sum.seq);
    } else {
        log::info!(
            "feed updated in {} ({}): seq {}, {} packages (+{} -{})",
            out_dir.display(),
            sum.mode,
            sum.seq,
            sum.packages,
            sum.added,
            sum.removed
        );
    }
    for e in &sum.errors {
        // A failed signature is the one case that is not routine staleness.
        if e.contains("SIGNATURE DID NOT VERIFY") {
            log::error!("{}: refusing to apply, keeping the existing index", e);
        } else {
            log::warn!("feed refresh: {}", e);
        }
    }

    if cli.json {
        let mut v = serde_json::to_value(&sum).unwrap_or_default();
        if let Some(m) = v.as_object_mut() {
            m.insert("ok".into(), serde_json::Value::Bool(true));
            m.insert(
                "out_dir".into(),
                serde_json::Value::String(out_dir.display().to_string()),
            );
        }
        println!("{}", v);
    }
    std::process::ExitCode::SUCCESS
}
