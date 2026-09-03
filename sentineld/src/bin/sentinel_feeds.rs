//! `sentinel-feeds` — fetches the abuse.ch feeds, run hourly by a timer.
//!
//! Exit status is always 0: the timer must never fail hard (CONTRACT §6.7).
//! Problems are logged; `--json` prints a machine-readable summary for the
//! socket's `feeds refresh` command.

use std::path::PathBuf;

use clap::Parser;

use sentineld::config::Config;
use sentineld::feeds::{self, FeedsConfig};

#[derive(Parser)]
#[command(
    name = "sentinel-feeds",
    version,
    about = "Fetch abuse.ch MalwareBazaar / ThreatFox / URLhaus indicators"
)]
struct Cli {
    /// feeds.toml (default /etc/sentinel/feeds.toml, or $SENTINEL_FEEDS_CONFIG).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Where hashes.txt, domains.txt, urls.txt and meta.json are written.
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// sentinel.toml, used only to find the default out-dir.
    #[arg(long)]
    sentinel_config: Option<PathBuf>,
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

    let out_dir = match cli.out_dir {
        Some(p) => p,
        None => {
            let sc = cli.sentinel_config.unwrap_or_else(Config::default_path);
            Config::load(&sc).unwrap_or_default().paths.feeds()
        }
    };

    let sum = feeds::refresh(&cfg, &out_dir);
    if sum.skipped {
        log::info!(
            "feeds not refreshed: {}",
            sum.reason.clone().unwrap_or_default()
        );
    } else {
        log::info!(
            "feeds updated in {}: {} hashes, {} domains, {} urls",
            out_dir.display(),
            sum.hashes,
            sum.domains,
            sum.urls
        );
    }
    for e in &sum.errors {
        log::warn!("feed source failed: {}", e);
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
