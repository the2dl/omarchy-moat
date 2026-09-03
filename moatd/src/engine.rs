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

use crate::alert::{Alert, UpdateLine};
use crate::allowlist::{Allowlist, Candidate};
use crate::config::Config;
use crate::event::{HookHit, RawEvent};
use crate::explain::{allowlist_note, build_alert, Finding};
use crate::feeds::Feeds;
use crate::policy::{family_of, PolicySet};
use crate::proctable::ProcTable;
use crate::rules::{RuleCtx, UserRule};
use crate::store::AlertStore;
use crate::tail::Tailer;
use crate::util;

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
    dedupe: HashMap<String, Dedupe>,
    /// exec_id -> alert id, for kill confirmation (NOTES §7).
    pending_kill: HashMap<String, String>,
}

impl Daemon {
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
        let mode = persisted_mode(&cfg.paths.state_file()).unwrap_or_else(|| cfg.mode.clone());
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
            started: util::unix_secs(),
            events_seen: 0,
            alerts_emitted: 0,
            dedupe: HashMap::new(),
            pending_kill: HashMap::new(),
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
            let findings = self.run_rules_exec(exec, &exec_id, now);
            self.emit_all(findings);
            return;
        }

        if let Some(exit) = &ev.process_exit {
            if let Some(exec_id) = self.table.on_exit(exit, now) {
                self.confirm_kill(&exec_id, exit.signal.as_deref());
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
    fn policy_finding(&self, hook: &HookHit, exec_id: &str, _now: u64) -> Option<Finding> {
        let name = hook.policy_name();
        if !name.starts_with("moat-") {
            return None;
        }
        let meta = self.policies.meta_or_fallback(name);
        let proc = self.table.get(exec_id)?.clone();
        let mut f = Finding::new(name, meta, proc);
        f.family_fixup();
        f.hook = hook.hook_name();
        f.exec_id = exec_id.to_string();
        f.ancestry = self.table.ancestry(exec_id).into_iter().cloned().collect();
        f.ancestry_line = self.table.ancestry_line(exec_id);
        f.mode = self.mode.clone();
        f.kill_expected = hook.action_is_kill();

        if let Some(path) = hook.file_path() {
            f.hook_detail = access_word(hook.int_arg());
            f.file = Some(crate::alert::FileRef { path, sha256: None });
        } else if let Some((ip, port)) = hook.dest() {
            f.net = Some(crate::alert::NetRef {
                dst_ip: ip,
                dst_port: port,
                domain: None,
            });
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

    fn emit_all(&mut self, findings: Vec<Finding>) {
        for f in findings {
            self.emit(f);
        }
    }

    /// Allowlist, dedupe, then append.
    pub fn emit(&mut self, f: Finding) -> Option<String> {
        let parents: Vec<String> = f.ancestry.iter().map(|p| p.exe.clone()).collect();
        let cand = Candidate {
            rule: &f.rule,
            exe: &f.proc.exe,
            file: f.file.as_ref().map(|x| x.path.as_str()),
            parents,
        };
        if let Some(hit) = self.allowlist.find(&cand) {
            log::debug!(
                "{} suppressed by allowlist rule {} in {}",
                f.rule,
                hit.index,
                hit.source.display()
            );
            return None;
        }

        let now = util::unix_secs();
        let key = f.dedupe_key();
        if let Some(d) = self.dedupe.get_mut(&key) {
            if now.saturating_sub(d.first_seen) < self.cfg.thresholds.dedupe_secs {
                d.count += 1;
                let update = UpdateLine::new(&d.id)
                    .set("count", Value::from(d.count))
                    .set("ts", Value::from(util::now_rfc3339()));
                let id = d.id.clone();
                if let Err(e) = self.store.append_update(&update) {
                    log::error!("alerts.jsonl: {}", e);
                }
                return Some(id);
            }
        }

        let id = ulid::Ulid::new().to_string();
        let note = allowlist_note(
            &self.cfg.paths.allowlist_dir.display().to_string(),
            self.allowlist.len(),
            &f.proc.exe,
            f.file.as_ref().map(|x| x.path.as_str()),
        );
        let alert = build_alert(
            &f,
            &id,
            &util::now_rfc3339(),
            &self.cfg.paths.user_allowlist().display().to_string(),
            &note,
        );
        if let Err(e) = self.store.append_alert(&alert) {
            log::error!("alerts.jsonl: {}", e);
            return None;
        }
        self.alerts_emitted += 1;
        log::info!(
            "alert {} {} {} pid {} ({})",
            id,
            alert.severity,
            alert.rule,
            alert.process.pid,
            alert.title
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
        Some(id)
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

    pub fn tetragon_state(&self) -> &'static str {
        if self.cfg.paths.tetragon_socket.exists() {
            return "running";
        }
        // No socket (or no permission to see it): fall back to "is the export
        // file being written?".
        if let Ok(m) = std::fs::metadata(&self.cfg.paths.tetragon_log) {
            use std::os::unix::fs::MetadataExt;
            let age = util::unix_secs().saturating_sub(m.mtime().max(0) as u64);
            if age < 300 {
                return "running";
            }
            return "stale";
        }
        "stopped"
    }

    pub fn sandbox_on(&self) -> bool {
        self.cfg.paths.sandbox_flag.exists()
    }

    pub fn status(&self) -> Value {
        let unacked = self.store.unacked();
        json!({
            "ok": true,
            "version": crate::VERSION,
            "mode": self.mode,
            "tetragon": self.tetragon_state(),
            "policies": self.policies.len(),
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
            "uptime_secs": util::unix_secs().saturating_sub(self.started),
            "events_seen": self.events_seen,
            "alerts": self.alerts_emitted,
            "processes": self.table.len(),
            "allowlist_rules": self.allowlist.len(),
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

fn persisted_mode(state: &Path) -> Option<String> {
    let text = std::fs::read_to_string(state).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let m = v.get("mode")?.as_str()?;
    (m == "monitor" || m == "enforce").then(|| m.to_string())
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
            daemon.lock().expect("daemon lock").write_state();
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
                d.table.prune(util::unix_secs());
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
        std::fs::create_dir_all(&cfg.paths.allowlist_dir).unwrap();
        let d = Daemon::new(cfg.clone(), &dir.join("moat.toml")).unwrap();
        (d, cfg)
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

    #[test]
    fn the_allowlist_suppresses_an_alert() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, cfg) = dev_daemon(dir.path());
        std::fs::write(
            cfg.paths.allowlist_dir.join("user.toml"),
            "# expected: our own node\n[[rule]]\nname = \"moat-cred-ssh-private-key-read\"\nexe = \"*/bin/node\"\n",
        )
        .unwrap();
        d.reload_allowlist();
        replay(&mut d);
        assert!(!d
            .store
            .load()
            .iter()
            .any(|a| a.rule == "moat-cred-ssh-private-key-read"));
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

    #[test]
    fn access_words() {
        assert_eq!(access_word(Some(4)).unwrap(), "read");
        assert_eq!(access_word(Some(2)).unwrap(), "write");
        assert_eq!(access_word(Some(6)).unwrap(), "read+write");
        assert_eq!(access_word(Some(0)).unwrap(), "mask 0");
        assert!(access_word(None).is_none());
    }
}
