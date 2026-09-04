//! The control socket (CONTRACT §5).
//!
//! Unix stream, newline-delimited JSON, one request → one response per
//! connection, socket mode 0660 root:moat.
//!
//! The safety property that makes this exposable to the user's group: **every
//! action references an alert id, never a raw pid or path**. A hostile process
//! in the `moat` group cannot ask the daemon to kill or move anything the
//! sensor did not already flag, and `kill` additionally re-checks that the pid
//! still belongs to the process the alert named before it signals it.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::allowlist::{append_rule, remove_rule, split_blocks};
use crate::engine::Daemon;
use crate::explain::scope_spec_from_alert;
use crate::util;

pub fn err(msg: impl Into<String>) -> Value {
    json!({"ok": false, "error": msg.into()})
}

fn ok(mut v: Value) -> Value {
    if let Some(m) = v.as_object_mut() {
        m.insert("ok".into(), Value::Bool(true));
    }
    v
}

/// Bind the socket, chmod/chown it, and serve until the process exits.
pub fn serve(daemon: Arc<Mutex<Daemon>>, path: &Path, group: &str) -> std::io::Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    // A stale socket from a crash would make bind() fail with EADDRINUSE.
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)?;
    util::secure_path(path, group, 0o660)?;
    log::info!("control socket at {} (0660 root:{})", path.display(), group);

    let d = daemon;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let d = Arc::clone(&d);
                    std::thread::spawn(move || {
                        if let Err(e) = handle_conn(d, s) {
                            log::debug!("control connection: {}", e);
                        }
                    });
                }
                Err(e) => log::warn!("accept: {}", e),
            }
        }
    });
    Ok(())
}

fn handle_conn(daemon: Arc<Mutex<Daemon>>, stream: UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = match serde_json::from_str::<Value>(line.trim()) {
        Ok(req) => {
            let mut d = daemon.lock().expect("daemon lock");
            dispatch(&mut d, &req)
        }
        Err(e) => err(format!("request was not JSON: {}", e)),
    };
    let mut w = stream;
    w.write_all(serde_json::to_string(&response)?.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

/// One request in, one response out. Pure apart from the daemon it mutates, so
/// tests drive it directly without a socket.
pub fn dispatch(d: &mut Daemon, req: &Value) -> Value {
    let cmd = req.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
    let id = || req.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    match cmd {
        "status" => ok(d.status()),
        "list" => cmd_list(d, req),
        "explain" => match d.find_alert(&id()) {
            Some(a) => ok(json!({ "alert": a })),
            None => err(format!("no alert {}", id())),
        },
        "ack" => cmd_ack(d, req, &id()),
        "kill" => cmd_kill(d, &id()),
        "quarantine" => cmd_quarantine(d, &id()),
        "ignore" => cmd_ignore(d, req, &id()),
        "unignore" => cmd_unignore(d, req),
        "allowlist" => cmd_allowlist(d),
        "set" => cmd_set(d, req),
        "feeds" => cmd_feeds(d, req),
        "baseline" => cmd_baseline(d, req),
        "receipts" => cmd_receipts(d, req),
        "incidents" => cmd_incidents(d, req),
        "bundle" => cmd_bundle(d, &id()),
        "analyze" => cmd_analyze(d, &id()),
        "rarity" => cmd_rarity(d, &id()),
        "digest" => cmd_digest(d, req),
        "" => err("missing `cmd`"),
        other => err(format!("unknown command {:?}", other)),
    }
}

fn cmd_list(d: &Daemon, req: &Value) -> Value {
    let since = req.get("since").and_then(|v| v.as_str()).unwrap_or("");
    let limit = req.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let mut alerts = d.store.load();
    if !since.is_empty() {
        alerts.retain(|a| a.id.as_str() > since);
    }
    if alerts.len() > limit {
        alerts = alerts.split_off(alerts.len() - limit);
    }
    ok(json!({ "alerts": alerts }))
}

/// LEARNING §3/§7: `{"cmd":"receipts","last":20}`. Informational only — a
/// receipt has no actions, no ack and no badge.
fn cmd_receipts(d: &Daemon, req: &Value) -> Value {
    let last = req.get("last").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let receipts = d.receipt_list(last.max(1));
    ok(json!({
        "receipts": receipts,
        "rendered": receipts.iter().map(|r| r.render()).collect::<Vec<_>>(),
        "open": d.receipts.len(),
    }))
}

/// LEARNING §7: `{"cmd":"incidents","last":20}` — what is on disk.
fn cmd_incidents(d: &Daemon, req: &Value) -> Value {
    let last = req.get("last").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let dir = d.incidents_dir();
    ok(json!({
        "dir": dir.display().to_string(),
        "incidents": crate::incident::list(&dir, last.max(1)),
        "retain_days": d.cfg.incidents.retain_days,
        "retain_max": d.cfg.incidents.retain_max,
        "snapshot_min_severity": d.cfg.incidents.snapshot_min_severity,
    }))
}

/// LEARNING §2 step 1 and §9: write `bundle.md`, return its path.
fn cmd_bundle(d: &Daemon, id: &str) -> Value {
    match d.write_bundle(id) {
        Ok(p) => ok(json!({"id": id, "path": p.display().to_string()})),
        Err(e) => err(e),
    }
}

/// LEARNING §7: bundle **plus** everything `moatctl` needs to do the launch.
/// The daemon deliberately does not launch anything: it has no session, and an
/// interactive agent started by a root service would be both broken and wrong.
fn cmd_analyze(d: &Daemon, id: &str) -> Value {
    let path = match d.write_bundle(id) {
        Ok(p) => p.display().to_string(),
        Err(e) => return err(e),
    };
    ok(json!({
        "id": id,
        "path": path,
        "preamble": crate::analysis::preamble(&path),
        "agent_args": d.cfg.analysis.agent_args,
        "launcher": crate::analysis::agent_launcher(),
        "note": "the daemon only writes the bundle; moatctl launches the agent in the user session",
    }))
}

/// LEARNING §7: the rarity sentences for one alert.
fn cmd_rarity(d: &Daemon, id: &str) -> Value {
    let Some(a) = d.find_alert(id) else {
        return err(format!("no alert {}", id));
    };
    ok(json!({
        "id": id,
        "rarity": a.rarity.as_str(),
        "rarity_text": a.rarity_text,
        "counters": d.rarity.len(),
        "sentences": a
            .explain
            .evidence
            .iter()
            .filter(|e| e.starts_with("rarity"))
            .collect::<Vec<_>>(),
    }))
}

/// LEARNING §5: `{"cmd":"digest"}` reads it, `{"cmd":"digest","action":"sent"}`
/// records a delivery so a catch-up run does not send twice.
fn cmd_digest(d: &mut Daemon, req: &Value) -> Value {
    let now = util::unix_secs();
    match req.get("action").and_then(|v| v.as_str()).unwrap_or("show") {
        "show" => ok(d.digest(now).to_json()),
        "sent" => {
            d.digest_sent(now);
            ok(d.digest(now).to_json())
        }
        other => err(format!(
            "unknown digest action {:?}; use show or sent",
            other
        )),
    }
}

fn cmd_ack(d: &mut Daemon, req: &Value, id: &str) -> Value {
    // Bulk ack. Retuning the rule set leaves a backlog of alerts about rules
    // that no longer exist — 1623 of them after the 2026-09-03 retune — and
    // acking those one id at a time is not a thing anyone will do, so the
    // backlog just sits there hiding real alerts and poisoning the learning
    // window. `rule` and `before` are the two cuts that matter: "this rule was
    // wrong" and "everything up to the point I fixed it".
    let rule = req["rule"].as_str().unwrap_or("");
    let before = req["before"].as_str().unwrap_or("");
    let all = req["all"] == Value::Bool(true);
    if all || !rule.is_empty() || !before.is_empty() {
        let targets: Vec<String> = d
            .store
            .load()
            .into_iter()
            .filter(|a| !a.acked)
            .filter(|a| rule.is_empty() || a.rule == rule)
            // Ids are monotonic, so an id comparison is a time comparison.
            .filter(|a| before.is_empty() || a.id.as_str() < before)
            .map(|a| a.id)
            .collect();
        let mut acked = 0usize;
        let mut failed = Vec::new();
        for id in &targets {
            match d.mark(id, "acked", Value::Bool(true)) {
                Ok(()) => acked += 1,
                Err(e) => failed.push(format!("{}: {}", id, e)),
            }
        }
        return ok(json!({ "acked": acked, "matched": targets.len(), "failed": failed }));
    }
    if d.find_alert(id).is_none() {
        return err(format!("no alert {}", id));
    }
    match d.mark(id, "acked", Value::Bool(true)) {
        Ok(()) => ok(json!({ "id": id, "acked": true })),
        Err(e) => err(e),
    }
}

fn cmd_kill(d: &mut Daemon, id: &str) -> Value {
    let Some(alert) = d.find_alert(id) else {
        return err(format!("no alert {}", id));
    };
    let pid = alert.process.pid;
    if pid <= 1 {
        return err(format!("alert {} has no usable pid", id));
    }
    if let Err(e) = verify_pid(pid, &alert.process.start_ts, &alert.process.exe) {
        return err(e);
    }

    // Children first, so a supervisor cannot respawn while we work upwards.
    let mut killed = Vec::new();
    let mut failed = Vec::new();
    let mut targets = util::proc_descendants(pid);
    targets.push(pid);
    for p in targets {
        let rc = unsafe { libc::kill(p as libc::pid_t, libc::SIGKILL) };
        if rc == 0 {
            killed.push(p);
        } else {
            failed.push(json!({"pid": p, "errno": std::io::Error::last_os_error().to_string()}));
        }
    }
    if killed.is_empty() {
        return err(format!(
            "could not signal pid {} (need CAP_KILL or the same uid): {:?}",
            pid, failed
        ));
    }
    if let Err(e) = d.mark(id, "action_taken", Value::from("killed")) {
        return err(e);
    }
    log::info!("alert {}: killed {:?}", id, killed);
    ok(json!({"id": id, "killed": killed, "failed": failed}))
}

/// Refuse to signal a recycled pid. The alert records the process start time;
/// `/proc/<pid>/stat` gives us the live one.
///
/// Public because the engine reuses it for enforce-mode kills: there is one
/// answer to "is this pid still the process we mean", not two.
pub fn verify_pid(pid: u32, start_ts: &str, exe: &str) -> Result<(), String> {
    let Some(live) = util::proc_start_nanos(pid) else {
        return Err(format!("pid {} is gone", pid));
    };
    if let Some(want) = util::rfc3339_to_nanos(start_ts) {
        // The alert stores milliseconds and clocks drift a little; 2 s is
        // generous and still far below any realistic pid recycle.
        if (live - want).abs() > 2_000_000_000 {
            return Err(format!(
                "pid {} no longer matches the process in this alert (start time differs); refusing to kill",
                pid
            ));
        }
    }
    if let Some(live_exe) = util::proc_exe(pid) {
        let live_exe = live_exe.trim_end_matches(" (deleted)");
        if !exe.is_empty() && live_exe != exe {
            return Err(format!(
                "pid {} now runs {} but the alert names {}; refusing to kill",
                pid, live_exe, exe
            ));
        }
    }
    Ok(())
}

fn cmd_quarantine(d: &mut Daemon, id: &str) -> Value {
    let Some(alert) = d.find_alert(id) else {
        return err(format!("no alert {}", id));
    };
    let target = alert
        .file
        .as_ref()
        .map(|f| f.path.clone())
        .unwrap_or_else(|| alert.process.exe.clone());
    if target.is_empty() {
        return err("this alert names no file to quarantine");
    }
    let mut roots = d.homes.clone();
    roots.extend(["/tmp".into(), "/var/tmp".into(), "/dev/shm".into()]);
    if !util::under_any(&target, &roots) {
        return err(format!(
            "{} is outside $HOME, /tmp, /var/tmp and /dev/shm; quarantine refuses to touch it",
            target
        ));
    }
    match quarantine_file(&d.cfg.paths.quarantine(), id, &target, &alert.rule, &alert.title) {
        Ok(dest) => {
            if let Err(e) = d.mark(id, "action_taken", Value::from("quarantined")) {
                return err(e);
            }
            log::info!("alert {}: quarantined {} -> {}", id, target, dest.display());
            ok(json!({"id": id, "from": target, "to": dest.display().to_string()}))
        }
        Err(e) => err(e),
    }
}

fn quarantine_file(
    base: &Path,
    id: &str,
    target: &str,
    rule: &str,
    title: &str,
) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = base.join(id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let name = util::basename(target);
    let dest = dir.join(if name.is_empty() { "file" } else { name });

    let sha = util::sha256_file(Path::new(target)).ok();
    // rename() fails across filesystems (/tmp is usually tmpfs); fall back.
    if std::fs::rename(target, &dest).is_err() {
        std::fs::copy(target, &dest).map_err(|e| format!("copy {}: {}", target, e))?;
        std::fs::remove_file(target).map_err(|e| format!("remove {}: {}", target, e))?;
    }
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o000))
        .map_err(|e| format!("chmod 000: {}", e))?;

    let meta = json!({
        "alert": id,
        "rule": rule,
        "title": title,
        "original_path": target,
        "quarantined_at": util::now_rfc3339(),
        "sha256": sha,
        "restore": format!("sudo chmod 600 {} && sudo mv {} {}", dest.display(), dest.display(), target),
    });
    util::atomic_write(
        &dir.join("meta.json"),
        format!("{}\n", serde_json::to_string_pretty(&meta).unwrap_or_default()).as_bytes(),
        0o600,
    )
    .map_err(|e| format!("meta.json: {}", e))?;
    Ok(dest)
}

fn cmd_ignore(d: &mut Daemon, req: &Value, id: &str) -> Value {
    let Some(alert) = d.find_alert(id) else {
        return err(format!("no alert {}", id));
    };
    let scope = req.get("scope").and_then(|v| v.as_str()).unwrap_or("exe");
    let spec = match scope_spec_from_alert(&alert, scope) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let user_comment = req.get("comment").and_then(|v| v.as_str()).unwrap_or("");
    let mut comment = format!(
        "added {} from alert {}: {}",
        chrono::Utc::now().format("%Y-%m-%d"),
        id,
        alert.title
    );
    if !user_comment.is_empty() {
        comment.push_str(&format!(" — {}", user_comment.replace('\n', " ")));
    }
    let path = d.cfg.paths.user_allowlist();
    let block = match append_rule(&path, &comment, &spec) {
        Ok(b) => b,
        Err(e) => return err(format!("{}: {}", path.display(), e)),
    };
    d.reload_allowlist();
    if let Err(e) = d.mark(id, "acked", Value::Bool(true)) {
        return err(e);
    }
    log::info!("alert {}: ignored with scope {}", id, scope);
    ok(json!({
        "id": id,
        "scope": scope,
        "file": path.display().to_string(),
        "block": block.trim_start_matches('\n'),
        "acked": true,
    }))
}

/// `{"cmd":"unignore","rule":N}` still means user.toml, for compatibility.
/// `{"cmd":"unignore","file":"baseline.toml","index":N}` removes a learned
/// entry the same way (BASELINE §8 "Resolved shapes"). Shipped files are
/// refused: they belong to the package, not to the user.
fn cmd_unignore(d: &mut Daemon, req: &Value) -> Value {
    let n = req
        .get("index")
        .or_else(|| req.get("rule"))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let Some(n) = n else {
        return err("`index` (with `file`) or `rule` must be the index shown by `allowlist`");
    };
    let path = match req.get("file").and_then(|v| v.as_str()) {
        None | Some("") => d.cfg.paths.user_allowlist(),
        Some(f) => {
            let name = Path::new(f)
                .file_name()
                .map(|x| x.to_os_string())
                .unwrap_or_default();
            let p = d.cfg.paths.allowlist_dir.join(&name);
            if !crate::allowlist::is_removable(&p) {
                return err(format!(
                    "{} is shipped by the package; it is not removable from here. Override it \
                     with an entry in user.toml instead.",
                    name.to_string_lossy()
                ));
            }
            p
        }
    };
    match remove_rule(&path, n as usize) {
        Ok(removed) => {
            d.reload_allowlist();
            ok(json!({"removed": removed, "file": path.display().to_string(), "index": n}))
        }
        Err(e) => err(e),
    }
}

fn cmd_allowlist(d: &Daemon) -> Value {
    let user = d.cfg.paths.user_allowlist();
    let rules: Vec<Value> = d
        .allowlist
        .rules
        .iter()
        .map(|r| {
            let removable = crate::allowlist::is_removable(&r.source);
            json!({
                // Position within its own file: `unignore {file, index}`.
                "index": r.index,
                "file": r.source.display().to_string(),
                "source": crate::allowlist::source_label(&r.source),
                "removable": removable,
                "comment": r.comment,
                "name": r.spec.name,
                "exe": r.spec.exe,
                "path": r.spec.file,
                "parent": r.spec.parent,
                "toml": r.to_toml(),
            })
        })
        .collect();
    ok(json!({
        "rules": rules,
        "dir": d.cfg.paths.allowlist_dir.display().to_string(),
        "user_file": user.display().to_string(),
        "baseline_file": d.cfg.paths.baseline_allowlist().display().to_string(),
        "errors": d.allowlist.failed,
    }))
}

/// `{"cmd":"baseline","action":"list|accept|dismiss|relearn|export|propose|undemote"}`
/// (CONTRACT §11, BASELINE §3 and §4).
fn cmd_baseline(d: &mut Daemon, req: &Value) -> Value {
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("list");
    let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let now = util::unix_secs();
    match action {
        "list" => ok(json!({
            "learning": d.baseline.learning(now),
            "learning_ends": d.baseline.learning_ends(),
            "proposals": d.baseline.proposals(),
            "learned": d.baseline.learned_entries(),
            "demoted_rules": d.baseline.demoted_rules(),
            "baseline_file": d.cfg.paths.baseline_allowlist().display().to_string(),
        })),
        "accept" => baseline_accept(d, id),
        "dismiss" => match d.baseline.dismiss(id) {
            Ok(p) => {
                d.baseline.save_if_due(now, true);
                ok(json!({"dismissed": p}))
            }
            Err(e) => err(e),
        },
        "relearn" => {
            let days = req.get("days").and_then(|v| v.as_u64());
            let until = d.baseline.relearn(days, now);
            d.baseline.save_if_due(now, true);
            log::info!("baseline: learning restarted until {}", util::rfc3339_of(until));
            ok(json!({
                "learning": true,
                "learning_ends": util::rfc3339_of(until),
                "days": days.unwrap_or(d.baseline.learning_days),
            }))
        }
        "export" => {
            let since = req.get("since").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
            let rows = d.baseline.export(since);
            ok(json!({
                "since": since,
                "generated": util::now_rfc3339(),
                "machine": std::fs::read_to_string("/etc/hostname")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default(),
                "trusted_repos": d.cfg.baseline.trusted_repos,
                "count": rows.len(),
                "tuples": rows,
            }))
        }
        "propose" => {
            let rule = req.get("rule").and_then(|v| v.as_str()).unwrap_or("");
            if rule.is_empty() {
                return err("`rule` is required for baseline propose");
            }
            let keys: Vec<String> = d
                .baseline
                .top_tuples(rule, req.get("top").and_then(|v| v.as_u64()).unwrap_or(5) as usize)
                .iter()
                .map(|t| t.key())
                .collect();
            let made = d.baseline.propose_keys(&keys);
            d.baseline.save_if_due(now, true);
            ok(json!({"rule": rule, "proposals": made}))
        }
        "undemote" => {
            let rule = req.get("rule").and_then(|v| v.as_str()).unwrap_or("");
            // Clearing every demotion at once. After a retune the demotions on
            // the board were caused by rules that no longer exist or no longer
            // misfire, and they are silencing whatever shares the board with
            // them — moat-cred-ssh-private-key-read was demoted on 2026-09-03 by
            // a flood from unrelated rules. They do expire on their own 24 h
            // later, but a day of a silenced key-theft rule is a day too long,
            // and clearing them one name at a time invites the text-parsing that
            // gets a rule name wrong.
            if req["all"] == Value::Bool(true) {
                let cleared: Vec<String> = d
                    .baseline
                    .demoted_rules()
                    .into_iter()
                    .filter(|r| d.baseline.undemote(r))
                    .collect();
                for r in &cleared {
                    log::info!("noise guard: {} is being watched again", r);
                }
                d.baseline.save_if_due(now, true);
                return ok(json!({
                    "cleared": cleared,
                    "demoted_rules": d.baseline.demoted_rules()
                }));
            }
            if rule.is_empty() {
                return err("`rule` is required for baseline undemote (or pass --all)");
            }
            if !d.baseline.undemote(rule) {
                return err(format!("{} is not demoted", rule));
            }
            d.baseline.save_if_due(now, true);
            log::info!("noise guard: {} is being watched again", rule);
            ok(json!({"rule": rule, "demoted_rules": d.baseline.demoted_rules()}))
        }
        other => err(format!(
            "unknown baseline action {:?}; use list, accept, dismiss, relearn, export, propose \
             or undemote",
            other
        )),
    }
}

fn baseline_accept(d: &mut Daemon, id: &str) -> Value {
    let (p, comment) = match d.baseline.accept(id, &acting_user()) {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    let path = d.cfg.paths.baseline_allowlist();
    let spec = crate::allowlist::RuleSpec {
        name: p.rule.clone(),
        exe: (!p.exe.is_empty()).then(|| p.exe.clone()),
        file: (!p.dir.is_empty()).then(|| format!("{}/*", p.dir.trim_end_matches('/'))),
        parent: (!p.parent.is_empty()).then(|| p.parent.clone()),
    };
    let block = match crate::allowlist::append_rule(&path, &comment, &spec) {
        Ok(b) => b,
        Err(e) => return err(format!("{}: {}", path.display(), e)),
    };
    d.reload_allowlist();
    d.baseline.save_if_due(util::unix_secs(), true);
    log::info!("baseline: accepted proposal {} for {}", id, p.rule);
    ok(json!({
        "accepted": p,
        "file": path.display().to_string(),
        "block": block.trim_start_matches('\n'),
    }))
}

/// Best effort: who the daemon can say accepted a proposal. The socket is
/// group-readable, so this is the machine's account, not an identity claim.
fn acting_user() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "the console".into())
}

fn cmd_set(d: &mut Daemon, req: &Value) -> Value {
    let key = req.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let value = req.get("value").and_then(|v| v.as_str()).unwrap_or("");
    match key {
        "mode" => set_mode(d, value, req["rule"].as_str().unwrap_or("")),
        "sandbox" => set_sandbox(d, value),
        "digest" => set_digest(d, value),
        "" => err("missing `key`"),
        other => err(format!(
            "unknown key {:?}; use mode, sandbox or digest",
            other
        )),
    }
}

/// LEARNING §9: `moatctl set digest on|off` -> `state.json.digest_enabled`,
/// and `status.digest`. The user timer keeps firing either way; with the digest
/// off, `moatctl digest --notify` simply sends nothing, so switching it off
/// needs neither root nor `systemctl`.
fn set_digest(d: &mut Daemon, value: &str) -> Value {
    let on = match value {
        "on" | "true" | "1" => true,
        "off" | "false" | "0" => false,
        other => return err(format!("digest must be on or off, got {:?}", other)),
    };
    d.set_digest(on);
    let mut v = d.digest(util::unix_secs()).to_json();
    if let Some(o) = v.as_object_mut() {
        o.insert("digest".into(), Value::Bool(on));
    }
    ok(v)
}

/// `tetra tp set-mode` takes effect immediately on the pinned `policy_conf` map
/// (NOTES §7); there is no reload. We apply it to every loaded policy and keep
/// our own copy in state.json, because the export cannot tell us the mode.
/// `set mode monitor|enforce [--rule NAME]`.
///
/// Without a rule this is the daemon-wide switch and every policy moves with
/// it. With one, exactly that policy is armed in the kernel and `mode` is left
/// alone — which also leaves the userland kill path off, because
/// `maybe_enforce` gates on the daemon-wide mode.
///
/// That distinction is the whole point. Seven shipped policies carry Sigkill,
/// and arming them together on a desktop kills the module loader on USB
/// hotplug and kills `ssh` for reading your own key. Enforcement has to be
/// something you can turn on one measured rule at a time.
fn set_mode(d: &mut Daemon, value: &str, rule: &str) -> Value {
    if value != "monitor" && value != "enforce" {
        return err(format!("mode must be monitor or enforce, got {:?}", value));
    }
    let tetra = d.cfg.paths.tetra.clone();
    let all = d.policies.names();
    let names: Vec<String> = if rule.is_empty() {
        all
    } else {
        if !all.iter().any(|n| n == rule) {
            return err(format!(
                "no policy {:?}; `moatctl status` lists how many are loaded",
                rule
            ));
        }
        vec![rule.to_string()]
    };

    let mut applied = Vec::new();
    let mut failed = Vec::new();
    for name in &names {
        match std::process::Command::new(&tetra)
            .args(["tp", "set-mode", name, value])
            .output()
        {
            Ok(o) if o.status.success() => applied.push(name.clone()),
            Ok(o) => failed.push(json!({
                "policy": name,
                "error": String::from_utf8_lossy(&o.stderr).trim().to_string(),
            })),
            Err(e) => failed.push(json!({"policy": name, "error": e.to_string()})),
        }
    }

    // Record intent even when nothing applied, so a restart does not silently
    // forget what the user asked for — but say so honestly below.
    if rule.is_empty() {
        d.mode = value.to_string();
    } else if value == "enforce" {
        d.enforcing_rules.insert(rule.to_string());
    } else {
        d.enforcing_rules.remove(rule);
    }
    d.write_state();
    log::info!(
        "mode {} for {} ({} applied, {} failed)",
        value,
        if rule.is_empty() { "all policies" } else { rule },
        applied.len(),
        failed.len()
    );

    // INTEGRATION §6.2: answering ok:true after applying to nothing told the
    // user their machine was enforcing when it was not. An enforce switch that
    // lies about whether it took is worse than not having one.
    if applied.is_empty() {
        return json!({
            "ok": false,
            "error": format!(
                "{} applied to no policies; the mode is recorded but nothing is enforcing it",
                value
            ),
            "mode": d.mode,
            "enforcing_rules": d.enforcing_rules.iter().cloned().collect::<Vec<_>>(),
            "applied": 0,
            "failed": failed,
        });
    }

    ok(json!({
        "mode": d.mode,
        "rule": rule,
        "enforcing_rules": d.enforcing_rules.iter().cloned().collect::<Vec<_>>(),
        "requested": value,
        "applied": applied.len(),
        "policies": names.len(),
        "failed": failed,
        "tetra": tetra.display().to_string(),
    }))
}

fn set_sandbox(d: &mut Daemon, value: &str) -> Value {
    let flag = d.cfg.paths.sandbox_flag.clone();
    match value {
        "on" | "true" | "1" => {
            if let Some(p) = flag.parent() {
                if let Err(e) = std::fs::create_dir_all(p) {
                    return err(format!("{}: {}", p.display(), e));
                }
            }
            if let Err(e) = std::fs::write(
                &flag,
                "# Presence of this file makes /etc/profile.d/moat-shims.sh\n\
                 # prepend the sandbox shims to PATH. Log out and back in to apply.\n",
            ) {
                return err(format!("{}: {}", flag.display(), e));
            }
        }
        "off" | "false" | "0" => {
            if flag.exists() {
                if let Err(e) = std::fs::remove_file(&flag) {
                    return err(format!("{}: {}", flag.display(), e));
                }
            }
        }
        other => return err(format!("sandbox must be on or off, got {:?}", other)),
    }
    ok(json!({
        "sandbox": d.sandbox_on(),
        "flag": flag.display().to_string(),
        "note": "shims apply to new login sessions; log out and back in",
    }))
}

fn cmd_feeds(d: &mut Daemon, req: &Value) -> Value {
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action != "refresh" {
        return err(format!("unknown feeds action {:?}; use refresh", action));
    }
    let bin = feeds_binary(&d.cfg.paths.feeds_bin);
    let out = std::process::Command::new(&bin)
        .arg("--out-dir")
        .arg(d.cfg.paths.feeds())
        .output();
    match out {
        Ok(o) => {
            let dir = d.cfg.paths.feeds();
            d.feeds.reload_if_changed(&dir);
            ok(json!({
                "ran": bin.display().to_string(),
                "status": o.status.code(),
                "stdout": String::from_utf8_lossy(&o.stdout).trim().to_string(),
                "stderr": String::from_utf8_lossy(&o.stderr).trim().to_string(),
                "feeds": {
                    "updated": d.feeds.meta.updated,
                    "hashes": d.feeds.meta.hashes,
                    "domains": d.feeds.meta.domains,
                },
            }))
        }
        Err(e) => err(format!("{}: {}", bin.display(), e)),
    }
}

/// In dev mode the configured `/usr/bin/moat-feeds` does not exist; fall
/// back to a binary sitting next to the running one (target/debug/…).
fn feeds_binary(configured: &Path) -> PathBuf {
    if configured.exists() {
        return configured.to_path_buf();
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(sibling) = exe.parent().map(|p| p.join("moat-feeds")) {
            if sibling.exists() {
                return sibling;
            }
        }
    }
    configured.to_path_buf()
}

/// What the `moat` group looks like from where this process is standing.
///
/// EACCES on the control socket has three different causes that need three
/// different fixes, and they are indistinguishable from the errno alone.
/// Telling someone to run `usermod` when they are already in the group sends
/// them round a loop that cannot terminate — the command succeeds, changes
/// nothing, and the socket still says no.
#[derive(Debug, PartialEq)]
pub enum GroupState {
    /// No `moat` line in /etc/group: the package is not fully installed.
    NoSuchGroup,
    /// The user is not listed as a member.
    NotAMember,
    /// Listed as a member, but this process does not carry the gid. Group
    /// membership is resolved once, at login, so a session that started before
    /// the `usermod` never picks it up — and neither does a new shell inside it.
    StaleSession,
    /// Member, and the gid is live in this process. Something else is wrong.
    Member,
}

pub fn group_state(members: Option<(u32, Vec<String>)>, user: &str, gids: &[u32]) -> GroupState {
    let Some((gid, members)) = members else {
        return GroupState::NoSuchGroup;
    };
    if gids.contains(&gid) {
        return GroupState::Member;
    }
    if members.iter().any(|m| m == user) {
        GroupState::StaleSession
    } else {
        GroupState::NotAMember
    }
}

/// The advice that goes with each state. `sock` is quoted so the reader can see
/// which socket was refused when a non-default one is configured.
pub fn permission_denied_help(sock: &str, state: GroupState) -> String {
    match state {
        GroupState::NoSuchGroup => format!(
            "permission denied on {sock}.\nThere is no `moat` group on this system, so the \
             package is not fully installed.\nReinstall it:\n  sudo pacman -S omarchy-moat"
        ),
        GroupState::NotAMember => format!(
            "permission denied on {sock}.\nYou are not in the `moat` group. Run:\n  \
             sudo usermod -aG moat $USER\nthen log out and back in (a new shell is not enough)."
        ),
        GroupState::StaleSession => format!(
            "permission denied on {sock}.\nYou are already in the `moat` group — running \
             `usermod` again will not help.\nThis login session started before you were added, \
             and a session resolves its groups once, at login.\nLog out and back in; a new shell \
             inside this session is not enough.\nTo get a shell that has it right now, without \
             logging out:\n  newgrp moat"
        ),
        GroupState::Member => format!(
            "permission denied on {sock}, and the `moat` group is not the reason: you are a \
             member and this session carries it.\nSo the socket's own permissions are wrong. \
             moatd recreates it 0660 root:moat every start:\n  ls -l {sock}\n  \
             sudo systemctl restart moatd"
        ),
    }
}

/// `moat:x:960:dan,other` -> `(960, ["dan", "other"])`.
fn moat_group(group_file: &Path) -> Option<(u32, Vec<String>)> {
    let text = std::fs::read_to_string(group_file).ok()?;
    for line in text.lines() {
        let mut f = line.split(':');
        if f.next()? != "moat" {
            continue;
        }
        let _passwd = f.next()?;
        let gid: u32 = f.next()?.parse().ok()?;
        let members = f
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|m| !m.is_empty())
            .map(str::to_string)
            .collect();
        return Some((gid, members));
    }
    None
}

/// The login name for this uid, from the passwd database. `$USER` is not used:
/// it is inherited and can name someone else entirely after `su`.
fn current_user(passwd_file: &Path) -> String {
    let uid = unsafe { libc::getuid() };
    let Ok(text) = std::fs::read_to_string(passwd_file) else {
        return String::new();
    };
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() > 2 && f[2].parse::<libc::uid_t>() == Ok(uid) {
            return f[0].to_string();
        }
    }
    String::new()
}

/// Every gid this process carries: the supplementary list plus real and
/// effective, which `getgroups` does not promise to include.
fn current_gids() -> Vec<u32> {
    let mut gids = unsafe { vec![libc::getgid() as u32, libc::getegid() as u32] };
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n > 0 {
        let mut buf = vec![0 as libc::gid_t; n as usize];
        let got = unsafe { libc::getgroups(n, buf.as_mut_ptr()) };
        if got > 0 {
            buf.truncate(got as usize);
            gids.extend(buf.into_iter().map(|g| g as u32));
        }
    }
    gids
}

/// Client half, shared by `moatctl` and the integration tests.
pub fn request(socket: &Path, req: &Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => permission_denied_help(
            &socket.display().to_string(),
            group_state(
                moat_group(Path::new("/etc/group")),
                &current_user(Path::new("/etc/passwd")),
                &current_gids(),
            ),
        ),
        std::io::ErrorKind::NotFound => format!(
            "{} does not exist. Is moatd running? Try: systemctl status moatd",
            socket.display()
        ),
        _ => format!("{}: {}", socket.display(), e),
    })?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    stream.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(b"\n").map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    reader.read_line(&mut resp).map_err(|e| e.to_string())?;
    if resp.trim().is_empty() {
        return Err("moatd closed the connection without answering".into());
    }
    serde_json::from_str(resp.trim()).map_err(|e| format!("bad response: {} ({})", e, resp.trim()))
}

/// Count of `[[rule]]` blocks in a file, for `unignore` bounds messages.
pub fn rule_count(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .map(|t| split_blocks(&t).1.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

    #[test]
    fn permission_denied_tells_a_member_to_relogin_not_to_usermod() {
        let members = Some((960u32, vec!["dan".to_string()]));

        // In the group on disk, but the session predates it.
        let stale = group_state(members.clone(), "dan", &[1000, 998]);
        assert_eq!(stale, GroupState::StaleSession);
        let msg = permission_denied_help("/run/moat/control.sock", stale);
        assert!(msg.contains("already in the `moat` group"), "{}", msg);
        assert!(msg.contains("newgrp moat"), "{}", msg);
        assert!(
            !msg.contains("usermod -aG moat"),
            "usermod cannot help a member: {}",
            msg
        );

        // Genuinely not a member: usermod is the right advice.
        let absent = group_state(members.clone(), "eve", &[1001]);
        assert_eq!(absent, GroupState::NotAMember);
        assert!(permission_denied_help("s", absent).contains("usermod -aG moat"));

        // Member and the gid is live: the socket itself is at fault.
        let member = group_state(members, "dan", &[1000, 960]);
        assert_eq!(member, GroupState::Member);
        let msg = permission_denied_help("/run/moat/control.sock", member);
        assert!(msg.contains("restart moatd"), "{}", msg);
        assert!(!msg.contains("usermod"), "{}", msg);

        // No group at all: the package is not installed properly.
        assert_eq!(group_state(None, "dan", &[1000]), GroupState::NoSuchGroup);
    }

    #[test]
    fn moat_group_parses_the_member_list() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("group");
        std::fs::write(&f, "root:x:0:\nwheel:x:998:dan\nmoat:x:960:dan,ops\n").unwrap();
        let (gid, members) = moat_group(&f).expect("moat line");
        assert_eq!(gid, 960);
        assert_eq!(members, vec!["dan".to_string(), "ops".to_string()]);

        // An empty member list must not become a member named "".
        std::fs::write(&f, "moat:x:960:\n").unwrap();
        assert_eq!(moat_group(&f).unwrap().1, Vec::<String>::new());
        assert_eq!(group_state(moat_group(&f), "", &[1]), GroupState::NotAMember);
    }
    use super::*;
    use crate::config::Config;

    fn daemon(dir: &Path) -> Daemon {
        let mut cfg = Config::default();
        cfg.paths.state_dir = dir.join("state");
        cfg.paths.policies_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/policies");
        cfg.paths.allowlist_dir = dir.join("allowlist.d");
        cfg.paths.tetragon_log = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sample.log");
        cfg.paths.sandbox_flag = dir.join("sandbox.enabled");
        // Snapshots and bundles must never touch the real /var/lib/moat.
        cfg.analysis.bundle_dir = dir.join("incidents");
        cfg.paths.tetra = dir.join("no-such-tetra");
        cfg.paths.pacman_local = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/pacman-local");
        cfg.paths.pacman = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/fake-pacman");
        std::fs::create_dir_all(&cfg.paths.allowlist_dir).unwrap();
        let mut d = Daemon::new(cfg, &dir.join("moat.toml")).unwrap();
        d.homes = vec!["/home/dan".into()];
        d.provenance.set_homes(&d.homes);
        let text = std::fs::read_to_string(&d.cfg.paths.tetragon_log).unwrap();
        for line in text.lines() {
            d.handle_line(line);
        }
        d
    }

    fn first_id(d: &Daemon, rule: &str) -> String {
        d.store
            .load()
            .into_iter()
            .find(|a| a.rule == rule)
            .unwrap_or_else(|| panic!("no alert for {}", rule))
            .id
    }

    #[test]
    fn unknown_and_malformed_commands_answer_ok_false() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        assert_eq!(dispatch(&mut d, &json!({"cmd":"nope"}))["ok"], false);
        assert_eq!(dispatch(&mut d, &json!({}))["ok"], false);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"explain","id":"nope"}))["ok"], false);
    }

    #[test]
    fn status_list_explain() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        assert_eq!(dispatch(&mut d, &json!({"cmd":"status"}))["ok"], true);

        let list = dispatch(&mut d, &json!({"cmd":"list","limit":2}));
        assert_eq!(list["alerts"].as_array().unwrap().len(), 2);

        let id = first_id(&d, "moat-cred-ssh-private-key-read");
        let e = dispatch(&mut d, &json!({"cmd":"explain","id":id}));
        assert_eq!(e["ok"], true);
        assert!(e["alert"]["explain"]["what"].as_str().unwrap().contains("SSH key"));

        // `since` filters by ULID.
        let all = dispatch(&mut d, &json!({"cmd":"list"}));
        let n = all["alerts"].as_array().unwrap().len();
        let since = all["alerts"][0]["id"].as_str().unwrap().to_string();
        let rest = dispatch(&mut d, &json!({"cmd":"list","since":since}));
        assert_eq!(rest["alerts"].as_array().unwrap().len(), n - 1);
    }

    #[test]
    fn ack_appends_an_update() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = first_id(&d, "moat-cred-ssh-private-key-read");
        assert_eq!(dispatch(&mut d, &json!({"cmd":"ack","id":id}))["ok"], true);
        assert!(d.find_alert(&id).unwrap().acked);
    }

    /// An alert killed by an individually-armed rule must not record itself as
    /// having happened in monitor mode. The first real enforcement on this
    /// machine produced `action: killed` next to `mode: monitor`, which reads
    /// as a contradiction to anyone auditing the record later.
    #[test]
    fn an_individually_armed_rule_records_enforce_not_monitor() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let armed = "moat-rootkit-ldso-preload-write".to_string();
        let other = "moat-cred-ssh-private-key-read";
        assert_eq!(d.mode, "monitor");

        assert_eq!(d.mode_for(&armed), "monitor", "nothing armed yet");
        d.enforcing_rules.insert(armed.clone());
        assert_eq!(d.mode_for(&armed), "enforce", "this rule kills");
        assert_eq!(d.mode_for(other), "monitor", "every other rule does not");

        // The daemon-wide switch still governs everything that is not armed.
        d.mode = "enforce".into();
        assert_eq!(d.mode_for(other), "enforce");
    }

    /// Enforcement has to be arm-able one rule at a time. Seven shipped
    /// policies carry Sigkill, and arming them together on a desktop kills the
    /// module loader on USB hotplug and kills ssh for reading your own key.
    #[test]
    fn one_rule_can_enforce_without_arming_the_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let rule = d.policies.names()[0].clone();
        assert_eq!(d.mode, "monitor");

        // tetra is absent in tests, so nothing can apply — and that is exactly
        // the case INTEGRATION §6.2 was about: it used to answer ok:true.
        let r = dispatch(
            &mut d,
            &json!({"cmd":"set","key":"mode","value":"enforce","rule":rule}),
        );
        assert_eq!(r["ok"], false, "applying to nothing must not answer ok");
        assert_eq!(r["applied"], 0);
        assert!(r["error"].as_str().unwrap().contains("no policies"));
        // The intent is still recorded, and the daemon is still not enforcing.
        assert!(d.enforcing_rules.contains(&rule));
        assert_eq!(d.mode, "monitor", "a per-rule arm must not move the daemon");

        // It shows up where a user would look, and survives a write/read cycle.
        let st = d.status();
        assert_eq!(st["enforcing_rules"][0], json!(rule));
        assert_eq!(st["mode"], "monitor");

        // Turning it back off removes it.
        dispatch(
            &mut d,
            &json!({"cmd":"set","key":"mode","value":"monitor","rule":rule}),
        );
        assert!(d.enforcing_rules.is_empty(), "disarmed");

        // An unknown rule is refused rather than silently recorded.
        let r = dispatch(
            &mut d,
            &json!({"cmd":"set","key":"mode","value":"enforce","rule":"moat-nope"}),
        );
        assert_eq!(r["ok"], false);
        assert!(d.enforcing_rules.is_empty());

        // The daemon-wide switch still works and still reports honestly.
        let r = dispatch(&mut d, &json!({"cmd":"set","key":"mode","value":"enforce"}));
        assert_eq!(r["ok"], false, "no tetra, so nothing applied");
        assert_eq!(d.mode, "enforce", "but the mode is still persisted");
    }

    /// Demotions outlive the noise that caused them by up to 24 h, and they
    /// silence whatever shares the board: a flood from unrelated rules demoted
    /// moat-cred-ssh-private-key-read on 2026-09-03.
    #[test]
    fn undemote_all_clears_the_board() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let now = crate::util::unix_secs();
        for rule in ["moat-cred-ssh-private-key-read", "moat-exec-untrusted-home"] {
            for _ in 0..(d.baseline.noisy_rule_per_day + 2) {
                d.baseline.note_alert(rule, now);
            }
            assert!(d.baseline.is_demoted(rule), "{} should be demoted", rule);
        }

        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"undemote","all":true}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["cleared"].as_array().unwrap().len(), 2);
        assert!(d.baseline.demoted_rules().is_empty(), "board is clear");

        // Idempotent, and still an honest answer when there is nothing to do.
        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"undemote","all":true}));
        assert_eq!(r["ok"], true);
        assert!(r["cleared"].as_array().unwrap().is_empty());

        // Without --all a name is still required, and still has to be demoted.
        assert_eq!(
            dispatch(&mut d, &json!({"cmd":"baseline","action":"undemote"}))["ok"],
            false
        );
        assert_eq!(
            dispatch(&mut d, &json!({"cmd":"baseline","action":"undemote","rule":"moat-nope"}))["ok"],
            false
        );
    }

    /// A retune leaves a backlog about rules that no longer exist. Acking it
    /// one id at a time is not something anyone does, so the backlog stays and
    /// hides live alerts; these are the two cuts that clear it.
    #[test]
    fn bulk_ack_clears_a_backlog_by_rule_and_by_age() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let before: Vec<String> = d
            .store
            .load()
            .into_iter()
            .filter(|a| !a.acked)
            .map(|a| a.id)
            .collect();
        assert!(before.len() > 2, "fixture must leave a backlog");
        let rule = d.find_alert(&before[0]).unwrap().rule;

        // By rule: only that rule's alerts, and nothing else, is touched.
        let r = dispatch(&mut d, &json!({"cmd":"ack","rule":rule}));
        assert_eq!(r["ok"], true);
        let n = r["acked"].as_u64().unwrap();
        assert!(n >= 1);
        assert!(d
            .store
            .load()
            .into_iter()
            .filter(|a| a.rule == rule)
            .all(|a| a.acked));

        // A rule nobody has alerts for acks nothing rather than erroring.
        let r = dispatch(&mut d, &json!({"cmd":"ack","rule":"moat-nope"}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["acked"], 0);

        // --all takes the rest.
        let r = dispatch(&mut d, &json!({"cmd":"ack","all":true}));
        assert_eq!(r["ok"], true);
        assert!(d.store.load().into_iter().all(|a| a.acked), "backlog cleared");

        // A bare id still works and still rejects an unknown one.
        assert_eq!(
            dispatch(&mut d, &json!({"cmd":"ack","id":"01NOPE"}))["ok"],
            false
        );
    }

    #[test]
    fn ignore_writes_the_exact_block_the_alert_advertised() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = first_id(&d, "moat-cred-ssh-private-key-read");
        let alert = d.find_alert(&id).unwrap();
        let advertised = alert
            .explain
            .if_expected
            .options
            .iter()
            .find(|o| o.scope == "exe")
            .unwrap()
            .line
            .clone();

        let r = dispatch(&mut d, &json!({"cmd":"ignore","id":id,"scope":"exe","comment":"my own build"}));
        assert_eq!(r["ok"], true);
        let block = r["block"].as_str().unwrap();
        assert!(block.contains(&advertised), "block must match the alert's promise");
        assert!(block.contains(&id), "the comment records where it came from");
        assert!(block.contains("my own build"));
        assert!(d.find_alert(&id).unwrap().acked, "ignore acks");

        // And it takes effect immediately.
        assert_eq!(d.allowlist.len(), 1);
        let list = dispatch(&mut d, &json!({"cmd":"allowlist"}));
        assert_eq!(list["rules"].as_array().unwrap().len(), 1);
        assert_eq!(list["rules"][0]["index"], 1);
        assert!(list["rules"][0]["comment"].as_str().unwrap().contains("my own build"));

        let un = dispatch(&mut d, &json!({"cmd":"unignore","rule":1}));
        assert_eq!(un["ok"], true);
        assert_eq!(d.allowlist.len(), 0);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"unignore","rule":1}))["ok"], false);
    }

    #[test]
    fn ignore_rejects_a_scope_the_alert_cannot_support() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = first_id(&d, "moat-net-reverse-shell");
        let r = dispatch(&mut d, &json!({"cmd":"ignore","id":id,"scope":"exe+file"}));
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("no file"));
    }

    #[test]
    fn kill_refuses_a_recycled_pid() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = first_id(&d, "moat-cred-ssh-private-key-read");
        // pid 41233 either does not exist or is something else entirely.
        let r = dispatch(&mut d, &json!({"cmd":"kill","id":id}));
        assert_eq!(r["ok"], false);
        let e = r["error"].as_str().unwrap();
        assert!(e.contains("gone") || e.contains("refusing to kill"), "{}", e);
    }

    #[test]
    fn kill_verification_accepts_our_own_process() {
        let pid = std::process::id();
        let start = util::proc_start_nanos(pid).unwrap();
        let secs = (start / 1_000_000_000) as i64;
        let nanos = (start % 1_000_000_000) as u32;
        let ts = chrono::DateTime::from_timestamp(secs, nanos)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let exe = util::proc_exe(pid).unwrap();
        assert!(verify_pid(pid, &ts, &exe).is_ok());
        assert!(verify_pid(pid, "2001-01-01T00:00:00.000Z", &exe).is_err());
        assert!(verify_pid(pid, &ts, "/usr/bin/definitely-not-this").is_err());
    }

    #[test]
    fn quarantine_moves_a_dropped_file_and_refuses_system_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let home = dir.path().join("home/dan");
        std::fs::create_dir_all(&home).unwrap();
        d.homes = vec![home.to_string_lossy().to_string()];

        let victim = home.join("dropper");
        std::fs::write(&victim, b"payload").unwrap();

        // Build an alert that points at it.
        let mut a = crate::alert::tests_support::demo_alert("01QQQQQQQQQQQQQQQQQQQQQQQQ");
        a.file = Some(crate::alert::FileRef {
            path: victim.to_string_lossy().to_string(),
            sha256: None,
        });
        d.store.append_alert(&a).unwrap();

        let r = dispatch(&mut d, &json!({"cmd":"quarantine","id":a.id}));
        assert_eq!(r["ok"], true, "{:?}", r);
        assert!(!victim.exists());
        let dest = PathBuf::from(r["to"].as_str().unwrap());
        assert!(dest.exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0);
        let meta: Value =
            serde_json::from_str(&std::fs::read_to_string(dest.parent().unwrap().join("meta.json")).unwrap())
                .unwrap();
        assert_eq!(meta["alert"], a.id);
        assert!(meta["sha256"].is_string());
        assert_eq!(d.find_alert(&a.id).unwrap().action_taken, "quarantined");

        // A system path is refused outright.
        let mut b = crate::alert::tests_support::demo_alert("01RRRRRRRRRRRRRRRRRRRRRRRR");
        b.file = Some(crate::alert::FileRef {
            path: "/usr/bin/ls".into(),
            sha256: None,
        });
        d.store.append_alert(&b).unwrap();
        let r = dispatch(&mut d, &json!({"cmd":"quarantine","id":b.id}));
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("outside"));
        assert!(Path::new("/usr/bin/ls").exists());
    }

    #[test]
    fn set_sandbox_toggles_the_flag_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        assert_eq!(dispatch(&mut d, &json!({"cmd":"status"}))["sandbox"], false);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"set","key":"sandbox","value":"on"}))["sandbox"], true);
        assert!(d.cfg.paths.sandbox_flag.exists());
        assert_eq!(dispatch(&mut d, &json!({"cmd":"set","key":"sandbox","value":"off"}))["sandbox"], false);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"set","key":"sandbox","value":"maybe"}))["ok"], false);
    }

    /// The mode is persisted even when it could not be pushed to a single
    /// policy — but the answer says so. This used to report ok:true after
    /// applying to nothing, which told a user their machine was enforcing when
    /// it was not (INTEGRATION §6.2). An enforce switch that lies about whether
    /// it took is worse than not having one, and §6.2 named this test as the
    /// one that would have to be rewritten.
    #[test]
    fn set_mode_persists_but_reports_honestly_when_tetra_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let r = dispatch(&mut d, &json!({"cmd":"set","key":"mode","value":"enforce"}));
        assert_eq!(r["ok"], false, "applied to nothing, so not ok");
        assert_eq!(r["applied"], 0);
        assert!(
            r["error"].as_str().unwrap().contains("nothing is enforcing it"),
            "{}",
            r["error"]
        );
        assert!(!r["failed"].as_array().unwrap().is_empty(), "missing tetra is reported");

        // Recorded regardless, so a restart does not forget what was asked for.
        assert_eq!(r["mode"], "enforce");
        assert_eq!(d.mode, "enforce");
        assert_eq!(dispatch(&mut d, &json!({"cmd":"status"}))["mode"], "enforce");
        assert_eq!(dispatch(&mut d, &json!({"cmd":"set","key":"mode","value":"sideways"}))["ok"], false);
    }

    #[test]
    fn the_socket_round_trips_a_request() {
        let dir = tempfile::tempdir().unwrap();
        let d = daemon(dir.path());
        let sock = dir.path().join("control.sock");
        let shared = Arc::new(Mutex::new(d));
        serve(Arc::clone(&shared), &sock, "moat").unwrap();
        let resp = request(&sock, &json!({"cmd":"status"})).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["socket_group"], "moat");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }

    // ---------------------------------------------- baselining (CONTRACT §11)

    /// Put one accepted-shaped proposal in the daemon's baseline.
    fn seed_proposal(d: &mut Daemon) -> String {
        d.baseline.state.learning_until = 1; // the window is closed
        let now = util::unix_secs();
        for day in 0..3u64 {
            d.baseline.observe(&crate::baseline::Observation {
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
        d.baseline.proposals()[0].id.clone()
    }

    #[test]
    fn baseline_list_reports_the_window_the_proposals_and_the_demotions() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = seed_proposal(&mut d);
        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"list"}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["learning"], false);
        assert_eq!(r["proposals"].as_array().unwrap().len(), 1);
        let p = &r["proposals"][0];
        assert_eq!(p["id"], id);
        for k in ["id", "rule", "exe", "parent", "dir", "count", "days", "first_seen", "last_seen", "toml"] {
            assert!(p.get(k).is_some(), "proposal has no {}", k);
        }
        assert!(r["demoted_rules"].as_array().unwrap().is_empty());
        assert!(r["baseline_file"].as_str().unwrap().ends_with("baseline.toml"));

        // An unknown action is a clear error, not a silent default.
        assert_eq!(dispatch(&mut d, &json!({"cmd":"baseline","action":"wat"}))["ok"], false);
    }

    #[test]
    fn accepting_a_proposal_writes_the_exact_toml_it_advertised() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = seed_proposal(&mut d);
        let advertised = d.baseline.proposal(&id).unwrap().toml.clone();

        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"accept","id":id}));
        assert_eq!(r["ok"], true, "{:?}", r);
        let block = r["block"].as_str().unwrap();
        assert!(block.contains(&advertised), "the block must match the promise");
        assert!(block.contains("accepted by"), "{}", block);
        assert!(r["file"].as_str().unwrap().ends_with("baseline.toml"));
        // It is live, it is out of the proposal list, and it cannot be accepted twice.
        assert_eq!(d.allowlist.len(), 1);
        assert!(d.baseline.proposals().is_empty());
        assert_eq!(dispatch(&mut d, &json!({"cmd":"baseline","action":"accept","id":id}))["ok"], false);

        // And it shows up as a `learned` entry in the allowlist listing.
        let al = dispatch(&mut d, &json!({"cmd":"allowlist"}));
        assert_eq!(al["rules"][0]["source"], "learned");
        assert_eq!(al["rules"][0]["removable"], true);
        assert_eq!(al["rules"][0]["index"], 1);
    }

    #[test]
    fn dismissing_a_proposal_drops_it_without_writing_anything() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = seed_proposal(&mut d);
        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"dismiss","id":id}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["dismissed"]["id"], id);
        assert!(d.baseline.proposals().is_empty());
        assert!(!d.cfg.paths.baseline_allowlist().exists());
        assert_eq!(dispatch(&mut d, &json!({"cmd":"baseline","action":"dismiss","id":id}))["ok"], false);
    }

    #[test]
    fn relearn_reopens_the_window_for_the_days_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        d.baseline.state.learning_until = 1;
        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"relearn","days":14}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["learning"], true);
        assert_eq!(r["days"], 14);
        assert!(d.baseline.learning(util::unix_secs()));
        assert_eq!(dispatch(&mut d, &json!({"cmd":"status"}))["baseline"]["learning"], true);
    }

    #[test]
    fn export_dumps_every_tuple_with_the_reviewers_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        seed_proposal(&mut d);
        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"export"}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["count"], r["tuples"].as_array().unwrap().len());
        assert!(r["count"].as_u64().unwrap() >= 1);
        let t = &r["tuples"][0];
        for k in ["rule", "exe", "provenance", "parent", "dir", "context", "severity", "count", "days", "first_seen", "last_seen", "suppressed", "demoted", "toml"] {
            assert!(t.get(k).is_some(), "export tuple has no {}", k);
        }
        assert!(r["trusted_repos"].as_array().unwrap().contains(&json!("core")));
        // `--since` in the future filters everything out.
        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"export","since":"2099-01-01"}));
        assert_eq!(r["count"], 0);
    }

    #[test]
    fn undemote_and_propose_are_the_two_answers_to_a_noisy_rule() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        seed_proposal(&mut d);
        d.baseline.dismiss(&d.baseline.proposals()[0].id.clone()).unwrap();

        // "these are expected": propose the rule's top tuples.
        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"propose","rule":"moat-persist-hypr-config-write"}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["proposals"].as_array().unwrap().len(), 1);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"baseline","action":"propose"}))["ok"], false);

        // "keep watching": clear a demotion.
        let now = util::unix_secs();
        for i in 0..25 {
            d.baseline.note_alert("moat-x-pkg-egress", now + i);
        }
        assert_eq!(dispatch(&mut d, &json!({"cmd":"status"}))["demoted_rules"][0], "moat-x-pkg-egress");
        let r = dispatch(&mut d, &json!({"cmd":"baseline","action":"undemote","rule":"moat-x-pkg-egress"}));
        assert_eq!(r["ok"], true);
        assert!(r["demoted_rules"].as_array().unwrap().is_empty());
        assert_eq!(dispatch(&mut d, &json!({"cmd":"baseline","action":"undemote","rule":"moat-x-pkg-egress"}))["ok"], false);
    }

    #[test]
    fn unignore_takes_a_file_and_an_index_and_refuses_shipped_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let spec = crate::allowlist::RuleSpec {
            name: "moat-persist-hypr-config-write".into(),
            exe: Some("/usr/bin/hyprctl".into()),
            ..Default::default()
        };
        crate::allowlist::append_rule(&d.cfg.paths.baseline_allowlist(), "learned", &spec).unwrap();
        crate::allowlist::append_rule(
            &d.cfg.paths.allowlist_dir.join("default.toml"),
            "shipped",
            &crate::allowlist::RuleSpec { name: "moat-net-*".into(), ..Default::default() },
        )
        .unwrap();
        d.reload_allowlist();
        assert_eq!(d.allowlist.len(), 2);

        let list = dispatch(&mut d, &json!({"cmd":"allowlist"}));
        let by_source: Vec<&str> = list["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["source"].as_str().unwrap())
            .collect();
        assert!(by_source.contains(&"learned") && by_source.contains(&"shipped"));

        // A shipped file is refused with an explanation.
        let r = dispatch(&mut d, &json!({"cmd":"unignore","file":"default.toml","index":1}));
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("shipped by the package"));

        // A learned entry comes out the same way a user one does.
        let r = dispatch(&mut d, &json!({"cmd":"unignore","file":"baseline.toml","index":1}));
        assert_eq!(r["ok"], true, "{:?}", r);
        assert!(r["removed"].as_str().unwrap().contains("hyprctl"));
        assert_eq!(d.allowlist.len(), 1);
        // Path traversal in `file` cannot escape allowlist.d.
        assert_eq!(
            dispatch(&mut d, &json!({"cmd":"unignore","file":"../../etc/passwd","index":1}))["ok"],
            false
        );
    }

    // ------------------------------- receipts, incidents, bundle, digest (§7)

    /// LEARNING §7: `receipts` is informational and never looks like an alert.
    #[test]
    fn receipts_are_listed_and_rendered() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let now = util::unix_secs();
        d.handle_line(&format!(
            r#"{{"process_exec":{{"process":{{"exec_id":"c-npm","pid":51201,"uid":1000,"cwd":"/home/dan/proj","binary":"/usr/bin/npm","arguments":"install","start_time":"{}"}}}}}}"#,
            util::rfc3339_of(now)
        ));
        d.handle_line(r#"{"process_exit":{"process":{"exec_id":"c-npm","pid":51201,"binary":"/usr/bin/npm","arguments":"install"},"status":0}}"#);

        let r = dispatch(&mut d, &json!({"cmd":"receipts","last":10}));
        assert_eq!(r["ok"], true);
        let list = r["receipts"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        for k in [
            "id", "root_exe", "root_args", "cwd", "started", "duration_s", "exit",
            "postinstall_scripts", "writes_outside_project", "network", "credential_reads",
            "persistence_writes", "execs_from_tree", "execs_from_tmp",
        ] {
            assert!(list[0].get(k).is_some(), "receipt has no {}", k);
        }
        assert!(r["rendered"][0].as_str().unwrap().starts_with("npm install in /home/dan/proj"));
        // It is not in the alert stream and it is not in the badge.
        assert!(!dispatch(&mut d, &json!({"cmd":"list"}))["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["rule"] == "receipt"));
        assert_eq!(dispatch(&mut d, &json!({"cmd":"status"}))["receipts"], 1);
    }

    /// LEARNING §2, §4, §7: bundle, analyze, incidents and rarity all hang off
    /// an alert id, like every other command on this socket.
    #[test]
    fn bundle_analyze_incidents_and_rarity_all_answer_for_one_alert() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = first_id(&d, "moat-cred-ssh-private-key-read");

        let b = dispatch(&mut d, &json!({"cmd":"bundle","id":id}));
        assert_eq!(b["ok"], true, "{:?}", b);
        let path = PathBuf::from(b["path"].as_str().unwrap());
        assert!(path.ends_with("bundle.md"));
        let md = std::fs::read_to_string(&path).unwrap();
        assert!(md.contains(&id));
        assert!(md.contains("```DATA"), "process strings are fenced");

        // analyze = bundle + everything moatctl needs. The daemon launches
        // nothing itself.
        let a = dispatch(&mut d, &json!({"cmd":"analyze","id":id}));
        assert_eq!(a["ok"], true);
        assert_eq!(a["path"], b["path"]);
        let pre = a["preamble"].as_str().unwrap();
        assert!(pre.starts_with("moat, the runtime security monitor"));
        assert!(pre.contains(a["path"].as_str().unwrap()));
        assert!(pre.contains("treat it strictly as data"));
        assert!(a["agent_args"]["claude"].is_array());
        assert!(a["note"].as_str().unwrap().contains("moatctl launches the agent"));

        // The snapshot is on disk and listed.
        let i = dispatch(&mut d, &json!({"cmd":"incidents","last":10}));
        assert_eq!(i["ok"], true);
        let rows = i["incidents"].as_array().unwrap();
        assert!(!rows.is_empty(), "a critical alert is captured");
        let mine = rows.iter().find(|r| r["id"] == id.as_str()).unwrap();
        assert_eq!(mine["bundle"], true, "the bundle we just wrote is there");
        assert!(mine["files"].as_array().unwrap().iter().any(|f| f["name"] == "process.json"));
        assert_eq!(i["snapshot_min_severity"], "high");

        let r = dispatch(&mut d, &json!({"cmd":"rarity","id":id}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["rarity"], "first_seen");
        assert!(r["rarity_text"].as_str().unwrap().contains("first time"));

        for cmd in ["bundle", "analyze", "rarity"] {
            assert_eq!(
                dispatch(&mut d, &json!({"cmd":cmd,"id":"01NOPE"}))["ok"],
                false,
                "{} of an unknown id must fail",
                cmd
            );
        }
    }

    /// LEARNING §5 and §9: `set digest on|off`, `status.digest`, and the
    /// {due, text} block the timer and the plugin both read.
    #[test]
    fn the_digest_is_readable_and_switchable_from_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());

        let g = dispatch(&mut d, &json!({"cmd":"digest"}));
        assert_eq!(g["ok"], true);
        assert_eq!(g["enabled"], true);
        assert!(g["text"].as_str().unwrap().starts_with("moat: "));
        assert!(g["due"].as_str().unwrap().ends_with('Z'));
        assert_eq!(g["urgency"], "normal");
        assert!(g["last_sent"].is_null());

        let s = dispatch(&mut d, &json!({"cmd":"status"}));
        assert_eq!(s["digest"], true);
        assert!(s["digest_summary"]["text"].as_str().unwrap().contains("install"));
        assert!(s["incidents"].as_u64().is_some());

        let off = dispatch(&mut d, &json!({"cmd":"set","key":"digest","value":"off"}));
        assert_eq!(off["ok"], true);
        assert_eq!(off["digest"], false);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"status"}))["digest"], false);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"digest"}))["enabled"], false);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"set","key":"digest","value":"on"}))["digest"], true);
        assert_eq!(dispatch(&mut d, &json!({"cmd":"set","key":"digest","value":"maybe"}))["ok"], false);

        // A delivery is recorded, so a catch-up run does not send twice.
        let sent = dispatch(&mut d, &json!({"cmd":"digest","action":"sent"}));
        assert!(sent["last_sent"].is_string());
        assert_eq!(dispatch(&mut d, &json!({"cmd":"digest","action":"wat"}))["ok"], false);
    }

    #[test]
    fn a_missing_socket_explains_the_group_setup() {
        let e = request(Path::new("/nonexistent/control.sock"), &json!({"cmd":"status"})).unwrap_err();
        assert!(e.contains("moatd running"));
    }
}
