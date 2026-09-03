//! The control socket (CONTRACT §5).
//!
//! Unix stream, newline-delimited JSON, one request → one response per
//! connection, socket mode 0660 root:sentinel.
//!
//! The safety property that makes this exposable to the user's group: **every
//! action references an alert id, never a raw pid or path**. A hostile process
//! in the `sentinel` group cannot ask the daemon to kill or move anything the
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
        "ack" => cmd_ack(d, &id()),
        "kill" => cmd_kill(d, &id()),
        "quarantine" => cmd_quarantine(d, &id()),
        "ignore" => cmd_ignore(d, req, &id()),
        "unignore" => cmd_unignore(d, req),
        "allowlist" => cmd_allowlist(d),
        "set" => cmd_set(d, req),
        "feeds" => cmd_feeds(d, req),
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

fn cmd_ack(d: &mut Daemon, id: &str) -> Value {
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
fn verify_pid(pid: u32, start_ts: &str, exe: &str) -> Result<(), String> {
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

fn cmd_unignore(d: &mut Daemon, req: &Value) -> Value {
    let n = req
        .get("rule")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let Some(n) = n else {
        return err("`rule` must be the index shown by `allowlist`");
    };
    let path = d.cfg.paths.user_allowlist();
    match remove_rule(&path, n as usize) {
        Ok(removed) => {
            d.reload_allowlist();
            ok(json!({"removed": removed, "file": path.display().to_string()}))
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
            json!({
                // Only user.toml entries can be removed with `unignore`.
                "index": if r.source == user { Some(r.index) } else { None },
                "file": r.source.display().to_string(),
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
        "errors": d.allowlist.failed,
    }))
}

fn cmd_set(d: &mut Daemon, req: &Value) -> Value {
    let key = req.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let value = req.get("value").and_then(|v| v.as_str()).unwrap_or("");
    match key {
        "mode" => set_mode(d, value),
        "sandbox" => set_sandbox(d, value),
        "" => err("missing `key`"),
        other => err(format!("unknown key {:?}; use mode or sandbox", other)),
    }
}

/// `tetra tp set-mode` takes effect immediately on the pinned `policy_conf` map
/// (NOTES §7); there is no reload. We apply it to every loaded policy and keep
/// our own copy in state.json, because the export cannot tell us the mode.
fn set_mode(d: &mut Daemon, value: &str) -> Value {
    if value != "monitor" && value != "enforce" {
        return err(format!("mode must be monitor or enforce, got {:?}", value));
    }
    let tetra = d.cfg.paths.tetra.clone();
    let names = d.policies.names();
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
    d.mode = value.to_string();
    d.write_state();
    log::info!(
        "mode set to {} ({} applied, {} failed)",
        value,
        applied.len(),
        failed.len()
    );
    ok(json!({
        "mode": value,
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
                "# Presence of this file makes /etc/profile.d/sentinel-shims.sh\n\
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

/// In dev mode the configured `/usr/bin/sentinel-feeds` does not exist; fall
/// back to a binary sitting next to the running one (target/debug/…).
fn feeds_binary(configured: &Path) -> PathBuf {
    if configured.exists() {
        return configured.to_path_buf();
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(sibling) = exe.parent().map(|p| p.join("sentinel-feeds")) {
            if sibling.exists() {
                return sibling;
            }
        }
    }
    configured.to_path_buf()
}

/// Client half, shared by `sentinelctl` and the integration tests.
pub fn request(socket: &Path, req: &Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => format!(
            "permission denied on {}.\nYou are not in the `sentinel` group. Run:\n  \
             sudo usermod -aG sentinel $USER\nthen log out and back in (a new shell is not enough).",
            socket.display()
        ),
        std::io::ErrorKind::NotFound => format!(
            "{} does not exist. Is sentineld running? Try: systemctl status sentineld",
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
        return Err("sentineld closed the connection without answering".into());
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
    use super::*;
    use crate::config::Config;

    fn daemon(dir: &Path) -> Daemon {
        let mut cfg = Config::default();
        cfg.paths.state_dir = dir.join("state");
        cfg.paths.policies_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/policies");
        cfg.paths.allowlist_dir = dir.join("allowlist.d");
        cfg.paths.tetragon_log = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sample.log");
        cfg.paths.sandbox_flag = dir.join("sandbox.enabled");
        cfg.paths.tetra = dir.join("no-such-tetra");
        std::fs::create_dir_all(&cfg.paths.allowlist_dir).unwrap();
        let mut d = Daemon::new(cfg, &dir.join("sentinel.toml")).unwrap();
        d.homes = vec!["/home/dan".into()];
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

        let id = first_id(&d, "sentinel-cred-ssh-private-key-read");
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
        let id = first_id(&d, "sentinel-cred-ssh-private-key-read");
        assert_eq!(dispatch(&mut d, &json!({"cmd":"ack","id":id}))["ok"], true);
        assert!(d.find_alert(&id).unwrap().acked);
    }

    #[test]
    fn ignore_writes_the_exact_block_the_alert_advertised() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = first_id(&d, "sentinel-cred-ssh-private-key-read");
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
        let id = first_id(&d, "sentinel-net-reverse-shell");
        let r = dispatch(&mut d, &json!({"cmd":"ignore","id":id,"scope":"exe+file"}));
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("no file"));
    }

    #[test]
    fn kill_refuses_a_recycled_pid() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let id = first_id(&d, "sentinel-cred-ssh-private-key-read");
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

    #[test]
    fn set_mode_persists_even_when_tetra_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon(dir.path());
        let r = dispatch(&mut d, &json!({"cmd":"set","key":"mode","value":"enforce"}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["mode"], "enforce");
        assert_eq!(r["applied"], 0);
        assert!(!r["failed"].as_array().unwrap().is_empty(), "missing tetra is reported");
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
        serve(Arc::clone(&shared), &sock, "sentinel").unwrap();
        let resp = request(&sock, &json!({"cmd":"status"})).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["socket_group"], "sentinel");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }

    #[test]
    fn a_missing_socket_explains_the_group_setup() {
        let e = request(Path::new("/nonexistent/control.sock"), &json!({"cmd":"status"})).unwrap_err();
        assert!(e.contains("sentineld running"));
    }
}
