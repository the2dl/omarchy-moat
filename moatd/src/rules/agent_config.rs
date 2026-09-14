//! Fingerprint executable workspace configuration and connect a subsequent
//! agent execution to an exact script reference. No model interpretation or
//! claim that a configuration file caused a command is required.
use crate::rules::{meta, RuleCtx, UserRule};
use crate::{
    config::Config,
    event::{ExecEvent, HookHit},
    explain::Finding,
    policy::PolicyMeta,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
};
pub const ID: &str = "moat-agent-config-executed";
const WINDOW: u64 = 600;
const MAX_STATES: usize = 512;
const CONFIGS: &[&str] = &[
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/hooks.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/tasks.json",
    ".vscode/launch.json",
    "CLAUDE.md",
    "AGENTS.md",
];
const EXTENDED_CONFIGS: &[&str] = &[
    ".codex/config.toml",
    ".gemini/settings.json",
    "opencode.json",
];

#[derive(Clone)]
struct Snapshot {
    hash: String,
    scripts: BTreeSet<String>,
}
struct State {
    fingerprint: Option<Snapshot>,
    changed_at: Option<u64>,
    verified_change: bool,
    last: u64,
    writer: Option<(u32, String)>,
    reported: BTreeSet<String>,
    last_report: Option<u64>,
}
#[derive(Default)]
pub struct AgentConfig {
    states: BTreeMap<(u32, String), State>,
    scanned: BTreeMap<(u32, String), u64>,
}

fn snapshot(path: &Path, uid: u32, workspace: &Path) -> Option<Snapshot> {
    let (file, real) = crate::util::open_suspect(path).ok()?;
    let stat = file.metadata().ok()?;
    // Never read through an alias into another file, another user's config,
    // a device, or an unbounded payload. No configuration bytes are persisted.
    if real != path.to_string_lossy() || stat.uid() != uid || stat.len() > 131072 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(131073).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 131072 {
        return None;
    }
    let mut scripts = BTreeSet::new();
    // Only structured command/args fields are executable configuration here.
    // Markdown instructions are fingerprinted, but not parsed as shell code.
    let parsed = if path.extension().and_then(|v| v.to_str()) == Some("toml") {
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| toml::from_str::<toml::Value>(text).ok())
            .and_then(|value| serde_json::to_value(value).ok())
    } else {
        serde_json::from_slice::<serde_json::Value>(&bytes).ok()
    };
    if let Some(value) = parsed {
        references(&value, workspace, false, &mut scripts);
    }
    Some(Snapshot {
        hash: format!("{:x}", Sha256::digest(&bytes)),
        scripts,
    })
}
fn script_path(token: &str, workspace: &Path) -> Option<String> {
    let token = token.trim_matches(|c| c == '\'' || c == '"');
    if token.contains(['\n', '\r', '$', '`']) || token.contains("://") {
        return None;
    }
    let path = Path::new(token);
    if !path.is_absolute() && !token.starts_with("./") {
        return None;
    }
    if !matches!(
        path.extension().and_then(|v| v.to_str()),
        Some("js" | "mjs" | "cjs" | "py" | "sh" | "bash")
    ) {
        return None;
    }
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace.join(path)
    };
    let mut normalized = PathBuf::new();
    for part in joined.components() {
        match part {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            part => normalized.push(part.as_os_str()),
        }
    }
    normalized
        .starts_with(workspace)
        .then(|| normalized.display().to_string())
}
fn references(
    value: &serde_json::Value,
    workspace: &Path,
    executable: bool,
    out: &mut BTreeSet<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                references(
                    value,
                    workspace,
                    matches!(key.as_str(), "command" | "args" | "program"),
                    out,
                );
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                references(value, workspace, executable, out);
            }
        }
        serde_json::Value::String(text) if executable => {
            for token in text.split_whitespace() {
                if out.len() >= 64 {
                    break;
                }
                if let Some(path) = script_path(token, workspace) {
                    out.insert(path);
                }
            }
        }
        _ => {}
    }
}

impl AgentConfig {
    fn room(&mut self, now: u64) {
        self.states
            .retain(|_, s| now.saturating_sub(s.last) < WINDOW);
        self.scanned.retain(|_, t| now.saturating_sub(*t) < WINDOW);
        if self.scanned.len() >= 128 {
            if let Some(key) = self
                .scanned
                .iter()
                .min_by_key(|(_, t)| *t)
                .map(|(key, _)| key.clone())
            {
                self.scanned.remove(&key);
            }
        }
        if self.states.len() >= MAX_STATES {
            if let Some(key) = self
                .states
                .iter()
                .min_by_key(|(_, s)| s.last)
                .map(|(key, _)| key.clone())
            {
                self.states.remove(&key);
            }
        }
    }
}
impl UserRule for AgentConfig {
    fn id(&self) -> &'static str {
        ID
    }
    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.agent_config_exec
    }
    fn meta(&self) -> PolicyMeta {
        meta(ID, "persist", "high", "An agent ran a script referenced by changed workspace configuration",
            "Executable agent configuration changed, and an agent in that workspace subsequently executed a script referenced by it. Review the change and script; this sequence does not prove prompt injection.",
            "Installing or updating a hook or MCP integration intentionally. A normal instruction-file edit with no matching script execution does not raise this alert.",
            &[], &["kill", "ignore"], "exe+file")
    }
    fn on_hook(&mut self, h: &HookHit, id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        if h.policy_name() != "moat-persist-agent-config-write" {
            return vec![];
        }
        let Some(path) = h.file_path() else {
            return vec![];
        };
        let Some(p) = ctx.table.get(id) else {
            return vec![];
        };
        self.room(ctx.now);
        let entry = self.states.entry((p.uid, path.clone())).or_insert(State {
            fingerprint: None,
            changed_at: None,
            verified_change: false,
            last: ctx.now,
            writer: None,
            reported: BTreeSet::new(),
            last_report: None,
        });
        entry.writer = Some((p.pid, p.exe.clone()));
        entry.last = ctx.now;
        // An open-for-write alone is not proof of changed contents. Hashes
        // captured on agent execution determine that separately.
        vec![]
    }
    fn on_exec(&mut self, _: &ExecEvent, id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some(proc) = ctx.table.get(id) else {
            return vec![];
        };
        let Some(session) = &proc.agent_session else {
            return vec![];
        };
        let workspace = Path::new(&session.workspace);
        if !workspace.is_absolute() || session.workspace == "/" {
            return vec![];
        }
        self.room(ctx.now);
        let mut result = Vec::new();
        // Match the executed script, not an arbitrary argv reference. Runtime
        // -e/-c strings, shell syntax and escaped paths are deliberately not
        // interpreted as an execution of a referenced file.
        let script = if matches!(
            crate::util::basename(&proc.exe),
            "node" | "bun" | "python" | "python3" | "bash" | "sh"
        ) {
            proc.args
                .split_whitespace()
                .next()
                .and_then(|arg| script_path(arg, Path::new(&proc.cwd)))
        } else {
            script_path(&proc.exe, Path::new(&proc.cwd))
        };
        let scan_key = (proc.uid, session.workspace.clone());
        if script.is_none() && self.scanned.get(&scan_key) == Some(&ctx.now) {
            return vec![];
        }
        self.scanned.insert(scan_key, ctx.now);
        let metadata = self.meta();
        let extra = if ctx.cfg.rules.agent_config_extended {
            EXTENDED_CONFIGS
        } else {
            &[]
        };
        for relative in CONFIGS.iter().chain(extra.iter()) {
            let path = workspace.join(relative);
            let key = (proc.uid, path.display().to_string());
            let current = snapshot(&path, proc.uid, workspace);
            if !self.states.contains_key(&key) {
                self.room(ctx.now);
            }
            let state = self.states.entry(key.clone()).or_insert(State {
                fingerprint: current.clone(),
                changed_at: current.as_ref().map(|_| ctx.now),
                verified_change: false,
                last: ctx.now,
                writer: None,
                reported: BTreeSet::new(),
                last_report: None,
            });
            let changed = match (&state.fingerprint, &current) {
                (Some(old), Some(new)) => old.hash != new.hash,
                (None, Some(_)) => false,
                _ => false,
            };
            if changed {
                state.changed_at = Some(ctx.now);
                state.verified_change = true;
                state.reported.clear();
            }
            if state.fingerprint.is_none() && current.is_some() {
                state.changed_at = Some(ctx.now);
                state.verified_change = false;
            }
            state.fingerprint = current;
            state.last = ctx.now;
            let Some(script) = &script else { continue };
            let Some(current) = &state.fingerprint else {
                continue;
            };
            if !state
                .changed_at
                .map(|t| ctx.now.saturating_sub(t) < WINDOW)
                .unwrap_or(false)
                || !state.verified_change
                || state
                    .last_report
                    .map(|t| ctx.now.saturating_sub(t) < WINDOW)
                    .unwrap_or(false)
                || !current.scripts.contains(script)
                || state.reported.contains(script)
            {
                continue;
            }
            let Some(mut f) = ctx.finding(ID, metadata.clone(), id) else {
                continue;
            };
            f.file = Some(crate::alert::FileRef {
                path: script.clone(),
                sha256: None,
            });
            f.extra_evidence.push(format!(
                "configuration: {}; current SHA-256 {}; exact executed script: {}",
                path.display(),
                current.hash,
                script
            ));
            f.extra_evidence.push(if state.verified_change {
                "configuration contents changed since the observed fingerprint; execution is correlated, not proof of causation"
            } else {
                "no prior content fingerprint: newly observed configuration, not a verified modification"
            }.into());
            if let Some((pid, exe)) = &state.writer {
                f.extra_evidence.push(format!("observed configuration write opener: {} (pid {}); final writer attribution is not guaranteed", exe, pid));
            }
            // Prevent staging a config containing embedded MCP credentials:
            // the target is the executed script, never the config contents.
            state.reported.insert(script.clone());
            state.last_report = Some(ctx.now);
            result.push(f);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{event::Process, proctable::ProcTable};
    fn process(table: &mut ProcTable, root: &Path, id: &str, parent: Option<&str>, args: &str) {
        table.observe(&Process {
            exec_id: Some(id.into()),
            pid: Some(if parent.is_none() { 100 } else { 101 }),
            uid: Some(unsafe { libc::geteuid() }),
            binary: Some(
                if parent.is_none() {
                    "/opt/claude"
                } else {
                    "/usr/bin/node"
                }
                .into(),
            ),
            arguments: Some(args.into()),
            cwd: Some(root.display().to_string()),
            parent_exec_id: parent.map(str::to_string),
            ..Default::default()
        });
    }
    fn exec(rule: &mut AgentConfig, table: &ProcTable, id: &str, now: u64) -> Vec<Finding> {
        exec_config(rule, table, id, now, &Config::default())
    }
    fn exec_config(
        rule: &mut AgentConfig,
        table: &ProcTable,
        id: &str,
        now: u64,
        config: &Config,
    ) -> Vec<Finding> {
        let feeds = crate::feeds::Feeds::default();
        let rarity = crate::rarity::RarityStore::default();
        let ctx = RuleCtx {
            cfg: &config,
            table,
            feeds: &feeds,
            rarity: &rarity,
            homes: &[],
            now,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
            names: &crate::rules::NO_NAMES,
        };
        rule.on_exec(&ExecEvent::default(), id, &ctx)
    }
    #[test]
    fn a_changed_config_requires_exact_script_execution_in_its_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".mcp.json");
        std::fs::write(&path, r#"{"mcpServers":{}}"#).unwrap();
        let mut table = ProcTable::new(8, 60);
        process(&mut table, dir.path(), "root", None, "");
        let mut rule = AgentConfig::default();
        assert!(exec(&mut rule, &table, "root", 100).is_empty());
        std::fs::write(
            &path,
            r#"{"mcpServers":{"test":{"command":"node","args":["./setup.mjs"]}}}"#,
        )
        .unwrap();
        process(
            &mut table,
            dir.path(),
            "unrelated",
            Some("root"),
            "./other.mjs",
        );
        assert!(exec(&mut rule, &table, "unrelated", 101).is_empty());
        process(
            &mut table,
            dir.path(),
            "inline",
            Some("root"),
            "-e './setup.mjs'",
        );
        assert!(exec(&mut rule, &table, "inline", 101).is_empty());
        process(
            &mut table,
            dir.path(),
            "script",
            Some("root"),
            "./setup.mjs",
        );
        let hits = exec(&mut rule, &table, "script", 102);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].meta.severity, "high");
        assert_eq!(
            hits[0].file.as_ref().unwrap().path,
            dir.path().join("setup.mjs").display().to_string()
        );
        assert!(hits[0]
            .extra_evidence
            .iter()
            .any(|line| line.contains("SHA-256")));
        assert!(
            exec(&mut rule, &table, "script", 103).is_empty(),
            "unchanged config should not repeat the alert"
        );
        let other = tempfile::tempdir().unwrap();
        process(&mut table, other.path(), "other-root", None, "");
        process(
            &mut table,
            other.path(),
            "other-script",
            Some("other-root"),
            "./setup.mjs",
        );
        assert!(exec(&mut rule, &table, "other-script", 103).is_empty());
    }
    #[test]
    fn first_observation_is_not_reported_as_a_verified_change() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".mcp.json"),
            r#"{"command":"node ./setup.mjs"}"#,
        )
        .unwrap();
        let mut table = ProcTable::new(8, 60);
        process(&mut table, dir.path(), "root", None, "");
        let mut rule = AgentConfig::default();
        exec(&mut rule, &table, "root", 100);
        process(
            &mut table,
            dir.path(),
            "script",
            Some("root"),
            "./setup.mjs",
        );
        let hits = exec(&mut rule, &table, "script", 101);
        assert!(
            hits.is_empty(),
            "first observation establishes a quiet baseline"
        );
        assert!(
            exec(&mut rule, &table, "script", 1000).is_empty(),
            "expiry also establishes a quiet baseline"
        );
    }
    #[test]
    fn extended_formats_are_opt_in_and_repeated_changes_are_quiet() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".codex")).unwrap();
        let path = dir.path().join(".codex/config.toml");
        std::fs::write(
            &path,
            "[mcp_servers.test]\ncommand = 'node'\nargs = ['./old.mjs']",
        )
        .unwrap();
        let mut table = ProcTable::new(8, 60);
        process(&mut table, dir.path(), "root", None, "");
        let mut disabled = AgentConfig::default();
        let mut enabled = AgentConfig::default();
        let mut config = Config::default();
        assert!(!config.rules.agent_config_extended);
        config.rules.agent_config_extended = true;
        exec(&mut disabled, &table, "root", 100);
        exec_config(&mut enabled, &table, "root", 100, &config);
        std::fs::write(
            &path,
            "[mcp_servers.test]\ncommand = 'node'\nargs = ['./setup.mjs']",
        )
        .unwrap();
        process(
            &mut table,
            dir.path(),
            "script",
            Some("root"),
            "./setup.mjs",
        );
        assert!(exec(&mut disabled, &table, "script", 101).is_empty());
        let hits = exec_config(&mut enabled, &table, "script", 101, &config);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].meta.severity, "high");
        for now in 102..202 {
            std::fs::write(
                &path,
                format!(
                    "# update {now}\n[mcp_servers.test]\ncommand = 'node'\nargs = ['./setup.mjs']"
                ),
            )
            .unwrap();
            assert!(exec_config(&mut enabled, &table, "script", now, &config).is_empty());
        }
        std::fs::write(
            &path,
            "[mcp_servers.test]\ncommand = 'node'\nargs = ['./next.mjs']",
        )
        .unwrap();
        process(&mut table, dir.path(), "next", Some("root"), "./next.mjs");
        assert_eq!(
            exec_config(&mut enabled, &table, "next", 702, &config).len(),
            1
        );
    }

    #[test]
    fn config_staging_rejects_symlinks_and_ignores_non_command_text() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, r#"{"command":"node ./leak.mjs"}"#).unwrap();
        let path = dir.path().join(".mcp.json");
        std::os::unix::fs::symlink(&secret, &path).unwrap();
        assert!(snapshot(&path, unsafe { libc::geteuid() }, dir.path()).is_none());
        let mut scripts = BTreeSet::new();
        references(
            &serde_json::json!({"description":"node ./leak.mjs", "env":{"KEY":"./leak.mjs"}}),
            dir.path(),
            false,
            &mut scripts,
        );
        assert!(scripts.is_empty());
        assert!(script_path("../../leak.mjs", dir.path()).is_none());
    }
}
