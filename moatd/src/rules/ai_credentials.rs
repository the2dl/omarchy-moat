//! Runtime names are not credential-reader identities. Inspect the actual
//! invocation and distinguish a session root's own authentication from tools.
use crate::rules::{meta, RuleCtx, UserRule};
use crate::{config::Config, event::HookHit, explain::Finding, policy::PolicyMeta};
use std::os::unix::fs::MetadataExt;
pub const ID: &str = "moat-cred-ai-credentials-read";

pub struct AiCredentials;
impl UserRule for AiCredentials {
    fn id(&self) -> &'static str {
        ID
    }
    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.ai_credentials
    }
    fn meta(&self) -> PolicyMeta {
        meta(ID, "cred", "high", "AI credentials accessed outside the owning agent",
            "An agent tool, MCP server or another program accessed stored AI credentials. A Node or Bun runtime is not permission to read them.",
            "Explicit credential migration, account management, or a usage integration. Verify the exact invocation before allowing it.",
            &["anthropic-token", "openai-token", "google-token"], &["kill", "ignore"], "exe")
    }
    fn on_hook(&mut self, h: &HookHit, id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        if h.policy_name() != ID || h.int_arg().map(|m| m & 4 == 0).unwrap_or(false) {
            return vec![];
        }
        let Some(path) = h.file_path() else {
            return vec![];
        };
        let Some(mut f) = ctx.finding(ID, self.meta(), id) else {
            return vec![];
        };
        let owner = if path.ends_with("/.claude/.credentials.json")
            || path.ends_with("/.claude.json")
        {
            "claude"
        } else if path.ends_with("/.codex/auth.json") || path.ends_with("/.config/openai/auth.json")
        {
            "codex"
        } else if path.ends_with("/.gemini/oauth_creds.json") {
            "gemini"
        } else if path.ends_with("/.config/opencode/auth.json") {
            "opencode"
        } else if path.ends_with("/.local/share/amazon-q/credentials.json") {
            "q"
        } else {
            return vec![];
        };
        let own_home = ctx.homes.iter().any(|home| {
            path.strip_prefix(&format!("{home}/"))
                .map(|tail| {
                    matches!(
                        tail,
                        ".claude/.credentials.json"
                            | ".claude.json"
                            | ".codex/auth.json"
                            | ".config/openai/auth.json"
                            | ".gemini/oauth_creds.json"
                            | ".config/opencode/auth.json"
                            | ".local/share/amazon-q/credentials.json"
                    )
                })
                .unwrap_or(false)
                && std::fs::metadata(home)
                    .map(|m| m.uid() == f.proc.uid)
                    .unwrap_or(false)
        });
        let own_auth = own_home
            && f.proc
                .agent_session
                .as_ref()
                .map(|session| {
                    let session_owner = session.root_pid == f.proc.pid;
                    let native_claude_helper = owner == "claude"
                        && f.proc.pid != session.root_pid
                        && f.proc.exe == session.executable
                        && (f.proc.args.starts_with("daemon run --origin transient --spawned-by ")
                            || (f.proc.args.contains("--fork-session")
                                && f.proc.args.contains("--resume ")));
                    let matches_owner = session.agent == owner
                        || (owner == "gemini"
                            && matches!(session.agent.as_str(), "agy" | "antigravity"));
                    (session_owner || native_claude_helper)
                        && matches_owner
                        && crate::agent::invocation(&f.proc.exe, &f.proc.args).as_deref()
                            == Some(session.agent.as_str())
                        && !crate::rules::pkgtree::in_pkg_subtree(ctx.table, id)
                })
                .unwrap_or(false);
        if own_auth {
            // Authentication by the launched agent is context, not a secret
            // sweep by its tools. Keep it recorded without creating cred->net
            // attack chains for every provider API call. This is not a grant.
            f.meta.family = "ai".into();
            f.meta.severity = "low".into();
            f.meta.title = "Agent accessed its own authentication store".into();
            f.meta.why = "The observed agent or its native session helper is authenticating to its own provider. Other tools do not receive this classification.".into();
            f.meta.tier = "signal".into();
            f.what_override = Some("The observed agent or its native session helper accessed its own authentication file.".into());
        }
        f.file = Some(crate::alert::FileRef { path, sha256: None });
        f.hook = h.hook_name();
        f.extra_evidence.push(if own_auth { "reader is the observed agent or a native session helper with the same executable; classification is behavioral, not proof of binary authenticity" } else { "reader is not the owning agent or a native session helper; runtime and ancestor names alone do not exempt it" }.into());
        vec![f]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event::{HookEvent, HookKind, Process},
        proctable::ProcTable,
    };
    #[test]
    fn own_auth_is_context_but_runtime_tools_and_other_accounts_are_detected() {
        let home = tempfile::tempdir().unwrap();
        let homes = vec![home.path().display().to_string()];
        let mut table = ProcTable::new(8, 60);
        let mut add = |id: &str, pid: u32, exe: &str, args: &str, parent: Option<&str>| {
            table.observe(&Process {
                exec_id: Some(id.into()),
                pid: Some(pid),
                uid: Some(unsafe { libc::geteuid() }),
                binary: Some(exe.into()),
                arguments: Some(args.into()),
                parent_exec_id: parent.map(str::to_string),
                cwd: Some(format!("{}/project", homes[0])),
                ..Default::default()
            });
        };
        add("agent", 100, "/opt/claude", "", None);
        add("delegated-codex", 107, "/opt/codex", "exec task", Some("agent"));
        add("codex-root", 120, "/opt/codex", "resume session", None);
        add("codex-exec", 121, "/mise/codex", "exec -C /workspace task", Some("codex-root"));
        add("codex-daemon", 122, "/packages/codex", "app-server --listen unix:// --managed-daemon", Some("codex-root"));
        add("codex-tool", 123, "/usr/bin/node", "/tmp/tool.js", Some("codex-root"));
        add("replaced-agent", 105, "/opt/claude (deleted)", "", None);
        add("replaced-child", 106, "/opt/claude (deleted)", "", Some("agent"));
        add("tool", 101, "/usr/bin/node", "/tmp/tool.js", Some("agent"));
        add("fake-agent-child", 102, "/opt/claude", "", Some("agent"));
        add("daemon", 108, "/opt/claude", "daemon run --origin transient", Some("agent"));
        add("spare", 109, "/opt/claude", "--bg-spare /tmp/cc-daemon-1000/session/spare/worker.claim.sock", Some("daemon"));
        add("forked", 110, "/opt/claude", "--session-id session-b --fork-session --resume /home/dan/session.jsonl", Some("agent"));
        add("pty-host", 111, "/opt/claude", "--bg-pty-host /tmp/pty.sock 200 50 -- /opt/claude --bg-spare /tmp/cc-daemon-1000/worker.claim.sock", Some("daemon"));
        add("daemon-tool", 112, "/usr/bin/node", "/tmp/tool.js", Some("daemon"));
        add(
            "unknown-node",
            103,
            "/usr/bin/node",
            "/tmp/tool.js claude",
            None,
        );
        add(
            "runtime-agent",
            104,
            "/usr/bin/node",
            "/opt/node_modules/@anthropic-ai/claude-code/cli.js",
            None,
        );
        add("native-claude", 113,
            "/home/dan/.local/share/mise/installs/npm-anthropic-ai-claude-code/latest/node_modules/.mise/@anthropic-ai+claude-code@2.1.280/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
            "--resume session", None);
        let native_exe = "/home/dan/.local/share/mise/installs/npm-anthropic-ai-claude-code/latest/node_modules/.mise/@anthropic-ai+claude-code@2.1.280/node_modules/@anthropic-ai/claude-code/bin/claude.exe";
        add("native-daemon", 114, native_exe,
            "daemon run --origin transient --spawned-by {\"label\":\"claude\",\"pid\":113}", Some("native-claude"));
        add("native-fork", 115, native_exe,
            "--session-id child --fork-session --resume /home/dan/session.jsonl", Some("native-claude"));
        let config = Config::default();
        let feeds = crate::feeds::Feeds::default();
        let rarity = crate::rarity::RarityStore::default();
        let ctx = RuleCtx {
            cfg: &config,
            table: &table,
            feeds: &feeds,
            rarity: &rarity,
            homes: &homes,
            now: 100,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
            names: &crate::rules::NO_NAMES,
        };
        let run = |id: &str, suffix: &str| {
            let event = HookEvent {
                function_name: Some("file_post_open".into()),
                policy_name: Some(ID.into()),
                args: vec![
                    serde_json::json!({"file_arg":{"path":format!("{}/{}", homes[0], suffix)}}),
                    serde_json::json!({"int_arg":4}),
                ],
                ..Default::default()
            };
            AiCredentials.on_hook(
                &HookHit {
                    kind: HookKind::Lsm,
                    ev: &event,
                },
                id,
                &ctx,
            )
        };
        for id in ["agent", "runtime-agent", "native-claude", "native-daemon", "native-fork", "replaced-agent", "daemon", "spare", "forked"] {
            let f = run(id, ".claude/.credentials.json");
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].meta.family, "ai");
            assert_eq!(f[0].meta.severity, "low");
        }
        for id in ["codex-root", "codex-exec", "codex-daemon"] {
            let own = run(id, ".codex/auth.json");
            assert_eq!(own[0].meta.family, "ai", "{id}");
            assert_eq!(run(id, ".claude/.credentials.json")[0].meta.family, "cred");
        }
        assert_eq!(run("codex-tool", ".codex/auth.json")[0].meta.family, "cred");
        for id in ["tool", "fake-agent-child", "unknown-node", "replaced-child", "pty-host", "daemon-tool"] {
            let f = run(id, ".claude/.credentials.json");
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].meta.family, "cred", "{id}");
            assert_eq!(f[0].meta.severity, "high", "{id}");
        }
        assert_eq!(run("agent", ".codex/auth.json")[0].meta.family, "cred");
        assert_eq!(run("forked", ".codex/auth.json")[0].meta.family, "cred");
        assert_eq!(run("delegated-codex", ".codex/auth.json")[0].meta.family, "ai");
        assert_eq!(run("delegated-codex", ".claude/.credentials.json")[0].meta.family, "cred");
        assert_eq!(
            run("agent", "backup/.claude/.credentials.json")[0]
                .meta
                .family,
            "cred"
        );
    }
}
