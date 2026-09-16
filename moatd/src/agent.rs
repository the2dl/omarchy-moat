//! Observed agent lineage. This is attribution, never proof of user approval.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSession {
    /// Sensor exec identity, not a PID, terminal, or caller-supplied environment variable.
    pub id: String,
    pub root_pid: u32,
    pub agent: String,
    pub executable: String,
    pub workspace: String,
}

/// Identify native agents and explicit runtime entrypoints. Generic Node/Bun
/// invocations and arbitrary argv mentions are never agent invocations.
pub fn invocation(exe: &str, args: &str) -> Option<String> {
    // Linux appends this marker when an update unlinks a running binary.
    // Normalize attribution only; this is never an authenticity check.
    let name = crate::util::basename(exe.strip_suffix(" (deleted)").unwrap_or(exe));
    if crate::rules::AI_CLIS.contains(&name) {
        // Bundled search applets are not a new agent session.
        if args
            .split_whitespace()
            .any(|a| matches!(a, "--glob" | "--files-with-matches" | "--line-number"))
        {
            return None;
        }
        return Some(name.to_string());
    }
    if !matches!(name, "node" | "bun") {
        return None;
    }
    let entry = args.split_whitespace().next()?;
    if entry.starts_with('-') {
        return None;
    }
    for (marker, agent) in [
        ("/@anthropic-ai/claude-code/", "claude"),
        ("/@openai/codex/", "codex"),
        ("/@google/gemini-cli/", "gemini"),
    ] {
        if entry.contains(marker) && entry.ends_with(".js") {
            return Some(agent.into());
        }
    }
    None
}

/// Explicit native Claude session/daemon entrypoints own their authentication,
/// even when launched from another Claude session. Bare same-name children and
/// bundled applets remain tools. This is attribution, not binary verification.
pub fn starts_nested_session(exe: &str, args: &str) -> bool {
    if crate::util::basename(exe.strip_suffix(" (deleted)").unwrap_or(exe)) != "claude"
        || invocation(exe, args).as_deref() != Some("claude")
    {
        return false;
    }
    let words: Vec<_> = args.split_whitespace().collect();
    if words.starts_with(&["daemon", "run"]) {
        return true;
    }
    // A prewarmed background worker is itself an agent, not the PTY host
    // that launches it. Do not match flags embedded in the host's arguments.
    if words.len() == 2 && words[0] == "--bg-spare" {
        return words[1].starts_with("/tmp/cc-daemon-")
            && words[1].ends_with(".claim.sock");
    }
    words.contains(&"--fork-session")
        && words.windows(2).any(|w| w[0] == "--session-id" && !w[1].starts_with('-'))
        && words.windows(2).any(|w| w[0] == "--resume" && !w[1].starts_with('-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_session_requires_native_entrypoint_not_embedded_flags() {
        assert!(starts_nested_session("/opt/claude", "daemon run --origin transient"));
        assert!(starts_nested_session("/opt/claude", "--session-id x --fork-session --resume y"));
        for args in ["", "--session-id x", "--fork-session --resume x", "--bg-spare /tmp/tool.sock",
            "--bg-pty-host /tmp/pty.sock 200 50 -- /opt/claude --bg-spare /tmp/cc-daemon-1000/a.claim.sock",
            "--files-with-matches --session-id x --fork-session --resume y"] {
            assert!(!starts_nested_session("/opt/claude", args), "{args}");
        }
        assert!(!starts_nested_session("/usr/bin/node", "daemon run"));
    }
    #[test]
    fn replaced_native_agent_keeps_identity_without_identifying_tools() {
        assert_eq!(invocation("/opt/claude (deleted)", "").as_deref(), Some("claude"));
        assert!(invocation("/opt/claude (deleted)", "--files-with-matches secret").is_none());
        assert!(invocation("/opt/claude (deleted)-fake", "").is_none());
    }
    #[test]
    fn runtime_identity_requires_an_entrypoint_not_an_argv_mention() {
        assert_eq!(
            invocation(
                "/usr/bin/node",
                "/opt/node_modules/@anthropic-ai/claude-code/cli.js -p hi"
            )
            .as_deref(),
            Some("claude")
        );
        assert!(invocation(
            "/usr/bin/node",
            "-e 'require(\"@anthropic-ai/claude-code\")'"
        )
        .is_none());
        assert!(invocation("/usr/bin/node", "/tmp/steal.js claude").is_none());
        assert!(invocation("/opt/claude", "--files-with-matches needle").is_none());
    }
}
