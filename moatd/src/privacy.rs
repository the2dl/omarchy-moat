//! Redact credential-bearing arguments at persistence and presentation boundaries.
//! Detection operates on the original in-memory event; stored evidence must not
//! become another credential store. Raw sensor logs remain root-only.
use serde_json::Value;

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    ["secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key"]
        .iter().any(|part| key.contains(part))
}

fn credential(token: &str) -> bool {
    ["tskey-", "ghp_", "gho_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "sk-ant-", "sk-proj-"]
        .iter().any(|prefix| token.contains(prefix))
}

/// Preserve whitespace and quoting in ordinary commands. Quoted arguments are
/// consumed as a unit, so a password containing spaces cannot be partly leaked.
pub fn text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut next_secret = false;
    let mut finish = |word: &str, out: &mut String| {
        let clean = word.trim_matches(['\'', '"', '`', '[', ']', ',', ';']);
        let assignment = clean.split_once('=');
        let secret_assignment = assignment.map(|(k, _)| sensitive_key(k)).unwrap_or(false)
            || clean.split(',').any(|part| part.split_once('=').map(|(k, _)| sensitive_key(k)).unwrap_or(false));
        if next_secret || secret_assignment || credential(clean) {
            out.push_str("<redacted>");
            next_secret = false;
        } else {
            out.push_str(word);
            next_secret = clean.starts_with('-') && sensitive_key(clean) && !clean.contains('=');
        }
    };
    for (i, ch) in input.char_indices() {
        if escaped { escaped = false; continue; }
        if ch == '\\' { escaped = true; continue; }
        if let Some(q) = quote {
            if ch == q { quote = None; }
        } else if (ch == '\'' || ch == '"') && (i == start || input[..i].ends_with('=')) {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if start < i { finish(&input[start..i], &mut out); }
            out.push(ch);
            start = i + ch.len_utf8();
        }
    }
    if start < input.len() { finish(&input[start..], &mut out); }
    out
}

pub fn value(value: &mut Value) {
    match value {
        Value::String(s) => *s = text(s),
        Value::Array(items) => {
            let mut next_secret = false;
            for item in items {
                if let Some(s) = item.as_str() {
                    if next_secret {
                        *item = Value::String("<redacted>".into());
                        next_secret = false;
                        continue;
                    }
                    next_secret = s.starts_with('-') && sensitive_key(s) && !s.contains('=');
                }
                self::value(item);
            }
        }
        Value::Object(map) => for (_, v) in map { self::value(v); },
        _ => {}
    }
}

pub fn json_line(line: &str) -> String {
    match serde_json::from_str::<Value>(line) {
        Ok(mut v) => { value(&mut v); v.to_string() }
        Err(_) => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_redact_assignments_flags_quotes_and_token_prefixes() {
        for command in [
            "helm upgrade --set-string oauth.clientSecret=fake-secret --wait",
            "tool --password 'fake secret with spaces' --verbose",
            "tool --password=\"fake secret with spaces\" --verbose",
            "tool --set foo=bar,oauth.clientSecret=fake-secret",
            "echo tskey-client-FAKE-TEST-ONLY",
        ] {
            let redacted = text(command);
            assert!(!redacted.contains("fake"), "{redacted}");
            assert!(!redacted.contains("FAKE"), "{redacted}");
            assert!(redacted.contains("<redacted>"));
        }
        assert_eq!(text("helm repo add tailscale https://pkgs.tailscale.com/helmcharts"), "helm repo add tailscale https://pkgs.tailscale.com/helmcharts");
    }
    #[test]
    fn structured_argv_and_nested_evidence_are_redacted() {
        let mut v = serde_json::json!({"cmdline":["helm","--password","fake value"],"tree":"tool oauth.clientSecret=fake-secret"});
        value(&mut v);
        assert!(!v.to_string().contains("fake"));
    }
}
