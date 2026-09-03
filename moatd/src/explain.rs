//! The `explain` block — the reason this project exists.
//!
//! Every alert answers five questions with no further digging: what happened,
//! why it was flagged, what the concrete evidence was, what to do if it was
//! expected (with the exact command *and* the exact TOML), and what to do if it
//! was not (including which secret to rotate).

use crate::alert::{
    Alert, Ancestor, Explain, ExplainOption, FileRef, IfExpected, IocRef, NetRef, ProcessRef,
    ALERT_V,
};
use crate::allowlist::{render_block, RuleSpec};
use crate::policy::PolicyMeta;
use crate::proctable::ProcInfo;
use crate::util::basename;

/// Everything a detection produced, before it becomes an alert. Policy events
/// and userland `moat-x-*` rules both fill this in.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub meta: PolicyMeta,
    /// `file_post_open`, `tcp_connect`, or `userland` for a `moat-x-*` rule.
    pub hook: String,
    /// Free-form tail of the hook evidence line, e.g. `(read)`.
    pub hook_detail: Option<String>,
    pub exec_id: String,
    pub proc: ProcInfo,
    /// Nearest ancestor first.
    pub ancestry: Vec<ProcInfo>,
    pub ancestry_line: String,
    pub file: Option<FileRef>,
    pub net: Option<NetRef>,
    pub ioc: Option<IocRef>,
    /// Rule-specific evidence appended after the standard four lines.
    pub extra_evidence: Vec<String>,
    /// Overrides the family template for `what`.
    pub what_override: Option<String>,
    pub mode: String,
    /// Set when the policy asked for a kill; only a `process_exit` with
    /// `signal: SIGKILL` turns this into `action_taken: killed`.
    pub kill_expected: bool,
    /// Set by a userland rule that enforces in the daemon rather than in the
    /// kernel (`moat-pkg-subtree-netcat-exec`). The engine kills the process
    /// **only** in `enforce` mode, and only after re-verifying its start time.
    pub request_kill: bool,

    // --- baselining (BASELINE §1, §2, §2b; LEARNING §1) ---------------------
    /// Who acted, once the interpreter rule has been applied.
    pub actor: crate::provenance::Actor,
    pub context: crate::context::Context,
    /// The provenance/context adjustment. `None` means "not scored yet", in
    /// which case the rule's own severity stands.
    pub score: Option<crate::scoring::Score>,
    pub rarity: Option<crate::rarity::RarityInfo>,
    /// The allowlist entry that suppressed this, if any.
    pub suppressed_by: Option<String>,
    /// The noise guard put this rule on the timeline. Not a suppression.
    pub demoted: bool,
    /// Extra `if_expected` options a rule offers beyond the four scopes.
    pub extra_options: Vec<crate::alert::ExplainOption>,
}

impl Finding {
    pub fn new(rule: &str, meta: PolicyMeta, proc: ProcInfo) -> Finding {
        Finding {
            rule: rule.to_string(),
            meta,
            hook: "userland".into(),
            hook_detail: None,
            exec_id: proc.exec_id.clone(),
            proc,
            ancestry: Vec::new(),
            ancestry_line: String::new(),
            file: None,
            net: None,
            ioc: None,
            extra_evidence: Vec::new(),
            what_override: None,
            mode: "monitor".into(),
            kill_expected: false,
            request_kill: false,
            actor: Default::default(),
            context: Default::default(),
            score: None,
            rarity: None,
            suppressed_by: None,
            demoted: false,
            extra_options: Vec::new(),
        }
    }

    /// The severity after scoring, or the rule's own when nothing scored it.
    pub fn severity(&self) -> &str {
        self.score
            .as_ref()
            .map(|s| s.severity.as_str())
            .unwrap_or(self.meta.severity.as_str())
    }

    /// The directory the baseline tuple keys on: the file's, or `""`.
    pub fn file_dir(&self) -> String {
        self.file
            .as_ref()
            .map(|f| crate::rarity::dir_of(&f.path))
            .unwrap_or_default()
    }

    /// The parent the baseline tuple keys on.
    pub fn parent_exe(&self) -> String {
        self.ancestry.first().map(|p| p.exe.clone()).unwrap_or_default()
    }

    /// Dedupe key: same rule + exe + file inside the window is one alert
    /// (CONTRACT §6.3).
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.rule,
            self.proc.exe,
            self.file.as_ref().map(|f| f.path.as_str()).unwrap_or("-")
        )
    }
}

/// Turn a finding into the record readers see.
pub fn build_alert(f: &Finding, id: &str, ts: &str, allowlist_file: &str, allowlist_note: &str) -> Alert {
    let ancestry: Vec<Ancestor> = f
        .ancestry
        .iter()
        .map(|p| Ancestor {
            pid: p.pid,
            exe: p.exe.clone(),
        })
        .collect();

    let explain = Explain {
        what: f
            .what_override
            .clone()
            .unwrap_or_else(|| what_sentence(f)),
        why: f.meta.why.clone(),
        evidence: evidence(f, allowlist_note),
        expected: f.meta.expected.clone(),
        if_expected: if_expected(f, id, allowlist_file),
        next: next_steps(f),
    };

    let score = f
        .score
        .clone()
        .unwrap_or_else(|| crate::scoring::Score::unadjusted(&f.meta.severity));
    let rarity = f.rarity.clone();
    // A demoted rule is not suppressed; it just stops being an Alerts-tab item.
    let surface = if f.demoted { "timeline".to_string() } else { score.surface.clone() };

    Alert {
        v: ALERT_V,
        id: id.to_string(),
        ts: ts.to_string(),
        severity: score.severity.clone(),
        rule: f.rule.clone(),
        family: f.meta.family.clone(),
        title: f.meta.title.clone(),
        summary: summary(f),
        process: ProcessRef {
            pid: f.proc.pid,
            uid: f.proc.uid,
            exe: f.proc.exe.clone(),
            args: f.proc.args.clone(),
            cwd: f.proc.cwd.clone(),
            start_ts: crate::util::normalize_ts(&f.proc.start_time),
            ancestry,
        },
        file: f.file.clone(),
        net: f.net.clone(),
        ioc: f.ioc.clone(),
        rotate: f.meta.rotate.clone(),
        explain,
        action_taken: "none".into(),
        actions: f.meta.actions.clone(),
        acked: false,
        mode: f.mode.clone(),
        count: None,
        actor: f.actor.clone(),
        context: f.context,
        severity_base: score.severity_base.clone(),
        severity_reason: score.severity_reason.clone(),
        surface,
        suppressed_by: f.suppressed_by.clone(),
        rarity: rarity.as_ref().map(|r| r.class).unwrap_or_default(),
        rarity_text: rarity.map(|r| r.text).unwrap_or_default(),
        // The snapshot arrives as an update line once the capture finishes
        // (LEARNING §4): the alert must not wait on a /proc walk.
        incident: None,
        exec_id: f.exec_id.clone(),
    }
}

// ---------------------------------------------------------------- summary/what

fn summary(f: &Finding) -> String {
    let comm = f.proc.comm();
    let mut s = format!("{} (pid {})", comm, f.proc.pid);
    match (&f.file, &f.net) {
        (Some(file), _) => {
            // Use the access word the hook gave us: "read" reads far better
            // than "touched" in a notification.
            let verb = match f.hook_detail.as_deref() {
                Some(d) if d.starts_with("read") => "read",
                Some(d) if d.starts_with("write") || d.starts_with("append") => "wrote to",
                // bprm_check_security carries no access mask: the "file" is the
                // binary being executed, so "touched" reads as nonsense.
                _ if f.hook == "bprm_check_security" => "executed",
                _ => "touched",
            };
            s.push_str(&format!(" {} {}.", verb, file.path));
        }
        (None, Some(net)) => s.push_str(&format!(" connected to {}:{}.", net.dst_ip, net.dst_port)),
        _ => s.push_str(&format!(" matched {}.", f.rule)),
    }
    if !f.ancestry_line.is_empty() {
        s.push_str(&format!(" Parent chain: {}.", f.ancestry_line));
    }
    s
}

/// One plain sentence, chosen by policy family (CONTRACT §3 lists them).
fn what_sentence(f: &Finding) -> String {
    let comm = f.proc.comm();
    let file = f.file.as_ref().map(|x| x.path.as_str());
    let dst = f
        .net
        .as_ref()
        .map(|n| format!("{}:{}", n.dst_ip, n.dst_port));
    match f.meta.family.as_str() {
        "cred" => match file {
            Some(p) => format!("{} read {}.", comm, describe_secret(p)),
            None => format!("{} touched a credential store.", comm),
        },
        // Every shipped `pkg-*` policy hooks bprm_check_security, so the file
        // in the event is the binary being EXECUTED inside the package-manager
        // process tree, not a secret being read. Saying "curl read /usr/bin/curl"
        // was both wrong and useless.
        "pkg" => match (f.hook.as_str(), file) {
            ("bprm_check_security", Some(p)) => format!(
                "A package install started {} ({}).",
                basename(p),
                p
            ),
            ("bprm_check_security", None) => {
                format!("A package install started {}.", comm)
            }
            (_, Some(p)) => format!("{} read {} during a package install.", comm, describe_secret(p)),
            (_, None) => format!("{} did something unusual during a package install.", comm),
        },
        "persist" => match file {
            Some(p) => format!(
                "{} wrote to {}, which runs automatically on your next login.",
                comm, p
            ),
            None => format!("{} installed something that survives a reboot.", comm),
        },
        "shell" => match &dst {
            Some(d) => format!("{} opened a shell-style connection to {}.", comm, d),
            None => format!("{} started a shell in a place a shell should not be.", comm),
        },
        "rootkit" => format!("{} tried to load kernel code or hide itself from the system.", comm),
        "priv" => match file {
            Some(p) => format!("{} tried to raise privileges via {}.", comm, p),
            None => format!("{} tried to raise its privileges ({}).", comm, f.hook),
        },
        "ai" => format!("{} ran an AI coding agent without a human at the terminal.", comm),
        "net" => match &dst {
            Some(d) => format!("{} connected out to {}.", comm, d),
            None => format!("{} made an unexpected network connection.", comm),
        },
        "exec" => match file {
            Some(p) => format!("{} executed a new binary at {}.", comm, p),
            None => format!("{} executed a binary that was not there before.", comm),
        },
        _ => format!("{} matched the rule {}.", comm, f.rule),
    }
}

/// Turn a credential path into words a person recognises.
pub fn describe_secret(path: &str) -> String {
    let base = basename(path);
    let known: &[(&str, &str)] = &[
        ("/.ssh/", "your private SSH key"),
        ("/.aws/", "your AWS credentials"),
        ("/.config/gh/", "your GitHub CLI token"),
        ("/.npmrc", "your npm registry token"),
        ("/.pypirc", "your PyPI upload token"),
        ("/.docker/config.json", "your Docker registry credentials"),
        ("/.kube/", "your Kubernetes cluster credentials"),
        ("/.gnupg/", "your GPG secret keyring"),
        ("/.local/share/keyrings/", "your login keyring"),
        ("/.netrc", "your .netrc credentials"),
        ("/.git-credentials", "your stored git credentials"),
        ("/.claude/", "your Claude CLI credentials"),
        ("/.codex/", "your Codex CLI credentials"),
        ("/.gemini/", "your Gemini CLI credentials"),
        ("/.mozilla/", "your Firefox profile (saved logins and cookies)"),
        ("/.config/google-chrome/", "your Chrome profile (cookies and saved logins)"),
        ("/.config/chromium/", "your Chromium profile (cookies and saved logins)"),
        ("/.config/BraveSoftware/", "your Brave profile (cookies and saved logins)"),
        ("/.password-store/", "your pass password store"),
        ("/.config/op/", "your 1Password CLI session"),
    ];
    for (needle, words) in known {
        if path.contains(needle) {
            return format!("{} ({})", words, base);
        }
    }
    path.to_string()
}

// ------------------------------------------------------------------- evidence

fn evidence(f: &Finding, allowlist_note: &str) -> Vec<String> {
    let mut ev = Vec::new();

    let mut hook_line = format!("hook: {}", f.hook);
    if let Some(file) = &f.file {
        hook_line.push_str(&format!(" on {}", file.path));
    } else if let Some(net) = &f.net {
        hook_line.push_str(&format!(" to {}:{}", net.dst_ip, net.dst_port));
    } else if !f.proc.args.is_empty() && !f.hook.starts_with("userland") {
        hook_line.push_str(&format!(" with args {}", f.proc.args));
    }
    if let Some(d) = &f.hook_detail {
        hook_line.push_str(&format!(" ({})", d));
    }
    ev.push(hook_line);

    ev.push(format!(
        "process: {} pid {} uid {}{}",
        f.proc.exe,
        f.proc.pid,
        f.proc.uid,
        if f.proc.args.is_empty() {
            String::new()
        } else {
            format!(" args {}", f.proc.args)
        }
    ));

    // A binary we had to reconstruct says so, right under the process line:
    // "exe" is a claim, and this is the footnote to it.
    if let Some(note) = &f.proc.exe_note {
        ev.push(note.clone());
    }

    if !f.ancestry_line.is_empty() {
        let cwd = if f.proc.cwd.is_empty() {
            String::new()
        } else {
            format!(" (cwd {})", f.proc.cwd)
        };
        ev.push(format!("ancestry: {}{}", f.ancestry_line, cwd));
    }

    if let Some(ioc) = &f.ioc {
        ev.push(format!("ioc: {} matched {}", ioc.source, ioc.matched));
    }

    // Baselining evidence: who acted, where from, how usual it is, and what
    // that did to the severity (BASELINE §1/§2/§2b, LEARNING §1). Provenance is
    // evidence, never a verdict, so it reads as a fact in this list.
    ev.push(f.actor.evidence());
    ev.push(format!("context: {}", f.context));
    if let Some(r) = &f.rarity {
        ev.push(format!("rarity: {} — {}", r.class, r.text));
    }
    if let Some(s) = &f.score {
        if s.severity != s.severity_base || s.matrix_row.is_some() {
            ev.push(format!(
                "severity: {}{}",
                s.severity_reason,
                s.matrix_row
                    .map(|k| format!(" [matrix row {}]", k))
                    .unwrap_or_default()
            ));
        }
    }
    if f.demoted {
        ev.push(format!(
            "noise guard: {} is demoted, so this is a timeline entry rather than an alert; \
             `moatctl baseline undemote {}` starts watching it again",
            f.rule, f.rule
        ));
    }

    ev.extend(f.extra_evidence.iter().cloned());
    match &f.suppressed_by {
        Some(by) => ev.push(format!(
            "suppressed by allowlist entry {}: recorded for the timeline, not notified and not \
             counted",
            by
        )),
        None => ev.push(allowlist_note.to_string()),
    }
    ev
}

/// The line explaining why the allowlist did not save this event.
pub fn allowlist_note(dir: &str, rules: usize, exe: &str, file: Option<&str>) -> String {
    let what = match file {
        Some(p) => format!("exe={} file={}", exe, p),
        None => format!("exe={}", exe),
    };
    format!(
        "not in allowlist: none of the {} rule(s) in {} matches {}",
        rules, dir, what
    )
}

// ---------------------------------------------------------------- if_expected

fn if_expected(f: &Finding, id: &str, allowlist_file: &str) -> IfExpected {
    let mut options: Vec<ExplainOption> = Vec::new();
    let mut push = |scope: &str, spec: RuleSpec| {
        options.push(ExplainOption {
            scope: scope.to_string(),
            cmd: format!("moatctl ignore {} --scope {}", id, scope),
            line: render_block(&spec),
        });
    };

    push(
        "exe",
        RuleSpec {
            name: f.rule.clone(),
            exe: Some(f.proc.exe.clone()),
            ..Default::default()
        },
    );
    if let Some(file) = &f.file {
        push(
            "exe+file",
            RuleSpec {
                name: f.rule.clone(),
                exe: Some(f.proc.exe.clone()),
                file: Some(file.path.clone()),
                ..Default::default()
            },
        );
    }
    if let Some(parent) = f.ancestry.first() {
        push(
            "parent",
            RuleSpec {
                name: f.rule.clone(),
                parent: Some(parent.exe.clone()),
                ..Default::default()
            },
        );
    }
    push(
        "rule",
        RuleSpec {
            name: f.rule.clone(),
            ..Default::default()
        },
    );

    // Recommended scope first; the plugin renders them in order.
    let hint = f.meta.fp_hint.clone();
    options.sort_by_key(|o| (o.scope != hint) as u8);
    // Rule-specific options (the noise guard's "these are expected" / "keep
    // watching") go last, after the four scopes.
    options.extend(f.extra_options.iter().cloned());

    IfExpected {
        hint,
        options,
        file: allowlist_file.to_string(),
    }
}

/// Available ignore scopes for a finding, in the same order `if_expected` uses.
pub fn scope_spec(f: &Finding, scope: &str) -> Result<RuleSpec, String> {
    match scope {
        "exe" => Ok(RuleSpec {
            name: f.rule.clone(),
            exe: Some(f.proc.exe.clone()),
            ..Default::default()
        }),
        "exe+file" => match &f.file {
            Some(file) => Ok(RuleSpec {
                name: f.rule.clone(),
                exe: Some(f.proc.exe.clone()),
                file: Some(file.path.clone()),
                ..Default::default()
            }),
            None => Err("this alert has no file, so scope exe+file does not apply".into()),
        },
        "parent" => match f.ancestry.first() {
            Some(p) => Ok(RuleSpec {
                name: f.rule.clone(),
                parent: Some(p.exe.clone()),
                ..Default::default()
            }),
            None => Err("this alert has no recorded parent, so scope parent does not apply".into()),
        },
        "rule" => Ok(RuleSpec {
            name: f.rule.clone(),
            ..Default::default()
        }),
        other => Err(format!(
            "unknown scope {:?}; use exe, exe+file, parent or rule",
            other
        )),
    }
}

/// Same thing, from a stored alert (the socket only has the alert, not the
/// finding that produced it).
pub fn scope_spec_from_alert(a: &Alert, scope: &str) -> Result<RuleSpec, String> {
    match scope {
        "exe" => Ok(RuleSpec {
            name: a.rule.clone(),
            exe: Some(a.process.exe.clone()),
            ..Default::default()
        }),
        "exe+file" => match &a.file {
            Some(f) => Ok(RuleSpec {
                name: a.rule.clone(),
                exe: Some(a.process.exe.clone()),
                file: Some(f.path.clone()),
                ..Default::default()
            }),
            None => Err("this alert has no file, so scope exe+file does not apply".into()),
        },
        "parent" => match a.process.ancestry.first() {
            Some(p) => Ok(RuleSpec {
                name: a.rule.clone(),
                parent: Some(p.exe.clone()),
                ..Default::default()
            }),
            None => Err("this alert has no recorded parent, so scope parent does not apply".into()),
        },
        "rule" => Ok(RuleSpec {
            name: a.rule.clone(),
            ..Default::default()
        }),
        other => Err(format!(
            "unknown scope {:?}; use exe, exe+file, parent or rule",
            other
        )),
    }
}

// --------------------------------------------------------------------- next

/// Rotation guidance, keyed by the policy's `moat.omarchy/rotate` values.
///
/// The authoritative vocabulary is whatever `policies/*.yaml` actually annotate
/// (CONTRACT §3 fixes the key, not the values). Every kind used by a shipped
/// policy MUST have an entry here — a rotate hint with no guidance tells a user
/// a secret leaked and then stops. `policies_rotate_vocabulary_is_covered`
/// below reads the real policy directory and fails if one is missing. The
/// shorter aliases (`aws`, `gh`, `gpg`, …) are kept so a hand-written policy or
/// an older rendered copy still resolves.
pub fn rotate_advice(kind: &str) -> Option<&'static str> {
    Some(match kind {
        // --- shipped policy vocabulary ---------------------------------------
        "ssh-key" => "Rotate the SSH key: `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519`, then replace the public key on GitHub (`gh ssh-key add`), on every host in ~/.ssh/config, and in any cloud console that pinned it.",
        "github-token" | "gh" => "Revoke the token at https://github.com/settings/tokens (or `gh auth logout && gh auth login`), issue a new one, and grep ~/.git-credentials, ~/.netrc and your shell rc files for copies.",
        "git-credentials" => "Treat every line of ~/.git-credentials as public: each one is a forge password or token in cleartext. Rotate them at their forges and switch to a credential helper that does not store plaintext.",
        "npm-token" => "Run `npm token list` then `npm token revoke <id>`, and delete the `_authToken` line from ~/.npmrc. If the token could publish, check your packages' recent versions.",
        "pypi-token" => "Revoke the token at https://pypi.org/manage/account/token/, issue a replacement, and update ~/.pypirc and any CI secret that held it.",
        "cargo-token" => "Revoke the token at https://crates.io/settings/tokens, then `cargo login` with a fresh one; the old value is in ~/.cargo/credentials.toml.",
        "docker-token" | "docker" => "Run `docker logout <registry>` for every entry in ~/.docker/config.json and rotate the registry password or personal access token.",
        "aws-key" | "aws" => "Run `aws iam create-access-key`, update ~/.aws/credentials, then `aws iam delete-access-key --access-key-id <old>`. Check CloudTrail for use you did not make.",
        "gcp-token" => "Run `gcloud auth revoke --all`, delete ~/.config/gcloud/application_default_credentials.json, and rotate any service-account key the file named in the Google Cloud console.",
        "azure-token" => "Run `az logout` and `az account clear` (this drops ~/.azure/msal_token_cache.json), then sign in again and revoke any service-principal secret that was cached.",
        "kubeconfig" | "kube" => "Rotate the cluster credential in ~/.kube/config (client cert, token, or exec-plugin credential) and check every path in $KUBECONFIG.",
        "gpg-key" | "gpg" | "gnupg" => "Generate and publish a revocation (`gpg --gen-revoke <keyid>`) and move to a new subkey. A passphrase only slows an offline crack of an exfiltrated secret key.",
        "keyring" => "Change the login keyring password and every secret stored in it (~/.local/share/keyrings): browser logins, Seahorse entries, and anything libsecret held.",
        "browser-passwords" => "Change every password saved in that browser profile, starting with any you reused. The profile's login database is decryptable with the keyring the same process could reach.",
        "browser-cookies" | "session-cookies" | "browser" => "Sign out of every session (\"sign out everywhere\" in each account's security page), then clear cookies. A stolen cookie jar bypasses both your password and 2FA.",
        "local-password" => "/etc/shadow was read: the hashes for every local account are offline-crackable now. Change every local password (`passwd`), and treat any that was reused elsewhere as public.",
        "anthropic-token" | "claude" => "Run `claude /logout` and log in again; if an API key was in ~/.claude/.credentials.json or ANTHROPIC_API_KEY, revoke it at console.anthropic.com/settings/keys.",
        "openai-token" | "openai" | "codex" => "Revoke the key at https://platform.openai.com/api-keys, issue a replacement, and clear OPENAI_API_KEY out of ~/.codex and your shell rc files.",
        "google-token" | "gemini" => "Revoke the key at https://aistudio.google.com/apikey and sign the Gemini CLI out (`gemini auth logout`); ~/.gemini may still hold the cached credential.",
        _ => return None,
    })
}

fn next_steps(f: &Finding) -> Vec<String> {
    let mut next = Vec::new();

    if f.meta.actions.iter().any(|a| a == "kill") {
        next.push(
            "If you did not expect this: stop it now with `moatctl kill <id>` (kills the recorded process tree), and `moatctl quarantine <id>` to move the file out of reach."
                .to_string(),
        );
    } else {
        next.push(
            "If you did not expect this: find the process with `ps -fp <pid>` and stop it before it finishes."
                .to_string(),
        );
    }

    for kind in &f.meta.rotate {
        if let Some(advice) = rotate_advice(kind) {
            next.push(advice.to_string());
        } else {
            next.push(format!(
                "Rotate the `{}` secret this rule covers; treat it as public from the moment of this alert.",
                kind
            ));
        }
    }

    let pkg = ["npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "cargo", "makepkg", "pacman"];
    if f.ancestry.iter().any(|p| pkg.contains(&p.comm())) || pkg.contains(&f.proc.comm()) {
        next.push(
            "Check what was installed: diff the lockfile (`git diff -- package-lock.json pnpm-lock.yaml uv.lock Cargo.lock`) and read the new package's install/postinstall script before you run anything else."
                .to_string(),
        );
    }

    if let Some(file) = &f.file {
        if crate::util::under_any(&file.path, &["/tmp".into(), "/var/tmp".into(), "/dev/shm".into()]) {
            next.push(
                "Inspect the dropped file before deleting it: `file <path>`, `strings -n 8 <path> | head`, and look its sha256 up before you lose the evidence."
                    .to_string(),
            );
        }
    }

    if let Some(net) = &f.net {
        next.push(format!(
            "Look the destination up ({}) and, if it is not yours, block it and check for other processes talking to it (`ss -tanp | grep {}`).",
            net.dst_ip, net.dst_ip
        ));
    }

    next.push(
        "If this was you, run one of the ignore commands above; otherwise `moatctl ack <id>` once you have finished checking."
            .to_string(),
    );
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc() -> ProcInfo {
        ProcInfo {
            exec_id: "e1".into(),
            pid: 41233,
            uid: 1000,
            exe: "/home/dan/.local/share/mise/installs/node/26.5.0/bin/node".into(),
            args: "/home/dan/proj/node_modules/evil/setup.mjs".into(),
            cwd: "/home/dan/proj".into(),
            start_time: "2026-09-03T16:21:06.900123456Z".into(),
            parent_exec_id: Some("e0".into()),
            exited_at: None,
            exit_signal: None,
            exe_note: None,
        }
    }

    fn finding() -> Finding {
        let mut meta = PolicyMeta::fallback("moat-cred-ssh-private-key-read");
        meta.severity = "high".into();
        meta.title = "Private SSH key read by an unexpected program".into();
        meta.why = "Private keys are the first thing stealers read.".into();
        meta.expected = "Backup tools and IDE git integrations.".into();
        meta.rotate = vec!["ssh-key".into()];
        meta.actions = vec!["kill".into(), "quarantine".into(), "ignore".into()];
        meta.fp_hint = "exe+file".into();

        let mut f = Finding::new("moat-cred-ssh-private-key-read", meta, proc());
        f.hook = "file_post_open".into();
        f.hook_detail = Some("read".into());
        f.file = Some(FileRef {
            path: "/home/dan/.ssh/id_ed25519".into(),
            sha256: None,
        });
        f.ancestry = vec![ProcInfo {
            exec_id: "e0".into(),
            pid: 41230,
            uid: 1000,
            exe: "/usr/bin/sh".into(),
            args: String::new(),
            cwd: "/home/dan/proj".into(),
            start_time: String::new(),
            parent_exec_id: Some("e-1".into()),
            exited_at: None,
            exit_signal: None,
            exe_note: None,
        }, ProcInfo {
            exec_id: "e-1".into(),
            pid: 41201,
            uid: 1000,
            exe: "/usr/bin/npm".into(),
            args: "install".into(),
            cwd: "/home/dan/proj".into(),
            start_time: String::new(),
            parent_exec_id: None,
            exited_at: None,
            exit_signal: None,
            exe_note: None,
        }];
        f.ancestry_line = "npm -> sh -> node".into();
        f
    }

    fn alert() -> Alert {
        build_alert(
            &finding(),
            "01J8ZK6B4Q3M7N9P2R5S8T1V4W",
            "2026-09-03T16:21:07.123Z",
            "/etc/moat/allowlist.d/user.toml",
            &allowlist_note(
                "/etc/moat/allowlist.d",
                3,
                "/usr/bin/node",
                Some("/home/dan/.ssh/id_ed25519"),
            ),
        )
    }

    #[test]
    fn summary_uses_the_access_word() {
        let a = alert();
        assert!(
            a.summary.starts_with("node (pid 41233) read /home/dan/.ssh/id_ed25519."),
            "{}",
            a.summary
        );
        assert!(a.summary.contains("Parent chain: npm -> sh -> node."));
    }

    #[test]
    fn what_is_one_plain_sentence() {
        let a = alert();
        assert_eq!(
            a.explain.what,
            "node read your private SSH key (id_ed25519)."
        );
        assert!(a.explain.what.matches('.').count() <= 2);
    }

    #[test]
    fn evidence_has_hook_process_ancestry_and_allowlist() {
        let a = alert();
        assert!(a.explain.evidence[0].starts_with("hook: file_post_open on /home/dan/.ssh/id_ed25519 (read)"));
        assert!(a.explain.evidence[1].starts_with("process: /home/dan/.local/share/mise"));
        assert!(a.explain.evidence[2].starts_with("ancestry: npm -> sh -> node (cwd /home/dan/proj)"));
        assert!(a.explain.evidence.last().unwrap().starts_with("not in allowlist:"));
    }

    #[test]
    fn every_scope_carries_a_command_and_a_toml_block() {
        let a = alert();
        let scopes: Vec<&str> = a
            .explain
            .if_expected
            .options
            .iter()
            .map(|o| o.scope.as_str())
            .collect();
        assert_eq!(scopes, vec!["exe+file", "exe", "parent", "rule"], "hint first");
        for o in &a.explain.if_expected.options {
            assert_eq!(
                o.cmd,
                format!("moatctl ignore 01J8ZK6B4Q3M7N9P2R5S8T1V4W --scope {}", o.scope)
            );
            assert!(o.line.starts_with("[[rule]]\n"));
            assert!(o.line.contains("name = \"moat-cred-ssh-private-key-read\""));
            // The block must be valid TOML that our own loader accepts.
            crate::allowlist::Allowlist::parse(&o.line, std::path::Path::new("x")).unwrap();
        }
        assert!(a.explain.if_expected.options[0].line.contains("file = \"/home/dan/.ssh/id_ed25519\""));
    }

    #[test]
    fn next_includes_rotation_and_package_context() {
        let a = alert();
        let joined = a.explain.next.join("\n");
        assert!(joined.contains("moatctl kill"));
        assert!(joined.contains("ssh-keygen -t ed25519"));
        assert!(joined.contains("lockfile"), "npm in the ancestry adds this");
        assert!(joined.contains("moatctl ack"));
    }

    #[test]
    fn rotate_table_covers_the_contract_kinds() {
        for kind in [
            "ssh-key",
            "github-token",
            "npm-token",
            "aws",
            "gh",
            "claude",
            "gpg",
            "keyring",
            "browser",
            "docker",
            "kube",
        ] {
            assert!(rotate_advice(kind).is_some(), "missing advice for {}", kind);
        }
        assert!(rotate_advice("nonesuch").is_none());
    }

    /// The shipped policies are the real vocabulary. If a policies-agent change
    /// introduces a new `moat.omarchy/rotate` value, this fails until the
    /// table above learns it — the seam that was actually broken at
    /// integration time (16 of the 20 values had no guidance).
    #[test]
    fn policies_rotate_vocabulary_is_covered() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("policies"));
        let Some(dir) = dir.filter(|d| d.is_dir()) else {
            // Building from a source tarball that ships only moatd/.
            return;
        };
        let set = crate::policy::PolicySet::load(&dir);
        assert!(!set.is_empty(), "no policies loaded from {}", dir.display());
        let mut missing: Vec<String> = Vec::new();
        for meta in set.policies.values() {
            for kind in &meta.rotate {
                if rotate_advice(kind).is_none() {
                    missing.push(format!("{} ({})", kind, meta.name));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "rotate kinds used by policies/ with no rotate_advice(): {}",
            missing.join(", ")
        );
    }

    /// CONTRACT §3 lists nine families; `what_sentence` must have a template
    /// for every one of them plus every family the shipped policies and the
    /// userland rules actually use, or the alert falls back to "node matched
    /// the rule moat-…", which explains nothing.
    ///
    /// The nine are asserted from the contract rather than counted from
    /// `policies/`, because a family can move from a kernel policy to a
    /// userland rule (`pkg` and `ai` did exactly that) without the alert text
    /// for it becoming any less necessary.
    #[test]
    fn every_shipped_family_has_a_what_template() {
        let mut families: Vec<String> = [
            "cred", "pkg", "persist", "shell", "rootkit", "priv", "ai", "net", "exec",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        for r in crate::rules::all() {
            families.push(r.meta().family);
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("policies"));
        if let Some(dir) = dir.filter(|d| d.is_dir()) {
            let set = crate::policy::PolicySet::load(&dir);
            assert!(!set.is_empty(), "no policies loaded from {}", dir.display());
            families.extend(set.policies.values().map(|m| m.family.clone()));
        }
        families.sort();
        families.dedup();
        // "x" is the userland namespace: those rules all set `what_override`.
        families.retain(|f| f != "x");
        assert!(families.len() >= 9, "expected all nine families, got {:?}", families);
        for family in families {
            let mut f = finding();
            f.meta.family = family.clone();
            let what = what_sentence(&f);
            assert!(
                !what.contains("matched the rule"),
                "family {:?} has no what template (got {:?})",
                family,
                what
            );
        }
    }

    #[test]
    fn a_pkg_exec_reads_as_an_exec_not_a_secret_read() {
        let mut f = finding();
        f.meta.family = "pkg".into();
        f.hook = "bprm_check_security".into();
        f.hook_detail = None;
        f.file = Some(FileRef {
            path: "/usr/bin/curl".into(),
            sha256: None,
        });
        let a = build_alert(&f, "01X", "t", "/x/user.toml", "not in allowlist: -");
        assert_eq!(a.explain.what, "A package install started curl (/usr/bin/curl).");
        assert!(a.summary.contains("executed /usr/bin/curl."), "{}", a.summary);
    }

    #[test]
    fn scope_spec_matches_the_option_it_advertises() {
        let f = finding();
        let a = alert();
        for o in &a.explain.if_expected.options {
            let spec = scope_spec(&f, &o.scope).unwrap();
            assert_eq!(render_block(&spec), o.line);
            let from_alert = scope_spec_from_alert(&a, &o.scope).unwrap();
            assert_eq!(from_alert, spec, "socket path must agree with the alert");
        }
        assert!(scope_spec(&f, "bogus").is_err());
    }

    #[test]
    fn a_netless_alert_has_no_exe_file_scope() {
        let mut f = finding();
        f.file = None;
        f.meta.family = "net".into();
        f.net = Some(NetRef {
            dst_ip: "185.220.101.55".into(),
            dst_port: 4444,
            domain: None,
        });
        let a = build_alert(&f, "01X", "t", "/x/user.toml", "not in allowlist: -");
        let scopes: Vec<&str> = a
            .explain
            .if_expected
            .options
            .iter()
            .map(|o| o.scope.as_str())
            .collect();
        assert!(!scopes.contains(&"exe+file"));
        assert!(a.explain.what.contains("185.220.101.55:4444"));
        assert!(a.explain.next.iter().any(|n| n.contains("ss -tanp")));
    }

    #[test]
    fn dedupe_key_folds_rule_exe_file() {
        let a = finding();
        let mut b = finding();
        assert_eq!(a.dedupe_key(), b.dedupe_key());
        b.file = Some(FileRef {
            path: "/home/dan/.ssh/id_rsa".into(),
            sha256: None,
        });
        assert_ne!(a.dedupe_key(), b.dedupe_key());
    }
}
