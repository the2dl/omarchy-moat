//! Selector re-validation.
//!
//! The first live run produced an event carrying the SSH-key policy's name and
//! the file `/sys/devices/system/cpu/online`. That policy's selector is an
//! `Equal` list of seven `$HOME/.ssh/id_*` paths: it cannot produce that path.
//! Something in the kernel path — an argument index read from the wrong probe,
//! a stale map, a Tetragon bug — reported a value its own filter should have
//! rejected.
//!
//! An alert is a claim about what happened. Raising
//! `moat-cred-ssh-private-key-read` for a sysfs read would be a false claim, so
//! moatd re-checks every policy event against the policy's own selectors,
//! parsed once at load time from the **rendered** YAML (the one Tetragon
//! actually loaded, `{{HOME}}` already expanded).
//!
//! Scope, deliberately narrow:
//!
//! * `matchArgs` on the indexes the hook declares as a path (`file`, `path`,
//!   `linux_binprm`, `fd`, `dentry`) — `Equal`, `Prefix`, `Postfix`,
//!   `NotEqual`/`NotIn`, `NotPrefix`, `NotPostfix`;
//! * `matchBinaries` — `In`, `NotIn`, `Prefix`, `NotPrefix`, `Postfix`,
//!   `NotPostfix`.
//!
//! Everything else (`Mask`, `Family`, `DPort`, `NotDAddr`, `matchPIDs`,
//! `matchNamespaces`, `matchCapabilities`, …) is **unknown, and unknown
//! passes**. A validator that guesses would suppress real detections; this one
//! only ever rejects a value it can prove the policy excluded.
//!
//! Tetragon semantics we mirror: the entries of `selectors:` are OR'd, the
//! clauses inside one selector are AND'd, and the `values:` of one clause are
//! OR'd.

use serde_yaml::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Equal,
    In,
    Prefix,
    Postfix,
    NotEqual,
    NotIn,
    NotPrefix,
    NotPostfix,
    /// An operator we do not model. Always passes.
    Unknown,
}

impl Op {
    fn parse(s: &str) -> Op {
        match s.to_ascii_lowercase().as_str() {
            "equal" => Op::Equal,
            "in" => Op::In,
            "prefix" => Op::Prefix,
            "postfix" => Op::Postfix,
            "notequal" => Op::NotEqual,
            "notin" => Op::NotIn,
            "notprefix" => Op::NotPrefix,
            "notpostfix" => Op::NotPostfix,
            _ => Op::Unknown,
        }
    }

    fn accepts(&self, values: &[String], v: &str) -> bool {
        match self {
            Op::Equal | Op::In => values.iter().any(|x| x == v),
            Op::NotEqual | Op::NotIn => !values.iter().any(|x| x == v),
            Op::Prefix => values.iter().any(|x| v.starts_with(x.as_str())),
            Op::NotPrefix => !values.iter().any(|x| v.starts_with(x.as_str())),
            Op::Postfix => values.iter().any(|x| v.ends_with(x.as_str())),
            Op::NotPostfix => !values.iter().any(|x| v.ends_with(x.as_str())),
            Op::Unknown => true,
        }
    }
}

/// One `matchArgs`/`matchBinaries` entry we understand.
#[derive(Debug, Clone)]
pub struct Clause {
    /// `matchArgs` or `matchBinaries`, for the evidence line.
    pub kind: &'static str,
    pub index: Option<u64>,
    pub op: Op,
    /// The operator exactly as the YAML spelled it.
    pub op_text: String,
    pub values: Vec<String>,
}

impl Clause {
    /// The evidence text: the selector that failed, in the policy's own words.
    pub fn describe(&self) -> String {
        let shown: Vec<String> = self.values.iter().take(4).map(|v| format!("{:?}", v)).collect();
        let more = self.values.len().saturating_sub(shown.len());
        format!(
            "{}{} operator {:?} values [{}{}]",
            self.kind,
            self.index.map(|i| format!(" index {}", i)).unwrap_or_default(),
            self.op_text,
            shown.join(", "),
            if more > 0 {
                format!(", … {} more", more)
            } else {
                String::new()
            }
        )
    }
}

/// One entry of a hook's `selectors:` list.
#[derive(Debug, Clone, Default)]
pub struct Selector {
    /// `matchArgs` clauses on a path-typed index.
    pub path: Vec<Clause>,
    pub binaries: Vec<Clause>,
}

impl Selector {
    fn is_empty(&self) -> bool {
        self.path.is_empty() && self.binaries.is_empty()
    }

    /// `Ok(())` when every clause we understand accepts the event; otherwise the
    /// first clause that rejected it.
    fn check(&self, path: Option<&str>, binary: &str) -> Result<(), (Clause, String)> {
        if let Some(p) = path.filter(|p| !p.is_empty()) {
            for c in &self.path {
                if !c.op.accepts(&c.values, p) {
                    return Err((c.clone(), p.to_string()));
                }
            }
        }
        if !binary.is_empty() {
            // The kernel tested the RESOLVED binary; we are handed the
            // REPORTED one.
            //
            // `matchBinaries` compares against `d_path(current->mm->exe_file)`
            // -- `/usr/bin/python3.14`. `process.binary` in the event comes
            // from the execve tracepoint's filename, i.e. the path as invoked
            // -- `/usr/bin/python`. So a clause like `NotPostfix "/python3"`
            // does not match in the kernel and DOES match here, and moat
            // reported `moat-x-sensor-mismatch` for a credential read that had
            // really happened: the .npmrc read of 2026-09-05 18:43.
            //
            // Accept if EITHER name passes. Whichever one the kernel actually
            // used, it used one of these two -- and re-validation exists to
            // catch a kernel that matched something it should not have, not to
            // second-guess which spelling of the same file it saw.
            let names = crate::contain::binary_aliases(binary);
            for c in &self.binaries {
                if !names.iter().any(|n| c.op.accepts(&c.values, n)) {
                    return Err((c.clone(), binary.to_string()));
                }
            }
        }
        Ok(())
    }
}

/// The selectors of one hook of one policy.
#[derive(Debug, Clone, Default)]
pub struct HookSelectors {
    /// `file_post_open`, `tcp_connect`, `raw_syscalls/sys_enter`, …
    pub hook: String,
    pub selectors: Vec<Selector>,
}

/// What a re-validation failure knows.
#[derive(Debug, Clone)]
pub struct Mismatch {
    pub policy: String,
    pub hook: String,
    /// The value the kernel reported that the selector rejects.
    pub reported: String,
    pub clause: Clause,
}

impl Mismatch {
    pub fn selector_line(&self) -> String {
        format!(
            "selector that rejects it: {} (in policy {} hook {})",
            self.clause.describe(),
            self.policy,
            self.hook
        )
    }

    pub fn why(&self) -> String {
        format!(
            "Tetragon reported this event under {}, but the value it reported ({}) is one the \
             policy's own in-kernel filter should have rejected: {}. A kernel match that \
             contradicts its own selector is not evidence that the thing the policy describes \
             happened, so no {} alert was raised. The record is kept at low severity because \
             the sensor, not the workload, is what misbehaved — it usually means an argument \
             index is being read from the wrong probe, or a policy was edited while loaded.",
            self.policy,
            self.reported,
            self.clause.describe(),
            self.policy
        )
    }
}

/// Every hook's selectors for one policy.
#[derive(Debug, Clone, Default)]
pub struct SelectorSet {
    pub hooks: Vec<HookSelectors>,
}

/// `spec` keys that hold a list of hooks, and the key naming the hook.
const HOOK_SECTIONS: &[&str] = &["kprobes", "lsmhooks", "tracepoints", "uprobes"];

/// Argument types whose value is a path we can compare a reported file against.
const PATH_TYPES: &[&str] = &["file", "path", "linux_binprm", "fd", "dentry"];

impl SelectorSet {
    /// Parse the selectors out of a rendered TracingPolicy document.
    pub fn parse(doc: &Value) -> SelectorSet {
        let mut set = SelectorSet::default();
        let Some(spec) = doc.get("spec") else {
            return set;
        };
        for section in HOOK_SECTIONS {
            let Some(list) = spec.get(section).and_then(|v| v.as_sequence()) else {
                continue;
            };
            for entry in list {
                set.hooks.push(parse_hook(entry));
            }
        }
        set
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.iter().all(|h| h.selectors.is_empty())
    }

    /// Does the event satisfy the policy's own selectors?
    ///
    /// `hook` is the reported `function_name` (or `subsys/event`); when no hook
    /// of the policy carries that name we check against all of them, because a
    /// name we cannot line up must not become a silent pass *or* a false
    /// mismatch.
    pub fn validate(
        &self,
        policy: &str,
        hook: &str,
        path: Option<&str>,
        binary: &str,
    ) -> Result<(), Box<Mismatch>> {
        let named: Vec<&HookSelectors> = self.hooks.iter().filter(|h| h.hook == hook).collect();
        let candidates: Vec<&HookSelectors> = if named.is_empty() {
            self.hooks.iter().collect()
        } else {
            named
        };
        if candidates.is_empty() {
            return Ok(());
        }

        let mut first_failure: Option<(Clause, String, String)> = None;
        for h in &candidates {
            // A hook with no selectors matches everything, by definition.
            if h.selectors.is_empty() || h.selectors.iter().all(|s| s.is_empty()) {
                return Ok(());
            }
            for s in &h.selectors {
                match s.check(path, binary) {
                    Ok(()) => return Ok(()),
                    Err((clause, reported)) => {
                        if first_failure.is_none() {
                            first_failure = Some((clause, reported, h.hook.clone()));
                        }
                    }
                }
            }
        }
        match first_failure {
            Some((clause, reported, hook_name)) => Err(Box::new(Mismatch {
                policy: policy.to_string(),
                hook: if hook_name.is_empty() {
                    hook.to_string()
                } else {
                    hook_name
                },
                reported,
                clause,
            })),
            None => Ok(()),
        }
    }
}

fn parse_hook(entry: &Value) -> HookSelectors {
    let mut out = HookSelectors {
        hook: hook_name(entry),
        selectors: Vec::new(),
    };
    let path_indexes = path_arg_indexes(entry);
    let Some(selectors) = entry.get("selectors").and_then(|v| v.as_sequence()) else {
        return out;
    };
    for sel in selectors {
        let mut s = Selector::default();
        if let Some(list) = sel.get("matchArgs").and_then(|v| v.as_sequence()) {
            for m in list {
                let index = m.get("index").and_then(|v| v.as_u64());
                // Only indexes the hook itself declares as a path can be
                // compared with the reported file path.
                if !index.map(|i| path_indexes.contains(&i)).unwrap_or(false) {
                    continue;
                }
                if let Some(c) = clause(m, "matchArgs", index) {
                    s.path.push(c);
                }
            }
        }
        if let Some(list) = sel.get("matchBinaries").and_then(|v| v.as_sequence()) {
            for m in list {
                if let Some(c) = clause(m, "matchBinaries", None) {
                    s.binaries.push(c);
                }
            }
        }
        out.selectors.push(s);
    }
    out
}

fn clause(m: &Value, kind: &'static str, index: Option<u64>) -> Option<Clause> {
    let op_text = m.get("operator").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let op = Op::parse(&op_text);
    if op == Op::Unknown {
        return None;
    }
    let values: Vec<String> = m
        .get("values")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if values.is_empty() {
        return None;
    }
    Some(Clause {
        kind,
        index,
        op,
        op_text,
        values,
    })
}

fn hook_name(entry: &Value) -> String {
    for key in ["hook", "call", "path"] {
        if let Some(s) = entry.get(key).and_then(|v| v.as_str()) {
            return s.to_string();
        }
    }
    let sub = entry.get("subsystem").and_then(|v| v.as_str());
    let ev = entry.get("event").and_then(|v| v.as_str());
    match (sub, ev) {
        (Some(s), Some(e)) => format!("{}/{}", s, e),
        (Some(s), None) => s.to_string(),
        _ => String::new(),
    }
}

fn path_arg_indexes(entry: &Value) -> Vec<u64> {
    entry
        .get("args")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter(|a| {
                    a.get("type")
                        .and_then(|t| t.as_str())
                        .map(|t| PATH_TYPES.contains(&t))
                        .unwrap_or(false)
                })
                .filter_map(|a| a.get("index").and_then(|i| i.as_u64()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The real shipped SSH policy, rendered the way Tetragon sees it.
    fn ssh_policy() -> SelectorSet {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("policies/cred-ssh-private-key-read.yaml"))
            .filter(|p| p.is_file())
            .or_else(|| {
                let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("testdata/templates/moat-cred-ssh-private-key-read.yaml");
                p.is_file().then_some(p)
            })
            .expect("the ssh policy template must exist");
        let text = std::fs::read_to_string(&src).unwrap();
        let (name, rendered) =
            crate::render::render_text(&text, &["/home/dan".to_string()], &crate::render::default_lists(), &Default::default()).unwrap();
        assert_eq!(name, "moat-cred-ssh-private-key-read");
        assert!(!rendered.contains("{{HOME}}"));
        let doc: Value = serde_yaml::from_str(&rendered).unwrap();
        SelectorSet::parse(&doc)
    }

    #[test]
    fn the_ssh_policy_accepts_the_paths_it_names() {
        let set = ssh_policy();
        assert!(!set.is_empty());
        assert_eq!(set.hooks.len(), 1);
        assert_eq!(set.hooks[0].hook, "file_post_open");
        for p in [
            "/home/dan/.ssh/id_rsa",
            "/home/dan/.ssh/id_ed25519",
            "/home/dan/.ssh/identity",
        ] {
            assert!(
                set.validate("moat-cred-ssh-private-key-read", "file_post_open", Some(p), "/usr/bin/node")
                    .is_ok(),
                "{} must validate",
                p
            );
        }
    }

    /// The event that started all this.
    #[test]
    fn a_sysfs_path_cannot_come_from_the_ssh_policy() {
        let set = ssh_policy();
        let m = set
            .validate(
                "moat-cred-ssh-private-key-read",
                "file_post_open",
                Some("/sys/devices/system/cpu/online"),
                "/usr/bin/node",
            )
            .expect_err("a sysfs read cannot satisfy an Equal list of ~/.ssh keys");
        assert_eq!(m.reported, "/sys/devices/system/cpu/online");
        assert_eq!(m.clause.kind, "matchArgs");
        assert_eq!(m.clause.op, Op::Equal);
        assert!(m.selector_line().contains("matchArgs index 0"));
        assert!(m.selector_line().contains("/home/dan/.ssh/id_rsa"));
        assert!(m.why().contains("should have rejected"));
    }

    #[test]
    fn a_binary_the_policy_excludes_is_a_mismatch_too() {
        let set = ssh_policy();
        // NotPostfix "/ssh": ssh itself can never be the reported binary.
        let m = set
            .validate(
                "moat-cred-ssh-private-key-read",
                "file_post_open",
                Some("/home/dan/.ssh/id_rsa"),
                "/usr/bin/ssh",
            )
            .expect_err("the policy excludes /usr/bin/ssh by NotPostfix");
        assert_eq!(m.clause.kind, "matchBinaries");
        assert_eq!(m.clause.op, Op::NotPostfix);
        assert_eq!(m.reported, "/usr/bin/ssh");
    }

    #[test]
    fn unknown_operators_and_non_path_indexes_pass() {
        // index 1 is the `int` mask with operator Mask: neither the index nor
        // the operator is something we model, and it must not be compared with
        // the file path.
        let set = ssh_policy();
        let sel = &set.hooks[0].selectors[0];
        assert_eq!(sel.path.len(), 1, "only index 0 (type file) is a path clause");
        assert_eq!(sel.path[0].index, Some(0));

        let doc: Value = serde_yaml::from_str(
            r#"
spec:
  kprobes:
  - call: "tcp_connect"
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPort"
        values: ["4444"]
"#,
        )
        .unwrap();
        let s = SelectorSet::parse(&doc);
        assert!(s.validate("p", "tcp_connect", Some("/anything"), "/usr/bin/nc").is_ok());
    }

    #[test]
    fn a_hook_without_selectors_always_passes() {
        let doc: Value = serde_yaml::from_str(
            r#"
spec:
  lsmhooks:
  - hook: "file_post_open"
    args:
    - index: 0
      type: "file"
"#,
        )
        .unwrap();
        let s = SelectorSet::parse(&doc);
        assert!(s.validate("p", "file_post_open", Some("/etc/shadow"), "/usr/bin/cat").is_ok());
        assert!(s.is_empty());
    }

    #[test]
    fn selectors_are_ored_and_clauses_are_anded() {
        let doc: Value = serde_yaml::from_str(
            r#"
spec:
  lsmhooks:
  - hook: "bprm_check_security"
    args:
    - index: 0
      type: "linux_binprm"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values: ["/tmp/"]
      matchBinaries:
      - operator: "NotIn"
        values: ["/usr/bin/pacman"]
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values: [".sh"]
"#,
        )
        .unwrap();
        let s = SelectorSet::parse(&doc);
        // First selector: prefix ok, binary ok.
        assert!(s.validate("p", "bprm_check_security", Some("/tmp/x"), "/usr/bin/bash").is_ok());
        // First selector fails on the binary, second one saves it on ".sh".
        assert!(s.validate("p", "bprm_check_security", Some("/tmp/x.sh"), "/usr/bin/pacman").is_ok());
        // Neither selector accepts this one.
        let m = s
            .validate("p", "bprm_check_security", Some("/usr/bin/ls"), "/usr/bin/pacman")
            .unwrap_err();
        assert_eq!(m.hook, "bprm_check_security");
    }

    #[test]
    fn an_event_with_no_path_is_never_a_path_mismatch() {
        let set = ssh_policy();
        assert!(set
            .validate("moat-cred-ssh-private-key-read", "file_post_open", None, "/usr/bin/node")
            .is_ok());
        assert!(set
            .validate("moat-cred-ssh-private-key-read", "file_post_open", Some(""), "")
            .is_ok());
    }

    #[test]
    fn every_shipped_policy_validates_its_own_selector_values() {
        // Whatever a policy names in an Equal/Postfix list must, by
        // construction, satisfy that policy. This catches a parser that reads
        // the wrong key far better than a hand-written fixture does.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("policies"));
        let Some(dir) = dir.filter(|d| d.is_dir()) else {
            return;
        };
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = entry.path();
            if p.extension().map(|e| e != "yaml").unwrap_or(true) {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            let Ok((name, rendered)) = crate::render::render_text(&text, &["/home/dan".into()], &crate::render::default_lists(), &Default::default())
            else {
                continue;
            };
            let doc: Value = serde_yaml::from_str(&rendered).unwrap();
            let set = SelectorSet::parse(&doc);
            for h in &set.hooks {
                for s in &h.selectors {
                    for c in &s.path {
                        if matches!(c.op, Op::Equal | Op::In) {
                            for v in &c.values {
                                assert!(
                                    set.validate(&name, &h.hook, Some(v), "").is_ok(),
                                    "{}: {} should accept its own value {}",
                                    name,
                                    h.hook,
                                    v
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
