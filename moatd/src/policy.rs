//! Policy annotations.
//!
//! The rendered policy directory is the source of truth for everything the
//! alert needs but the event does not carry: severity, title, why, expected,
//! rotate hints. CONTRACT §3 fixes the annotation keys. Reloaded on SIGHUP.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

const NS: &str = "moat.omarchy/";

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PolicyMeta {
    pub name: String,
    pub family: String,
    pub severity: String,
    pub title: String,
    pub rotate: Vec<String>,
    /// What the policy does in enforce mode: `kill` | `none`.
    pub enforce: String,
    /// What the UI may offer.
    pub actions: Vec<String>,
    pub why: String,
    pub expected: String,
    /// Best ignore scope for a false positive: exe | exe+file | rule | parent.
    pub fp_hint: String,
    /// `spec.options[policy-mode]`, i.e. the mode before `tetra tp set-mode`.
    pub mode_default: String,
}

impl PolicyMeta {
    /// A rule id we know nothing about still has to produce a usable alert.
    pub fn fallback(name: &str) -> PolicyMeta {
        PolicyMeta {
            name: name.to_string(),
            family: family_of(name),
            severity: "medium".into(),
            title: name.to_string(),
            rotate: Vec::new(),
            enforce: "none".into(),
            actions: vec!["ignore".into()],
            why: "This policy is loaded in Tetragon but carries no \
                  moat.omarchy/why annotation, so there is no explanation to show."
                .into(),
            expected: "Unknown: the policy does not declare when it fires legitimately.".into(),
            fp_hint: "exe".into(),
            mode_default: "monitor".into(),
        }
    }
}

/// `moat-cred-ssh-private-key-read` -> `cred`. `moat-x-mass-read` -> `x`.
pub fn family_of(name: &str) -> String {
    let mut it = name.split('-');
    match (it.next(), it.next()) {
        (Some("moat"), Some(f)) => f.to_string(),
        _ => "other".to_string(),
    }
}

#[derive(Debug, Default, Clone)]
pub struct PolicySet {
    pub policies: BTreeMap<String, PolicyMeta>,
    /// Files in the directory that did not parse, by file name.
    pub failed: Vec<String>,
}

impl PolicySet {
    pub fn load(dir: &Path) -> PolicySet {
        let mut set = PolicySet::default();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return set;
        };
        let mut paths: Vec<_> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .map(|e| e == "yaml" || e == "yml")
                    .unwrap_or(false)
            })
            .collect();
        paths.sort();
        for p in paths {
            let file = p
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(parse) {
                Ok(meta) => {
                    set.policies.insert(meta.name.clone(), meta);
                }
                Err(e) => {
                    log::warn!("policy {}: {}", p.display(), e);
                    set.failed.push(file);
                }
            }
        }
        set
    }

    pub fn get(&self, name: &str) -> Option<&PolicyMeta> {
        self.policies.get(name)
    }

    pub fn meta_or_fallback(&self, name: &str) -> PolicyMeta {
        self.get(name)
            .cloned()
            .unwrap_or_else(|| PolicyMeta::fallback(name))
    }

    pub fn names(&self) -> Vec<String> {
        self.policies.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.policies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

fn parse(text: String) -> Result<PolicyMeta, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|e| e.to_string())?;
    let name = doc
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .ok_or("metadata.name missing")?
        .to_string();

    let ann = |key: &str| -> Option<String> {
        doc.get("metadata")?
            .get("annotations")?
            .get(format!("{}{}", NS, key))?
            .as_str()
            .map(|s| s.trim().to_string())
    };

    let mode_default = doc
        .get("spec")
        .and_then(|s| s.get("options"))
        .and_then(|o| o.as_sequence())
        .and_then(|opts| {
            opts.iter().find_map(|o| {
                (o.get("name")?.as_str()? == "policy-mode")
                    .then(|| o.get("value")?.as_str().map(str::to_string))?
            })
        })
        .unwrap_or_else(|| "monitor".into());

    let mut meta = PolicyMeta::fallback(&name);
    meta.mode_default = mode_default;
    if let Some(v) = ann("severity") {
        meta.severity = v;
    }
    if let Some(v) = ann("title") {
        meta.title = v;
    }
    if let Some(v) = ann("rotate") {
        meta.rotate = split_list(&v);
    }
    if let Some(v) = ann("enforce") {
        meta.enforce = v;
    }
    if let Some(v) = ann("actions") {
        meta.actions = split_list(&v);
    }
    if let Some(v) = ann("why") {
        meta.why = squash(&v);
    }
    if let Some(v) = ann("expected") {
        meta.expected = squash(&v);
    }
    if let Some(v) = ann("fp-hint") {
        meta.fp_hint = v;
    }
    if !meta.actions.iter().any(|a| a == "ignore") {
        meta.actions.push("ignore".into());
    }
    Ok(meta)
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// YAML folded scalars keep their newlines; alerts are one-line JSON.
fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotations_map_onto_the_struct() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("p.yaml"),
            r#"apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: moat-cred-ssh-private-key-read
  annotations:
    moat.omarchy/severity: high
    moat.omarchy/title: "Private SSH key read by an unexpected program"
    moat.omarchy/rotate: "ssh-key, github-token"
    moat.omarchy/enforce: "kill"
    moat.omarchy/actions: "kill,quarantine"
    moat.omarchy/why: >-
      Private keys are the first thing
      stealers read.
    moat.omarchy/expected: "Backup tools."
    moat.omarchy/fp-hint: "exe"
spec:
  options:
  - name: policy-mode
    value: monitor
"#,
        )
        .unwrap();
        let set = PolicySet::load(dir.path());
        let m = set.get("moat-cred-ssh-private-key-read").unwrap();
        assert_eq!(m.severity, "high");
        assert_eq!(m.family, "cred");
        assert_eq!(m.rotate, vec!["ssh-key", "github-token"]);
        assert_eq!(m.actions, vec!["kill", "quarantine", "ignore"]);
        assert_eq!(m.why, "Private keys are the first thing stealers read.");
        assert_eq!(m.mode_default, "monitor");
        assert!(set.failed.is_empty());
    }

    #[test]
    fn a_broken_file_is_recorded_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.yaml"), "metadata: [\n").unwrap();
        let set = PolicySet::load(dir.path());
        assert_eq!(set.failed, vec!["bad.yaml"]);
        assert!(set.is_empty());
    }

    #[test]
    fn fallback_is_still_usable() {
        let m = PolicyMeta::fallback("moat-net-reverse-shell");
        assert_eq!(m.family, "net");
        assert_eq!(m.severity, "medium");
        assert!(m.actions.contains(&"ignore".to_string()));
    }

    #[test]
    fn testdata_policies_load() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/policies");
        let set = PolicySet::load(&dir);
        assert!(set.len() >= 3, "testdata policies should load");
        assert!(set.failed.is_empty());
    }
}
