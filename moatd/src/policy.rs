//! Policy annotations.
//!
//! The rendered policy directory is the source of truth for everything the
//! alert needs but the event does not carry: severity, title, why, expected,
//! rotate hints. CONTRACT §3 fixes the annotation keys. Reloaded on SIGHUP.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::selectors::{Mismatch, SelectorSet};

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
    /// `detection` (the default) or `signal` — BASELINE §4.
    ///
    /// A `signal` rule is a building block: it is right about what it saw and
    /// weak about what it means, and it exists so that `chain.rs` has something
    /// to correlate on. It is recorded, it is a full chain trigger, and it
    /// never reaches the badge on its own. Absent means `detection`, so a
    /// policy that says nothing is a detection — the safe default, since a
    /// missing annotation must never quieten a rule.
    pub tier: String,
}

/// The two values of `moat.omarchy/tier` (BASELINE §4).
pub const TIER_DETECTION: &str = "detection";
pub const TIER_SIGNAL: &str = "signal";

impl PolicyMeta {
    /// Is this rule a building block rather than a conclusion?
    pub fn is_signal(&self) -> bool {
        self.tier == TIER_SIGNAL
    }
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
            tier: TIER_DETECTION.into(),
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
    /// The selectors each policy actually loaded with, for re-validating what
    /// the kernel reports (see `selectors.rs`). Keyed by policy name.
    pub selectors: BTreeMap<String, SelectorSet>,
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
                Ok((meta, selectors)) => {
                    set.selectors.insert(meta.name.clone(), selectors);
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

    /// Re-validate a reported event against the policy's own selectors.
    ///
    /// A policy we never loaded (or one with no selectors we model) passes:
    /// this can only ever *reject* a value the policy provably excludes.
    pub fn validate(
        &self,
        name: &str,
        hook: &str,
        path: Option<&str>,
        binary: &str,
    ) -> Result<(), Box<Mismatch>> {
        match self.selectors.get(name) {
            Some(s) => s.validate(name, hook, path, binary),
            None => Ok(()),
        }
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

fn parse(text: String) -> Result<(PolicyMeta, SelectorSet), String> {
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
    // An unknown value falls back to `detection` rather than failing the file.
    // The value decides whether a rule can reach the badge, so the failure mode
    // of a typo has to be "keeps asking" and never "goes quiet"; `check.py`
    // rejects anything but the two words at build time, which is where a typo
    // should be caught.
    if let Some(v) = ann("tier") {
        match v.as_str() {
            TIER_SIGNAL | TIER_DETECTION => meta.tier = v,
            other => log::warn!(
                "policy {}: moat.omarchy/tier {:?} is not signal|detection; treating it as \
                 detection",
                name,
                other
            ),
        }
    }
    if !meta.actions.iter().any(|a| a == "ignore") {
        meta.actions.push("ignore".into());
    }
    Ok((meta, SelectorSet::parse(&doc)))
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
        assert_eq!(m.tier, TIER_DETECTION, "no annotation means detection");
        assert!(set.failed.is_empty());
    }

    /// BASELINE §4: `signal` is a declaration that a rule is a building block.
    /// A missing annotation, and a misspelt one, both mean `detection` —
    /// silence must never be the failure mode of a typo.
    #[test]
    fn the_tier_annotation_is_read_and_a_typo_stays_a_detection() {
        let dir = tempfile::tempdir().unwrap();
        let policy = |name: &str, tier: &str| {
            format!(
                r#"apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: {}
  annotations:
    moat.omarchy/severity: low
    moat.omarchy/title: "t"
    moat.omarchy/tier: "{}"
spec:
  options:
  - name: policy-mode
    value: monitor
"#,
                name, tier
            )
        };
        std::fs::write(dir.path().join("a.yaml"), policy("moat-net-first-contact", "signal")).unwrap();
        std::fs::write(dir.path().join("b.yaml"), policy("moat-cred-etc-shadow-read", "sginal")).unwrap();
        let set = PolicySet::load(dir.path());
        let signal = set.get("moat-net-first-contact").unwrap();
        assert_eq!(signal.tier, TIER_SIGNAL);
        assert!(signal.is_signal());
        let typo = set.get("moat-cred-etc-shadow-read").unwrap();
        assert_eq!(typo.tier, TIER_DETECTION, "a typo must not quieten a rule");
        assert!(!typo.is_signal());
        assert!(set.failed.is_empty(), "a bad tier is not a broken file");
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
        // A real policy name: `moat-net-reverse-shell` stood here for months
        // and no such policy has ever existed, which made the fixture look like
        // a rule anyone could grep for (2026-09-05).
        let m = PolicyMeta::fallback("moat-net-suspicious-port-egress");
        assert_eq!(m.family, "net");
        assert_eq!(m.severity, "medium");
        assert!(m.actions.contains(&"ignore".to_string()));
    }

    /// The `signal` set is a claim the docs make (BASELINE §4a,
    /// policies/README.md), so it is pinned rather than left to drift.
    ///
    /// It is also not an arbitrary list: it is exactly what the noise guard's
    /// (now removed) rule-wide fan-out demotion had discovered on this machine,
    /// once a day, through a circuit breaker that forgets. Adding a rule here
    /// takes it off the badge for good; that should be a decision somebody
    /// makes on purpose and a test they had to update.
    #[test]
    fn the_shipped_signal_rules_are_the_seven_the_docs_name() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().map(|p| p.join("policies"));
        // Building from a source tarball that ships only moatd/.
        let Some(dir) = dir.filter(|d| d.is_dir()) else { return };
        let set = PolicySet::load(&dir);
        assert!(!set.is_empty(), "no policies loaded from {}", dir.display());
        let mut signal: Vec<&str> = set
            .policies
            .values()
            .filter(|m| m.is_signal())
            .map(|m| m.name.as_str())
            .collect();
        signal.sort_unstable();
        assert_eq!(
            signal,
            vec![
                "moat-exec-untrusted-home",
                "moat-exec-untrusted-tmpfs",
                "moat-net-first-contact",
                "moat-persist-desktop-entry-write",
                "moat-persist-omarchy-menu-extension-write",
                "moat-persist-omarchy-plugin-write",
            ],
            "the seventh, moat-pkg-subtree-interpreter-spawn, is a userland rule"
        );
        // A building block must not be able to end a process on evidence it has
        // declared too weak for the badge. `check.py` says the same at build
        // time; this says it at test time, over the rendered set.
        for m in set.policies.values().filter(|m| m.is_signal()) {
            assert_eq!(m.enforce, "none", "{} is a signal rule and must not enforce", m.name);
        }
    }

    /// The userland half of the same claim.
    #[test]
    fn the_userland_signal_rules_are_the_two_the_docs_name() {
        let mut signal: Vec<String> = crate::rules::all()
            .iter()
            .map(|r| r.meta())
            .filter(|m| m.is_signal())
            .map(|m| m.name)
            .collect();
        signal.sort();
        assert_eq!(
            signal,
            vec!["moat-net-first-contact", "moat-pkg-subtree-interpreter-spawn"],
            "moat-net-first-contact is both a policy and a userland rule, and both halves \
             have to agree or the tier depends on which one fired"
        );
    }

    #[test]
    fn testdata_policies_load() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/policies");
        let set = PolicySet::load(&dir);
        assert!(set.len() >= 3, "testdata policies should load");
        assert!(set.failed.is_empty());
    }

    #[test]
    fn selectors_load_alongside_the_annotations() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/policies");
        let set = PolicySet::load(&dir);
        let ssh = "moat-cred-ssh-private-key-read";
        assert!(set.selectors.contains_key(ssh), "every loaded policy keeps its selectors");
        // The rendered testdata policy names /home/dan's keys.
        assert!(set
            .validate(ssh, "file_post_open", Some("/home/dan/.ssh/id_rsa"), "/usr/bin/node")
            .is_ok());
        assert!(set
            .validate(ssh, "file_post_open", Some("/sys/devices/system/cpu/online"), "/usr/bin/node")
            .is_err());
        // A policy we never loaded cannot be contradicted.
        assert!(set.validate("moat-nope", "x", Some("/anything"), "/bin/sh").is_ok());
    }
}
