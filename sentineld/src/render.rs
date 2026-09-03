//! `sentineld render-policies`.
//!
//! Tetragon has no middle wildcard on path arguments (NOTES §3, gap 2), so the
//! policies in `policies/` are templates carrying `{{HOME}}`. This turns them
//! into real policies, one value per human home, and regenerates the
//! `export-allowlist` conf.d fragment with the exact policy names — Tetragon's
//! `policy_names` filter is exact-match only (NOTES §8, gap 8).
//!
//! Expansion happens on the *parsed* YAML, never on the text, so a home
//! containing a quote or a colon cannot break the document:
//!
//! * a sequence item that contains `{{HOME}}` becomes N items, one per home
//!   (this is the `values:` case the templates are written for);
//! * any other scalar containing `{{HOME}}` is substituted with the first home
//!   and a warning is logged — there is no way to fan a scalar out.
//!
//! Writes are atomic and idempotent: an unchanged file is not rewritten, so
//! running this as tetragon.service's `ExecStartPre` on every boot does not
//! churn mtimes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_yaml::Value;

use crate::util::{atomic_write, human_homes};

pub const PLACEHOLDER: &str = "{{HOME}}";

/// The two export-allowlist lines, matching `policies/export-allowlist.example`.
///
/// Line 1 keeps exec/exit — they carry no `policy_name`, so there is no other
/// way to select them, and without them there is no ancestry. Line 2 restricts
/// the hook events to exactly the policies we rendered; `policy_names` is
/// exact-match with no globs (NOTES §8, gap 8), which is why this file is
/// regenerated on every render. NOTES §8 also offers a CEL `startsWith`
/// variant, but that is UNVERIFIED live and exact names cost nothing.
fn allowlist_body(names: &BTreeSet<String>) -> String {
    let list = names
        .iter()
        .map(|n| serde_json::to_string(n).unwrap_or_else(|_| format!("\"{}\"", n)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"event_set\":[\"PROCESS_EXEC\",\"PROCESS_EXIT\"]}}\n\
         {{\"event_set\":[\"PROCESS_KPROBE\",\"PROCESS_LSM\",\"PROCESS_TRACEPOINT\",\"PROCESS_UPROBE\"],\"policy_names\":[{}]}}\n",
        list
    )
}

#[derive(Debug, Default)]
pub struct RenderReport {
    /// `metadata.name` of every policy written.
    pub rendered: Vec<String>,
    /// Template stem -> reason, for templates that could not be rendered.
    pub failed: Vec<(String, String)>,
    pub files_changed: usize,
    pub removed: Vec<PathBuf>,
    pub allowlist_changed: bool,
}

impl RenderReport {
    pub fn failed_names(&self) -> Vec<String> {
        self.failed.iter().map(|(n, _)| n.clone()).collect()
    }
}

pub struct RenderOptions<'a> {
    pub templates_dir: &'a Path,
    pub out_dir: &'a Path,
    pub export_allowlist: Option<&'a Path>,
    pub passwd: &'a Path,
    /// Overrides `passwd` discovery; used by tests and by `--home`.
    pub homes: Option<Vec<String>>,
}

pub fn render(opts: &RenderOptions) -> Result<RenderReport, String> {
    let homes = match &opts.homes {
        Some(h) => h.clone(),
        None => human_homes(opts.passwd),
    };
    let mut report = RenderReport::default();

    let mut templates: Vec<PathBuf> = std::fs::read_dir(opts.templates_dir)
        .map_err(|e| format!("{}: {}", opts.templates_dir.display(), e))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|e| e == "yaml" || e == "yml")
                .unwrap_or(false)
        })
        .collect();
    templates.sort();

    std::fs::create_dir_all(opts.out_dir).map_err(|e| format!("{}: {}", opts.out_dir.display(), e))?;

    let mut produced: BTreeSet<PathBuf> = BTreeSet::new();
    let mut names: BTreeSet<String> = BTreeSet::new();

    for tpl in &templates {
        let stem = tpl
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        match render_one(tpl, &homes) {
            Ok((name, body)) => {
                let out = opts.out_dir.join(&stem);
                match atomic_write(&out, body.as_bytes(), 0o644) {
                    Ok(changed) => {
                        if changed {
                            report.files_changed += 1;
                        }
                        produced.insert(out);
                        names.insert(name.clone());
                        report.rendered.push(name);
                    }
                    Err(e) => report.failed.push((stem, format!("write: {}", e))),
                }
            }
            Err(e) => report.failed.push((stem, e)),
        }
    }

    // Drop policies from a previous render that no longer have a template, so
    // Tetragon does not load a stale file on the next start.
    if let Ok(rd) = std::fs::read_dir(opts.out_dir) {
        for e in rd.flatten() {
            let p = e.path();
            let is_yaml = p
                .extension()
                .map(|x| x == "yaml" || x == "yml")
                .unwrap_or(false);
            if is_yaml && !produced.contains(&p) && std::fs::remove_file(&p).is_ok() {
                report.removed.push(p);
            }
        }
    }

    if let Some(path) = opts.export_allowlist {
        report.allowlist_changed = atomic_write(path, allowlist_body(&names).as_bytes(), 0o644)
            .map_err(|e| format!("{}: {}", path.display(), e))?;
    }

    Ok(report)
}

/// Render one template. Returns `(policy name, YAML text)`.
pub fn render_one(path: &Path, homes: &[String]) -> Result<(String, String), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    render_text(&text, homes)
}

pub fn render_text(text: &str, homes: &[String]) -> Result<(String, String), String> {
    if text.contains(PLACEHOLDER) && homes.is_empty() {
        return Err("template uses {{HOME}} but no human user was found in /etc/passwd".into());
    }
    let mut doc: Value = serde_yaml::from_str(text).map_err(|e| format!("yaml: {}", e))?;
    expand(&mut doc, homes);

    let name = doc
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| "metadata.name missing".to_string())?
        .to_string();
    if !name.starts_with("sentinel-") {
        return Err(format!(
            "policy name {:?} does not start with `sentinel-`; it would never be alerted on",
            name
        ));
    }
    let body = serde_yaml::to_string(&doc).map_err(|e| e.to_string())?;
    if body.contains(PLACEHOLDER) {
        return Err("placeholder survived expansion".into());
    }
    Ok((name, format!("{}{}", HEADER, body)))
}

const HEADER: &str = "# rendered by `sentineld render-policies` — edit the template, not this file\n";

/// Recursive `{{HOME}}` expansion on the parsed document.
fn expand(v: &mut Value, homes: &[String]) {
    match v {
        Value::Sequence(seq) => {
            let mut out: Vec<Value> = Vec::with_capacity(seq.len());
            for item in seq.drain(..) {
                match item {
                    Value::String(s) if s.contains(PLACEHOLDER) => {
                        for h in homes {
                            let candidate = Value::String(s.replace(PLACEHOLDER, h));
                            if !out.contains(&candidate) {
                                out.push(candidate);
                            }
                        }
                    }
                    mut other => {
                        expand(&mut other, homes);
                        out.push(other);
                    }
                }
            }
            *seq = out;
        }
        Value::Mapping(map) => {
            let keys: Vec<Value> = map.keys().cloned().collect();
            for k in keys {
                if let Some(val) = map.get_mut(&k) {
                    expand(val, homes);
                }
            }
        }
        Value::String(s) if s.contains(PLACEHOLDER) => {
            // Not in a sequence: nothing to fan out into. Use the first home.
            let first = homes.first().cloned().unwrap_or_default();
            if homes.len() > 1 {
                log::warn!(
                    "{{{{HOME}}}} in a scalar ({:?}) cannot fan out; using {}",
                    s,
                    first
                );
            }
            *s = s.replace(PLACEHOLDER, &first);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TPL: &str = r#"apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sentinel-cred-ssh-private-key-read
  annotations:
    sentinel.omarchy/severity: high
    sentinel.omarchy/title: "Private SSH key read by an unexpected program"
    sentinel.omarchy/why: "Keys are the first thing stealers read."
    sentinel.omarchy/expected: "Backup tools and IDE git integrations."
    sentinel.omarchy/fp-hint: exe
spec:
  options:
    - name: policy-mode
      value: monitor
  lsmhooks:
  - hook: "file_post_open"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "{{HOME}}/.ssh/"
"#;

    #[test]
    fn one_home_gives_one_value() {
        let (name, out) = render_text(TPL, &["/home/dan".into()]).unwrap();
        assert_eq!(name, "sentinel-cred-ssh-private-key-read");
        let doc: Value = serde_yaml::from_str(&out).unwrap();
        let values = dig(&doc);
        assert_eq!(values, vec!["/home/dan/.ssh/"]);
    }

    #[test]
    fn two_homes_fan_the_list_item_out() {
        let (_, out) = render_text(TPL, &["/home/dan".into(), "/var/home/ada".into()]).unwrap();
        assert!(!out.contains(PLACEHOLDER));
        let doc: Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(dig(&doc), vec!["/home/dan/.ssh/", "/var/home/ada/.ssh/"]);
    }

    #[test]
    fn structure_survives_a_hostile_home() {
        let (_, out) = render_text(TPL, &["/home/a: b\"c".into()]).unwrap();
        let doc: Value = serde_yaml::from_str(&out).expect("still valid yaml");
        assert_eq!(dig(&doc), vec!["/home/a: b\"c/.ssh/"]);
    }

    #[test]
    fn no_homes_is_a_failure_not_an_empty_list() {
        let err = render_text(TPL, &[]).unwrap_err();
        assert!(err.contains("no human user"), "{}", err);
    }

    #[test]
    fn non_sentinel_name_is_rejected() {
        let t = TPL.replace("sentinel-cred-ssh-private-key-read", "some-other-policy");
        assert!(render_text(&t, &["/home/dan".into()]).is_err());
    }

    #[test]
    fn allowlist_has_exec_exit_and_exact_names() {
        let mut names = BTreeSet::new();
        names.insert("sentinel-cred-a".to_string());
        names.insert("sentinel-net-b".to_string());
        let body = allowlist_body(&names);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], r#"{"event_set":["PROCESS_EXEC","PROCESS_EXIT"]}"#);
        assert_eq!(
            lines[1],
            r#"{"event_set":["PROCESS_KPROBE","PROCESS_LSM","PROCESS_TRACEPOINT","PROCESS_UPROBE"],"policy_names":["sentinel-cred-a","sentinel-net-b"]}"#
        );
        for l in lines {
            let _: serde_json::Value = serde_json::from_str(l).expect("each line is valid JSON");
        }
    }

    #[test]
    fn render_dir_is_idempotent_and_prunes() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("templates");
        let odir = dir.path().join("out");
        std::fs::create_dir_all(&tdir).unwrap();
        std::fs::write(tdir.join("a.yaml"), TPL).unwrap();
        let al = dir.path().join("export-allowlist");
        let opts = RenderOptions {
            templates_dir: &tdir,
            out_dir: &odir,
            export_allowlist: Some(&al),
            passwd: Path::new("/etc/passwd"),
            homes: Some(vec!["/home/dan".into()]),
        };
        let r1 = render(&opts).unwrap();
        assert_eq!(r1.rendered.len(), 1);
        assert_eq!(r1.files_changed, 1);
        assert!(r1.allowlist_changed);

        let r2 = render(&opts).unwrap();
        assert_eq!(r2.files_changed, 0, "second run must not rewrite");
        assert!(!r2.allowlist_changed);

        // A stale rendered policy is removed.
        std::fs::write(odir.join("stale.yaml"), "x: 1\n").unwrap();
        let r3 = render(&opts).unwrap();
        assert_eq!(r3.removed.len(), 1);
        assert!(!odir.join("stale.yaml").exists());
    }

    #[test]
    fn broken_template_lands_in_failed() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("t");
        std::fs::create_dir_all(&tdir).unwrap();
        std::fs::write(tdir.join("ok.yaml"), TPL).unwrap();
        std::fs::write(tdir.join("bad.yaml"), "spec: [unclosed\n").unwrap();
        let opts = RenderOptions {
            templates_dir: &tdir,
            out_dir: &dir.path().join("o"),
            export_allowlist: None,
            passwd: Path::new("/etc/passwd"),
            homes: Some(vec!["/home/dan".into()]),
        };
        let r = render(&opts).unwrap();
        assert_eq!(r.rendered.len(), 1);
        assert_eq!(r.failed_names(), vec!["bad.yaml"]);
    }

    fn dig(doc: &Value) -> Vec<String> {
        doc["spec"]["lsmhooks"][0]["selectors"][0]["matchArgs"][0]["values"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }
}
