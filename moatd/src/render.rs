//! `moatd render-policies`.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_yaml::Value;

use crate::util::{atomic_write, human_homes};

pub const PLACEHOLDER: &str = "{{HOME}}";

/// List placeholders: a sequence item that is exactly one of these is replaced
/// by the whole configured list, and each entry then goes through `{{HOME}}`
/// expansion like any other value.
///
/// This is how a telemetry class's *scope* comes out of `moat.toml` rather than
/// being frozen into a shipped YAML file. It matters most for
/// `telemetry-file-exec-shape.yaml`: an unscoped file policy is the difference
/// between 0.3 events a second and 19, so the scope has to be something a user
/// can see, narrow and widen without editing a policy.
pub const FILE_SCOPE: &str = "{{FILE_SCOPE}}";
pub const FILE_SUFFIXES: &str = "{{FILE_SUFFIXES}}";

/// The three export-allowlist lines, matching `policies/export-allowlist.example`.
///
/// Line 1 keeps exec/exit — they carry no `policy_name`, so there is no other
/// way to select them, and without them there is no ancestry. Line 2 restricts
/// the hook events to exactly the policies we rendered; `policy_names` is
/// exact-match with no globs (NOTES §8, gap 8), which is why this file is
/// regenerated on every render. NOTES §8 also offers a CEL `startsWith`
/// variant, but that is UNVERIFIED live and exact names cost nothing.
///
/// Line 3 is `PROCESS_THROTTLE`, and its absence until 2026-09-08 was a hole
/// in moat's account of itself. Tetragon is run with `--cgroup-rate` set;
/// when a cgroup exceeds that, base events are DROPPED and a `process_throttle`
/// event says so. moatd parses those (`event::ThrottleEvent`) and raises
/// `moat-x-sensor-throttled` — a rule that could never once have fired, because
/// this filter discarded the only event that triggers it. So "no throttle
/// alerts" meant "moat cannot see whether it is losing events", which is the
/// worst thing for a sensor to be quietly unsure about: every ancestry gap and
/// every unformed chain downstream had an explanation nobody could check.
/// It carries no `policy_name`, so like exec/exit it needs its own line.
fn allowlist_body(names: &BTreeSet<String>) -> String {
    let list = names
        .iter()
        .map(|n| serde_json::to_string(n).unwrap_or_else(|_| format!("\"{}\"", n)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"event_set\":[\"PROCESS_EXEC\",\"PROCESS_EXIT\"]}}\n\
         {{\"event_set\":[\"PROCESS_KPROBE\",\"PROCESS_LSM\",\"PROCESS_TRACEPOINT\",\"PROCESS_UPROBE\"],\"policy_names\":[{}]}}\n\
         {{\"event_set\":[\"PROCESS_THROTTLE\"]}}\n",
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
    /// Telemetry templates that were deliberately not rendered, with the class
    /// that is off. Reported rather than silent: "why is there no network
    /// telemetry" must have an answer that is not "read the source".
    pub skipped: Vec<(String, String)>,
    /// Telemetry class names that are on for this render.
    pub telemetry_classes: Vec<String>,
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
    /// `[telemetry]`. Decides which `telemetry-*.yaml` templates are rendered
    /// at all, and supplies the values for the list placeholders.
    pub telemetry: crate::config::TelemetryConfig,
    /// Per-policy binaries the KERNEL should stop watching, as
    /// `{policy name: [absolute exe, ...]}`.
    ///
    /// This is how "allow this program" is honoured for a rule that is ARMED.
    /// An allowlist entry is a userspace suppression and cannot reach a policy
    /// enforcing in the kernel -- the process dies before moatd sees the event
    /// -- so allowing an armed rule used to silence the alert and change
    /// nothing. Excluding the binary from the policy itself is the only thing
    /// that actually stops the killing while the rule stays armed for
    /// everything else.
    pub exclusions: std::collections::BTreeMap<String, Vec<String>>,
    /// `[contain] max`: how many containment policy names to reserve in the
    /// export allowlist. See the note at the write site -- a runtime policy
    /// whose name is not in this file is invisible to moatd.
    pub contain_slots: usize,
}

impl Default for RenderOptions<'_> {
    fn default() -> Self {
        RenderOptions {
            templates_dir: Path::new("/usr/lib/moat/policies"),
            out_dir: Path::new("/run/moat/policies"),
            export_allowlist: None,
            passwd: Path::new("/etc/passwd"),
            homes: None,
            telemetry: crate::config::TelemetryConfig::default(),
            exclusions: std::collections::BTreeMap::new(),
            contain_slots: crate::config::ContainConfig::default().max,
        }
    }
}

pub fn render(opts: &RenderOptions) -> Result<RenderReport, String> {
    let homes = match &opts.homes {
        Some(h) => h.clone(),
        None => human_homes(opts.passwd),
    };
    let mut lists: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    lists.insert(FILE_SCOPE, opts.telemetry.file_scope.clone());
    lists.insert(FILE_SUFFIXES, opts.telemetry.file_suffixes.clone());

    let mut report = RenderReport {
        telemetry_classes: opts
            .telemetry
            .classes()
            .into_iter()
            .map(str::to_string)
            .collect(),
        ..RenderReport::default()
    };

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
        // A telemetry template whose class is off is not rendered, so it is
        // not in tracing-policy-dir, so the kernel never attaches it and not a
        // byte is written for it. That is what "switchable" has to mean here:
        // filtering a loaded policy in userspace would already have cost the
        // export write and moatd's parse.
        if let Some(class) = crate::telemetry::class_of_template(&stem) {
            if !opts.telemetry.enabled(class) {
                report
                    .skipped
                    .push((stem.clone(), format!("telemetry.{} is off", class)));
                continue;
            }
        }
        match render_one_with(tpl, &homes, &lists, &opts.exclusions) {
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
        // The containment slots, always, whether or not any containment is
        // live right now.
        //
        // `policy_names` is exact-match with no globs and this file is only
        // read when tetragon starts, so a policy moatd writes at RUNTIME can
        // never be added to it in time. Containment used to name its policy
        // after the chain's ULID, which meant its events were filtered out of
        // the export: the connection was refused in the kernel and moatd never
        // heard about it, so the panel could not say a thing had been blocked.
        // Fixed names, bounded by `contain.max` (the same cap that already
        // evicts the oldest containment), are what make that visible.
        let mut names = names.clone();
        for slot in 0..opts.contain_slots.max(1) {
            names.insert(crate::contain::policy_name(slot));
        }
        report.allowlist_changed = atomic_write(path, allowlist_body(&names).as_bytes(), 0o644)
            .map_err(|e| format!("{}: {}", path.display(), e))?;
    }

    Ok(report)
}

/// Render one template. Returns `(policy name, YAML text)`.
pub fn render_one(
    path: &Path,
    homes: &[String],
    lists: &BTreeMap<&'static str, Vec<String>>,
) -> Result<(String, String), String> {
    render_one_with(path, homes, lists, &BTreeMap::new())
}

/// `render_one`, with the kernel exclusions the daemon has recorded.
pub fn render_one_with(
    path: &Path,
    homes: &[String],
    lists: &BTreeMap<&'static str, Vec<String>>,
    exclusions: &BTreeMap<String, Vec<String>>,
) -> Result<(String, String), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    render_text(&text, homes, lists, exclusions)
}

/// The list placeholders filled from the built-in `[telemetry]` defaults.
///
/// For callers that only want `{{HOME}}` expansion — validating a shipped
/// template, re-reading a rendered policy — and do not have a live config in
/// hand.
pub fn default_lists() -> BTreeMap<&'static str, Vec<String>> {
    let t = crate::config::TelemetryConfig::default();
    let mut m = BTreeMap::new();
    m.insert(FILE_SCOPE, t.file_scope);
    m.insert(FILE_SUFFIXES, t.file_suffixes);
    m
}

/// Stop a policy watching these binaries, in the kernel.
///
/// Every selector gains the binaries in its `matchBinaries` NOT-list. Two
/// details matter and both are failure modes if missed:
///
/// * A selector with no `matchBinaries` at all watches every binary, so one is
///   ADDED. Without that the exclusion would apply to some selectors of a
///   policy and silently not others -- an exclusion that does not exclude is
///   worse than a refusal, because the user believes the program is allowed.
/// * Only negative operators are extended. Adding a value to an `In` or
///   `Equal` list would WIDEN what the policy matches, turning "stop watching
///   cat" into "also watch cat".
fn exclude_binaries(doc: &mut Value, bins: &[String]) -> Result<(), String> {
    if bins.is_empty() {
        return Ok(());
    }
    let Some(spec) = doc.get_mut("spec").and_then(|s| s.as_mapping_mut()) else {
        return Err("policy has no spec".into());
    };
    for (_, hooks) in spec.iter_mut() {
        let Some(hooks) = hooks.as_sequence_mut() else { continue };
        for hook in hooks.iter_mut() {
            let Some(selectors) = hook.get_mut("selectors").and_then(|s| s.as_sequence_mut())
            else {
                continue;
            };
            for sel in selectors.iter_mut() {
                let Some(map) = sel.as_mapping_mut() else { continue };
                let key = Value::String("matchBinaries".into());
                let entry = map.entry(key).or_insert_with(|| {
                    Value::Sequence(vec![serde_yaml::from_str::<Value>(
                        "operator: \"NotIn\"\nvalues: []",
                    )
                    .expect("literal parses")])
                });
                let Some(list) = entry.as_sequence_mut() else { continue };
                for m in list.iter_mut() {
                    let is_negative = m
                        .get("operator")
                        .and_then(|o| o.as_str())
                        .map(|o| o.starts_with("Not"))
                        .unwrap_or(false);
                    if !is_negative {
                        continue;
                    }
                    let Some(values) = m.get_mut("values").and_then(|v| v.as_sequence_mut())
                    else {
                        continue;
                    };
                    for b in bins {
                        let v = Value::String(b.clone());
                        if !values.contains(&v) {
                            values.push(v);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Enforcement is a decision about THIS machine, so it stops at the namespace
/// boundary. Every selector that would kill or deny is scoped to the host mount
/// namespace, and a copy of it WITHOUT the action is added for everywhere else.
///
/// A container is somebody else's filesystem wearing our path names. `/etc/shadow`
/// inside an image is not this machine's; `/tmp/rustup-init` in a `docker build`
/// is the documented way a Rust toolchain installs. Refusing those is refusing
/// work the user asked for, in a process tree they cannot see, with an errno that
/// points at nothing. Two of those landed on 2026-09-07 and -09-08: `pg_isready`
/// denied reading its own container's shadow file, and a build's rustup-init took
/// a CRITICAL EPERM.
///
/// The events are NOT dropped. The copy still posts, so container activity stays
/// on the timeline and in the chain correlator; what it loses is the power to
/// refuse. That is the whole trade, and it is the conservative half of it: an
/// attacker who can start a container can already reach root on the host, and
/// the rules that catch THAT -- a kernel module, a BPF program load -- are global
/// and have no namespace to hide in, so they are deliberately left alone below.
fn split_container_enforcement(doc: &mut Value) {
    fn ns_clause(op: &str) -> Value {
        serde_yaml::from_str(&format!(
            "namespace: Mnt\noperator: \"{}\"\nvalues:\n- \"host_ns\"",
            op
        ))
        .expect("literal parses")
    }
    // A policy whose object is GLOBAL opts out by annotation. There is one
    // kernel: a module loaded from inside a container is loaded on this
    // machine, and scoping that to the host namespace would let anyone who can
    // start a container load a rootkit and be merely watched doing it. The
    // annotation lives in the YAML, next to the hook it describes, because
    // deciding this from Rust means the list and the policies drift apart.
    if doc
        .get("metadata")
        .and_then(|m| m.get("annotations"))
        .and_then(|a| a.get("moat.omarchy/namespace"))
        .and_then(|v| v.as_str())
        == Some("global")
    {
        return;
    }
    let Some(spec) = doc.get_mut("spec").and_then(|s| s.as_mapping_mut()) else { return };
    for (_, hooks) in spec.iter_mut() {
        let Some(hooks) = hooks.as_sequence_mut() else { continue };
        for hook in hooks.iter_mut() {
            let Some(selectors) = hook.get_mut("selectors").and_then(|s| s.as_sequence_mut())
            else {
                continue;
            };
            let mut mirrors: Vec<Value> = Vec::new();
            for sel in selectors.iter_mut() {
                let Some(map) = sel.as_mapping_mut() else { continue };
                if !selector_enforces(map) {
                    continue;
                }
                // The mirror REPLACES any hand-written Mnt clause rather than
                // skipping it. Three policies already carried `Mnt In host_ns`,
                // added in September to stop a container's own /etc/shadow
                // being refused -- which fixed the denial by making container
                // activity invisible. Monitoring it is strictly better, and it
                // is what this function exists to say.
                let mut mirror = map.clone();
                mirror.remove(Value::String("matchActions".into()));
                mirror.insert(
                    Value::String("matchNamespaces".into()),
                    Value::Sequence(vec![ns_clause("NotIn")]),
                );
                mirrors.push(Value::Mapping(mirror));
                map.insert(
                    Value::String("matchNamespaces".into()),
                    Value::Sequence(vec![ns_clause("In")]),
                );
            }
            selectors.extend(mirrors);
        }
    }
}

/// Does this selector kill or deny? `Post` and friends are not enforcement.
fn selector_enforces(map: &serde_yaml::Mapping) -> bool {
    map.get(Value::String("matchActions".into()))
        .and_then(|a| a.as_sequence())
        .map(|acts| {
            acts.iter().any(|a| {
                matches!(
                    a.get("action").and_then(|v| v.as_str()),
                    Some("Override") | Some("Sigkill")
                )
            })
        })
        .unwrap_or(false)
}

pub fn render_text(
    text: &str,
    homes: &[String],
    lists: &BTreeMap<&'static str, Vec<String>>,
    exclusions: &BTreeMap<String, Vec<String>>,
) -> Result<(String, String), String> {
    if text.contains(PLACEHOLDER) && homes.is_empty() {
        return Err("template uses {{HOME}} but no human user was found in /etc/passwd".into());
    }
    for (name, values) in lists {
        if text.contains(*name) && values.is_empty() {
            return Err(format!(
                "template uses {} but the configured list is empty; an unscoped policy here \
                 would match every file on the machine",
                name
            ));
        }
    }
    let mut doc: Value = serde_yaml::from_str(text).map_err(|e| format!("yaml: {}", e))?;
    expand_lists(&mut doc, lists);
    expand(&mut doc, homes);

    let name = doc
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| "metadata.name missing".to_string())?
        .to_string();
    if !name.starts_with("moat-") {
        return Err(format!(
            "policy name {:?} does not start with `moat-`; it would never be alerted on",
            name
        ));
    }
    if let Some(bins) = exclusions.get(&name) {
        exclude_binaries(&mut doc, bins)?;
    }
    split_container_enforcement(&mut doc);

    let body = serde_yaml::to_string(&doc).map_err(|e| e.to_string())?;
    if body.contains(PLACEHOLDER) {
        return Err("placeholder survived expansion".into());
    }
    Ok((name, format!("{}{}", HEADER, body)))
}

const HEADER: &str = "# rendered by `moatd render-policies` — edit the template, not this file\n";

/// Replace a sequence item that is exactly `{{FILE_SCOPE}}` (or another list
/// placeholder) with the configured list.
///
/// Runs before [`expand`], so every value it inserts is then `{{HOME}}`-fanned
/// like any other. Only whole-item matches are replaced: a scalar elsewhere in
/// the document is left alone and [`render_text`]'s "placeholder survived
/// expansion" check turns it into a loud failure rather than a policy that
/// matches a literal `{{FILE_SCOPE}}` path.
fn expand_lists(v: &mut Value, lists: &BTreeMap<&'static str, Vec<String>>) {
    match v {
        Value::Sequence(seq) => {
            let mut out: Vec<Value> = Vec::with_capacity(seq.len());
            for item in seq.drain(..) {
                match item {
                    Value::String(ref s) if lists.contains_key(s.as_str()) => {
                        for value in &lists[s.as_str()] {
                            out.push(Value::String(value.clone()));
                        }
                    }
                    mut other => {
                        expand_lists(&mut other, lists);
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
                    expand_lists(val, lists);
                }
            }
        }
        _ => {}
    }
}

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
  name: moat-cred-ssh-private-key-read
  annotations:
    moat.omarchy/severity: high
    moat.omarchy/title: "Private SSH key read by an unexpected program"
    moat.omarchy/why: "Keys are the first thing stealers read."
    moat.omarchy/expected: "Backup tools and IDE git integrations."
    moat.omarchy/fp-hint: exe
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
        let (name, out) = render_text(TPL, &["/home/dan".into()], &default_lists(), &Default::default()).unwrap();
        assert_eq!(name, "moat-cred-ssh-private-key-read");
        let doc: Value = serde_yaml::from_str(&out).unwrap();
        let values = dig(&doc);
        assert_eq!(values, vec!["/home/dan/.ssh/"]);
    }

    #[test]
    fn two_homes_fan_the_list_item_out() {
        let (_, out) = render_text(TPL, &["/home/dan".into(), "/var/home/ada".into()], &default_lists(), &Default::default()).unwrap();
        assert!(!out.contains(PLACEHOLDER));
        let doc: Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(dig(&doc), vec!["/home/dan/.ssh/", "/var/home/ada/.ssh/"]);
    }

    #[test]
    fn structure_survives_a_hostile_home() {
        let (_, out) = render_text(TPL, &["/home/a: b\"c".into()], &default_lists(), &Default::default()).unwrap();
        let doc: Value = serde_yaml::from_str(&out).expect("still valid yaml");
        assert_eq!(dig(&doc), vec!["/home/a: b\"c/.ssh/"]);
    }

    #[test]
    fn no_homes_is_a_failure_not_an_empty_list() {
        let err = render_text(TPL, &[], &default_lists(), &Default::default()).unwrap_err();
        assert!(err.contains("no human user"), "{}", err);
    }

    #[test]
    fn non_moat_name_is_rejected() {
        let t = TPL.replace("moat-cred-ssh-private-key-read", "some-other-policy");
        assert!(render_text(&t, &["/home/dan".into()], &default_lists(), &Default::default()).is_err());
    }

    /// The gap that made a working containment silent.
    #[test]
    fn the_allowlist_reserves_the_containment_slots() {
        let dir = tempfile::tempdir().unwrap();
        let al = dir.path().join("export-allowlist");
        let out = dir.path().join("out");
        let tpl = dir.path().join("tpl");
        std::fs::create_dir_all(&tpl).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let opts = RenderOptions {
            templates_dir: &tpl,
            out_dir: &out,
            export_allowlist: Some(&al),
            homes: Some(vec!["/home/x".into()]),
            contain_slots: 4,
            ..Default::default()
        };
        render(&opts).expect("render");
        let body = std::fs::read_to_string(&al).unwrap();
        for slot in 0..4 {
            assert!(
                body.contains(&crate::contain::policy_name(slot)),
                "slot {} must be exported or a containment that fires is invisible:\n{}",
                slot,
                body
            );
        }
        assert!(
            !body.contains("moat-contain-4"),
            "and no more than `contain.max` are reserved"
        );
    }

    #[test]
    fn allowlist_has_exec_exit_and_exact_names() {
        let mut names = BTreeSet::new();
        names.insert("moat-cred-a".to_string());
        names.insert("moat-net-b".to_string());
        let body = allowlist_body(&names);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], r#"{"event_set":["PROCESS_EXEC","PROCESS_EXIT"]}"#);
        assert_eq!(
            lines[1],
            r#"{"event_set":["PROCESS_KPROBE","PROCESS_LSM","PROCESS_TRACEPOINT","PROCESS_UPROBE"],"policy_names":["moat-cred-a","moat-net-b"]}"#
        );
        // PROCESS_THROTTLE carries no policy_name, so it needs its own line --
        // and without it `moat-x-sensor-throttled` can never fire, which means
        // moat cannot tell whether it is losing events. This assertion is the
        // whole guard: the old test checked lines[0] and lines[1] and passed
        // happily while the third line did not exist.
        assert_eq!(lines[2], r#"{"event_set":["PROCESS_THROTTLE"]}"#);
        assert_eq!(lines.len(), 3, "three lines, no more: {:?}", lines);
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
            telemetry: crate::config::TelemetryConfig::default(),
            exclusions: Default::default(),
            contain_slots: 0,
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
            telemetry: crate::config::TelemetryConfig::default(),
            exclusions: Default::default(),
            contain_slots: 0,
        };
        let r = render(&opts).unwrap();
        assert_eq!(r.rendered.len(), 1);
        assert_eq!(r.failed_names(), vec!["bad.yaml"]);
    }

    const TELEM: &str = r#"apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: moat-telemetry-file-exec-shape
  annotations:
    moat.omarchy/telemetry-class: file
spec:
  kprobes:
  - call: "security_file_post_open"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "{{FILE_SUFFIXES}}"
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "{{FILE_SCOPE}}"
"#;

    fn telem_lists(scope: &[&str], suffixes: &[&str]) -> BTreeMap<&'static str, Vec<String>> {
        let mut m = BTreeMap::new();
        m.insert(FILE_SCOPE, scope.iter().map(|s| s.to_string()).collect());
        m.insert(
            FILE_SUFFIXES,
            suffixes.iter().map(|s| s.to_string()).collect(),
        );
        m
    }

    /// The scope has to come out of moat.toml, or "switchable" means "edit a
    /// YAML file in /usr". It also has to fan `{{HOME}}` out afterwards, so a
    /// scope entry can be written once and apply to every user.
    #[test]
    fn a_list_placeholder_becomes_the_configured_list_and_then_fans_home_out() {
        let lists = telem_lists(&["/usr/bin/", "{{HOME}}/.local/bin/"], &[".sh", ".js"]);
        let (name, out) =
            render_text(TELEM, &["/home/dan".into(), "/var/home/ada".into()], &lists, &Default::default()).unwrap();
        assert_eq!(name, "moat-telemetry-file-exec-shape");
        let doc: Value = serde_yaml::from_str(&out).unwrap();
        let sel = &doc["spec"]["kprobes"][0]["selectors"];
        let suffixes: Vec<String> = sel[0]["matchArgs"][0]["values"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(suffixes, vec![".sh", ".js"]);
        let scope: Vec<String> = sel[1]["matchArgs"][0]["values"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            scope,
            vec!["/usr/bin/", "/home/dan/.local/bin/", "/var/home/ada/.local/bin/"]
        );
        assert!(!out.contains("{{"));
    }

    /// An unscoped file policy matches every write on the machine — 19 events
    /// a second here against 0.3 with a scope. It is a failure, not a render.
    #[test]
    fn an_empty_scope_is_refused_rather_than_rendered_wide_open() {
        let lists = telem_lists(&[], &[".sh"]);
        let err = render_text(TELEM, &["/home/dan".into()], &lists, &Default::default()).unwrap_err();
        assert!(err.contains("FILE_SCOPE"), "{}", err);
        assert!(err.contains("every file"), "{}", err);
    }

    /// A class that is off produces no policy at all: nothing in
    /// tracing-policy-dir, nothing in the export allowlist, nothing attached.
    #[test]
    fn a_telemetry_class_that_is_off_is_not_rendered_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("templates");
        let odir = dir.path().join("out");
        std::fs::create_dir_all(&tdir).unwrap();
        std::fs::write(tdir.join("cred-a.yaml"), TPL).unwrap();
        std::fs::write(tdir.join("telemetry-file-exec-shape.yaml"), TELEM).unwrap();
        std::fs::write(
            tdir.join("telemetry-network-connect.yaml"),
            TELEM.replace(
                "moat-telemetry-file-exec-shape",
                "moat-telemetry-network-connect",
            ),
        )
        .unwrap();
        let al = dir.path().join("export-allowlist");

        let mut telemetry = crate::config::TelemetryConfig::default();
        assert!(!telemetry.file && !telemetry.network, "both ship off");
        let opts = RenderOptions {
            templates_dir: &tdir,
            out_dir: &odir,
            export_allowlist: Some(&al),
            passwd: Path::new("/etc/passwd"),
            homes: Some(vec!["/home/dan".into()]),
            telemetry: telemetry.clone(),
            exclusions: Default::default(),
            contain_slots: 0,
        };
        let r = render(&opts).unwrap();
        assert_eq!(r.rendered, vec!["moat-cred-ssh-private-key-read"]);
        assert_eq!(r.skipped.len(), 2, "and it says which and why");
        assert!(r.skipped.iter().all(|(_, why)| why.contains("is off")));
        assert!(!odir.join("telemetry-file-exec-shape.yaml").exists());
        let body = std::fs::read_to_string(&al).unwrap();
        assert!(!body.contains("telemetry"), "not in the export allowlist either");

        // Turn one on: it renders, and its name reaches the export allowlist so
        // Tetragon will actually export what it posts.
        telemetry.network = true;
        let opts = RenderOptions {
            telemetry,
            ..opts
        };
        let r2 = render(&opts).unwrap();
        assert!(r2.rendered.contains(&"moat-telemetry-network-connect".to_string()));
        assert_eq!(r2.skipped.len(), 1);
        assert_eq!(r2.telemetry_classes, vec!["alerts", "network"]);
        assert!(std::fs::read_to_string(&al)
            .unwrap()
            .contains("moat-telemetry-network-connect"));

        // …and turning it back off removes the rendered file, so a restart
        // does not silently keep collecting.
        let opts = RenderOptions {
            telemetry: crate::config::TelemetryConfig::default(),
            ..opts
        };
        let r3 = render(&opts).unwrap();
        assert!(!odir.join("telemetry-network-connect.yaml").exists());
        assert_eq!(r3.removed.len(), 1);
    }

    /// The shipped telemetry templates are real files with real placeholders;
    /// this is the test that catches a typo in one of them at build time.
    #[test]
    fn the_shipped_telemetry_templates_render_with_the_shipped_scope() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("policies");
        let lists = default_lists();
        for t in crate::telemetry::all_templates() {
            let p = dir.join(t);
            if !p.exists() {
                continue; // not laid out as a checkout
            }
            let (name, body) = render_one(&p, &["/home/dan".into()], &lists)
                .unwrap_or_else(|e| panic!("{}: {}", t, e));
            assert!(crate::telemetry::is_telemetry_policy(&name), "{} -> {}", t, name);
            assert!(!body.contains("{{"), "{} still has a placeholder", t);
            // A telemetry policy must never be able to act.
            for forbidden in ["Sigkill", "Override", "NotifyEnforcer", "Signal"] {
                assert!(
                    !body.contains(forbidden),
                    "{} carries the {} action; telemetry observes and never acts",
                    t,
                    forbidden
                );
            }
        }
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

#[cfg(test)]
mod exclusion_tests {
    use super::*;

    const ARMED: &str = r#"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: moat-cred-etc-shadow-read
spec:
  lsmhooks:
  - hook: "file_post_open"
    selectors:
    - matchBinaries:
      - operator: "NotIn"
        values:
        - "/usr/bin/passwd"
      matchArgs:
      - index: 0
        operator: "Equal"
        values: ["/etc/shadow"]
    - matchArgs:
      - index: 0
        operator: "Equal"
        values: ["/etc/gshadow"]
"#;

    /// "Allow this program" has to reach the kernel for an armed rule, and it
    /// has to reach EVERY selector of it.
    #[test]
    fn an_excluded_binary_is_added_to_every_selector() {
        let mut ex = BTreeMap::new();
        ex.insert(
            "moat-cred-etc-shadow-read".to_string(),
            vec!["/usr/bin/cat".to_string()],
        );
        let (name, out) = render_text(ARMED, &["/home/dan".into()], &default_lists(), &ex).unwrap();
        assert_eq!(name, "moat-cred-etc-shadow-read");

        let doc: Value = serde_yaml::from_str(&out).unwrap();
        let sels = doc["spec"]["lsmhooks"][0]["selectors"].as_sequence().unwrap();
        assert_eq!(sels.len(), 2);

        // The selector that already had a NotIn list gains the binary...
        let first = sels[0]["matchBinaries"][0]["values"].as_sequence().unwrap();
        assert!(first.iter().any(|v| v.as_str() == Some("/usr/bin/cat")));
        assert!(first.iter().any(|v| v.as_str() == Some("/usr/bin/passwd")),
                "the shipped exclusions survive");

        // ...and the one with NO matchBinaries gets one. Without this the
        // exclusion would apply to part of a policy and silently not the rest,
        // which is worse than refusing: the user believes it is allowed.
        let second = sels[1]["matchBinaries"][0]["values"].as_sequence().unwrap();
        assert!(second.iter().any(|v| v.as_str() == Some("/usr/bin/cat")));
        assert_eq!(sels[1]["matchBinaries"][0]["operator"].as_str(), Some("NotIn"));

        // A positive match is never widened: adding to an `Equal` list would
        // turn "stop watching cat" into "also watch cat".
        assert_eq!(
            sels[0]["matchArgs"][0]["values"].as_sequence().unwrap().len(),
            1
        );
    }

    #[test]
    fn a_policy_with_no_exclusions_is_untouched() {
        let plain = render_text(ARMED, &["/home/dan".into()], &default_lists(), &BTreeMap::new())
            .unwrap()
            .1;
        let other = {
            let mut ex = BTreeMap::new();
            ex.insert("moat-some-other-rule".to_string(), vec!["/usr/bin/cat".into()]);
            render_text(ARMED, &["/home/dan".into()], &default_lists(), &ex).unwrap().1
        };
        assert_eq!(plain, other, "an exclusion names one policy and touches only it");
    }

    /// The template every container test below renders: one enforcing selector.
    const DENIES: &str = r#"apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: moat-cred-thing-read
spec:
  lsmhooks:
  - hook: "file_post_open"
    selectors:
    - matchBinaries:
      - operator: "NotIn"
        values: ["/usr/bin/cat"]
      matchActions:
      - action: Override
        argError: -1
"#;

    fn sels(text: &str) -> Vec<serde_yaml::Mapping> {
        let (_, y) =
            render_text(text, &["/home/dan".into()], &default_lists(), &BTreeMap::new()).unwrap();
        let doc: Value = serde_yaml::from_str(&y).unwrap();
        doc["spec"]["lsmhooks"][0]["selectors"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|s| s.as_mapping().unwrap().clone())
            .collect()
    }

    fn ns_of(m: &serde_yaml::Mapping) -> Option<String> {
        m.get(Value::String("matchNamespaces".into()))?
            .as_sequence()?
            .iter()
            .find(|e| e.get("namespace").and_then(|v| v.as_str()) == Some("Mnt"))?
            .get("operator")?
            .as_str()
            .map(|s| s.to_string())
    }

    #[test]
    fn enforcement_is_scoped_to_the_host_and_containers_are_still_watched() {
        let s = sels(DENIES);
        assert_eq!(s.len(), 2, "one enforcing selector becomes host + container");
        assert_eq!(ns_of(&s[0]).as_deref(), Some("In"), "the deny is host-only");
        assert!(s[0].contains_key(Value::String("matchActions".into())));
        assert_eq!(ns_of(&s[1]).as_deref(), Some("NotIn"), "the mirror is everywhere else");
        assert!(
            !s[1].contains_key(Value::String("matchActions".into())),
            "a container is watched, never refused -- that is the whole point"
        );
    }

    #[test]
    fn the_container_mirror_keeps_every_filter_the_deny_had() {
        let s = sels(DENIES);
        assert_eq!(
            s[0].get(Value::String("matchBinaries".into())),
            s[1].get(Value::String("matchBinaries".into())),
            "a mirror that watches MORE than the deny would invent container noise"
        );
    }

    #[test]
    fn a_global_object_is_never_scoped_to_a_namespace() {
        // There is one kernel. Scoping a module load to the host namespace
        // would let anyone who can start a container load a rootkit and be
        // merely watched doing it.
        let global = DENIES.replace(
            "  name: moat-cred-thing-read",
            "  name: moat-rootkit-thing-load
  annotations:
    moat.omarchy/namespace: \"global\"",
        );
        let s = sels(&global);
        assert_eq!(s.len(), 1, "no mirror was added");
        assert_eq!(ns_of(&s[0]), None, "and the deny still applies everywhere");
    }

    #[test]
    fn a_policy_that_only_watches_is_left_exactly_as_it_was() {
        let watch = DENIES
            .replace("      matchActions:\n      - action: Override\n        argError: -1\n", "");
        let s = sels(&watch);
        assert_eq!(s.len(), 1, "nothing to split: it was never enforcing");
        assert_eq!(ns_of(&s[0]), None);
    }

    #[test]
    fn a_hand_written_host_clause_is_replaced_not_doubled() {
        // Three shipped policies already carried `Mnt In host_ns`, added to stop
        // a container's own /etc/shadow being refused -- which fixed the denial
        // by making container activity invisible. The mirror must OVERWRITE
        // that clause, or the container copy inherits `In` and matches nothing.
        let already = DENIES.replace(
            "      matchActions:",
            "      matchNamespaces:\n      - namespace: Mnt\n        operator: \"In\"\n        values: [\"host_ns\"]\n      matchActions:",
        );
        let s = sels(&already);
        assert_eq!(s.len(), 2);
        assert_eq!(ns_of(&s[0]).as_deref(), Some("In"));
        assert_eq!(ns_of(&s[1]).as_deref(), Some("NotIn"), "the mirror now sees containers");
        assert_eq!(
            s[1].get(Value::String("matchNamespaces".into())).unwrap().as_sequence().unwrap().len(),
            1,
            "one Mnt clause, not two contradicting each other"
        );
    }
}
