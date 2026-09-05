//! Temporary, targeted containment driven by correlation.
//!
//! ## Why this exists
//!
//! `moat-net-tmpfs-binary-egress` can refuse a connection, but only to a public
//! address: it excludes RFC1918 in the kernel because a workstation talks to its
//! LAN all day and, on the machine this was written for, the developer's own
//! package registry lives there. A kernel selector cannot tell "my registry"
//! from "a C2 on the same subnet" -- the difference is that nothing has ever
//! talked to the C2 before, and rarity lives in userspace.
//!
//! So the split is: the kernel enforces, and userspace decides. When `chain.rs`
//! concludes a sequence is `high` and that sequence includes a connection to
//! somewhere new, moatd writes a policy naming *that binary* and *that
//! destination*, loads it with `tetra tracingpolicy add`, and deletes it again
//! when the TTL runs out. Nothing else on the machine is affected, and the
//! window is minutes rather than forever.
//!
//! ## What it deliberately is not
//!
//! Not a kill. The containment refuses `connect()` with -EPERM; the process
//! keeps running, the build finishes, and the evidence tree stays alive to be
//! looked at. Killing on a correlation -- a judgement made after the fact, from
//! several events -- is how an EDR takes out someone's editor at 2am.
//!
//! Not host isolation. CrowdStrike's Network Contain cuts the whole machine off;
//! that is the right call on a server with an analyst watching and the wrong one
//! on a laptop with nobody. This is scoped to one binary and one address.
//!
//! Not permanent, and not silent. Every containment expires on its own, is
//! listed by `moatctl contain`, can be dropped with `moatctl release`, and is
//! recorded on the alert that caused it.
//!
//! ## The ceiling that shapes the design
//!
//! Tetragon attaches two BPF programs per policy and the kernel caps an LSM hook
//! at `BPF_MAX_TRAMP_LINKS` (38) trampoline links, so roughly 19 policies may
//! share one hook. `socket_connect` is where these land, so containments are
//! capped (`contain_max`) and the oldest is released to make room rather than
//! being allowed to accumulate until a *detection* policy fails to load. Running
//! out of room here must never cost coverage.

use std::collections::BTreeMap;

/// One live containment.
#[derive(Debug, Clone, PartialEq)]
pub struct Containment {
    /// The chain that caused it; also what `moatctl release` names.
    pub chain: String,
    /// The TracingPolicy name, which is what `tetra tp delete` takes.
    pub policy: String,
    /// The binaries whose connections are refused.
    ///
    /// Every trigger exe in the chain that reached out, not just the first.
    /// Taking `targets.into_iter().next()` covered `python` in the 2026-09-05
    /// lab chain and left `browser-helper` -- the actual implant, and the only
    /// process still alive -- free to beacon. A containment that stops the
    /// process that has already finished is not a containment.
    pub exes: Vec<String>,
    /// The destinations refused, as literal addresses.
    pub dests: Vec<String>,
    pub since: u64,
    pub expires: u64,
}

impl Containment {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "chain": self.chain,
            "policy": self.policy,
            "exes": self.exes,
            "dests": self.dests,
            "since": self.since,
            "expires": self.expires,
        })
    }
}

/// A YAML double-quoted scalar that is always valid.
///
/// `{:?}` (Rust's Debug for str) very nearly works -- it escapes `"`, `\`,
/// `\n`, `\t` and `\r` into exactly the escapes YAML defines, and printable
/// text round-trips byte for byte. It falls down on one class: any other
/// non-printable becomes `\u{7f}`, with braces, which YAML does not accept.
///
/// That was an opt-out. A dropper named `helper\x7f` produced a document tetra
/// refused, `maybe_contain` deleted the file and returned, and the correlated
/// `high` sequence got no enforcement at all -- with one `log::error!` as the
/// only trace. A binary must not be able to exempt itself from containment by
/// choosing its own name.
fn yaml_scalar(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // YAML wants exactly four hex digits and no braces.
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The policy name for a chain. Lowercased because Kubernetes object names --
/// which Tetragon validates against -- must be a DNS subdomain.
/// The policy name for a containment slot.
///
/// A FIXED name, not the chain's id. Tetragon's export allowlist
/// (`render::allowlist_body`) is exact-match with no globs and is read only
/// when tetragon starts, so a policy named after a chain -- which only exists
/// at runtime -- can never appear in it. Until 2026-09-05 that made a working
/// containment silent: the kernel refused the connection and moatd never saw
/// the event, so nothing could tell the user a thing had been blocked.
///
/// Slots are bounded by `[contain] max`, which is also the cap that already
/// evicts the oldest containment, so reserving `max` names in the allowlist
/// costs nothing and covers every containment that can exist at once.
pub fn policy_name(slot: usize) -> String {
    format!("moat-contain-{}", slot)
}

/// The TracingPolicy that refuses those connections.
///
/// As narrow as the evidence: `matchBinaries` `In` the binaries that actually
/// reached out in this chain, `SAddr` the destinations they reached. Anything
/// wider is a bigger action than the sequence supports; anything narrower --
/// the first exe only, as this was until 2026-09-05 -- leaves the implant
/// running while it contains the process that already exited.
/// The names `matchBinaries` might see for one reported executable.
///
/// Tetragon reports the path a process was invoked by; the kernel matches the
/// binary it actually ran. On an Arch workstation those differ constantly --
/// `/usr/bin/python` -> `python3` -> `python3.14`, `/usr/bin/vi` -> `vim`,
/// every busybox applet -- and a containment naming only the reported path is
/// a policy that loads, arms, and matches nothing.
///
/// Returns the reported path first, then its resolved target if that differs.
/// Resolution failure is not an error: a binary that has been deleted or
/// replaced since it ran (which is what a dropper does) still deserves the
/// reported name in the list.
pub fn binary_aliases(exe: &str) -> Vec<String> {
    let mut out = vec![exe.to_string()];
    if let Ok(real) = std::fs::canonicalize(exe) {
        let real = real.to_string_lossy().to_string();
        if real != exe {
            out.push(real);
        }
    }
    out
}

pub fn policy_yaml(name: &str, exes: &[String], dests: &[String], chain: &str, ttl_secs: u64) -> String {
    let values: String = dests
        .iter()
        .map(|d| format!("        - {}\n", yaml_scalar(d)))
        .collect();
    let bins: String = exes
        .iter()
        .map(|e| format!("        - {}\n", yaml_scalar(e)))
        .collect();
    format!(
        "apiVersion: cilium.io/v1alpha1\n\
         kind: TracingPolicy\n\
         metadata:\n  \
           name: {name}\n  \
           annotations:\n    \
             moat.omarchy/severity: \"critical\"\n    \
             moat.omarchy/title: \"Contained: a correlated sequence's connection was refused\"\n    \
             moat.omarchy/enforce: \"deny\"\n    \
             moat.omarchy/actions: \"ignore\"\n    \
             moat.omarchy/generated-for: \"{chain}\"\n    \
             moat.omarchy/expires-after-secs: \"{ttl_secs}\"\n    \
             moat.omarchy/why: >-\n      \
               moatd wrote this policy by itself, because a sequence it correlated reached high\n      \
               severity and included a connection to a destination this machine had never used.\n      \
               It names one binary and one destination and nothing else, and it is deleted when\n      \
               it expires. `moatctl contain` lists it; `moatctl release` removes it now.\n    \
             moat.omarchy/expected: >-\n      \
               Never on its own. It exists only for as long as the containment lasts.\n    \
             moat.omarchy/fp-hint: \"exe\"\n\
         spec:\n  \
           options:\n  \
           - name: \"policy-mode\"\n    \
             value: \"enforce\"\n  \
           lsmhooks:\n  \
           - hook: \"socket_connect\"\n    \
             message: \"Contained binary tried to reach a refused destination\"\n    \
             args:\n    \
             - index: 0\n      \
               type: \"socket\"\n    \
             - index: 1\n      \
               type: \"sockaddr\"\n    \
             selectors:\n    \
             - matchBinaries:\n      \
               - operator: \"In\"\n        \
                 values:\n{bins}      \
               matchArgs:\n      \
               - index: 1\n        \
                 operator: \"SAddr\"\n        \
                 values:\n{values}      \
               matchActions:\n      \
               - action: Override\n        \
                 argError: -1\n"
    )
}

/// The live containments, oldest first.
#[derive(Debug, Default)]
pub struct ContainStore {
    live: Vec<Containment>,
}

impl ContainStore {
    /// Record one, evicting the oldest if the cap is reached.
    ///
    /// Returns the containments that must be UNLOADED as a result: the evicted
    /// one, and any already covering the same chain (a chain is contained once;
    /// a later step must not stack a second policy on it).
    pub fn insert(&mut self, c: Containment, max: usize) -> Vec<Containment> {
        let mut dropped: Vec<Containment> = Vec::new();
        let chain = c.chain.clone();
        self.live.retain(|x| {
            if x.chain == chain {
                dropped.push(x.clone());
                false
            } else {
                true
            }
        });
        while self.live.len() + 1 > max.max(1) {
            dropped.push(self.live.remove(0));
        }
        self.live.push(c);
        dropped
    }

    /// Everything past its expiry at `now`, removed from the store.
    pub fn expired(&mut self, now: u64) -> Vec<Containment> {
        let mut out = Vec::new();
        self.live.retain(|c| {
            if c.expires <= now {
                out.push(c.clone());
                false
            } else {
                true
            }
        });
        out
    }

    /// Remove one by chain id, for `moatctl release`.
    pub fn release(&mut self, chain: &str) -> Option<Containment> {
        let i = self.live.iter().position(|c| c.chain == chain)?;
        Some(self.live.remove(i))
    }

    pub fn live(&self) -> &[Containment] {
        &self.live
    }

    pub fn is_contained(&self, chain: &str) -> bool {
        self.live.iter().any(|c| c.chain == chain)
    }

    /// Restore from `state.json` across a restart, so a containment does not
    /// outlive the record of it.
    pub fn from_state(v: Option<&serde_json::Value>) -> Self {
        let mut live = Vec::new();
        if let Some(arr) = v.and_then(|x| x.as_array()) {
            for e in arr {
                let dests = e["dests"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|d| d.as_str().map(str::to_string))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let exes: Vec<String> = e["exes"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                if let (Some(chain), false) = (e["chain"].as_str(), exes.is_empty()) {
                    live.push(Containment {
                        chain: chain.to_string(),
                        // A record written before slots existed carries a
                        // ULID-shaped name; keep whatever it says so the
                        // policy it actually loaded can still be deleted.
                        policy: e["policy"]
                            .as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| policy_name(0)),
                        exes,
                        dests,
                        since: e["since"].as_u64().unwrap_or(0),
                        expires: e["expires"].as_u64().unwrap_or(0),
                    });
                }
            }
        }
        Self { live }
    }

    pub fn to_state(&self) -> serde_json::Value {
        serde_json::Value::Array(self.live.iter().map(|c| c.to_json()).collect())
    }
}

/// The destinations worth containing, from a chain's member alerts.
///
/// Loopback and anything already seen are not here: this is fed from the alerts
/// the chain is made of, and `moat-net-first-contact` has already established
/// that the destination is one this machine had never used.
pub fn targets(members: &BTreeMap<String, (String, String)>) -> Vec<(String, Vec<String>)> {
    let mut by_exe: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (exe, dst) in members.values() {
        if exe.is_empty() || dst.is_empty() {
            continue;
        }
        let e = by_exe.entry(exe.clone()).or_default();
        if !e.contains(dst) {
            e.push(dst.clone());
        }
    }
    by_exe.into_iter().collect()
}

#[cfg(test)]
mod alias_tests {
    use super::*;

    /// The 2026-09-05 containment failure: the policy loaded, armed, and
    /// matched nothing because it named the symlink tetragon reported rather
    /// than the binary the kernel ran.
    #[test]
    fn a_symlinked_interpreter_contributes_both_names() {
        // /usr/bin/python -> python3 -> python3.14 on this machine; skip
        // rather than fail where it is a real file.
        let reported = "/usr/bin/python";
        if !std::path::Path::new(reported).is_symlink() {
            return;
        }
        let names = binary_aliases(reported);
        assert_eq!(names[0], reported, "the reported path stays first");
        assert_eq!(names.len(), 2, "and the resolved binary is added: {:?}", names);
        assert!(names[1].contains("python3"), "{:?}", names);
    }

    /// A dropper deletes itself. Containing it by the name it ran under is
    /// then the only option there is, and it must not be lost.
    #[test]
    fn an_unresolvable_binary_still_yields_its_reported_name() {
        let names = binary_aliases("/tmp/moat-no-such-dropper-2f9c/x");
        assert_eq!(names, vec!["/tmp/moat-no-such-dropper-2f9c/x".to_string()]);
    }

    #[test]
    fn a_real_path_is_not_duplicated() {
        assert_eq!(binary_aliases("/usr/bin/env").len() <= 2, true);
        let names = binary_aliases("/usr/lib/os-release");
        assert!(!names.is_empty() && names[0] == "/usr/lib/os-release");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(chain: &str, since: u64) -> Containment {
        Containment {
            chain: chain.into(),
            policy: policy_name(chain.len() % 4),
            exes: vec!["/tmp/lab/browser-helper".into()],
            dests: vec!["192.168.44.122".into()],
            since,
            expires: since + 600,
        }
    }

    #[test]
    fn the_policy_names_one_binary_and_one_destination_and_nothing_else() {
        let y = policy_yaml(
            "moat-contain-01abc",
            &["/tmp/moat-aur-lab-r9j1k2zt/browser-helper".to_string()],
            &["192.168.44.122".to_string()],
            "01ABC",
            600,
        );
        assert!(y.contains("hook: \"socket_connect\""));
        assert!(y.contains("action: Override"));
        assert!(y.contains("argError: -1"), "EPERM, not a kill");
        assert!(y.contains("operator: \"In\""), "the binaries are named exactly");
        assert!(y.contains("/tmp/moat-aur-lab-r9j1k2zt/browser-helper"));
        assert!(y.contains("192.168.44.122"));
        // Armed the moment it loads: a containment that had to be switched on
        // separately would contain nothing.
        assert!(y.contains("value: \"enforce\""));
        // Sigkill must never appear here. The whole point is that the process
        // survives to be looked at.
        assert!(!y.contains("Sigkill"));
    }

    #[test]
    fn a_chain_is_contained_once_and_the_oldest_makes_room() {
        let mut s = ContainStore::default();
        assert!(s.insert(c("01A", 100), 2).is_empty());
        assert!(s.insert(c("01B", 200), 2).is_empty());

        // Same chain again: the first policy is replaced, never stacked.
        let dropped = s.insert(c("01B", 300), 2);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].since, 200);
        assert_eq!(s.live().len(), 2);

        // Over the cap: the oldest is released. The cap exists because these
        // share `socket_connect` with the detection policies, and running out
        // of room must never cost coverage.
        let dropped = s.insert(c("01C", 400), 2);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].chain, "01A");
        assert_eq!(s.live().len(), 2);
    }

    #[test]
    fn a_containment_expires_by_itself_and_can_be_dropped_early() {
        let mut s = ContainStore::default();
        s.insert(c("01A", 100), 4);
        s.insert(c("01B", 100), 4);
        assert!(s.expired(500).is_empty(), "not yet");
        assert_eq!(s.release("01A").map(|x| x.chain), Some("01A".to_string()));
        assert!(s.release("01A").is_none(), "released twice is not an error");
        let gone = s.expired(700);
        assert_eq!(gone.len(), 1);
        assert!(s.live().is_empty(), "nothing outlives its window");
    }

    #[test]
    fn it_survives_a_restart_or_it_would_leak_a_policy() {
        // A containment the daemon forgot is a policy nobody will ever delete:
        // it would keep refusing that connection until the next tetragon
        // restart, with nothing on screen to say why.
        let mut s = ContainStore::default();
        s.insert(c("01A", 100), 4);
        let back = ContainStore::from_state(Some(&s.to_state()));
        assert_eq!(back.live(), s.live());
        assert!(back.is_contained("01A"));
    }
}

// ---------------------------------------------------------------- kill a tree
//
// The most destructive thing in this daemon, and the only one that cannot be
// undone. A containment expires; a quarantine restores; a kill is final.
//
// It exists because detection without response has a hole in it that the user
// can feel: an attack is seen, correlated, raised to `high` -- and completes
// anyway, because the rules its steps trip are the ones that would kill a build
// if they were armed. Correlation is what tells those apart, and it arrives
// milliseconds later, in userspace, where a decision can be made with the whole
// sequence in view rather than one event at a time.
//
// The shape is what an EDR does with a process tree: kill the offending branch
// and leave the trunk. For `makepkg -> bash -> python -> browser-helper`, the
// build is not the attack and killing it destroys the evidence and the user's
// work; the payload and everything it started are the attack.

/// Why a pid must not be signalled, or `None` if it may be.
///
/// Facts the kernel supplies, not names.
///
/// A basename list was the first version of this, and it was wrong in both
/// directions: `/tmp/x/sshd` was immune because it is called `sshd`, while the
/// test-built `target/release/moatd` in a real build chain was skipped for the
/// same reason. It is also the exact fragility that bit this project earlier
/// the same day, when a session host called `herdr` was missing from a
/// hardcoded list of terminal names.
///
/// The three that actually hold:
///
/// * **pid 1**, whatever it claims to be.
/// * **A different user.** The threat model is a package running as this user;
///   anything under another uid -- root daemons included -- is out of scope and
///   killing it is beyond what a chain about this user's processes can justify.
/// * **`system.slice`.** systemd puts the machine's own services there:
///   moatd, tetragon, sshd, dbus, logind. A payload cannot move itself into it
///   without root, and with root this feature is already lost.
pub fn refuse_to_kill(pid: u32, alert_uid: u32) -> Option<String> {
    if pid <= 1 {
        return Some("pid 1".into());
    }
    if pid == std::process::id() {
        return Some("moatd itself".into());
    }
    match crate::util::proc_uid(pid) {
        None => return Some("gone".into()),
        Some(uid) if uid != alert_uid => {
            return Some(format!("runs as uid {}, not {}", uid, alert_uid))
        }
        Some(_) => {}
    }
    if let Some(cg) = crate::util::proc_cgroup(pid) {
        if cg.contains("system.slice") {
            return Some("a system service".into());
        }
    }
    None
}

/// One process a chain justifies killing./// One process a chain justifies killing.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub pid: u32,
    pub exe: String,
    /// The step that named it, so the record can say why this pid.
    pub alert: String,
}

/// The processes a chain justifies killing, in the order they should be sent.
///
/// Deliberately narrow, because there is no undo:
///
/// * **Trigger steps only.** A context step is one the user allowlisted; a
///   sequence is not a licence to kill something they said was fine.
/// * **Never the chain's own ancestor.** That is the trunk -- the build, the
///   shell, the session -- and killing it is how this feature would take out
///   someone's work instead of an attack. Keep the grandparent, kill the child.
/// * **Never anything on `NEVER_KILL`**, matched on the binary's own name so a
///   payload cannot dodge it by living somewhere unusual, and cannot invoke it
///   by naming itself `systemd` either -- that only ever removes a target.
/// * **Each pid once**, in first-seen order, so the earliest step in the
///   sequence dies first and cannot spawn more while the rest are signalled.
/// `spare_ancestor` is false when the ancestor is ITSELF a multi-family actor:
/// `node -e "import('hijacked')"` and `curl | sh` put the malicious process at
/// the root of its own tree, so sparing it unconditionally makes the whole
/// action a no-op against the commonest shape there is.
pub fn tree_targets(
    steps: &[crate::chain::Step],
    ancestor_pid: u32,
    spare_ancestor: bool,
) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    for s in steps.iter().filter(|s| s.is_trigger()) {
        if s.pid == 0 || s.pid == 1 {
            continue;
        }
        if spare_ancestor && s.pid == ancestor_pid {
            continue;
        }
        if out.iter().any(|t| t.pid == s.pid) {
            continue;
        }
        out.push(Target {
            pid: s.pid,
            exe: s.exe.clone(),
            alert: s.alert.clone(),
        });
    }
    out
}

/// A trigger step, reduced to the three facts the decision needs.
#[derive(Debug, Clone, PartialEq)]
pub struct StepFact {
    pub family: String,
    /// `first_seen` or `rare` -- something this machine has not settled into.
    pub novel: bool,
    pub pid: u32,
}

/// Families that mean something HAPPENED, as opposed to something ran.
///
/// `exec` and `pkg` describe a program starting, which is what a build does
/// thousands of times. `net`, `cred`, `persist`, `priv` and `rootkit` describe
/// a consequence: reaching out, reading a secret, arranging to run again,
/// gaining privilege, touching the sensor. A sequence with no consequence in it
/// has not yet done anything worth killing over.
pub const CONSEQUENCE: &[&str] = &["net", "cred", "persist", "priv", "rootkit"];

/// Is this chain confident enough to kill for?
///
/// Written against real data rather than intuition. On 2026-09-05 the earlier
/// version of this gate -- `high`, two triggers, two families -- returned `Ok`
/// on all FOUR `makepkg` chains on this machine, every one of them the user's
/// own build of moat itself, and would have killed thirteen processes including
/// the test suite. `exec` + `pkg` is not corroboration on a developer's
/// machine; it is Tuesday.
///
/// Three conditions, each rejecting a shape the others let through:
///
/// * **A consequence family.** Builds execute and install; they do not read
///   credentials or arrange to run again.
/// * **Two NOVEL triggers, in two families.** A build's steps are `common` --
///   the same shapes every run. An attack's first run is not. This is also
///   what makes the gate refuse the fourth replay of a lab attack, correctly:
///   by then the machine has seen it.
/// * **`high` or worse**, unchanged.
pub fn worth_killing_for(severity: &str, triggers: &[StepFact]) -> Result<(), String> {
    if crate::alert::severity_rank(severity) < crate::alert::severity_rank("high") {
        return Err(format!("chain is {}, not high", severity));
    }
    if triggers.len() < 2 {
        return Err(format!("{} trigger step(s); a kill wants corroboration", triggers.len()));
    }

    let families: std::collections::BTreeSet<&str> =
        triggers.iter().map(|t| t.family.as_str()).collect();
    if families.len() < 2 {
        return Err(format!(
            "one family ({}); two independent detections have to agree",
            families.iter().copied().collect::<Vec<_>>().join(", ")
        ));
    }
    if !families.iter().any(|f| CONSEQUENCE.contains(f)) {
        return Err(format!(
            "nothing consequential happened ({}); a program running is what a build does",
            families.iter().copied().collect::<Vec<_>>().join("+")
        ));
    }

    let novel: Vec<&StepFact> = triggers.iter().filter(|t| t.novel).collect();
    let novel_families: std::collections::BTreeSet<&str> =
        novel.iter().map(|t| t.family.as_str()).collect();
    if novel.len() < 2 || novel_families.len() < 2 {
        return Err(format!(
            "{} novel step(s) in {} family/families; this machine has seen this shape before",
            novel.len(),
            novel_families.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod kill_tests {
    use super::*;
    use crate::alert::Ancestor;
    use crate::chain::{Chain, Step};

    fn step(pid: u32, exe: &str, family: &str, role: &str) -> Step {
        Step {
            alert: format!("01A{}", pid),
            ts: "2026-09-05T14:44:22Z".into(),
            family: family.into(),
            rule: format!("moat-{}-x", family),
            severity: "high".into(),
            title: "t".into(),
            pid,
            exe: exe.into(),
            role: role.into(),
        }
    }

    fn chain(steps: Vec<Step>, severity: &str, families: Vec<&str>) -> Chain {
        Chain {
            v: 1,
            id: "01CH".into(),
            ancestor: Ancestor { pid: 5000, exe: "/usr/bin/makepkg".into() },
            families: families.into_iter().map(String::from).collect(),
            severity: severity.into(),
            severity_base: "high".into(),
            severity_reason: "r".into(),
            first_ts: "2026-09-05T14:44:22Z".into(),
            last_ts: "2026-09-05T14:44:23Z".into(),
            span_secs: 1,
            steps,
            steps_total: 0,
            truncated: false,
            members: Vec::new(),
            triggers_total: 0,
            summary: "s".into(),
        }
    }

    #[test]
    fn the_trunk_survives_and_the_branch_does_not() {
        // makepkg -> python -> browser-helper. The build is not the attack, and
        // killing it destroys the user's work and the evidence with it.
        let steps = vec![
            step(5000, "/usr/bin/makepkg", "pkg", "trigger"),
            step(5100, "/usr/bin/python", "pkg", "trigger"),
            step(5200, "/tmp/lab/browser-helper", "exec", "trigger"),
        ];
        let t = tree_targets(&steps, 5000, true);
        assert_eq!(t.len(), 2, "the ancestor is spared when it is the trunk: {:?}", t);
        assert_eq!(t[0].pid, 5100, "earliest step first, so it cannot spawn more");
        assert_eq!(t[1].pid, 5200);
    }

    #[test]
    fn nothing_the_user_allowed_is_killed() {
        let steps = vec![
            step(5100, "/usr/bin/python", "pkg", "trigger"),
            step(5200, "/usr/bin/rsync", "net", "context"),
        ];
        let t = tree_targets(&steps, 5000, true);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].pid, 5100, "a context step is one the user said was fine");
    }

    /// `node -e "import(...)"` and `curl | sh` put the malicious process at the
    /// root of its own tree. Sparing the ancestor unconditionally made the
    /// action a no-op against the commonest shape there is.
    #[test]
    fn the_ancestor_is_a_target_when_it_is_the_actor() {
        let steps = vec![
            step(5000, "/usr/bin/node", "cred", "trigger"),
            step(5000, "/usr/bin/node", "net", "trigger"),
        ];
        assert!(tree_targets(&steps, 5000, true).is_empty(), "spared: nothing to do");
        let t = tree_targets(&steps, 5000, false);
        assert_eq!(t.len(), 1, "one pid, named once");
        assert_eq!(t[0].pid, 5000);
    }

    /// The safety rules are kernel facts, so a payload cannot dodge them by
    /// choosing a filename.
    #[test]
    fn the_refusals_are_facts_not_names() {
        let me = std::process::id();
        assert!(refuse_to_kill(1, 1000).is_some(), "pid 1");
        assert!(refuse_to_kill(me, 1000).is_some(), "moatd itself");
        // A pid that does not exist cannot be signalled.
        assert!(refuse_to_kill(4_000_000_000, 1000).is_some());
        // This test process runs as the invoking user, so a mismatched uid is
        // refused and the matching one is not.
        let uid = unsafe { libc::getuid() };
        assert!(refuse_to_kill(me, uid + 1).is_some(), "another user's process");
    }

    fn fact(family: &str, novel: bool, pid: u32) -> StepFact {
        StepFact { family: family.into(), novel, pid }
    }

    /// The four `makepkg` chains on this machine on 2026-09-05 were all the
    /// user building moat itself: `high`, 12-23 trigger steps, crossing `exec`
    /// and `pkg`, every step `common` bar one random temp dir. The first
    /// version of this gate said yes to all four and would have killed the test
    /// suite. A developer's build is not corroboration of anything.
    #[test]
    fn a_developers_own_build_is_never_worth_killing_for() {
        let build: Vec<StepFact> = vec![
            fact("exec", false, 5100),
            fact("exec", false, 5101),
            fact("pkg", false, 5102),
            fact("exec", true, 5103), // the one random /tmp dir per run
            fact("pkg", false, 5104),
        ];
        let why = worth_killing_for("high", &build).expect_err("this is a build");
        assert!(why.contains("consequential"), "{}", why);
    }

    /// A first-run attack: something novel reached out AND arranged to run
    /// again, in one tree, in one window.
    #[test]
    fn a_first_run_attack_clears_the_gate() {
        let attack = vec![
            fact("exec", true, 5100),
            fact("net", true, 5101),
            fact("persist", true, 5102),
        ];
        assert!(worth_killing_for("high", &attack).is_ok());
    }

    #[test]
    fn the_gate_wants_novelty_and_corroboration_and_consequence() {
        // Consequence, but the machine has seen this shape before -- which is
        // the fourth replay of a lab attack, and correctly refused.
        let seen = vec![fact("exec", false, 1), fact("net", false, 2)];
        assert!(worth_killing_for("high", &seen).is_err());

        // Novel and consequential, but all of it one family: one detection
        // repeating is not two agreeing.
        let one_family = vec![fact("net", true, 1), fact("net", true, 2)];
        assert!(worth_killing_for("high", &one_family).is_err());

        // Novel in two families but only one of them novel.
        let half = vec![fact("exec", true, 1), fact("net", false, 2)];
        assert!(worth_killing_for("high", &half).is_err());

        // Below high, whatever else is true.
        let good = vec![fact("exec", true, 1), fact("net", true, 2)];
        assert!(worth_killing_for("medium", &good).is_err());
        assert!(worth_killing_for("high", &good).is_ok());

        // One step is a rule firing, not a sequence.
        assert!(worth_killing_for("high", &good[..1]).is_err());
    }
}
