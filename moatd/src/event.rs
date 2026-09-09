//! Tetragon JSON export parsing.
//!
//! Shapes come from TETRAGON-NOTES §9: `protojson` with `UseProtoNames: true`,
//! so every field is snake_case, one event per line, the event kind is a
//! top-level oneof key. Unknown fields are ignored on purpose — the export gains
//! fields between Tetragon releases and we must not stop parsing because of it.

use serde::Deserialize;
use serde_json::Value;

/// One line of the export file.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawEvent {
    pub process_exec: Option<ExecEvent>,
    pub process_exit: Option<ExitEvent>,
    pub process_kprobe: Option<HookEvent>,
    pub process_lsm: Option<HookEvent>,
    pub process_tracepoint: Option<HookEvent>,
    /// Tetragon telling us it is DROPPING events.
    ///
    /// `cgroup-rate` is configured at 20000 events/s per cgroup PER CPU, and serde
    /// ignores unknown fields -- so this message was parsed into nothing and
    /// discarded. An attacker who exceeds that rate in their own cgroup gets
    /// the sensor to drop their own events, which is the cheapest blinding
    /// there is: unlike every other evasion it leaves no record at all,
    /// because the record is what never gets written.
    pub process_throttle: Option<ThrottleEvent>,
    pub node_name: Option<String>,
    pub time: Option<String>,
}

/// `{"type":"THROTTLE_START"|"THROTTLE_STOP","cgroup":"...","ticks":N}`
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ThrottleEvent {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub cgroup: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ExecEvent {
    pub process: Option<Process>,
    pub parent: Option<Process>,
    #[serde(default)]
    pub ancestors: Vec<Process>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ExitEvent {
    pub process: Option<Process>,
    pub parent: Option<Process>,
    /// Present only on signal death. This — not `action` — is what proves a kill
    /// happened (NOTES §7).
    pub signal: Option<String>,
    pub status: Option<u32>,
    pub time: Option<String>,
}

/// `process_kprobe`, `process_lsm` and `process_tracepoint` share enough shape
/// to be one struct; `subsys`/`event` are only set on tracepoints.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HookEvent {
    pub process: Option<Process>,
    pub parent: Option<Process>,
    #[serde(default)]
    pub ancestors: Vec<Process>,
    pub function_name: Option<String>,
    pub subsys: Option<String>,
    pub event: Option<String>,
    #[serde(default)]
    pub args: Vec<Value>,
    #[serde(rename = "return")]
    pub ret: Option<Value>,
    pub action: Option<String>,
    pub return_action: Option<String>,
    pub policy_name: Option<String>,
    pub message: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub ima_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct Process {
    pub exec_id: Option<String>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub uid: Option<u32>,
    pub auid: Option<u32>,
    pub cwd: Option<String>,
    pub binary: Option<String>,
    pub arguments: Option<String>,
    pub flags: Option<String>,
    pub start_time: Option<String>,
    pub parent_exec_id: Option<String>,
    pub in_init_tree: Option<bool>,
    /// Only present with `--enable-process-ns`. The namespaces the process was
    /// in AT EVENT TIME, which is the only time they can be trusted: by the
    /// time moatd reads the event, a `psql` or a `pg_isready` in a container has
    /// long exited and `/proc/<pid>/ns/mnt` is gone.
    pub ns: Option<Namespaces>,
    pub binary_properties: Option<BinaryProperties>,
    /// Only present with `--enable-process-environment-variables`. protojson
    /// capitalises the keys of this message (NOTES §4).
    #[serde(default)]
    pub environment_variables: Vec<EnvVar>,
}

/// `process.ns`. Only `mnt` is read: it is the one that answers "is this this
/// machine's filesystem", which is the question every path-matching policy is
/// really asking.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct Namespaces {
    pub mnt: Option<Namespace>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct Namespace {
    pub inum: Option<u64>,
    #[serde(rename = "is_host", alias = "isHost")]
    pub is_host: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct BinaryProperties {
    pub setuid: Option<u32>,
    pub setgid: Option<u32>,
    #[serde(default)]
    pub privileges_changed: Vec<String>,
    pub file: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct EnvVar {
    #[serde(rename = "Key", alias = "key")]
    pub key: Option<String>,
    #[serde(rename = "Value", alias = "value")]
    pub value: Option<String>,
}

impl Process {
    /// Did this run in a container?
    ///
    /// `None` when the sensor did not say -- `--enable-process-ns` off, or an
    /// event shape that carries no `ns`. The caller decides what silence means;
    /// this does not guess, because the two callers want opposite defaults.
    pub fn in_container(&self) -> Option<bool> {
        self.ns.as_ref()?.mnt.as_ref()?.is_host.map(|host| !host)
    }

    pub fn exe(&self) -> &str {
        self.binary.as_deref().unwrap_or("")
    }
    pub fn comm(&self) -> &str {
        crate::util::basename(self.exe())
    }
    pub fn args(&self) -> &str {
        self.arguments.as_deref().unwrap_or("")
    }
    pub fn env(&self, key: &str) -> Option<&str> {
        self.environment_variables
            .iter()
            .find(|e| e.key.as_deref() == Some(key))
            .and_then(|e| e.value.as_deref())
    }
}

/// Which oneof the line carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    Kprobe,
    Lsm,
    Tracepoint,
}

impl HookKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookKind::Kprobe => "process_kprobe",
            HookKind::Lsm => "process_lsm",
            HookKind::Tracepoint => "process_tracepoint",
        }
    }
}

/// Anything that is not exec/exit, flattened so the rest of the daemon never
/// has to care which oneof carried it.
#[derive(Debug, Clone)]
pub struct HookHit<'a> {
    pub kind: HookKind,
    pub ev: &'a HookEvent,
}

impl<'a> HookHit<'a> {
    /// `security_file_open`, or `raw_syscalls/sys_enter` for tracepoints.
    pub fn hook_name(&self) -> String {
        if let Some(f) = &self.ev.function_name {
            return f.clone();
        }
        match (&self.ev.subsys, &self.ev.event) {
            (Some(s), Some(e)) => format!("{}/{}", s, e),
            (Some(s), None) => s.clone(),
            _ => "unknown".into(),
        }
    }

    pub fn policy_name(&self) -> &str {
        self.ev.policy_name.as_deref().unwrap_or("")
    }

    /// First `file_arg`/`path_arg`/`linux_binprm_arg` path in the argument list.
    pub fn file_path(&self) -> Option<String> {
        self.ev.args.iter().find_map(arg_file_path)
    }

    /// The `linux_binprm` argument only: the file being **executed**.
    ///
    /// Unlike [`file_path`](Self::file_path) this never returns the file an
    /// open-hook touched, so it is safe to use as "what binary is this really",
    /// which is how a `/proc/self/fd/<n>` exe gets its name back.
    pub fn binprm_path(&self) -> Option<String> {
        self.ev.args.iter().find_map(|a| {
            a.get("linux_binprm_arg")
                .and_then(|v| v.get("path"))
                .and_then(|p| p.as_str())
                .map(str::to_string)
        })
    }

    /// First `int_arg` — the access mask on `file_post_open` /
    /// `file_permission`, the mode on `path_chmod`, the id on module hooks.
    pub fn int_arg(&self) -> Option<i64> {
        self.ev.args.iter().find_map(|a| {
            a.get("int_arg")
                .or_else(|| a.get("uint_arg"))
                .and_then(json_i64)
        })
    }

    pub fn string_arg(&self) -> Option<String> {
        self.ev.args.iter().find_map(|a| {
            a.get("string_arg")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
    }

    /// Destination of a connection, from either a `sock_arg` (`tcp_connect`) or
    /// a `sockaddr_arg` (LSM `socket_connect`). NOTES §5.
    pub fn dest(&self) -> Option<(String, u16)> {
        for a in &self.ev.args {
            if let Some(s) = a.get("sock_arg") {
                let ip = s.get("daddr").and_then(|v| v.as_str())?.to_string();
                let port = s.get("dport").and_then(json_i64).unwrap_or(0) as u16;
                return Some((ip, port));
            }
            if let Some(s) = a.get("sockaddr_arg") {
                let ip = s.get("addr").and_then(|v| v.as_str())?.to_string();
                let port = s.get("port").and_then(json_i64).unwrap_or(0) as u16;
                return Some((ip, port));
            }
        }
        None
    }

    /// Did the policy *configure* a kill? In monitor mode this is still
    /// reported, so it is a hint only (NOTES §7).
    /// The kernel REFUSED the operation (`Override`) rather than killing the
    /// process. `connect()` returned -EPERM and the program is still running,
    /// so this is a containment that already happened -- unlike a kill, which
    /// is only believed once `process_exit` reports SIGKILL.
    pub fn action_is_deny(&self) -> bool {
        matches!(self.ev.action.as_deref(), Some("KPROBE_ACTION_OVERRIDE"))
    }

    pub fn action_is_kill(&self) -> bool {
        matches!(
            self.ev.action.as_deref(),
            Some("KPROBE_ACTION_SIGKILL") | Some("KPROBE_ACTION_SIGNAL")
        )
    }
}

fn arg_file_path(a: &Value) -> Option<String> {
    for key in ["file_arg", "path_arg", "linux_binprm_arg"] {
        if let Some(v) = a.get(key) {
            if let Some(p) = v.get("path").and_then(|p| p.as_str()) {
                return Some(p.to_string());
            }
        }
    }
    None
}

/// protojson emits 64-bit ints as strings; accept both.
fn json_i64(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

impl RawEvent {
    pub fn parse(line: &str) -> Option<RawEvent> {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            return None;
        }
        serde_json::from_str(line).ok()
    }

    pub fn hook(&self) -> Option<HookHit<'_>> {
        if let Some(e) = &self.process_kprobe {
            return Some(HookHit {
                kind: HookKind::Kprobe,
                ev: e,
            });
        }
        if let Some(e) = &self.process_lsm {
            return Some(HookHit {
                kind: HookKind::Lsm,
                ev: e,
            });
        }
        if let Some(e) = &self.process_tracepoint {
            return Some(HookHit {
                kind: HookKind::Tracepoint,
                ev: e,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample_lines() -> Vec<String> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sample.log");
        std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn every_sample_line_parses() {
        let lines = sample_lines();
        assert!(lines.len() >= 8, "need >= 8 sample lines, got {}", lines.len());
        for l in &lines {
            let ev = RawEvent::parse(l).unwrap_or_else(|| panic!("failed to parse: {}", l));
            assert!(
                ev.process_exec.is_some()
                    || ev.process_exit.is_some()
                    || ev.hook().is_some(),
                "line carried no known oneof: {}",
                l
            );
        }
    }

    #[test]
    fn exec_carries_process_and_parent() {
        let ev = sample_lines()
            .iter()
            .filter_map(|l| RawEvent::parse(l))
            .find(|e| {
                e.process_exec
                    .as_ref()
                    .and_then(|x| x.process.as_ref())
                    .and_then(|p| p.pid)
                    == Some(41233)
            })
            .unwrap();
        let ex = ev.process_exec.unwrap();
        let p = ex.process.unwrap();
        assert_eq!(p.pid, Some(41233));
        assert!(p.exe().ends_with("/node"));
        assert_eq!(ex.parent.unwrap().comm(), "sh");
    }

    #[test]
    fn lsm_file_hit_exposes_path_and_mask() {
        let ev = sample_lines()
            .iter()
            .filter_map(|l| RawEvent::parse(l))
            .find(|e| e.process_lsm.is_some())
            .unwrap();
        let h = ev.hook().unwrap();
        assert_eq!(h.kind, HookKind::Lsm);
        assert_eq!(h.hook_name(), "file_post_open");
        assert!(h.policy_name().starts_with("moat-cred-"));
        assert!(h.file_path().unwrap().contains("/.ssh/"));
        assert_eq!(h.int_arg(), Some(4)); // MAY_READ
    }

    #[test]
    fn sock_arg_yields_destination() {
        let ev = sample_lines()
            .iter()
            .filter_map(|l| RawEvent::parse(l))
            .find(|e| {
                e.hook()
                    .map(|h| h.hook_name() == "tcp_connect")
                    .unwrap_or(false)
            })
            .unwrap();
        let h = ev.hook().unwrap();
        let (ip, port) = h.dest().unwrap();
        assert_eq!(ip, "185.220.101.55");
        assert_eq!(port, 4444);
        assert!(h.action_is_kill());
    }

    #[test]
    fn exit_signal_is_the_kill_proof() {
        let ev = sample_lines()
            .iter()
            .filter_map(|l| RawEvent::parse(l))
            .find(|e| {
                e.process_exit
                    .as_ref()
                    .map(|x| x.signal.is_some())
                    .unwrap_or(false)
            })
            .unwrap();
        assert_eq!(ev.process_exit.unwrap().signal.as_deref(), Some("SIGKILL"));
    }

    #[test]
    fn unknown_fields_do_not_break_parsing() {
        let l = r#"{"process_exec":{"process":{"pid":1,"binary":"/bin/x","future_field":7}},"brand_new":true}"#;
        let ev = RawEvent::parse(l).unwrap();
        assert_eq!(ev.process_exec.unwrap().process.unwrap().pid, Some(1));
    }
}

#[cfg(test)]
mod ns_tests {
    use super::Process;

    fn parse(js: &str) -> Process {
        serde_json::from_str(js).expect("parses")
    }

    #[test]
    fn a_host_process_is_not_in_a_container() {
        let p = parse(r#"{"ns":{"mnt":{"inum":4026531840,"is_host":true}}}"#);
        assert_eq!(p.in_container(), Some(false));
    }

    #[test]
    fn a_process_whose_mount_namespace_is_not_the_hosts_is() {
        let p = parse(r#"{"ns":{"mnt":{"inum":4026532999,"is_host":false}}}"#);
        assert_eq!(p.in_container(), Some(true));
    }

    #[test]
    fn protojson_camel_case_is_accepted_too() {
        // Tetragon's protojson export capitalises differently to its proto
        // field names; NOTES section 4 records the same trap for env vars.
        let p = parse(r#"{"ns":{"mnt":{"inum":4026532999,"isHost":false}}}"#);
        assert_eq!(p.in_container(), Some(true));
    }

    #[test]
    fn a_sensor_that_did_not_say_is_not_guessed_at() {
        // `--enable-process-ns` off, or an older daemon. The caller decides
        // what silence means; this must never invent an answer.
        assert_eq!(parse("{}").in_container(), None);
        assert_eq!(parse(r#"{"ns":{}}"#).in_container(), None);
        assert_eq!(parse(r#"{"ns":{"mnt":{"inum":1}}}"#).in_container(), None);
    }
}
