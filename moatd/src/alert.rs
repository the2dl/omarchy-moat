//! The alert record of CONTRACT §4, and the folded view readers get.
//!
//! Nothing is ever rewritten in place: state changes are appended as
//! `{"v":1,"id":"<same id>","update":{...}}` lines and folded by id.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const ALERT_V: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessRef {
    pub pid: u32,
    pub uid: u32,
    pub exe: String,
    pub args: String,
    pub cwd: String,
    pub start_ts: String,
    pub ancestry: Vec<Ancestor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ancestor {
    pub pid: u32,
    pub exe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileRef {
    pub path: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetRef {
    pub dst_ip: String,
    pub dst_port: u16,
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IocRef {
    pub source: String,
    pub matched: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExplainOption {
    pub scope: String,
    /// Ready to paste: `moatctl ignore <id> --scope exe`.
    pub cmd: String,
    /// The exact TOML block that command would write.
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IfExpected {
    /// The policy's `fp-hint`: the scope we recommend first.
    pub hint: String,
    pub options: Vec<ExplainOption>,
    /// Where the block lands.
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Explain {
    pub what: String,
    pub why: String,
    pub evidence: Vec<String>,
    pub expected: String,
    pub if_expected: IfExpected,
    pub next: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub v: u32,
    pub id: String,
    pub ts: String,
    pub severity: String,
    pub rule: String,
    pub family: String,
    pub title: String,
    pub summary: String,
    pub process: ProcessRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc: Option<IocRef>,
    pub rotate: Vec<String>,
    pub explain: Explain,
    /// `none` | `killed` | `quarantined`. Only ever `killed` once a
    /// `process_exit` with `signal: SIGKILL` confirmed it (NOTES §7).
    pub action_taken: String,
    pub actions: Vec<String>,
    pub acked: bool,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// Not serialised: only the live daemon uses it, to tie a later
    /// `process_exit` back to the alert that predicted the kill.
    #[serde(skip)]
    pub exec_id: String,
}

impl Alert {
    pub fn severity_rank(&self) -> u8 {
        severity_rank(&self.severity)
    }
}

pub fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

/// One appended state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateLine {
    pub v: u32,
    pub id: String,
    pub update: Map<String, Value>,
}

impl UpdateLine {
    pub fn new(id: &str) -> UpdateLine {
        UpdateLine {
            v: ALERT_V,
            id: id.to_string(),
            update: Map::new(),
        }
    }
    pub fn set(mut self, key: &str, value: Value) -> Self {
        self.update.insert(key.to_string(), value);
        self
    }
}

/// Apply an update line to an alert, the way every reader must.
pub fn fold(alert: &mut Alert, update: &Map<String, Value>) {
    for (k, v) in update {
        match (k.as_str(), v) {
            ("acked", Value::Bool(b)) => alert.acked = *b,
            ("action_taken", Value::String(s)) => alert.action_taken = s.clone(),
            ("count", Value::Number(n)) => alert.count = n.as_u64(),
            ("severity", Value::String(s)) => alert.severity = s.clone(),
            ("ts", Value::String(s)) => alert.ts = s.clone(),
            _ => {}
        }
    }
}

/// One line of `alerts.jsonl`: either a full alert or an update.
pub enum Record {
    Full(Box<Alert>),
    Update(UpdateLine),
}

pub fn parse_record(line: &str) -> Option<Record> {
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("update").is_some() {
        serde_json::from_value::<UpdateLine>(v).ok().map(Record::Update)
    } else {
        serde_json::from_value::<Alert>(v)
            .ok()
            .map(|a| Record::Full(Box::new(a)))
    }
}

/// Shared fixture: other modules' tests need a realistic alert.
#[cfg(test)]
pub mod tests_support {
    use super::*;

    pub fn demo_alert(id: &str) -> Alert {
        Alert {
            v: ALERT_V,
            id: id.into(),
            ts: "2026-09-03T16:21:07.123Z".into(),
            severity: "high".into(),
            rule: "moat-cred-ssh-private-key-read".into(),
            family: "cred".into(),
            title: "Private SSH key read by an unexpected program".into(),
            summary: "node (pid 41233) read /home/dan/.ssh/id_rsa.".into(),
            process: ProcessRef {
                pid: 41233,
                uid: 1000,
                exe: "/usr/bin/node".into(),
                args: "setup.mjs".into(),
                cwd: "/home/dan/proj".into(),
                start_ts: "2026-09-03T16:21:06.900Z".into(),
                ancestry: vec![Ancestor {
                    pid: 41230,
                    exe: "/usr/bin/sh".into(),
                }],
            },
            file: Some(FileRef {
                path: "/home/dan/.ssh/id_rsa".into(),
                sha256: None,
            }),
            net: None,
            ioc: None,
            rotate: vec!["ssh-key".into()],
            explain: Explain {
                what: "node read your private SSH key.".into(),
                why: "why".into(),
                evidence: vec!["hook: ...".into()],
                expected: "expected".into(),
                if_expected: IfExpected {
                    hint: "exe".into(),
                    options: vec![ExplainOption {
                        scope: "exe".into(),
                        cmd: "moatctl ignore 01J8ZK6B4Q3M7N9P2R5S8T1V4W --scope exe".into(),
                        line: "[[rule]]\nname = \"x\"\n".into(),
                    }],
                    file: "/etc/moat/allowlist.d/user.toml".into(),
                },
                next: vec!["rotate".into()],
            },
            action_taken: "none".into(),
            actions: vec!["kill".into()],
            acked: false,
            mode: "monitor".into(),
            count: None,
            exec_id: "abc".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::demo_alert;
    use super::*;

    fn demo() -> Alert {
        demo_alert("01J8ZK6B4Q3M7N9P2R5S8T1V4W")
    }

    #[test]
    fn a_full_alert_round_trips_as_one_line() {
        let a = demo();
        let line = serde_json::to_string(&a).unwrap();
        assert!(!line.contains('\n'));
        assert!(!line.contains("exec_id"), "internal field must not leak");
        assert!(!line.contains("\"count\""), "absent optionals are omitted");
        assert!(!line.contains("\"net\""));
        match parse_record(&line).unwrap() {
            Record::Full(b) => {
                let mut back = *b;
                back.exec_id = a.exec_id.clone();
                assert_eq!(back, a);
            }
            _ => panic!("should parse as a full alert"),
        }
    }

    #[test]
    fn updates_fold_by_id() {
        let mut a = demo();
        let u = UpdateLine::new(&a.id)
            .set("acked", Value::Bool(true))
            .set("action_taken", Value::String("killed".into()))
            .set("count", Value::from(3u64));
        let line = serde_json::to_string(&u).unwrap();
        match parse_record(&line).unwrap() {
            Record::Update(u) => {
                assert_eq!(u.id, a.id);
                fold(&mut a, &u.update);
            }
            _ => panic!("should parse as an update"),
        }
        assert!(a.acked);
        assert_eq!(a.action_taken, "killed");
        assert_eq!(a.count, Some(3));
    }

    #[test]
    fn severity_ordering() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
    }
}
