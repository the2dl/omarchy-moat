//! Name resolution artifacts: which name was resolved to reach an address.
//!
//! Every network alert carries `{dst_ip, dst_port, domain}` and until
//! 2026-09-10 `domain` was always null -- there is no DNS in the kernel and
//! none in the export (NOTES gap 4). This module fills it from the one place on
//! an Omarchy machine that sees every resolution: **systemd-resolved**, whose
//! `io.systemd.Resolve.Monitor` varlink service streams each query it answers,
//! cache hits included, whichever way the query arrived (nss-resolve over
//! varlink, the `127.0.0.53` stub, the Docker bridge stub). `docs/DNS.md` is
//! the audit that led here; this file is its "build" section.
//!
//! What this is NOT:
//!
//! * not a DNS-tunnelling or C2 detector -- it is evidence on an alert;
//! * not reverse DNS -- moat never sends a query of its own. A PTR answers "what
//!   does the address's owner call it", not "what did this program ask for";
//! * not attribution -- resolved does not say which process asked, so the cache
//!   is keyed by address and the name on an alert is "the most recent name this
//!   machine resolved to that address", with its age, and nothing stronger.
//!
//! A name is never fabricated: a literal-IP connection, a resolution that
//! bypassed resolved (DoH inside a browser, a container with its own DNS), or
//! an answer older than `retain_secs` all leave `domain` null and the record
//! says "not recorded" out loud.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::SyncSender;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// resolved's monitor endpoint. World-connectable, but the subscribe method is
/// polkit-gated (`org.freedesktop.resolve1.subscribe-query-results`,
/// `auth_admin_keep`); uid 0 -- moatd -- passes without a prompt.
pub const DEFAULT_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve.Monitor";
const METHOD: &str = "io.systemd.Resolve.Monitor.SubscribeQueryResults";

/// The label the alert and the status put on this source.
pub const SOURCE: &str = "systemd-resolved";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NamesConfig {
    /// Subscribe to systemd-resolved's query stream and put the resolved name
    /// on every network alert. Off means every `domain` stays null and the
    /// record says why.
    pub enabled: bool,
    pub socket: String,
    /// How long a name stays attached to an address after it was resolved.
    /// Programs keep their own caches well past the DNS TTL, so this is
    /// hours, not the TTL; the alert carries the age so the reader can judge.
    pub retain_secs: u64,
    /// Distinct addresses remembered. Oldest go first at the cap.
    pub max_addresses: usize,
}

impl Default for NamesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket: DEFAULT_SOCKET.into(),
            retain_secs: 6 * 3_600,
            max_addresses: 8_192,
        }
    }
}

/// One address a resolution produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// What the program asked for.
    pub question: String,
    /// The owner name of the A/AAAA record that answered, when it is not the
    /// question -- i.e. the end of a CNAME chain.
    pub answer_name: Option<String>,
    pub ip: IpAddr,
    /// From the RR wire bytes when they decoded; informational.
    pub ttl: Option<u32>,
}

/// What the reader thread sends the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// `connected`, `unavailable: <reason>`, ... -- shown in `status`.
    State(String),
    Resolved(Vec<Resolved>),
}

#[derive(Debug, Clone)]
struct Entry {
    question: String,
    answer_name: Option<String>,
    ttl: Option<u32>,
    at: u64,
}

/// What `lookup` hands back for an alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub name: String,
    pub cname: Option<String>,
    /// Seconds between the resolution and `now`.
    pub age_secs: u64,
    pub ttl: Option<u32>,
}

/// address -> the names recently resolved to it, newest first.
#[derive(Debug)]
pub struct NameCache {
    by_ip: HashMap<IpAddr, VecDeque<Entry>>,
    /// Insertion order for eviction at the cap.
    order: VecDeque<IpAddr>,
    retain_secs: u64,
    max_addresses: usize,
    /// Answers recorded since start (each A/AAAA record is one).
    pub recorded: u64,
}

const PER_IP: usize = 4;

impl Default for NameCache {
    fn default() -> Self {
        let c = NamesConfig::default();
        NameCache::new(c.retain_secs, c.max_addresses)
    }
}

impl NameCache {
    pub fn new(retain_secs: u64, max_addresses: usize) -> NameCache {
        NameCache {
            by_ip: HashMap::new(),
            order: VecDeque::new(),
            retain_secs,
            max_addresses: max_addresses.max(1),
            recorded: 0,
        }
    }

    pub fn record(&mut self, r: &Resolved, now: u64) {
        self.recorded += 1;
        let entry = Entry {
            question: r.question.clone(),
            answer_name: r.answer_name.clone(),
            ttl: r.ttl,
            at: now,
        };
        match self.by_ip.get_mut(&r.ip) {
            Some(q) => {
                // The same name again just refreshes its timestamp; a different
                // name is a new fact about the address.
                q.retain(|e| e.question != entry.question);
                q.push_front(entry);
                q.truncate(PER_IP);
            }
            None => {
                if self.by_ip.len() >= self.max_addresses {
                    if let Some(old) = self.order.pop_front() {
                        self.by_ip.remove(&old);
                    }
                }
                self.by_ip.insert(r.ip, VecDeque::from([entry]));
                self.order.push_back(r.ip);
            }
        }
    }

    /// The most recent name resolved to `ip` inside the retention window.
    pub fn lookup(&self, ip: &IpAddr, now: u64) -> Option<Lookup> {
        let e = self.by_ip.get(ip)?.front()?;
        let age = now.saturating_sub(e.at);
        if age > self.retain_secs {
            return None;
        }
        Some(Lookup {
            name: e.question.clone(),
            cname: e.answer_name.clone(),
            age_secs: age,
            ttl: e.ttl,
        })
    }

    /// Drop everything past the window. Called from the daemon's tick.
    pub fn prune(&mut self, now: u64) {
        let keep = self.retain_secs;
        self.by_ip.retain(|_, q| {
            q.retain(|e| now.saturating_sub(e.at) <= keep);
            !q.is_empty()
        });
        self.order.retain(|ip| self.by_ip.contains_key(ip));
    }

    /// Distinct addresses currently held.
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }
}

// ------------------------------------------------------------------ parsing

/// DNS RR types this cares about. PTR (12) is deliberately absent: a reverse
/// lookup names an address by its owner's choice, which is a different claim
/// from "this program asked for this name", and recording it would let a PTR
/// of `1e100.net` stand in for whatever was actually looked up.
const TYPE_A: u64 = 1;
const TYPE_AAAA: u64 = 28;

/// One varlink reply from the monitor -> the addresses it resolved.
///
/// Shape (systemd 261, measured on this machine):
/// `{"parameters":{"state":"success","question":[{"class":1,"type":1,"name":"www.google.com"}, ...],
///   "answer":[{"rr":{"key":{"class":1,"type":1,"name":"www.google.com"},"address":[142,251,154,119]},
///             "raw":"<base64 wire RR>","ifindex":3}, ...]},"continues":true}`
///
/// `question` lists what was asked (A and AAAA together for a getaddrinfo);
/// each answer RR carries its owner name, which differs from the question at
/// the end of a CNAME chain. Every A/AAAA answer is attributed to the FIRST
/// question name, which is what the program typed.
pub fn parse_monitor_reply(v: &Value) -> Vec<Resolved> {
    let Some(p) = v.get("parameters") else {
        return Vec::new();
    };
    if p.get("state").and_then(Value::as_str) != Some("success") {
        return Vec::new();
    }
    let questions: Vec<(u64, String)> = p
        .get("question")
        .and_then(Value::as_array)
        .map(|qs| {
            qs.iter()
                .filter_map(|q| {
                    Some((
                        q.get("type").and_then(Value::as_u64)?,
                        normalize_name(q.get("name").and_then(Value::as_str)?),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    // Only forward lookups. A PTR question (in-addr.arpa) or anything
    // exotic is not a name-to-address claim and is not recorded.
    let Some(question) = questions
        .iter()
        .find(|(t, _)| *t == TYPE_A || *t == TYPE_AAAA)
        .map(|(_, n)| n.clone())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for a in p.get("answer").and_then(Value::as_array).into_iter().flatten() {
        let Some(rr) = a.get("rr") else { continue };
        let Some(key) = rr.get("key") else { continue };
        let rtype = key.get("type").and_then(Value::as_u64).unwrap_or(0);
        let Some(addr) = rr.get("address").and_then(Value::as_array) else {
            continue;
        };
        let bytes: Vec<u8> = addr
            .iter()
            .filter_map(|b| b.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect();
        let ip = match (rtype, bytes.len()) {
            (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            (TYPE_AAAA, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&bytes);
                IpAddr::V6(Ipv6Addr::from(o))
            }
            _ => continue,
        };
        let owner = key
            .get("name")
            .and_then(Value::as_str)
            .map(normalize_name)
            .unwrap_or_default();
        let answer_name = if !owner.is_empty() && owner != question {
            Some(owner)
        } else {
            None
        };
        let ttl = a.get("raw").and_then(Value::as_str).and_then(rr_ttl_from_raw);
        out.push(Resolved {
            question: question.clone(),
            answer_name,
            ip,
            ttl,
        });
    }
    out
}

/// Lowercase, no trailing dot: the form the feed is normalised to.
pub fn normalize_name(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The TTL out of a base64 wire-format RR: labels, then TYPE(2) CLASS(2)
/// TTL(4). A standalone RR has no compression pointers, so the name is a
/// plain label sequence ending in a zero byte.
pub fn rr_ttl_from_raw(b64: &str) -> Option<u32> {
    let bytes = base64_decode(b64)?;
    let mut i = 0;
    loop {
        let len = *bytes.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None; // a pointer; not expected here
        }
        i += len;
    }
    let ttl = bytes.get(i + 4..i + 8)?;
    Some(u32::from_be_bytes([ttl[0], ttl[1], ttl[2], ttl[3]]))
}

/// Standard alphabet, padding optional. Small enough not to be worth a crate.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

// ------------------------------------------------------------------- reader

/// Split a varlink byte stream into messages: JSON objects terminated by NUL.
/// Returns complete messages and leaves the remainder in `buf`.
pub fn split_messages(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(pos) = buf.iter().position(|b| *b == 0) {
        let msg: Vec<u8> = buf.drain(..=pos).collect();
        out.push(msg[..msg.len() - 1].to_vec());
    }
    out
}

/// Subscribe on an already-connected stream and pump replies into `tx` until
/// the stream ends or errors. Returns the reason it stopped.
fn pump(mut s: UnixStream, tx: &SyncSender<Msg>) -> String {
    let req = serde_json::json!({ "method": METHOD, "parameters": {}, "more": true });
    let mut bytes = serde_json::to_vec(&req).unwrap_or_default();
    bytes.push(0);
    if let Err(e) = s.write_all(&bytes) {
        return format!("write: {}", e);
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    let mut first = true;
    loop {
        let n = match s.read(&mut chunk) {
            Ok(0) => return "resolved closed the stream".into(),
            Ok(n) => n,
            Err(e) => return format!("read: {}", e),
        };
        buf.extend_from_slice(&chunk[..n]);
        // A hostile or broken peer could stream forever without a NUL.
        if buf.len() > 4 * 1024 * 1024 {
            return "message over 4 MiB without a terminator".into();
        }
        for m in split_messages(&mut buf) {
            let v: Value = match serde_json::from_slice(&m) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(e) = v.get("error").and_then(Value::as_str) {
                // `io.systemd.InteractiveAuthenticationRequired` is what a
                // non-root client sees; say it in the status rather than
                // retrying in silence.
                return format!("refused: {}", e);
            }
            if first {
                first = false;
                let _ = tx.send(Msg::State("connected".into()));
            }
            let resolved = parse_monitor_reply(&v);
            if !resolved.is_empty() && tx.send(Msg::Resolved(resolved)).is_err() {
                return "daemon gone".into();
            }
        }
    }
}

/// Run the reader until the receiver goes away. Reconnects with backoff, so a
/// resolved restart costs a few seconds of names and nothing else.
pub fn run(socket: String, tx: SyncSender<Msg>) {
    let mut backoff = Duration::from_secs(2);
    loop {
        let why = match UnixStream::connect(&socket) {
            Ok(s) => pump(s, &tx),
            Err(e) => format!("unavailable: {}: {}", socket, e),
        };
        if tx.send(Msg::State(why.clone())).is_err() {
            return;
        }
        log::warn!("names: {} (retrying in {} s)", why, backoff.as_secs());
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// Start the reader thread. The channel is bounded: a burst of resolutions
/// waits on the daemon rather than growing without limit, and the daemon
/// drains it on every pass of its loop.
pub fn spawn(cfg: &NamesConfig) -> std::sync::mpsc::Receiver<Msg> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1024);
    let socket = cfg.socket.clone();
    std::thread::Builder::new()
        .name("moat-names".into())
        .spawn(move || run(socket, tx))
        .expect("spawn names reader");
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `resolvectl monitor --json=short` on 2026-09-10, minus
    /// most of the answer set.
    fn google() -> Value {
        serde_json::json!({"parameters": {"state":"success",
            "question":[{"class":1,"type":1,"name":"www.google.com"},{"class":1,"type":28,"name":"www.google.com"}],
            "answer":[
              {"rr":{"key":{"class":1,"type":28,"name":"www.google.com"},"address":[32,1,72,96,72,38,119,0,0,0,0,0,0,0,0,0]},
               "raw":"A3d3dwZnb29nbGUDY29tAAAcAAEAAADgABAgAUhgSCZ3AAAAAAAAAAAA","ifindex":3},
              {"rr":{"key":{"class":1,"type":1,"name":"www.google.com"},"address":[142,251,154,119]},
               "raw":"A3d3dwZnb29nbGUDY29tAAABAAEAAAEZAASO+5p3","ifindex":3}
            ]}, "continues": true})
    }

    #[test]
    fn a_reply_maps_every_address_to_the_question_name() {
        let r = parse_monitor_reply(&google());
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].question, "www.google.com");
        assert_eq!(r[1].ip, "142.251.154.119".parse::<IpAddr>().unwrap());
        assert_eq!(r[1].answer_name, None, "no CNAME: owner == question");
        assert_eq!(r[1].ttl, Some(281), "TTL decoded from the wire bytes");
        assert_eq!(r[0].ip, "2001:4860:4826:7700::".parse::<IpAddr>().unwrap());
        assert_eq!(r[0].ttl, Some(224));
    }

    #[test]
    fn a_cname_chain_keeps_what_the_program_asked_for() {
        let v = serde_json::json!({"parameters": {"state":"success",
            "question":[{"class":1,"type":1,"name":"www.microsoft.com"}],
            "answer":[
              {"rr":{"key":{"class":1,"type":5,"name":"www.microsoft.com"},"name":"www.microsoft.com-c-3.edgekey.net"}},
              {"rr":{"key":{"class":1,"type":1,"name":"e13678.dscb.akamaiedge.net"},"address":[23,45,67,89]}}
            ]}});
        let r = parse_monitor_reply(&v);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].question, "www.microsoft.com");
        assert_eq!(r[0].answer_name.as_deref(), Some("e13678.dscb.akamaiedge.net"));
    }

    #[test]
    fn reverse_lookups_and_failures_are_not_recorded() {
        let ptr = serde_json::json!({"parameters": {"state":"success",
            "question":[{"class":1,"type":12,"name":"119.154.251.142.in-addr.arpa"}],
            "answer":[{"rr":{"key":{"class":1,"type":12,"name":"119.154.251.142.in-addr.arpa"},"name":"x.1e100.net"}}]}});
        assert!(parse_monitor_reply(&ptr).is_empty(), "a PTR is not a name the program asked for");
        let nx = serde_json::json!({"parameters": {"state":"rcode","rcode":3,
            "question":[{"class":1,"type":1,"name":"nonexistent.invalid.example"}]}});
        assert!(parse_monitor_reply(&nx).is_empty());
        assert!(parse_monitor_reply(&serde_json::json!({"error":"io.systemd.InteractiveAuthenticationRequired"})).is_empty());
    }

    #[test]
    fn names_are_normalised_like_the_feed() {
        assert_eq!(normalize_name("WWW.Example.COM."), "www.example.com");
        let v = serde_json::json!({"parameters": {"state":"success",
            "question":[{"class":1,"type":1,"name":"Evil.Example."}],
            "answer":[{"rr":{"key":{"class":1,"type":1,"name":"evil.example"},"address":[10,0,0,1]}}]}});
        let r = parse_monitor_reply(&v);
        assert_eq!(r[0].question, "evil.example");
        assert_eq!(r[0].answer_name, None, "case and the trailing dot are not a CNAME");
    }

    #[test]
    fn the_cache_answers_newest_first_and_forgets_on_time() {
        let mut c = NameCache::new(100, 2);
        let ip: IpAddr = "142.251.154.119".parse().unwrap();
        let mk = |q: &str, ip: IpAddr| Resolved { question: q.into(), answer_name: None, ip, ttl: Some(60) };
        c.record(&mk("www.google.com", ip), 1_000);
        c.record(&mk("google.com", ip), 1_010);
        let l = c.lookup(&ip, 1_020).unwrap();
        assert_eq!(l.name, "google.com");
        assert_eq!(l.age_secs, 10);
        assert_eq!(l.ttl, Some(60));
        // Past retention: null, not a stale name.
        assert!(c.lookup(&ip, 1_111).is_none());
        c.prune(1_111);
        assert!(c.is_empty());

        // The address cap evicts the oldest address, not the newest.
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let d: IpAddr = "10.0.0.3".parse().unwrap();
        c.record(&mk("a", a), 1);
        c.record(&mk("b", b), 2);
        c.record(&mk("d", d), 3);
        assert_eq!(c.len(), 2);
        assert!(c.lookup(&a, 3).is_none());
        assert!(c.lookup(&d, 3).is_some());
        assert_eq!(c.recorded, 5);
    }

    #[test]
    fn varlink_messages_split_on_nul() {
        let mut buf = b"{\"a\":1}\0{\"b\":2}\0{\"partial".to_vec();
        let msgs = split_messages(&mut buf);
        assert_eq!(msgs, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
        assert_eq!(buf, b"{\"partial".to_vec());
    }

    #[test]
    fn base64_and_wire_ttl() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert!(base64_decode("not base64!").is_none());
        // www.google.com A, TTL 0x119 = 281.
        assert_eq!(rr_ttl_from_raw("A3d3dwZnb29nbGUDY29tAAABAAEAAAEZAASO+5p3"), Some(281));
        assert_eq!(rr_ttl_from_raw("AAAA"), None);
    }

    #[test]
    fn the_reader_reports_a_refusal_rather_than_retrying_in_silence() {
        // A fake resolved that answers the subscribe with the error a
        // non-root client gets. The state message has to carry it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitor.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut b = [0u8; 1];
            while s.read(&mut b).unwrap() == 1 && b[0] != 0 {
                req.push(b[0]);
            }
            let v: Value = serde_json::from_slice(&req).unwrap();
            assert_eq!(v["method"], METHOD);
            assert_eq!(v["more"], true);
            s.write_all(b"{\"error\":\"io.systemd.InteractiveAuthenticationRequired\"}\0")
                .unwrap();
        });
        let (tx, _rx) = std::sync::mpsc::sync_channel(8);
        let why = pump(UnixStream::connect(&path).unwrap(), &tx);
        server.join().unwrap();
        assert_eq!(why, "refused: io.systemd.InteractiveAuthenticationRequired");
    }

    #[test]
    fn the_reader_streams_resolutions_after_a_successful_subscribe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitor.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let reply = serde_json::to_vec(&google()).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut b = [0u8; 1];
            while s.read(&mut b).unwrap() == 1 && b[0] != 0 {}
            // Two replies in one write, then hang up.
            let mut out = reply.clone();
            out.push(0);
            out.extend_from_slice(&reply);
            out.push(0);
            s.write_all(&out).unwrap();
        });
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        let why = pump(UnixStream::connect(&path).unwrap(), &tx);
        server.join().unwrap();
        assert_eq!(why, "resolved closed the stream");
        assert_eq!(rx.recv().unwrap(), Msg::State("connected".into()));
        match rx.recv().unwrap() {
            Msg::Resolved(r) => assert_eq!(r.len(), 2),
            other => panic!("{:?}", other),
        }
        assert!(matches!(rx.recv().unwrap(), Msg::Resolved(_)));
    }
}
