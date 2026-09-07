//! `moat-ship` — getting the record off the machine.
//!
//! # Why this is not in moatd
//!
//! `moatd` runs as root with the kernel sensor attached to it. Putting an
//! outbound HTTPS client there would put a TLS stack, a retry loop and a
//! response parser inside the one process that owns detection, and would give
//! a remote endpoint a way to make that process block. `alerts.jsonl` is
//! `0640 root:moat`, so a shipper needs **no privilege at all**: it is a
//! separate binary in group `moat`, exactly as `moat-feeds` is a separate
//! binary for the other direction of network I/O.
//!
//! # The contract
//!
//! At-least-once with receiver-side dedupe. Every record carries an
//! `event_id`: the alert's own ULID for a full alert record, and
//! `<id>.<12 hex of sha256(line)>` for anything else, so a re-send after a
//! crash is byte-identical and idempotent at the collector. The cursor
//! ([`Cursor`]) is written only after a batch is acknowledged, so a restart
//! re-sends at worst one batch and skips nothing.
//!
//! # Four things this refuses to do
//!
//! 1. **Ship staged evidence.** `incidents/<id>/…` and `*.suspect` are the
//!    accused artefacts — a copy of whatever the alert was about, which may be
//!    the user's credentials. `evidence.rs` already refuses to hand those to an
//!    AI; [`Guard`] refuses to hand them to a remote endpoint, and it works by
//!    path shape so it holds even for a record shape that does not exist yet.
//! 2. **Leak the token.** It is resolved at send time, never stored in a
//!    struct that is serialised, never printed by `status` or `--dry-run`, and
//!    [`Scrubber`] rewrites it out of every error string and response body
//!    before anything is logged.
//! 3. **Skip TLS verification.** There is no flag for it. A security product
//!    with a MITM switch is not one. `http://` is refused for anything but
//!    loopback, where there is no network to be in the middle of.
//! 4. **Grow without limit.** The buffer is bounded in both records and bytes;
//!    an endpoint that stays down costs the oldest records, counted, reported
//!    in the heartbeat, and never a byte of unbounded memory.
//!
//! # The heartbeat
//!
//! A shipper that has gone quiet is indistinguishable from a quiet machine.
//! That is the same failure mode as the blind sensor of 2026-09-03, where
//! every surface read "running" for 25 minutes with nothing loaded. So the
//! shipper emits `{"kind":"heartbeat","shipped":N,"dropped":M,…}` on a timer
//! whether or not anything happened, and absence at the collector is a fact
//! you can alert on.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::evidence::is_secret_path;
use crate::util;

pub const DEFAULT_CONFIG: &str = "/etc/moat/ship.toml";

/// Envelope version. Bumped only when a collector would have to change.
pub const V: u32 = 1;

// =============================================================== configuration

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShipConfig {
    /// Master switch. Off by default: shipping is a decision, not a default.
    pub enabled: bool,
    /// `none` | `https` | `syslog`.
    pub transport: String,
    /// Telemetry classes to ship, of `alerts`, `process`, `network`, `file`.
    /// A class moatd is not recording produces nothing, whatever is listed.
    pub classes: Vec<String>,
    /// Value of the `host` field on every record. Empty reads the hostname.
    pub host: String,
    /// Seconds between polls of the source files.
    pub poll_secs: u64,
    /// Seconds between heartbeats. 0 disables them, which you should not do.
    pub heartbeat_secs: u64,
    pub https: HttpsConfig,
    pub syslog: SyslogConfig,
    pub buffer: BufferConfig,
    pub redact: RedactConfig,
}

impl Default for ShipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: "none".into(),
            classes: vec!["alerts".into()],
            host: String::new(),
            poll_secs: 10,
            heartbeat_secs: 300,
            https: HttpsConfig::default(),
            syslog: SyslogConfig::default(),
            buffer: BufferConfig::default(),
            redact: RedactConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpsConfig {
    /// Collector endpoint. Splunk HEC, Elastic, Loki and Datadog all take
    /// NDJSON on a URL with an auth header, which is what `headers` is for.
    pub url: String,
    /// Sent verbatim, except that `${token}` in any value is replaced with the
    /// resolved secret at send time. That indirection is the whole point: the
    /// header template can be printed, logged and diffed; the token cannot.
    pub headers: BTreeMap<String, String>,
    /// A file containing the token, one line. **Must be 0600.** Preferred over
    /// `token`: a secret in its own file can be rotated, backed up and
    /// permissioned separately from the configuration around it.
    pub token_file: String,
    /// Environment variable holding the token. Second choice: the environment
    /// of a systemd unit is readable by root and shows up in `systemctl show`
    /// unless it came from a credential.
    pub token_env: String,
    /// Inline token. Last resort, and only accepted when `ship.toml` itself is
    /// 0600 — otherwise every user on the machine can read your collector key.
    pub token: String,
    pub content_type: String,
    pub batch_max_records: usize,
    pub batch_max_bytes: usize,
    pub timeout_secs: u64,
}

impl Default for HttpsConfig {
    fn default() -> Self {
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".into(), "Bearer ${token}".into());
        Self {
            url: String::new(),
            headers,
            token_file: String::new(),
            token_env: String::new(),
            token: String::new(),
            content_type: "application/x-ndjson".into(),
            batch_max_records: 200,
            batch_max_bytes: 1024 * 1024,
            timeout_secs: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyslogConfig {
    /// `/dev/log`, or `tcp://host:port`.
    pub target: String,
    /// RFC5424 facility. 13 is "log audit", which is what this is.
    pub facility: u8,
    pub app_name: String,
    /// Hard cap on one syslog line. RFC5424 guarantees only 480 bytes and most
    /// daemons accept 2048; a moat alert with its ancestry and explain block is
    /// several kilobytes, which is why syslog gets a summary and not the record
    /// (see [`syslog_line`]).
    pub max_len: usize,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            target: "/dev/log".into(),
            facility: 13,
            app_name: "moat".into(),
            max_len: 2048,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BufferConfig {
    pub max_records: usize,
    pub max_bytes: usize,
    pub retry_min_secs: u64,
    pub retry_max_secs: u64,
    /// Records read from the source files in one poll. Bounds the work a burst
    /// can create, which matters when the source is the `process` class.
    pub read_max_records: usize,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            max_records: 20_000,
            max_bytes: 32 * 1024 * 1024,
            retry_min_secs: 5,
            retry_max_secs: 300,
            read_max_records: 5_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedactConfig {
    /// Rewrite every human home to `~`. On: the username is the one identifier
    /// in a moat record that is about the person rather than the machine.
    pub home: bool,
    /// Replace the last component of a path that looks like key material with
    /// `<redacted>`, keeping the directory. On.
    ///
    /// You keep "something read a private key out of `~/.ssh/`", which is the
    /// whole content of the alert, and lose which key. Turn it off if your
    /// collector is the place you do that triage.
    pub secret_paths: bool,
    /// Extra literal strings scrubbed from every record before it is sent.
    pub extra: Vec<String>,
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            home: true,
            secret_paths: true,
            extra: Vec::new(),
        }
    }
}

impl ShipConfig {
    pub fn load(path: &Path) -> Result<ShipConfig, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {}", path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ShipConfig::default()),
            Err(e) => Err(format!("{}: {}", path.display(), e)),
        }
    }

    pub fn default_path() -> PathBuf {
        std::env::var_os("MOAT_SHIP_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG))
    }

    /// Everything that would stop this configuration from shipping safely.
    ///
    /// Called before the first byte moves and again by `moat-ship check`, so a
    /// broken endpoint is a message on install rather than silence for a week.
    pub fn problems(&self, config_path: &Path) -> Vec<String> {
        let mut out = Vec::new();
        match self.transport.as_str() {
            "none" => {}
            "https" => {
                if self.https.url.is_empty() {
                    out.push("transport is https but [https] url is empty".into());
                }
                if let Err(e) = check_url(&self.https.url) {
                    out.push(e);
                }
                if self.https.batch_max_records == 0 {
                    out.push("[https] batch_max_records is 0".into());
                }
                out.extend(self.token_problems(config_path));
            }
            "syslog" => {
                if self.syslog.target.is_empty() {
                    out.push("transport is syslog but [syslog] target is empty".into());
                }
                if self.syslog.facility > 23 {
                    out.push(format!(
                        "[syslog] facility {} is above the RFC5424 maximum of 23",
                        self.syslog.facility
                    ));
                }
                if self.syslog.max_len < 480 {
                    out.push("[syslog] max_len below the RFC5424 minimum of 480".into());
                }
            }
            other => out.push(format!(
                "transport {:?} is not one of none, https, syslog",
                other
            )),
        }
        for c in &self.classes {
            if !crate::telemetry::CLASSES.contains(&c.as_str()) {
                out.push(format!(
                    "class {:?} is not one of {:?}",
                    c,
                    crate::telemetry::CLASSES
                ));
            }
        }
        if self.enabled && self.heartbeat_secs == 0 {
            out.push(
                "heartbeat_secs = 0: a shipper that never says it is alive cannot be \
                 distinguished at the collector from a machine that has nothing to say"
                    .into(),
            );
        }
        out
    }

    /// Mode checks on whatever holds the secret. Refusals, not warnings: a
    /// world-readable collector token is a credential leak on the box the
    /// product is meant to be protecting.
    fn token_problems(&self, config_path: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let want_token = self
            .https
            .headers
            .values()
            .any(|v| v.contains(TOKEN_PLACEHOLDER));
        if !want_token {
            return out;
        }
        if !self.https.token_file.is_empty() {
            let p = Path::new(&self.https.token_file);
            match mode_of(p) {
                None => out.push(format!("[https] token_file {} cannot be read", p.display())),
                Some(m) if m & 0o077 != 0 => out.push(format!(
                    "[https] token_file {} is mode {:04o}; it must be 0600",
                    p.display(),
                    m
                )),
                Some(_) => {}
            }
        } else if !self.https.token_env.is_empty() {
            if std::env::var(&self.https.token_env).is_err() {
                out.push(format!(
                    "[https] token_env {} is not set in this process's environment",
                    self.https.token_env
                ));
            }
        } else if !self.https.token.is_empty() {
            match mode_of(config_path) {
                None => {}
                Some(m) if m & 0o077 != 0 => out.push(format!(
                    "{} holds an inline [https] token and is mode {:04o}; it must be 0600, or \
                     move the secret to token_file",
                    config_path.display(),
                    m
                )),
                Some(_) => {}
            }
        } else {
            out.push(
                "a header uses ${token} but none of token_file, token_env or token is set".into(),
            );
        }
        out
    }

    /// Resolve the secret. The only function that ever returns it, and its
    /// result is never stored anywhere that is printed or serialised.
    pub fn token(&self) -> Result<String, String> {
        if !self.https.token_file.is_empty() {
            let p = Path::new(&self.https.token_file);
            let t = std::fs::read_to_string(p)
                .map_err(|e| format!("{}: {}", p.display(), e))?
                .trim()
                .to_string();
            if t.is_empty() {
                return Err(format!("{} is empty", p.display()));
            }
            return Ok(t);
        }
        if !self.https.token_env.is_empty() {
            return std::env::var(&self.https.token_env)
                .map_err(|_| format!("${} is not set", self.https.token_env));
        }
        if !self.https.token.is_empty() {
            return Ok(self.https.token.clone());
        }
        Ok(String::new())
    }
}

pub const TOKEN_PLACEHOLDER: &str = "${token}";

fn mode_of(p: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).ok().map(|m| m.permissions().mode() & 0o7777)
}

/// TLS is not optional, so the scheme is checked rather than the certificate.
///
/// `http://` is allowed only for loopback, where "verify the peer" has no
/// meaning: there is no network segment for anyone to sit on, and a local
/// vector/fluent-bit/rsyslog sidecar on 127.0.0.1 is how most of these
/// deployments actually look. Everything else must be `https://`, and its
/// certificate is verified — there is no switch to turn that off.
pub fn check_url(url: &str) -> Result<(), String> {
    let rest = if let Some(r) = url.strip_prefix("https://") {
        return if r.is_empty() {
            Err("[https] url has no host".into())
        } else {
            Ok(())
        };
    } else if let Some(r) = url.strip_prefix("http://") {
        r
    } else {
        return Err(format!(
            "[https] url {:?} must start with https:// (or http:// for a loopback collector)",
            url
        ));
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    // Parsed, not prefix-matched.
    //
    // `host.starts_with("127.")` accepted `127.0.0.1.evil.example` -- a name
    // anyone can register -- and the authority was taken before the userinfo
    // was removed, so `http://127.0.0.1@evil.example/` passed as well. Either
    // one sent the whole record stream in cleartext to someone else's host with
    // `Authorization: Bearer <token>` attached. An exception carved out for
    // loopback has to mean loopback.
    if authority.contains('@') {
        return Err(format!(
            "[https] url {:?} carries userinfo before the host; that is never a loopback \
             collector and is refused",
            url
        ));
    }
    let is_loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if is_loopback {
        Ok(())
    } else {
        Err(format!(
            "[https] url {:?} is plain http to {:?}. TLS is not optional here; http:// is \
             accepted only for a loopback collector",
            url, host
        ))
    }
}

// ==================================================================== scrubbing

/// Rewrites secrets out of any string that is about to be logged or printed.
///
/// The token reaches exactly two places: the header map handed to the HTTP
/// client, and this scrubber's deny list. Every error, every response body,
/// every `--dry-run` line goes through [`Scrubber::scrub`] first, so a
/// collector that echoes the Authorization header back in a 401 body cannot
/// put it in the journal.
#[derive(Debug, Default, Clone)]
pub struct Scrubber {
    secrets: Vec<String>,
}

impl Scrubber {
    pub fn new(secrets: impl IntoIterator<Item = String>) -> Scrubber {
        Scrubber {
            // A very short "secret" would rewrite half the message; anything
            // under 6 characters is not a credential worth protecting.
            secrets: secrets.into_iter().filter(|s| s.len() >= 6).collect(),
        }
    }

    pub fn scrub(&self, s: &str) -> String {
        let mut out = s.to_string();
        for sec in &self.secrets {
            if out.contains(sec.as_str()) {
                out = out.replace(sec.as_str(), "<redacted>");
            }
        }
        out
    }

    /// Scrub, then cap. Response bodies are attacker-influenced and unbounded.
    pub fn scrub_short(&self, s: &str, max: usize) -> String {
        let mut t = self.scrub(s);
        if t.len() > max {
            t.truncate(max);
            t.push('…');
        }
        t.replace(['\n', '\r'], " ")
    }
}

// ==================================================================== redaction

/// `$HOME` → `~`, and the leaf of a credential path → `<redacted>`.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    homes: Vec<String>,
    home: bool,
    secret_paths: bool,
    extra: Vec<String>,
}

impl Redactor {
    pub fn new(cfg: &RedactConfig, homes: &[String]) -> Redactor {
        let mut homes: Vec<String> = homes
            .iter()
            .map(|h| h.trim_end_matches('/').to_string())
            .filter(|h| h.len() > 1)
            .collect();
        // Longest first, so /var/home/ada is not half-rewritten by /var/home.
        homes.sort_by_key(|h| std::cmp::Reverse(h.len()));
        Redactor {
            homes,
            home: cfg.home,
            secret_paths: cfg.secret_paths,
            extra: cfg.extra.iter().filter(|s| !s.is_empty()).cloned().collect(),
        }
    }

    /// One string. Order matters: the secret-path test runs on the real path,
    /// because `is_secret_path` knows `/home/dan/.ssh/`, not `~/.ssh/`.
    ///
    /// The string is not always *just* a path. An alert's `summary` and every
    /// line of its `evidence` are sentences with paths in them — "node (pid
    /// 41233) read /home/dan/.ssh/id_rsa" — so redacting only whole-string
    /// paths would leave the key name in the prose next to the field it was
    /// removed from.
    pub fn string(&self, s: &str) -> String {
        let mut out = s.to_string();
        if self.secret_paths {
            out = redact_paths_in(&out);
        }
        if self.home {
            for h in &self.homes {
                if out.contains(h.as_str()) {
                    out = out.replace(h.as_str(), "~");
                }
            }
        }
        for e in &self.extra {
            if out.contains(e.as_str()) {
                out = out.replace(e.as_str(), "<redacted>");
            }
        }
        out
    }

    /// Every string in a JSON document, recursively. Object *keys* are left
    /// alone: they are field names from moat's own code, never user data.
    pub fn value(&self, v: &mut Value) {
        match v {
            Value::String(s) => {
                let r = self.string(s);
                if &r != s {
                    *s = r;
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.value(x)),
            Value::Object(o) => o.iter_mut().for_each(|(_, x)| self.value(x)),
            _ => {}
        }
    }
}

/// `/home/dan/.ssh/id_ed25519` → `/home/dan/.ssh/<redacted>`.
fn redact_leaf(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => format!("{}/<redacted>", dir),
        _ => "<redacted>".into(),
    }
}

/// Every absolute path inside a string, whether the string is a path or a
/// sentence containing one.
///
/// Words are split on whitespace and quoting, and trailing sentence
/// punctuation is peeled off before the test so `…read /home/dan/.ssh/id_rsa.`
/// is recognised. A word that is not a secret path is put back untouched.
fn redact_paths_in(s: &str) -> String {
    if !s.contains('/') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            out.push_str(&redact_word(word));
            word.clear();
        }
    };
    for c in s.chars() {
        if c.is_whitespace() || matches!(c, '"' | '\'' | '(' | '[' | '{' | '<' | '=' | ',') {
            flush(&mut word, &mut out);
            out.push(c);
        } else {
            word.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

const TRAILING: &[char] = &['.', ',', ';', ':', ')', ']', '}', '>', '"', '\'', '!', '?'];

fn redact_word(w: &str) -> String {
    if !w.starts_with('/') {
        return w.to_string();
    }
    let core = w.trim_end_matches(TRAILING);
    let tail = &w[core.len()..];
    if core.len() > 1 && is_secret_path(core) {
        format!("{}{}", redact_leaf(core), tail)
    } else {
        w.to_string()
    }
}

// ======================================================================= guard

/// The one refusal that is not configurable.
///
/// Staged evidence is a *copy of the accused file*, written by
/// `evidence::stage` as `<bundle_dir>/<alert id>/<role>.<name>.suspect`. It may
/// be a dropper; it may equally be whatever the dropper was reading. `evidence.rs`
/// will not hand one to an AI API and this will not hand one to a collector.
///
/// The check is on path *shape*, not on which field it appeared in, so a record
/// shape invented later cannot route around it by putting the path somewhere
/// new.
#[derive(Debug, Clone)]
pub struct Guard {
    bundle_dir: String,
    quarantine_dir: String,
}

pub const WITHHELD: &str = "<withheld: staged evidence>";

impl Guard {
    pub fn new(bundle_dir: &Path, quarantine_dir: &Path) -> Guard {
        Guard {
            bundle_dir: bundle_dir.to_string_lossy().trim_end_matches('/').to_string(),
            quarantine_dir: quarantine_dir
                .to_string_lossy()
                .trim_end_matches('/')
                .to_string(),
        }
    }

    pub fn is_forbidden(&self, s: &str) -> bool {
        if s.ends_with(".suspect") {
            return true;
        }
        if !self.bundle_dir.is_empty() && s.starts_with(&self.bundle_dir) {
            return true;
        }
        if !self.quarantine_dir.is_empty() && s.starts_with(&self.quarantine_dir) {
            return true;
        }
        false
    }

    /// Replace every forbidden path in the document. Returns how many it hit,
    /// which the shipper counts and the heartbeat reports: a non-zero number
    /// means some record shape is trying to carry evidence and someone should
    /// look at it.
    pub fn sweep(&self, v: &mut Value) -> usize {
        let mut n = 0;
        self.sweep_into(v, &mut n);
        n
    }

    fn sweep_into(&self, v: &mut Value, n: &mut usize) {
        match v {
            Value::String(s) => {
                if self.is_forbidden(s) {
                    *s = WITHHELD.to_string();
                    *n += 1;
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.sweep_into(x, n)),
            Value::Object(o) => o.iter_mut().for_each(|(_, x)| self.sweep_into(x, n)),
            _ => {}
        }
    }
}

// ==================================================================== envelope

/// One record on its way out.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub event_id: String,
    /// The telemetry class this record belongs to, taken from the record
    /// itself. `alerts`, `process`, `network`, `file`, or `moat` for a
    /// heartbeat.
    pub class: String,
    /// The cursor key of the file it was read from. Not the same thing as
    /// `class`: moatd writes every non-alert class into one `telemetry.jsonl`,
    /// so three classes share one file and one cursor.
    pub source: String,
    pub kind: String,
    pub severity: String,
    pub value: Value,
}

impl Envelope {
    pub fn to_line(&self) -> String {
        serde_json::to_string(&self.value).unwrap_or_default()
    }
}

fn short_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    util::hex(&h.finalize())[..12].to_string()
}

/// Turn one source line into an envelope, or `None` if it is not shippable.
///
/// `class` is the stream the line came from. Redaction and the evidence guard
/// are applied here, once, before the record can reach any transport — a
/// transport added later inherits both rather than having to remember them.
pub fn envelope(
    line: &str,
    source: &str,
    host: &str,
    red: &Redactor,
    guard: &Guard,
    withheld: &mut usize,
) -> Option<Envelope> {
    let mut body: Value = serde_json::from_str(line).ok()?;
    if !body.is_object() {
        return None;
    }

    // A telemetry record names its own class; the alert store's lines do not,
    // because that file *is* the alerts class.
    let class: String = if source == "alerts" {
        "alerts".to_string()
    } else {
        body.get("class")
            .and_then(|v| v.as_str())
            .unwrap_or(source)
            .to_string()
    };
    let (kind, id, severity) = classify(&body, &class);
    let event_id = match (&kind[..], &id) {
        // A full alert is identified by its own ULID: stable, sortable, and
        // the same string the user sees in `moatctl explain`.
        ("alert", Some(i)) => i.clone(),
        (_, Some(i)) => format!("{}.{}", i, short_hash(line)),
        (_, None) => short_hash(line),
    };

    *withheld += guard.sweep(&mut body);
    red.value(&mut body);

    let value = json!({
        "v": V,
        "event_id": event_id,
        "host": host,
        "class": class.clone(),
        "kind": kind,
        "moat_tier": moat_tier(&body, &class, &kind),
        "severity": severity,
        "@timestamp": body.get("ts").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        "moat": body,
    });

    Some(Envelope {
        event_id,
        class,
        source: source.to_string(),
        kind,
        severity,
        value,
    })
}

/// What kind of line is this, what is its id, and how loud is it?
///
/// `alerts.jsonl` carries three shapes (CONTRACT §4): a full alert, an
/// `{"id":…,"update":{…}}` state change, and a `{"receipt":{…}}` install
/// receipt. `telemetry.jsonl` carries the class records of `telemetry.rs`.
/// The moat's own vocabulary for how much attention a record is asking for.
///
/// A collector wants one field to facet on, and "surface", "tier",
/// "suppressed_by" and "action_taken" are four. This is derived from all four
/// and is purely additive: every field it comes from is still under `moat`, so
/// it is a convenience for the query bar and never the source of truth.
///
/// * `gator`  — the moat bit. Something was blocked, contained, killed or
///   quarantined. The highest-value audit record moat produces.
/// * `alert`  — on the badge. A person has not answered it yet.
/// * `duck`   — belongs in the moat: an allowlist or baseline rule said so.
///   Still recorded, because a suppression nobody can see is a silence.
/// * `ripple` — a building block (`tier: signal`). One ripple means nothing;
///   several in a row is something moving, which is what a chain is made of.
/// * `silt`   — settled. Recorded, in the timeline, asking nothing.
/// * `current`— the water itself: telemetry, which never entered rule
///   evaluation at all.
fn moat_tier(body: &Value, class: &str, kind: &str) -> &'static str {
    if class != "alerts" {
        return "current";
    }
    // Updates and receipts describe a record rather than being one.
    if kind != "alert" {
        return "silt";
    }
    let s = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let acted = s("action_taken");
    if !acted.is_empty() && acted != "none" {
        return "gator";
    }
    if body
        .get("suppressed_by")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        return "duck";
    }
    if s("surface") == "alerts" {
        return "alert";
    }
    if s("tier") == "signal" {
        return "ripple";
    }
    "silt"
}

fn classify(body: &Value, class: &str) -> (String, Option<String>, String) {
    if class == "alerts" {
        if body.get("update").is_some() {
            return (
                "update".into(),
                body.get("id").and_then(|v| v.as_str()).map(str::to_string),
                "info".into(),
            );
        }
        if body.get("receipt").is_some() {
            return ("receipt".into(), None, "info".into());
        }
        if body.get("id").is_some() && body.get("rule").is_some() {
            return (
                "alert".into(),
                body.get("id").and_then(|v| v.as_str()).map(str::to_string),
                body.get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("low")
                    .to_string(),
            );
        }
        return ("unknown".into(), None, "info".into());
    }
    (
        body.get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("telemetry")
            .to_string(),
        body.get("exec_id").and_then(|v| v.as_str()).map(str::to_string),
        "info".into(),
    )
}

// ====================================================================== syslog

/// RFC5424 severity for a moat severity name.
fn syslog_severity(sev: &str) -> u8 {
    match sev {
        "critical" => 2, // crit
        "high" => 3,     // err
        "medium" => 4,   // warning
        "low" => 5,      // notice
        _ => 6,          // informational
    }
}

/// The **summary projection**, and the reason it exists.
///
/// A moat alert carries full ancestry and an explain block with evidence,
/// expected-cases and next steps. That is several kilobytes. RFC5424 guarantees
/// 480 bytes and most receivers stop somewhere near 2 KB, so shipping the whole
/// record over syslog does not deliver a moat alert — it delivers the first
/// third of one, silently, with the `explain` block that makes it actionable
/// cut off mid-sentence.
///
/// So syslog gets a deliberate summary: who, what, where, how bad, and the
/// alert id to look the rest up by. It is lossy **on purpose and visibly** —
/// the id is right there — rather than lossy by accident.
pub fn syslog_line(cfg: &SyslogConfig, env: &Envelope, host: &str, ts: &str) -> String {
    let pri = (cfg.facility as u16) * 8 + syslog_severity(&env.severity) as u16;
    let m = &env.value["moat"];
    let mut fields: Vec<String> = Vec::new();

    let get = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("");
    match env.kind.as_str() {
        "alert" => {
            fields.push(format!("id={}", env.event_id));
            fields.push(format!("severity={}", env.severity));
            fields.push(format!("rule={}", get("rule")));
            fields.push(format!("family={}", get("family")));
            push_kv(&mut fields, "pid", m.pointer("/process/pid"));
            push_str(&mut fields, "exe", m.pointer("/process/exe"));
            push_str(&mut fields, "file", m.pointer("/file/path"));
            push_str(&mut fields, "dst", m.pointer("/net/dst_ip"));
            push_kv(&mut fields, "dport", m.pointer("/net/dst_port"));
            fields.push(format!("action={}", get("action_taken")));
            fields.push(format!("title={:?}", get("title")));
        }
        "update" => {
            fields.push(format!("id={}", get("id")));
            fields.push(format!("update={}", compact(m.get("update"))));
        }
        "heartbeat" => {
            fields.push(format!("shipped={}", num(m.get("shipped"))));
            fields.push(format!("dropped={}", num(m.get("dropped"))));
            fields.push(format!("backlog={}", num(m.get("backlog"))));
            fields.push(format!("classes={}", compact(m.get("classes"))));
        }
        _ => {
            fields.push(format!("class={}", env.class));
            fields.push(format!("kind={}", env.kind));
            push_str(&mut fields, "exe", m.get("exe"));
            push_str(&mut fields, "path", m.get("path"));
            push_str(&mut fields, "verdict", m.get("verdict"));
            push_str(&mut fields, "dst_ip", m.get("dst_ip"));
            push_kv(&mut fields, "dst_port", m.get("dst_port"));
            push_kv(&mut fields, "pid", m.get("pid"));
        }
    }

    let msg = fields
        .into_iter()
        .filter(|f| !f.ends_with('=') && !f.ends_with("=\"\""))
        .collect::<Vec<_>>()
        .join(" ");
    let head = format!(
        "<{}>1 {} {} {} {} {} - ",
        pri,
        ts,
        nilify(host),
        nilify(&cfg.app_name),
        std::process::id(),
        nilify(&env.kind),
    );
    let mut line = format!("{}{}", head, msg);
    if line.len() > cfg.max_len {
        // Truncate visibly. A receiver that sees `…[truncated]` knows to go and
        // fetch the record by id; one that sees a sentence stop does not.
        let cut = cfg.max_len.saturating_sub(12).max(head.len());
        line.truncate(floor_char(&line, cut));
        line.push_str("…[truncated]");
    }
    line
}

fn floor_char(s: &str, mut i: usize) -> usize {
    if i > s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn nilify(s: &str) -> String {
    let t: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(48)
        .collect();
    if t.is_empty() {
        "-".into()
    } else {
        t
    }
}

fn push_str(out: &mut Vec<String>, k: &str, v: Option<&Value>) {
    if let Some(s) = v.and_then(|x| x.as_str()) {
        if !s.is_empty() {
            out.push(format!("{}={:?}", k, s));
        }
    }
}

fn push_kv(out: &mut Vec<String>, k: &str, v: Option<&Value>) {
    if let Some(n) = v.and_then(|x| x.as_i64()) {
        out.push(format!("{}={}", k, n));
    }
}

fn num(v: Option<&Value>) -> i64 {
    v.and_then(|x| x.as_i64()).unwrap_or(0)
}

fn compact(v: Option<&Value>) -> String {
    v.map(|x| serde_json::to_string(x).unwrap_or_default())
        .unwrap_or_else(|| "null".into())
}

// =================================================================== transport

pub trait Transport {
    /// Send a whole batch. `Ok(())` means the collector has it.
    fn send(&mut self, batch: &[Envelope]) -> Result<(), SendError>;
    fn name(&self) -> &'static str;
}

#[derive(Debug)]
pub struct SendError {
    pub message: String,
    /// Retry, or is this batch never going to be accepted?
    pub retryable: bool,
}

impl SendError {
    fn retry(m: impl Into<String>) -> SendError {
        SendError {
            message: m.into(),
            retryable: true,
        }
    }
    fn permanent(m: impl Into<String>) -> SendError {
        SendError {
            message: m.into(),
            retryable: false,
        }
    }
}

/// NDJSON over HTTPS with caller-supplied headers.
pub struct HttpsTransport {
    agent: ureq::Agent,
    url: String,
    /// `${token}` already substituted. Never printed; see [`Scrubber`].
    headers: Vec<(String, String)>,
    content_type: String,
    scrub: Scrubber,
}

impl HttpsTransport {
    pub fn new(cfg: &HttpsConfig, token: &str, scrub: Scrubber) -> HttpsTransport {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(cfg.timeout_secs.max(1))))
            .user_agent(concat!("moat-ship/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let headers = cfg
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.replace(TOKEN_PLACEHOLDER, token)))
            .collect();
        HttpsTransport {
            agent,
            url: cfg.url.clone(),
            headers,
            content_type: cfg.content_type.clone(),
            scrub,
        }
    }
}

impl Transport for HttpsTransport {
    fn name(&self) -> &'static str {
        "https"
    }

    fn send(&mut self, batch: &[Envelope]) -> Result<(), SendError> {
        if batch.is_empty() {
            return Ok(());
        }
        let body = batch
            .iter()
            .map(|e| e.to_line())
            .collect::<Vec<_>>()
            .join("\n");
        let mut req = self
            .agent
            .post(&self.url)
            .header("Content-Type", &self.content_type);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        match req.send(&body) {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                if (200..300).contains(&status) {
                    return Ok(());
                }
                let text = resp
                    .body_mut()
                    .read_to_string()
                    .unwrap_or_else(|_| String::new());
                let msg = format!(
                    "HTTP {} from collector: {}",
                    status,
                    self.scrub.scrub_short(&text, 200)
                );
                // 408 and 429 are "later"; other 4xx will never be accepted, so
                // retrying one forever would wedge the whole stream behind it.
                if status == 408 || status == 429 || status >= 500 {
                    Err(SendError::retry(msg))
                } else {
                    Err(SendError::permanent(msg))
                }
            }
            Err(e) => Err(SendError::retry(self.scrub.scrub(&e.to_string()))),
        }
    }
}

/// RFC5424 to `/dev/log` or a TCP collector.
pub struct SyslogTransport {
    cfg: SyslogConfig,
    host: String,
}

impl SyslogTransport {
    pub fn new(cfg: &SyslogConfig, host: &str) -> SyslogTransport {
        SyslogTransport {
            cfg: cfg.clone(),
            host: host.to_string(),
        }
    }

    fn write_all(&self, lines: &[String]) -> Result<(), SendError> {
        if let Some(addr) = self.cfg.target.strip_prefix("tcp://") {
            let mut s = std::net::TcpStream::connect(addr)
                .map_err(|e| SendError::retry(format!("{}: {}", addr, e)))?;
            for l in lines {
                // RFC6587 octet counting: the only framing that survives a
                // message containing a newline.
                let framed = format!("{} {}", l.len(), l);
                s.write_all(framed.as_bytes())
                    .map_err(|e| SendError::retry(e.to_string()))?;
            }
            s.flush().map_err(|e| SendError::retry(e.to_string()))?;
            return Ok(());
        }
        let path = self.cfg.target.as_str();
        // Datagram first: that is what /dev/log is on systemd. A journald
        // socket that is a stream (or a message over the datagram size limit)
        // falls through to SOCK_STREAM rather than dropping the record.
        if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
            let mut ok = true;
            for l in lines {
                if sock.send_to(l.as_bytes(), path).is_err() {
                    ok = false;
                    break;
                }
            }
            if ok {
                return Ok(());
            }
        }
        let mut s = std::os::unix::net::UnixStream::connect(path)
            .map_err(|e| SendError::retry(format!("{}: {}", path, e)))?;
        for l in lines {
            s.write_all(l.as_bytes())
                .map_err(|e| SendError::retry(e.to_string()))?;
            s.write_all(b"\n")
                .map_err(|e| SendError::retry(e.to_string()))?;
        }
        s.flush().map_err(|e| SendError::retry(e.to_string()))?;
        Ok(())
    }
}

impl Transport for SyslogTransport {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn send(&mut self, batch: &[Envelope]) -> Result<(), SendError> {
        let ts = util::now_rfc3339();
        let lines: Vec<String> = batch
            .iter()
            .map(|e| syslog_line(&self.cfg, e, &self.host, &ts))
            .collect();
        self.write_all(&lines)
    }
}

/// Prints what would have been sent. Used by `--dry-run`, and by the tests, so
/// the exact bytes a collector would receive are asserted rather than assumed.
pub struct DryRunTransport {
    pub sent: Vec<String>,
    pub print: bool,
    pub syslog: Option<(SyslogConfig, String)>,
}

impl Transport for DryRunTransport {
    fn name(&self) -> &'static str {
        "dry-run"
    }

    fn send(&mut self, batch: &[Envelope]) -> Result<(), SendError> {
        let ts = util::now_rfc3339();
        for e in batch {
            let line = match &self.syslog {
                Some((c, h)) => syslog_line(c, e, h, &ts),
                None => e.to_line(),
            };
            if self.print {
                println!("{}", line);
            }
            self.sent.push(line);
        }
        Ok(())
    }
}

// ====================================================================== buffer

/// Bounded, drop-oldest, counted.
///
/// Dropping the newest would be easier and is wrong: the newest records are the
/// ones describing whatever is happening right now, which is what an outage
/// during an incident would otherwise cost you. Dropping the oldest keeps the
/// window closest to the present.
#[derive(Debug, Default)]
pub struct Buffer {
    q: VecDeque<Envelope>,
    bytes: usize,
    max_records: usize,
    max_bytes: usize,
    pub dropped: u64,
    pub dropped_bytes: u64,
}

impl Buffer {
    pub fn new(cfg: &BufferConfig) -> Buffer {
        Buffer {
            q: VecDeque::new(),
            bytes: 0,
            max_records: cfg.max_records.max(1),
            max_bytes: cfg.max_bytes.max(4096),
            dropped: 0,
            dropped_bytes: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.q.len()
    }
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Returns whatever had to be dropped to make room, so the caller can keep
    /// its per-class bookkeeping honest. A record that was dropped is no longer
    /// pending, and the cursor must be free to move past it — counted as a
    /// loss, never as a silent skip.
    pub fn push(&mut self, e: Envelope) -> Vec<Envelope> {
        let n = e.to_line().len();
        self.bytes += n;
        self.q.push_back(e);
        let mut evicted = Vec::new();
        while self.q.len() > self.max_records || self.bytes > self.max_bytes {
            let Some(old) = self.q.pop_front() else { break };
            let m = old.to_line().len();
            self.bytes = self.bytes.saturating_sub(m);
            self.dropped += 1;
            self.dropped_bytes += m as u64;
            evicted.push(old);
            if self.q.is_empty() {
                break;
            }
        }
        evicted
    }

    /// The next batch, without removing it: a batch is only consumed once the
    /// collector has acknowledged it.
    pub fn peek(&self, max_records: usize, max_bytes: usize) -> Vec<Envelope> {
        let mut out = Vec::new();
        let mut n = 0usize;
        for e in &self.q {
            let len = e.to_line().len();
            if !out.is_empty() && (out.len() >= max_records.max(1) || n + len > max_bytes.max(1)) {
                break;
            }
            n += len;
            out.push(e.clone());
        }
        out
    }

    pub fn commit(&mut self, count: usize) {
        for _ in 0..count {
            let Some(e) = self.q.pop_front() else { break };
            self.bytes = self.bytes.saturating_sub(e.to_line().len());
        }
    }
}

// ====================================================================== cursor

/// Where each source got to, on disk.
///
/// Offset plus inode is the fast path; `recent` is the correctness backstop.
/// A source file that rotated between two runs of a `--once` shipper cannot be
/// resumed by offset alone, so the last few hundred `event_id`s are kept and
/// anything already in that set is not sent again. At-least-once with a small
/// exactly-once window, which is the shape ULIDs and receiver dedupe want.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceCursor {
    pub inode: u64,
    pub offset: u64,
    #[serde(default)]
    pub recent: VecDeque<String>,
}

const RECENT_MAX: usize = 512;

impl SourceCursor {
    pub fn seen(&self, id: &str) -> bool {
        self.recent.iter().any(|x| x == id)
    }
    pub fn note(&mut self, id: &str) {
        self.recent.push_back(id.to_string());
        while self.recent.len() > RECENT_MAX {
            self.recent.pop_front();
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Cursor {
    pub v: u32,
    pub sources: BTreeMap<String, SourceCursor>,
    pub shipped: u64,
    pub dropped: u64,
    pub withheld: u64,
    pub last_ok: String,
    pub last_error: String,
}

impl Cursor {
    pub fn load(path: &Path) -> Cursor {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<Cursor>(&t).ok())
            .map(|mut c| {
                c.v = V;
                c
            })
            .unwrap_or(Cursor {
                v: V,
                ..Default::default()
            })
    }

    /// Atomic, 0640 so the group that reads the alerts can read the lag too.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let body = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        util::atomic_write(path, &body, 0o640)
            .map(|_| ())
            .map_err(|e| format!("{}: {}", path.display(), e))
    }
}

// ===================================================================== sources

/// One append-only JSON-lines file and its rotated sibling.
pub struct Source {
    pub class: String,
    pub path: PathBuf,
    pub rotated: PathBuf,
}

/// Read what is new, honouring rotation and truncation.
///
/// Returns the lines and the cursor position they end at. The cursor is
/// **not** written here: it moves only after the collector has the records.
pub fn read_new(src: &Source, cur: &SourceCursor, max: usize) -> (Vec<String>, u64, u64) {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;

    let mut out: Vec<String> = Vec::new();

    let meta = std::fs::metadata(&src.path).ok();
    let (inode, size) = match &meta {
        Some(m) => (m.ino(), m.len()),
        None => return (out, cur.inode, cur.offset),
    };

    // The file we were reading has been renamed away. Finish it, then start on
    // the new one — a rotation must not lose the tail of the old file.
    if cur.inode != 0 && cur.inode != inode {
        if let Ok(rm) = std::fs::metadata(&src.rotated) {
            if rm.ino() == cur.inode {
                if let Ok(mut f) = std::fs::File::open(&src.rotated) {
                    if f.seek(SeekFrom::Start(cur.offset)).is_ok() {
                        for l in BufReader::new(f).lines().map_while(Result::ok) {
                            if out.len() >= max {
                                break;
                            }
                            if !l.trim().is_empty() {
                                out.push(l);
                            }
                        }
                    }
                }
            }
        }
        return read_from(&src.path, 0, max, out).map(|(v, o)| (v, inode, o)).unwrap_or((Vec::new(), inode, 0));
    }

    // Truncated in place: start over rather than read garbage from mid-record.
    let start = if size < cur.offset { 0 } else { cur.offset };
    read_from(&src.path, start, max, out)
        .map(|(v, o)| (v, inode, o))
        .unwrap_or((Vec::new(), inode, start))
}

fn read_from(
    path: &Path,
    start: u64,
    max: usize,
    mut out: Vec<String>,
) -> Option<(Vec<String>, u64)> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut pos = start;
    let mut r = BufReader::new(f);
    let mut line = String::new();
    loop {
        if out.len() >= max {
            break;
        }
        line.clear();
        let n = r.read_line(&mut line).ok()?;
        if n == 0 {
            break;
        }
        // A line without its newline is still being written; stop before it so
        // the next poll reads the whole record.
        if !line.ends_with('\n') {
            break;
        }
        pos += n as u64;
        let t = line.trim_end_matches(['\n', '\r']);
        if !t.is_empty() {
            out.push(t.to_string());
        }
    }
    Some((out, pos))
}

// ===================================================================== shipper

#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub shipped: u64,
    pub dropped: u64,
    pub withheld: u64,
    pub backlog: usize,
    pub backlog_bytes: usize,
    pub last_ok: String,
    pub last_error: String,
}

pub struct Shipper {
    pub cfg: ShipConfig,
    pub host: String,
    pub cursor_path: PathBuf,
    pub cursor: Cursor,
    pub sources: Vec<Source>,
    pub buffer: Buffer,
    pub redact: Redactor,
    pub guard: Guard,
    pub scrub: Scrubber,
    backoff: u64,
    next_attempt: u64,
    last_heartbeat: u64,
    pub withheld: usize,
    /// How far each source has been *read*, which runs ahead of how far it has
    /// been *acknowledged*. Only the second of those is ever written to disk.
    frontier: BTreeMap<String, (u64, u64)>,
    /// Buffer evictions already folded into the persisted `dropped` total, so
    /// a restart neither loses the count nor double-counts it.
    buffer_dropped_seen: u64,
    /// Records from each source that are in the buffer and not yet accounted
    /// for. While this is non-zero the durable cursor must not move, or an
    /// endpoint outage across a restart would skip exactly the records the
    /// outage was about.
    pending: BTreeMap<String, usize>,
    /// Classes the operator asked for. Checked per record, because moatd
    /// writes `process`, `network` and `file` into one file: enabling one class
    /// for collection and a different one for shipping has to work.
    pub class_filter: Vec<String>,
    /// Write the cursor to disk. False under `--dry-run`, so a dry run can be
    /// run twice and show the same records both times instead of quietly
    /// consuming the backlog it was supposed to be previewing.
    pub persist: bool,
}

/// Heartbeats belong to no source file, so they carry a cursor key of their
/// own and can never hold a real source's offset back.
pub const HEARTBEAT_SOURCE: &str = "@heartbeat";

impl Shipper {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: ShipConfig,
        host: String,
        cursor_path: PathBuf,
        sources: Vec<Source>,
        homes: &[String],
        bundle_dir: &Path,
        quarantine_dir: &Path,
        scrub: Scrubber,
    ) -> Shipper {
        let redact = Redactor::new(&cfg.redact, homes);
        let guard = Guard::new(bundle_dir, quarantine_dir);
        let buffer = Buffer::new(&cfg.buffer);
        let cursor = Cursor::load(&cursor_path);
        Shipper {
            cfg,
            host,
            cursor_path,
            cursor,
            sources,
            buffer,
            redact,
            guard,
            scrub,
            backoff: 0,
            next_attempt: 0,
            last_heartbeat: 0,
            withheld: 0,
            frontier: BTreeMap::new(),
            buffer_dropped_seen: 0,
            pending: BTreeMap::new(),
            class_filter: Vec::new(),
            persist: true,
        }
    }

    fn wants(&self, class: &str) -> bool {
        if class == "moat" {
            return true; // the heartbeat is never filtered out
        }
        let list = if self.class_filter.is_empty() {
            &self.cfg.classes
        } else {
            &self.class_filter
        };
        list.iter().any(|c| c == class)
    }

    pub fn stats(&self) -> Stats {
        Stats {
            shipped: self.cursor.shipped,
            dropped: self.cursor.dropped + (self.buffer.dropped - self.buffer_dropped_seen),
            withheld: self.cursor.withheld,
            backlog: self.buffer.len(),
            backlog_bytes: self.buffer.bytes(),
            last_ok: self.cursor.last_ok.clone(),
            last_error: self.cursor.last_error.clone(),
        }
    }

    /// Read every enabled source into the buffer.
    ///
    /// This moves the in-memory frontier only. The durable cursor is advanced
    /// in [`Shipper::settle`], once every record read past it has either been
    /// acknowledged by the collector or counted as a drop.
    pub fn collect(&mut self) {
        let max = self.cfg.buffer.read_max_records;
        let sources: Vec<(String, PathBuf, PathBuf)> = self
            .sources
            .iter()
            .filter(|s| self.cfg.classes.iter().any(|c| c == &s.class))
            .map(|s| (s.class.clone(), s.path.clone(), s.rotated.clone()))
            .collect();
        for (class, path, rotated) in sources {
            let saved = self.cursor.sources.entry(class.clone()).or_default().clone();
            // Resume from the frontier if this process has already read past
            // the durable cursor; otherwise from the durable cursor itself.
            let mut cur = saved.clone();
            if let Some((ino, off)) = self.frontier.get(&class) {
                cur.inode = *ino;
                cur.offset = *off;
            }
            let src = Source {
                class: class.clone(),
                path,
                rotated,
            };
            let (lines, inode, offset) = read_new(&src, &cur, max);
            let mut withheld = 0usize;
            for l in &lines {
                let Some(env) = envelope(
                    l,
                    &class,
                    &self.host,
                    &self.redact,
                    &self.guard,
                    &mut withheld,
                ) else {
                    continue;
                };
                if saved.seen(&env.event_id) {
                    continue;
                }
                if !self.wants(&env.class) {
                    continue;
                }
                *self.pending.entry(class.clone()).or_insert(0) += 1;
                for ev in self.buffer.push(env) {
                    self.forget(&ev.source);
                }
            }
            self.frontier.insert(class.clone(), (inode, offset));
            self.withheld += withheld;
            self.cursor.withheld += withheld as u64;
        }
    }

    fn forget(&mut self, class: &str) {
        if let Some(n) = self.pending.get_mut(class) {
            *n = n.saturating_sub(1);
        }
    }

    /// Move the durable cursor up to the frontier for every source with nothing
    /// outstanding. This is the only place `cursor.sources[*].offset` grows.
    fn save_cursor(&mut self) {
        if !self.persist {
            return;
        }
        if let Err(e) = self.cursor.save(&self.cursor_path) {
            log::warn!("ship: cursor not saved: {}", e);
        }
    }

    fn settle(&mut self) {
        let frontier = self.frontier.clone();
        for (class, (inode, offset)) in frontier {
            if self.pending.get(&class).copied().unwrap_or(0) != 0 {
                continue;
            }
            let e = self.cursor.sources.entry(class).or_default();
            e.inode = inode;
            e.offset = offset;
        }
    }

    /// Is a heartbeat due? Also true on the very first pass, so a shipper that
    /// starts and immediately loses its network still says so once.
    pub fn heartbeat_due(&self, now: u64) -> bool {
        self.cfg.heartbeat_secs > 0
            && (self.last_heartbeat == 0 || now.saturating_sub(self.last_heartbeat) >= self.cfg.heartbeat_secs)
    }

    pub fn heartbeat(&self, now: u64) -> Envelope {
        let s = self.stats();
        let body = json!({
            "kind": "heartbeat",
            "ts": util::rfc3339_of(now),
            "version": crate::VERSION,
            "classes": self.cfg.classes,
            "transport": self.cfg.transport,
            "shipped": s.shipped,
            "dropped": s.dropped,
            "withheld": s.withheld,
            "backlog": s.backlog,
            "backlog_bytes": s.backlog_bytes,
            "last_ok": s.last_ok,
            "last_error": s.last_error,
        });
        Envelope {
            event_id: format!("hb.{}.{}", self.host, now),
            class: "moat".into(),
            source: HEARTBEAT_SOURCE.into(),
            kind: "heartbeat".into(),
            severity: "info".into(),
            value: json!({
                "v": V,
                "event_id": format!("hb.{}.{}", self.host, now),
                "host": self.host,
                "class": "moat",
                "kind": "heartbeat",
                "severity": "info",
                "@timestamp": util::rfc3339_of(now),
                "moat": body,
            }),
        }
    }

    /// One pass: collect, heartbeat if due, then send while the collector will
    /// take it. Returns how many records went out.
    pub fn pass(&mut self, tx: &mut dyn Transport, now: u64) -> usize {
        self.collect();
        if self.heartbeat_due(now) {
            let hb = self.heartbeat(now);
            for ev in self.buffer.push(hb) {
                self.forget(&ev.source);
            }
            self.last_heartbeat = now;
        }
        if now < self.next_attempt {
            self.settle();
            self.cursor.dropped += self.buffer.dropped - self.buffer_dropped_seen;
            self.buffer_dropped_seen = self.buffer.dropped;
            self.save_cursor();
            return 0;
        }

        let mut sent = 0usize;
        loop {
            let batch = self.buffer.peek(
                self.cfg.https.batch_max_records,
                self.cfg.https.batch_max_bytes,
            );
            if batch.is_empty() {
                break;
            }
            match tx.send(&batch) {
                Ok(()) => {
                    for e in &batch {
                        self.cursor
                            .sources
                            .entry(e.source.clone())
                            .or_default()
                            .note(&e.event_id);
                        self.forget(&e.source);
                    }
                    self.buffer.commit(batch.len());
                    sent += batch.len();
                    self.cursor.shipped += batch.len() as u64;
                    self.cursor.last_ok = util::rfc3339_of(now);
                    self.cursor.last_error.clear();
                    self.backoff = 0;
                    self.next_attempt = 0;
                }
                Err(e) => {
                    let msg = self.scrub.scrub_short(&e.message, 300);
                    self.cursor.last_error = msg.clone();
                    if e.retryable {
                        self.backoff = next_backoff(
                            self.backoff,
                            self.cfg.buffer.retry_min_secs,
                            self.cfg.buffer.retry_max_secs,
                            now,
                        );
                        self.next_attempt = now + self.backoff;
                        log::warn!("ship: {} (retrying in {}s)", msg, self.backoff);
                    } else {
                        // Never accepted: dropping it is the only way the rest
                        // of the stream ever moves. Counted like any other loss.
                        for e in &batch {
                            self.forget(&e.source);
                        }
                        self.buffer.commit(batch.len());
                        self.cursor.dropped += batch.len() as u64;
                        log::error!("ship: {} (batch dropped, {} records)", msg, batch.len());
                    }
                    break;
                }
            }
        }
        self.settle();
        self.cursor.dropped += self.buffer.dropped - self.buffer_dropped_seen;
        self.buffer_dropped_seen = self.buffer.dropped;
        self.save_cursor();
        sent
    }
}

/// Exponential with a little jitter, so a fleet coming back from an outage does
/// not arrive at the collector in lockstep.
pub fn next_backoff(prev: u64, min: u64, max: u64, seed: u64) -> u64 {
    let min = min.max(1);
    let max = max.max(min);
    let base = if prev == 0 { min } else { (prev * 2).min(max) };
    let jitter = seed % (base / 4 + 1);
    (base + jitter).min(max)
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// Printable description of the HTTPS destination, with the header **template**
/// rather than the header. Used by `--dry-run` and `moat-ship status`.
pub fn describe_https(cfg: &HttpsConfig) -> String {
    let mut s = format!("POST {}\n", cfg.url);
    s.push_str(&format!("  Content-Type: {}\n", cfg.content_type));
    for (k, v) in &cfg.headers {
        s.push_str(&format!("  {}: {}\n", k, v));
    }
    let src = if !cfg.token_file.is_empty() {
        format!("token_file {}", cfg.token_file)
    } else if !cfg.token_env.is_empty() {
        format!("token_env ${}", cfg.token_env)
    } else if !cfg.token.is_empty() {
        "inline token in ship.toml".to_string()
    } else {
        "no token configured".to_string()
    };
    s.push_str(&format!("  (${{token}} resolved from {})\n", src));
    s
}

#[cfg(test)]
mod tests {
    /// The moat vocabulary a collector facets on. Derived, additive, and every
    /// field it comes from is still under `moat` in the same record.
    #[test]
    fn every_record_carries_the_tier_it_belongs_to() {
        let host = "mars";
        let red = Redactor::default();
        let guard = guard();
        let mut w = 0usize;
        let mut tier = |line: &str, source: &str| -> String {
            envelope(line, source, host, &red, &guard, &mut w)
                .expect("an envelope")
                .value["moat_tier"]
                .as_str()
                .unwrap()
                .to_string()
        };

        let base = |extra: &str| {
            format!(
                r#"{{"id":"01ABC","rule":"moat-x-test","severity":"high","ts":"2026-09-07T00:00:00Z"{}}}"#,
                extra
            )
        };

        // The moat bit outranks everything: it is the audit record that matters.
        assert_eq!(tier(&base(r#","surface":"alerts","action_taken":"contained""#), "alerts"), "gator");
        assert_eq!(tier(&base(r#","surface":"alerts","action_taken":"killed""#), "alerts"), "gator");
        // Answered by a rule you wrote: recorded, never on the badge.
        assert_eq!(tier(&base(r#","surface":"alerts","suppressed_by":"user.toml#3""#), "alerts"), "duck");
        // Waiting for a person.
        assert_eq!(tier(&base(r#","surface":"alerts","action_taken":"none""#), "alerts"), "alert");
        // A building block: only means something with the others.
        assert_eq!(tier(&base(r#","surface":"timeline","tier":"signal""#), "alerts"), "ripple");
        // Settled.
        assert_eq!(tier(&base(r#","surface":"timeline""#), "alerts"), "silt");
        // The water itself, which never reached rule evaluation.
        assert_eq!(
            tier(r#"{"class":"file","ts":"2026-09-07T00:00:00Z"}"#, "telemetry"),
            "current"
        );
    }

    use super::*;

    fn red() -> Redactor {
        Redactor::new(&RedactConfig::default(), &["/home/dan".to_string()])
    }
    fn guard() -> Guard {
        Guard::new(
            Path::new("/var/lib/moat/incidents"),
            Path::new("/var/lib/moat/quarantine"),
        )
    }

    const ALERT: &str = r#"{"v":1,"id":"01J8ZK6B4Q3M7N9P2R5S8T1V4W","ts":"2026-09-03T16:21:07.123Z",
      "severity":"high","rule":"moat-cred-ssh-private-key-read","family":"cred",
      "title":"Private SSH key read by an unexpected program",
      "summary":"node read /home/dan/.ssh/id_rsa",
      "process":{"pid":41233,"uid":1000,"exe":"/home/dan/.local/bin/node","args":"x.mjs","cwd":"/home/dan/p"},
      "file":{"path":"/home/dan/.ssh/id_rsa","sha256":null},
      "action_taken":"none","acked":false}"#;

    // ---------------------------------------------------------------- security

    /// The single most important test in this file. A staged artefact is a copy
    /// of the accused file; it may be the user's private key. It must not reach
    /// a collector by any field, in any record shape.
    #[test]
    fn staged_evidence_never_leaves_the_machine() {
        let g = guard();
        for p in [
            "/var/lib/moat/incidents/01J8ZK/actor.setup.mjs.suspect",
            "/var/lib/moat/incidents/01J8ZK/bundle.md",
            "/var/lib/moat/incidents/01J8ZK/file/id_rsa",
            "/tmp/whatever.suspect",
            "/var/lib/moat/quarantine/01J8ZK/x",
        ] {
            assert!(g.is_forbidden(p), "{} must never be shipped", p);
        }
        assert!(!g.is_forbidden("/home/dan/.ssh/id_rsa"));
        assert!(!g.is_forbidden("/var/lib/moat/alerts.jsonl"));

        // …and it is swept out wherever it appears, however deeply nested and
        // whatever the key is called.
        let mut v: Value = serde_json::from_str(
            r#"{"a":"/var/lib/moat/incidents/01/actor.x.suspect",
                "b":{"c":["ok","/var/lib/moat/incidents/01/bundle.md"]},
                "brand_new_field":"/tmp/z.suspect"}"#,
        )
        .unwrap();
        assert_eq!(g.sweep(&mut v), 3);
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("suspect"), "{}", s);
        assert!(!s.contains("incidents"), "{}", s);
        assert!(s.contains(WITHHELD));
    }

    #[test]
    fn the_token_never_reaches_a_log_line_or_an_error() {
        let secret = "hec-8f2b1c9e-super-secret";
        let s = Scrubber::new(vec![secret.to_string()]);
        // The classic leak: a 401 body that echoes the header back.
        let body = format!("{{\"error\":\"bad token\",\"sent\":\"Bearer {}\"}}", secret);
        let out = s.scrub(&body);
        assert!(!out.contains(secret), "{}", out);
        assert!(out.contains("<redacted>"));
        // …and in a connection error, and truncated for a hostile body.
        assert!(!s
            .scrub(&format!("connect to https://x/?key={} failed", secret))
            .contains(secret));
        let long = format!("{}{}", "x".repeat(500), secret);
        let short = s.scrub_short(&long, 100);
        assert!(!short.contains(secret));
        assert!(short.len() <= 104);
    }

    /// The header template is printable; the header value is not. This is what
    /// makes `--dry-run` and `moat-ship check` safe to paste into a bug report.
    #[test]
    fn dry_run_output_contains_no_secret() {
        let cfg = HttpsConfig {
            url: "https://splunk.example/services/collector/raw".into(),
            token: "hec-8f2b1c9e-super-secret".into(),
            ..HttpsConfig::default()
        };
        let printable = describe_https(&cfg);
        assert!(printable.contains("Authorization: Bearer ${token}"));
        assert!(!printable.contains("hec-8f2b1c9e"));
        assert!(printable.contains("splunk.example"));
    }

    #[test]
    fn tls_verification_has_no_off_switch_and_plain_http_is_refused() {
        assert!(check_url("https://collector.example/v1").is_ok());
        assert!(check_url("http://127.0.0.1:8088/services/collector").is_ok());
        assert!(check_url("http://localhost:3100/loki/api/v1/push").is_ok());
        assert!(check_url("http://collector.example/v1").is_err());
        assert!(check_url("http://192.168.1.10:8088/x").is_err());
        assert!(check_url("ftp://x/y").is_err());
        // There is no configuration key that could turn verification off.
        let t = toml::to_string(&ShipConfig::default()).unwrap();
        for bad in ["insecure", "skip_verify", "verify", "danger", "self_signed"] {
            assert!(!t.contains(bad), "ship.toml must not offer {:?}", bad);
        }
    }

    #[test]
    fn a_world_readable_secret_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tok = dir.path().join("token");
        std::fs::write(&tok, "abc123456").unwrap();
        std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut c = ShipConfig {
            enabled: true,
            transport: "https".into(),
            ..Default::default()
        };
        c.https.url = "https://x.example/v1".into();
        c.https.token_file = tok.display().to_string();
        let p = c.problems(dir.path().join("ship.toml").as_path());
        assert!(p.iter().any(|s| s.contains("0600")), "{:?}", p);

        std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(c.problems(dir.path().join("ship.toml").as_path()).is_empty());
        assert_eq!(c.token().unwrap(), "abc123456");
    }

    #[test]
    fn an_inline_token_requires_a_0600_config_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cf = dir.path().join("ship.toml");
        std::fs::write(&cf, "").unwrap();
        std::fs::set_permissions(&cf, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut c = ShipConfig {
            enabled: true,
            transport: "https".into(),
            ..Default::default()
        };
        c.https.url = "https://x.example/v1".into();
        c.https.token = "inline-secret-1".into();
        assert!(c.problems(&cf).iter().any(|s| s.contains("0600")));
        std::fs::set_permissions(&cf, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(c.problems(&cf).is_empty());
    }

    // --------------------------------------------------------------- redaction

    #[test]
    fn home_becomes_tilde_and_a_key_name_is_dropped() {
        let r = red();
        assert_eq!(r.string("/home/dan/Projects/x"), "~/Projects/x");
        assert_eq!(r.string("/home/dan/.ssh/id_ed25519"), "~/.ssh/<redacted>");
        assert_eq!(r.string("/home/dan/.aws/credentials"), "~/.aws/<redacted>");
        // The directory survives, so the alert still reads "read something out
        // of ~/.ssh", which is the whole content of it.
        assert!(r.string("/home/dan/.ssh/id_rsa").contains(".ssh"));
        // Ordinary system paths are untouched.
        assert_eq!(r.string("/usr/bin/node"), "/usr/bin/node");
    }

    #[test]
    fn redaction_reaches_every_string_in_the_record() {
        let mut v: Value = serde_json::from_str(ALERT).unwrap();
        red().value(&mut v);
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("/home/dan"), "{}", s);
        assert!(!s.contains("id_rsa"), "{}", s);
        assert!(s.contains("~/.ssh/<redacted>"));
    }

    #[test]
    fn redaction_can_be_turned_off_but_the_evidence_guard_cannot() {
        let off = RedactConfig {
            home: false,
            secret_paths: false,
            extra: vec![],
        };
        let r = Redactor::new(&off, &["/home/dan".into()]);
        assert_eq!(r.string("/home/dan/.ssh/id_rsa"), "/home/dan/.ssh/id_rsa");
        // Guard::sweep is not driven by RedactConfig at all.
        let mut w = 0;
        let line = r#"{"id":"01A","rule":"r","file":{"path":"/var/lib/moat/incidents/01A/x.suspect"}}"#;
        let e = envelope(line, "alerts", "mars", &r, &guard(), &mut w).unwrap();
        assert_eq!(w, 1);
        assert!(e.to_line().contains(WITHHELD));
    }

    // ---------------------------------------------------------------- envelope

    #[test]
    fn an_alert_is_identified_by_its_own_ulid() {
        let mut w = 0;
        let e = envelope(ALERT, "alerts", "mars", &red(), &guard(), &mut w).unwrap();
        assert_eq!(e.event_id, "01J8ZK6B4Q3M7N9P2R5S8T1V4W");
        assert_eq!(e.kind, "alert");
        assert_eq!(e.severity, "high");
        assert_eq!(e.value["host"], "mars");
        assert_eq!(e.value["@timestamp"], "2026-09-03T16:21:07.123Z");
        // Re-shipping the same line produces the identical id: that is what
        // makes at-least-once safe with receiver-side dedupe.
        let e2 = envelope(ALERT, "alerts", "mars", &red(), &guard(), &mut w).unwrap();
        assert_eq!(e.event_id, e2.event_id);
        assert_eq!(e.to_line(), e2.to_line());
    }

    #[test]
    fn updates_receipts_and_telemetry_get_content_addressed_ids() {
        let mut w = 0;
        let u = r#"{"v":1,"id":"01J8ZK6B4Q3M7N9P2R5S8T1V4W","update":{"acked":true}}"#;
        let a = envelope(u, "alerts", "mars", &red(), &guard(), &mut w).unwrap();
        assert_eq!(a.kind, "update");
        assert!(a.event_id.starts_with("01J8ZK6B4Q3M7N9P2R5S8T1V4W."));
        // A different update on the same alert is a different record.
        let u2 = r#"{"v":1,"id":"01J8ZK6B4Q3M7N9P2R5S8T1V4W","update":{"acked":false}}"#;
        let b = envelope(u2, "alerts", "mars", &red(), &guard(), &mut w).unwrap();
        assert_ne!(a.event_id, b.event_id);

        let t = r#"{"v":1,"class":"file","kind":"file_write","ts":"2026-09-04T10:00:00Z",
                    "path":"/home/dan/x.js","verdict":"modify","exec_id":"e1"}"#;
        let c = envelope(t, "file", "mars", &red(), &guard(), &mut w).unwrap();
        assert_eq!(c.kind, "file_write");
        assert!(c.event_id.starts_with("e1."));
        assert_eq!(c.value["moat"]["path"], "~/x.js");
    }

    #[test]
    fn a_garbage_line_is_skipped_not_shipped() {
        let mut w = 0;
        assert!(envelope("not json", "alerts", "m", &red(), &guard(), &mut w).is_none());
        assert!(envelope("[1,2]", "alerts", "m", &red(), &guard(), &mut w).is_none());
        assert!(envelope("", "alerts", "m", &red(), &guard(), &mut w).is_none());
    }

    // ------------------------------------------------------------------ syslog

    #[test]
    fn syslog_ships_a_summary_and_says_so_when_it_truncates() {
        let mut w = 0;
        let e = envelope(ALERT, "alerts", "mars", &red(), &guard(), &mut w).unwrap();
        let cfg = SyslogConfig::default();
        let l = syslog_line(&cfg, &e, "mars", "2026-09-03T16:21:07.123Z");
        // RFC5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG.
        // facility 13 * 8 + err(3) = 107.
        assert!(l.starts_with("<107>1 2026-09-03T16:21:07.123Z mars moat "), "{}", l);
        assert!(l.contains("id=01J8ZK6B4Q3M7N9P2R5S8T1V4W"));
        assert!(l.contains("severity=high"));
        assert!(l.contains("rule=moat-cred-ssh-private-key-read"));
        assert!(l.contains("exe="));
        // The lossy part is deliberate: no explain block, no ancestry.
        assert!(!l.contains("explain"));
        assert!(l.len() < cfg.max_len);

        // A record that does not fit says so rather than stopping mid-sentence.
        let small = SyslogConfig {
            max_len: 480,
            ..SyslogConfig::default()
        };
        let mut big = e.clone();
        big.value["moat"]["title"] = json!("x".repeat(2000));
        let t = syslog_line(&small, &big, "mars", "2026-09-03T16:21:07.123Z");
        assert!(t.len() <= 480 + 14);
        assert!(t.ends_with("…[truncated]"), "{}", t);
    }

    #[test]
    fn syslog_severity_follows_the_alert_severity() {
        assert_eq!(syslog_severity("critical"), 2);
        assert_eq!(syslog_severity("high"), 3);
        assert_eq!(syslog_severity("medium"), 4);
        assert_eq!(syslog_severity("low"), 5);
        assert_eq!(syslog_severity("info"), 6);
    }

    // ------------------------------------------------------------------ buffer

    #[test]
    fn the_buffer_is_bounded_and_counts_what_it_drops() {
        let cfg = BufferConfig {
            max_records: 10,
            max_bytes: 10 * 1024 * 1024,
            ..BufferConfig::default()
        };
        let mut b = Buffer::new(&cfg);
        let mut w = 0;
        for i in 0..25 {
            let line = ALERT.replace("01J8ZK6B4Q3M7N9P2R5S8T1V4W", &format!("01{:024}", i));
            b.push(envelope(&line, "alerts", "m", &red(), &guard(), &mut w).unwrap());
        }
        assert_eq!(b.len(), 10, "never grows past the cap");
        assert_eq!(b.dropped, 15, "and the loss is counted, not silent");
        // Drop-oldest: what survived is the most recent window.
        let head = b.peek(1, 1 << 20);
        assert!(head[0].event_id.ends_with("15"), "{}", head[0].event_id);
    }

    #[test]
    fn a_byte_cap_bounds_the_buffer_even_with_few_records() {
        let cfg = BufferConfig {
            max_records: 1_000_000,
            max_bytes: 4096,
            ..BufferConfig::default()
        };
        let mut b = Buffer::new(&cfg);
        let mut w = 0;
        for i in 0..50 {
            let line = ALERT.replace("01J8ZK6B4Q3M7N9P2R5S8T1V4W", &format!("01{:024}", i));
            b.push(envelope(&line, "alerts", "m", &red(), &guard(), &mut w).unwrap());
        }
        assert!(b.bytes() <= 4096 + 2048, "bytes = {}", b.bytes());
        assert!(b.dropped > 0);
    }

    #[test]
    fn a_batch_is_only_consumed_once_it_is_acknowledged() {
        let cfg = BufferConfig::default();
        let mut b = Buffer::new(&cfg);
        let mut w = 0;
        b.push(envelope(ALERT, "alerts", "m", &red(), &guard(), &mut w).unwrap());
        let batch = b.peek(10, 1 << 20);
        assert_eq!(batch.len(), 1);
        assert_eq!(b.len(), 1, "peek does not consume");
        b.commit(1);
        assert!(b.is_empty());
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let (min, max) = (5, 300);
        let mut d = 0;
        let mut seen = Vec::new();
        for i in 0..12 {
            d = next_backoff(d, min, max, i);
            seen.push(d);
        }
        assert!(seen[0] >= min && seen[0] <= min + min / 4 + 1);
        assert!(seen.windows(2).all(|w| w[1] >= w[0] || w[1] == max));
        assert!(seen.iter().all(|d| *d <= max));
        assert_eq!(*seen.last().unwrap(), max);
    }

    // ------------------------------------------------------------------ cursor

    fn write(p: &Path, s: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap();
        f.write_all(s.as_bytes()).unwrap();
    }

    fn shipper(dir: &Path, cfg: ShipConfig) -> Shipper {
        Shipper::new(
            cfg,
            "mars".into(),
            dir.join("cursor.json"),
            vec![Source {
                class: "alerts".into(),
                path: dir.join("alerts.jsonl"),
                rotated: dir.join("alerts.1.jsonl"),
            }],
            &["/home/dan".to_string()],
            &dir.join("incidents"),
            &dir.join("quarantine"),
            Scrubber::default(),
        )
    }

    fn alert_line(i: usize) -> String {
        format!(
            "{}\n",
            ALERT
                .replace("01J8ZK6B4Q3M7N9P2R5S8T1V4W", &format!("01{:024}", i))
                .replace('\n', " ")
        )
    }

    /// The contract in one test: restart re-sends nothing and skips nothing.
    #[test]
    fn a_restart_neither_reships_nor_skips() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("alerts.jsonl");
        for i in 0..3 {
            write(&a, &alert_line(i));
        }
        let cfg = ShipConfig {
            enabled: true,
            transport: "none".into(),
            heartbeat_secs: 0,
            ..Default::default()
        };

        let mut s = shipper(dir.path(), cfg.clone());
        let mut tx = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s.pass(&mut tx, 100), 3);

        // A completely fresh Shipper, as after a service restart.
        let mut s2 = shipper(dir.path(), cfg.clone());
        let mut tx2 = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s2.pass(&mut tx2, 200), 0, "nothing is sent twice");

        write(&a, &alert_line(3));
        assert_eq!(s2.pass(&mut tx2, 300), 1, "and the new one is not skipped");
        assert!(tx2.sent[0].contains(&format!("01{:024}", 3)));
    }

    /// A collector that is down costs nothing but time, and the cursor does not
    /// move past records the collector never got.
    #[test]
    fn an_outage_does_not_advance_the_cursor() {
        struct Dead;
        impl Transport for Dead {
            fn name(&self) -> &'static str {
                "dead"
            }
            fn send(&mut self, _b: &[Envelope]) -> Result<(), SendError> {
                Err(SendError::retry("connection refused"))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("alerts.jsonl");
        write(&a, &alert_line(0));
        let cfg = ShipConfig {
            heartbeat_secs: 0,
            ..Default::default()
        };
        let mut s = shipper(dir.path(), cfg.clone());
        assert_eq!(s.pass(&mut Dead, 100), 0);
        assert_eq!(s.buffer.len(), 1, "held, not lost");
        assert!(s.stats().last_error.contains("connection refused"));

        // The collector comes back; a fresh process delivers the held record.
        let mut s2 = shipper(dir.path(), cfg);
        let mut tx = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s2.pass(&mut tx, 1000), 1, "not lost across the restart");
    }

    #[test]
    fn a_rotation_between_polls_loses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("alerts.jsonl");
        let r = dir.path().join("alerts.1.jsonl");
        write(&a, &alert_line(0));
        let cfg = ShipConfig {
            heartbeat_secs: 0,
            ..Default::default()
        };
        let mut s = shipper(dir.path(), cfg);
        let mut tx = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s.pass(&mut tx, 100), 1);

        // Two more land, then the store rotates, then one more.
        write(&a, &alert_line(1));
        write(&a, &alert_line(2));
        std::fs::rename(&a, &r).unwrap();
        write(&a, &alert_line(3));

        assert_eq!(s.pass(&mut tx, 200), 3, "the tail of the old file is not lost");
        let all = tx.sent.join("\n");
        for i in 0..4 {
            assert!(all.contains(&format!("01{:024}", i)), "missing alert {}", i);
        }
    }

    #[test]
    fn truncation_in_place_restarts_rather_than_reading_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("alerts.jsonl");
        write(&a, &alert_line(0));
        write(&a, &alert_line(1));
        let cfg = ShipConfig {
            heartbeat_secs: 0,
            ..Default::default()
        };
        let mut s = shipper(dir.path(), cfg);
        let mut tx = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s.pass(&mut tx, 100), 2);
        std::fs::write(&a, alert_line(9)).unwrap();
        assert_eq!(s.pass(&mut tx, 200), 1);
        assert!(tx.sent.last().unwrap().contains(&format!("01{:024}", 9)));
    }

    #[test]
    fn a_half_written_line_waits_for_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("alerts.jsonl");
        write(&a, &alert_line(0));
        write(&a, "{\"v\":1,\"id\":\"01PARTIAL");
        let cfg = ShipConfig {
            heartbeat_secs: 0,
            ..Default::default()
        };
        let mut s = shipper(dir.path(), cfg);
        let mut tx = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s.pass(&mut tx, 100), 1);
        write(&a, "\",\"rule\":\"r\",\"severity\":\"low\"}\n");
        assert_eq!(s.pass(&mut tx, 200), 1);
        assert!(tx.sent[1].contains("01PARTIAL"));
    }

    // --------------------------------------------------------------- heartbeat

    #[test]
    fn the_heartbeat_makes_silence_detectable() {
        let dir = tempfile::tempdir().unwrap();
        // No alerts at all: the quiet machine and the dead shipper look the
        // same at a collector unless this record exists.
        let cfg = ShipConfig {
            heartbeat_secs: 60,
            ..Default::default()
        };
        let mut s = shipper(dir.path(), cfg);
        let mut tx = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s.pass(&mut tx, 1000), 1, "alive with nothing to say");
        let hb: Value = serde_json::from_str(&tx.sent[0]).unwrap();
        assert_eq!(hb["kind"], "heartbeat");
        assert_eq!(hb["moat"]["shipped"], 0);
        assert_eq!(hb["moat"]["dropped"], 0);
        assert_eq!(hb["moat"]["backlog"], 0);
        assert_eq!(hb["host"], "mars");

        assert_eq!(s.pass(&mut tx, 1030), 0, "not before it is due");
        assert_eq!(s.pass(&mut tx, 1070), 1, "and again when it is");
    }

    #[test]
    fn the_heartbeat_reports_the_loss() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("alerts.jsonl");
        let mut cfg = ShipConfig {
            heartbeat_secs: 60,
            ..Default::default()
        };
        cfg.buffer.max_records = 3;
        for i in 0..20 {
            write(&a, &alert_line(i));
        }
        let mut s = shipper(dir.path(), cfg);
        let hb = s.heartbeat(1000);
        assert_eq!(hb.value["moat"]["dropped"], 0);
        s.collect();
        let hb2 = s.heartbeat(1000);
        assert!(
            hb2.value["moat"]["dropped"].as_u64().unwrap() >= 17,
            "{}",
            hb2.to_line()
        );
    }

    #[test]
    fn a_permanent_rejection_drops_the_batch_instead_of_wedging_the_stream() {
        struct Refuse(usize);
        impl Transport for Refuse {
            fn name(&self) -> &'static str {
                "refuse"
            }
            fn send(&mut self, b: &[Envelope]) -> Result<(), SendError> {
                self.0 += b.len();
                Err(SendError::permanent("HTTP 400 from collector: bad index"))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("alerts.jsonl");
        write(&a, &alert_line(0));
        let cfg = ShipConfig {
            heartbeat_secs: 0,
            ..Default::default()
        };
        let mut s = shipper(dir.path(), cfg);
        assert_eq!(s.pass(&mut Refuse(0), 100), 0);
        assert!(s.buffer.is_empty(), "the batch is dropped, not retried forever");
        assert_eq!(s.stats().dropped, 1);
        assert!(s.stats().last_error.contains("400"));
    }

    #[test]
    fn classes_gate_what_is_read_at_all() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("alerts.jsonl"), &alert_line(0));
        let cfg = ShipConfig {
            classes: vec!["process".into()], // alerts not listed
            heartbeat_secs: 0,
            ..Default::default()
        };
        let mut s = shipper(dir.path(), cfg);
        let mut tx = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s.pass(&mut tx, 100), 0);
    }

    /// moatd writes `process`, `network` and `file` into ONE telemetry.jsonl,
    /// so the class on a record is a field inside the line and not the file it
    /// came from. Recording a class locally while shipping only some of it has
    /// to work, and the cursor must still be keyed on the file.
    #[test]
    fn classes_are_filtered_per_record_out_of_one_telemetry_file() {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path().join("telemetry.jsonl");
        for (class, kind) in [
            ("process", "exec"),
            ("network", "connect"),
            ("file", "file_write"),
            ("process", "exit"),
        ] {
            write(
                &t,
                &format!(
                    "{{\"v\":1,\"class\":\"{}\",\"kind\":\"{}\",\"ts\":\"2026-09-04T10:00:00Z\",\
                      \"exec_id\":\"e-{}-{}\"}}\n",
                    class, kind, class, kind
                ),
            );
        }
        let mut s = Shipper::new(
            ShipConfig {
                classes: vec!["network".into(), "file".into()],
                heartbeat_secs: 0,
                ..Default::default()
            },
            "mars".into(),
            dir.path().join("cursor.json"),
            vec![Source {
                // One source over the whole file, whatever classes it holds.
                class: "telemetry".into(),
                path: t,
                rotated: dir.path().join("telemetry.1.jsonl"),
            }],
            &["/home/dan".to_string()],
            &dir.path().join("incidents"),
            &dir.path().join("quarantine"),
            Scrubber::default(),
        );
        s.cfg.classes.push("telemetry".into()); // so the source itself is read
        let mut tx = DryRunTransport {
            sent: vec![],
            print: false,
            syslog: None,
        };
        assert_eq!(s.pass(&mut tx, 100), 2, "only network and file");
        let classes: Vec<String> = tx
            .sent
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["class"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(classes, vec!["network", "file"]);
        // The two `process` records were skipped, not held: the cursor moved
        // past them, so they are never reconsidered.
        assert_eq!(s.pass(&mut tx, 200), 0);
        let c = Cursor::load(&dir.path().join("cursor.json"));
        assert!(c.sources.contains_key("telemetry"), "cursor is keyed on the FILE");
        assert!(c.sources["telemetry"].offset > 0);
    }

    #[test]
    fn config_problems_name_the_key_that_is_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let cf = dir.path().join("ship.toml");
        let c = ShipConfig {
            enabled: true,
            transport: "carrier-pigeon".into(),
            classes: vec!["alerts".into(), "nonsense".into()],
            heartbeat_secs: 0,
            ..Default::default()
        };
        let p = c.problems(&cf);
        assert!(p.iter().any(|s| s.contains("carrier-pigeon")));
        assert!(p.iter().any(|s| s.contains("nonsense")));
        assert!(p.iter().any(|s| s.contains("heartbeat_secs = 0")));
    }

    /// The shipped file is the documentation. A key that is only in the struct
    /// is a switch nobody knows exists; a value that disagrees with its default
    /// is a user reading one thing and getting another.
    #[test]
    fn the_shipped_ship_toml_documents_every_key_and_agrees_with_the_defaults() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/ship.toml");
        let text = std::fs::read_to_string(&p).expect("etc/ship.toml must exist");
        let shipped: toml::Value = toml::from_str(&text).expect("etc/ship.toml must parse");
        let defaults = toml::Value::try_from(ShipConfig::default()).unwrap();
        let want = defaults.as_table().unwrap();
        let got = shipped.as_table().unwrap();
        for (key, val) in want {
            let g = got
                .get(key)
                .unwrap_or_else(|| panic!("etc/ship.toml does not document {}", key));
            if let Some(sub) = val.as_table() {
                let gsub = g.as_table().unwrap_or_else(|| panic!("[{}] is not a table", key));
                for k in sub.keys() {
                    assert!(gsub.contains_key(k), "etc/ship.toml does not document {}.{}", key, k);
                }
            }
        }
        let c = ShipConfig::load(&p).expect("etc/ship.toml must load");
        assert_eq!(c, ShipConfig::default(), "a shipped ship.toml key drifted");
        assert!(!c.enabled, "shipping must ship off");
        assert_eq!(c.transport, "none");
        assert!(c.redact.home && c.redact.secret_paths, "redaction must ship on");
    }

    #[test]
    fn a_missing_ship_toml_is_defaults_and_a_broken_one_is_an_error() {
        assert!(!ShipConfig::load(Path::new("/nonexistent/ship.toml"))
            .unwrap()
            .enabled);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ship.toml");
        std::fs::write(&p, "transport = [oops\n").unwrap();
        assert!(ShipConfig::load(&p).is_err());
        std::fs::write(&p, "trnasport = \"https\"\n").unwrap();
        assert!(ShipConfig::load(&p).is_err(), "a typo must be loud");
    }
}

#[cfg(test)]
mod loopback_tests {
    use super::check_url;

    /// The http:// exception exists for a collector on this machine. It was a
    /// prefix match, so a registerable subdomain or a userinfo segment walked
    /// through it -- and what walks through is the whole record stream, in
    /// cleartext, with the bearer token attached.
    #[test]
    fn only_real_loopback_may_be_plain_http() {
        for ok in [
            "http://127.0.0.1:8088/v1",
            "http://localhost:8088/v1",
            "http://[::1]:8088/v1",
            "http://127.5.5.5/v1",
            "https://collector.example/v1",
        ] {
            assert!(check_url(ok).is_ok(), "{} should be accepted", ok);
        }
        for bad in [
            "http://collector.example/v1",
            "http://127.0.0.1.evil.example/x",
            "http://127.0.0.1@evil.example/x",
            "http://localhost:8088@evil.example/x",
            "http://localhost.evil.example/x",
        ] {
            assert!(check_url(bad).is_err(), "{} must be refused", bad);
        }
    }
}
