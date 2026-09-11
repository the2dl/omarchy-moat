//! Threat feeds.
//!
//! Two halves:
//!
//! * the **cache** (`Feeds`), which moatd reads from the feed directory and
//!   reloads when the files move on disk;
//! * the **client** (`refresh`), run by `moat-feeds` from a 15-minute timer.
//!
//! This used to fetch abuse.ch MalwareBazaar / ThreatFox / URLhaus directly.
//! All three require an `Auth-Key`, which meant a machine without a key had no
//! feed at all — and the six scanners consulted no feed in the first place.
//! It now pulls a signed, keyless **malicious-package index** from an
//! aggregator, and the scanners read that file offline before an install runs.
//! `docs/PACKAGE-FEED.md` is the format contract; this file implements the
//! "Client contract" section of it.
//!
//! Three rules run through everything below:
//!
//! * a stale feed is not a broken feed — every failure path leaves the previous
//!   files in place and exits 0, because the timer must never fail hard
//!   (CONTRACT §6.7);
//! * nothing is written until the signature verifies, because this file decides
//!   what moat warns about;
//! * the common tick is a 304 on a 200-byte object and must cost nothing.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Where the signed index is published. Overridable so a site can mirror it,
/// and so the tests can point at a local fixture.
pub const DEFAULT_BASE_URL: &str = "https://feed.runts.net";

/// The placeholder that shipped before the aggregator existed. It never
/// resolved and never will.
///
/// It matters because `/etc/moat/feeds.toml` is in pacman's `backup` array: an
/// upgrade keeps the file the machine already has and writes a `.pacnew`
/// beside it. So every machine installed before the feed went live would carry
/// this dead name forever, `moat-feeds` would fail to resolve it on every tick,
/// and the feed would be silently inert -- on exactly the machines that already
/// trusted moat enough to install it. Nobody edits a config file they were
/// never told about.
const DEAD_PLACEHOLDER_URL: &str = "https://feed.omarchy-moat.org";

/// Shipped with the package; the private half never leaves the aggregator.
pub const DEFAULT_PUBLIC_KEY_PATH: &str = "/usr/share/moat/feed-key.pub";

/// Files the client owns. `hashes.txt`, `domains.txt` and `urls.txt` are *not*
/// in this list: they are operator-supplied and a refresh must never touch
/// them.
///
/// `domains-feed.txt` is a fourth file and a deliberately separate one. The
/// aggregator now publishes a domain list, and writing it into `domains.txt`
/// would silently eat whatever the operator had put there -- the one thing
/// this module has always promised not to do. Two files, two owners, and
/// `Feeds` reads both: an operator entry wins, because a line somebody typed
/// on this machine is a deliberate act and the feed is a wholesale import.
const PACKAGES_FILE: &str = "packages.txt";
const DOMAINS_FEED_FILE: &str = "domains-feed.txt";
const META_FILE: &str = "meta.json";
const STATE_FILE: &str = "state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeedsConfig {
    /// Set false to pin the machine to whatever it already has on disk.
    pub enabled: bool,
    pub base_url: String,
    /// ed25519 public key, hex or base64, 32 bytes. Empty means read
    /// `public_key_path`.
    pub public_key: String,
    pub public_key_path: String,
    /// Refuse to apply an unsigned or badly-signed artifact. Turning this off
    /// means trusting whoever can answer for `base_url`; it exists for local
    /// mirror testing, not for production.
    pub require_signature: bool,
    pub timeout_secs: u64,
    /// Guards against a hostile or broken server handing us an endless body.
    pub max_artifact_bytes: u64,
    pub max_pointer_bytes: u64,

    // --- accepted and ignored -------------------------------------------
    // The abuse.ch settings, kept only so that an upgraded machine whose
    // /etc/moat/feeds.toml predates this change still parses. Dropping them
    // would make `deny_unknown_fields` reject the old file, and because
    // pacman leaves the existing config in place and writes a .pacnew, the
    // refresh would fail on every tick with nothing but a journal line to
    // say why. `legacy_keys_present` reports them so the failure is loud
    // once rather than silent forever.
    #[serde(default, skip_serializing)]
    auth_key: Option<String>,
    #[serde(default, skip_serializing)]
    malwarebazaar: Option<bool>,
    #[serde(default, skip_serializing)]
    threatfox: Option<bool>,
    #[serde(default, skip_serializing)]
    urlhaus: Option<bool>,
    #[serde(default, skip_serializing)]
    malwarebazaar_url: Option<String>,
    #[serde(default, skip_serializing)]
    threatfox_url: Option<String>,
    #[serde(default, skip_serializing)]
    urlhaus_url: Option<String>,
    #[serde(default, skip_serializing)]
    threatfox_days: Option<u32>,
    #[serde(default, skip_serializing)]
    urlhaus_limit: Option<u32>,
    #[serde(default, skip_serializing)]
    max_hashes: Option<usize>,
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_url: DEFAULT_BASE_URL.into(),
            public_key: String::new(),
            public_key_path: DEFAULT_PUBLIC_KEY_PATH.into(),
            require_signature: true,
            timeout_secs: 30,
            // The full index is ~1.6 MB gzipped; 64 MB is room to grow by a
            // factor of forty before anyone has to think about it again.
            max_artifact_bytes: 64 * 1024 * 1024,
            max_pointer_bytes: 256 * 1024,
            auth_key: None,
            malwarebazaar: None,
            threatfox: None,
            urlhaus: None,
            malwarebazaar_url: None,
            threatfox_url: None,
            urlhaus_url: None,
            threatfox_days: None,
            urlhaus_limit: None,
            max_hashes: None,
        }
    }
}

impl FeedsConfig {
    pub fn load(path: &Path) -> Result<FeedsConfig, String> {
        let mut cfg = match std::fs::read_to_string(path) {
            Ok(t) => toml::from_str::<FeedsConfig>(&t)
                .map_err(|e| format!("{}: {}", path.display(), e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FeedsConfig::default(),
            Err(e) => return Err(format!("{}: {}", path.display(), e)),
        };
        // Migrate the dead placeholder in place rather than asking anyone to
        // edit a file. A config that names a host which has never existed is
        // not a preference to respect -- it is the absence of one.
        if cfg.base_url.trim().trim_end_matches('/') == DEAD_PLACEHOLDER_URL {
            log::info!(
                "{}: base_url was the pre-deployment placeholder ({}); using {} instead. \
                 Merge the .pacnew to silence this.",
                path.display(),
                DEAD_PLACEHOLDER_URL,
                DEFAULT_BASE_URL
            );
            cfg.base_url = DEFAULT_BASE_URL.to_string();
        }
        Ok(cfg)
    }

    /// Names any abuse.ch-era settings still in the file. They do nothing now;
    /// saying so once is the difference between an obvious no-op and a user
    /// believing a key still buys them a feed.
    pub fn legacy_keys_present(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.auth_key.is_some() { v.push("auth_key"); }
        if self.malwarebazaar.is_some() { v.push("malwarebazaar"); }
        if self.threatfox.is_some() { v.push("threatfox"); }
        if self.urlhaus.is_some() { v.push("urlhaus"); }
        if self.malwarebazaar_url.is_some() { v.push("malwarebazaar_url"); }
        if self.threatfox_url.is_some() { v.push("threatfox_url"); }
        if self.urlhaus_url.is_some() { v.push("urlhaus_url"); }
        if self.threatfox_days.is_some() { v.push("threatfox_days"); }
        if self.urlhaus_limit.is_some() { v.push("urlhaus_limit"); }
        if self.max_hashes.is_some() { v.push("max_hashes"); }
        v
    }

    /// The pinned verification key, from the config or the shipped file.
    pub fn verifying_key(&self) -> Result<Option<[u8; 32]>, String> {
        let raw = if !self.public_key.trim().is_empty() {
            self.public_key.trim().to_string()
        } else {
            match std::fs::read_to_string(&self.public_key_path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(format!("{}: {}", self.public_key_path, e)),
            }
        };
        // The file may carry a comment line, as minisign-style keys do.
        let body = raw
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("untrusted comment:"))
            .unwrap_or("");
        if body.is_empty() {
            return Ok(None);
        }
        // The shipped file is type-tagged, ssh-style:
        //     moat-feed-ed25519 <base64 of 32 bytes>
        // A bare key is accepted too, so an operator can paste one in. The tag
        // is checked rather than skipped: an `ssh-ed25519` line is a different
        // encoding entirely (an SSH wire blob, not the raw point), and "that is
        // the wrong kind of key" is a far better answer than a length error.
        let mut fields = body.split_whitespace();
        let first = fields.next().unwrap_or("");
        let (tag, encoded) = match fields.next() {
            Some(second) => (Some(first), second),
            None => (None, first),
        };
        if let Some(tag) = tag {
            if tag != "moat-feed-ed25519" {
                return Err(format!(
                    "{}: this is a {:?} key; moat pins a `moat-feed-ed25519` key \
                     (generate one with aggregator/scripts/keygen.mjs)",
                    self.public_key_path, tag
                ));
            }
        }
        let bytes = decode_key(encoded).ok_or_else(|| {
            format!(
                "{}: public key is neither 64 hex chars nor base64 of 32 bytes \
                 (got {} characters)",
                self.public_key_path,
                encoded.len()
            )
        })?;
        Ok(Some(bytes))
    }
}

fn decode_key(s: &str) -> Option<[u8; 32]> {
    if let Some(v) = crate::util::from_hex(s) {
        return v.try_into().ok();
    }
    crate::util::from_base64(s).and_then(|v| v.try_into().ok())
}

// ------------------------------------------------------------------- the cache

#[derive(Debug, Default, Clone, Serialize)]
pub struct FeedMeta {
    pub updated: Option<String>,
    pub seq: u64,
    pub packages: usize,
    /// Operator-supplied since abuse.ch was dropped; see docs/PACKAGE-FEED.md.
    pub hashes: usize,
    pub domains: usize,
    pub urls: usize,
    /// The fetched domain list, counted separately from the operator's.
    pub domain_feed: usize,
    pub domain_feed_seq: u64,
    pub domain_feed_updated: Option<String>,
}

/// What the published domain list says about one entry.
///
/// The family and the compromised flag are not decoration. "your browser
/// reached a hacked bakery" and "your shell reached a Cobalt Strike server"
/// are the same event to a suffix match and completely different things to the
/// person being woken up, and roughly one entry in five is the former.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DomainEntry {
    pub family: String,
    pub confidence: u8,
    /// A legitimate site that has been broken into, rather than a domain
    /// registered to do harm.
    pub compromised: bool,
    pub first_seen: String,
}

/// Which list an entry came from. An operator's file is a local decision and
/// says so in the alert; the feed is a wholesale import and says that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DomainSource {
    Operator,
    Feed,
}

impl DomainSource {
    pub fn file(self) -> &'static str {
        match self {
            DomainSource::Operator => "feeds/domains.txt",
            DomainSource::Feed => "feeds/domains-feed.txt",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainHit {
    /// The feed line that fired -- not the name that was resolved. The alert
    /// says which entry matched, which is what whoever maintains the list needs.
    pub entry: String,
    pub source: DomainSource,
    /// Present for a feed entry; an operator's file is bare domains.
    pub info: Option<DomainEntry>,
}

#[derive(Debug, Default)]
pub struct Feeds {
    pub hashes: HashSet<String>,
    pub domains: HashSet<String>,
    pub domain_feed: BTreeMap<String, DomainEntry>,
    pub meta: FeedMeta,
    stamp: Option<Vec<(u64, u64)>>,
}

impl Feeds {
    pub fn load(dir: &Path) -> Feeds {
        let hashes = read_set(&dir.join("hashes.txt"));
        // Normalised like the names they are matched against: a trailing dot
        // or a capital in the operator's file must not make an entry inert.
        let domains: HashSet<String> = read_set(&dir.join("domains.txt"))
            .into_iter()
            .map(|d| crate::names::normalize_name(&d))
            .collect();
        let urls = read_set(&dir.join("urls.txt"));
        let domain_feed = read_domain_feed(&dir.join(DOMAINS_FEED_FILE));
        let feed_header = domain_feed_header(&dir.join(DOMAINS_FEED_FILE));
        let meta_json = std::fs::read_to_string(dir.join(META_FILE))
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
        let get_u = |k: &str| -> u64 {
            meta_json
                .as_ref()
                .and_then(|v| v.get(k))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        };
        Feeds {
            meta: FeedMeta {
                updated: meta_json
                    .as_ref()
                    .and_then(|v| v.get("updated"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                seq: get_u("seq"),
                packages: get_u("packages") as usize,
                hashes: hashes.len(),
                domains: domains.len(),
                urls: urls.len(),
                domain_feed: domain_feed.len(),
                domain_feed_seq: feed_header.0,
                domain_feed_updated: feed_header.1,
            },
            hashes,
            domains,
            domain_feed,
            stamp: stamp(dir),
        }
    }

    /// mtime+size poll: reload only when something actually moved. The daemon
    /// deliberately does not hold the 242k package entries in memory — the
    /// scanners read `packages.txt` directly, and moatd only reports on it.
    pub fn reload_if_changed(&mut self, dir: &Path) -> bool {
        let now = stamp(dir);
        if now == self.stamp {
            return false;
        }
        *self = Feeds::load(dir);
        true
    }

    pub fn hash_hit(&self, sha256: &str) -> bool {
        self.hashes.contains(&sha256.to_ascii_lowercase())
    }

    /// The entry `name` falls under, if any: the name itself or any parent
    /// domain of it down to two labels, so `cdn.evil.example` matches an entry
    /// of `evil.example`. A feed of registrable domains is the common shape,
    /// and a campaign rotates the leftmost label freely.
    ///
    /// The operator's file is consulted first. A line somebody typed on this
    /// machine is a deliberate local decision; the published feed is a
    /// wholesale import of forty-eight thousand names. When both cover a name,
    /// the alert should say which one the reader can go and edit.
    ///
    /// Returns the ENTRY, not the name: the alert says which line fired.
    pub fn domain_hit(&self, name: &str) -> Option<DomainHit> {
        if self.domains.is_empty() && self.domain_feed.is_empty() {
            return None;
        }
        let name = crate::names::normalize_name(name);
        let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
        if labels.len() < 2 {
            return None;
        }
        for i in 0..=labels.len() - 2 {
            let candidate = labels[i..].join(".");
            if self.domains.contains(&candidate) {
                return Some(DomainHit {
                    entry: candidate,
                    source: DomainSource::Operator,
                    info: None,
                });
            }
            if let Some(info) = self.domain_feed.get(&candidate) {
                return Some(DomainHit {
                    entry: candidate,
                    source: DomainSource::Feed,
                    info: Some(info.clone()),
                });
            }
        }
        None
    }

    /// Total entries across both lists, for the status surfaces.
    pub fn domains_known(&self) -> usize {
        self.domains.len() + self.domain_feed.len()
    }
}

/// `domain \t family \t confidence \t flags \t first_seen`, as published.
///
/// Tolerant on purpose: a short line still yields the domain, because a feed
/// that gains a column must not silently stop matching on a machine running an
/// older build. The domain is the part that decides anything.
fn read_domain_feed(path: &Path) -> BTreeMap<String, DomainEntry> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split('\t');
        let Some(domain) = f.next() else { continue };
        let domain = crate::names::normalize_name(domain);
        if domain.is_empty() {
            continue;
        }
        let family = f.next().unwrap_or("").to_string();
        let confidence = f.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let compromised = f.next() == Some("c");
        let first_seen = f.next().unwrap_or("").to_string();
        out.insert(
            domain,
            DomainEntry {
                family: if family.is_empty() { "unknown".into() } else { family },
                confidence,
                compromised,
                first_seen,
            },
        );
    }
    out
}

impl DomainHit {
    /// The evidence line, identical wherever the hit is found.
    ///
    /// Names the file, because the reader's next move differs: an operator
    /// entry is a line on this machine they can go and look at, a feed entry
    /// came from the published list and is the same on every machine.
    pub fn evidence(&self, name: &str, meta: &FeedMeta) -> String {
        let mut line = format!("feed: {} matched entry {} of {}", name, self.entry, self.source.file());
        match (self.source, &self.info) {
            (DomainSource::Feed, Some(i)) => {
                line.push_str(&format!(" ({} entries", meta.domain_feed));
                if let Some(u) = &meta.domain_feed_updated {
                    line.push_str(&format!(", published {}", u));
                }
                line.push(')');
                if !i.family.is_empty() && i.family != "unknown" {
                    line.push_str(&format!("; attributed to {}", i.family));
                }
                if i.confidence > 0 {
                    line.push_str(&format!(" at {}% confidence", i.confidence));
                }
                if !i.first_seen.is_empty() {
                    line.push_str(&format!("; first reported {}", i.first_seen));
                }
                if i.compromised {
                    // Worth saying out loud. Roughly one entry in five is a
                    // real business whose site was broken into, and "stop
                    // visiting that bakery" is a different instruction from
                    // "you are talking to a C2 server".
                    line.push_str(
                        "; reported as a legitimate site that was compromised, not a domain \
                         registered to do harm",
                    );
                }
            }
            _ => line.push_str(&format!(" ({} entries)", meta.domains)),
        }
        line
    }

    /// What goes in `IocRef.matched`.
    pub fn matched(&self) -> String {
        format!("domain:{}", self.entry)
    }
}

/// `# seq` and `# generated` off the top of the published list.
fn domain_feed_header(path: &Path) -> (u64, Option<String>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (0, None);
    };
    let head: String = text.lines().take_while(|l| l.starts_with('#')).collect::<Vec<_>>().join("\n");
    (
        header_u64(&head, "# seq ").unwrap_or(0),
        head.lines()
            .find_map(|l| l.strip_prefix("# generated "))
            .map(|v| v.trim().to_string()),
    )
}

fn stamp(dir: &Path) -> Option<Vec<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    // Watch the operator-supplied files too: they change without a refresh.
    for f in [
        PACKAGES_FILE, META_FILE, DOMAINS_FEED_FILE, "hashes.txt", "domains.txt", "urls.txt",
    ] {
        match std::fs::metadata(dir.join(f)) {
            Ok(m) => out.push((m.mtime() as u64, m.size())),
            Err(_) => out.push((0, 0)),
        }
    }
    Some(out)
}

fn read_set(path: &Path) -> HashSet<String> {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .map(|l| l.trim().to_ascii_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        })
        .unwrap_or_default()
}

// ------------------------------------------------------------------- the state

/// What we carry between ticks. Kept separate from `meta.json` because that one
/// is a status surface other things read; this one is ours.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct State {
    seq: u64,
    pointer_etag: String,
    /// Tracked separately because the two wings publish independently: a quiet
    /// week for packages is a busy week for domains and the other way round.
    #[serde(default)]
    domains_seq: u64,
}

impl State {
    fn load(dir: &Path) -> State {
        std::fs::read_to_string(dir.join(STATE_FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save(&self, dir: &Path) -> Result<(), String> {
        crate::util::atomic_write(
            &dir.join(STATE_FILE),
            format!("{}\n", serde_json::to_string_pretty(self).unwrap_or_default()).as_bytes(),
            0o644,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }
}

// ----------------------------------------------------------------- the pointer

#[derive(Debug, Clone, Deserialize)]
pub struct Pointer {
    pub version: u32,
    pub seq: u64,
    #[serde(default)]
    pub generated: String,
    #[serde(default)]
    pub entries: usize,
    pub artifact: String,
    pub sha256: String,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub deltas: BTreeMap<String, String>,
    /// The domain wing. Absent on an aggregator older than it, and absent
    /// here on a build older than the aggregator -- `serde` ignores what it
    /// does not know, which is what lets the two roll out independently.
    #[serde(default)]
    pub domains: Option<DomainsRef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainsRef {
    pub seq: u64,
    #[serde(default)]
    pub generated: String,
    #[serde(default)]
    pub entries: usize,
    pub artifact: String,
    pub sha256: String,
    #[serde(default)]
    pub bytes: u64,
}

// ------------------------------------------------------------------ the client

#[derive(Debug, Default, Serialize)]
pub struct RefreshSummary {
    pub skipped: bool,
    pub reason: Option<String>,
    /// "full", "delta", "unchanged" or "none".
    pub mode: String,
    pub seq: u64,
    pub packages: usize,
    pub added: usize,
    pub removed: usize,
    /// The domain wing, reported separately: it can move when packages do not,
    /// and it can fail without the package index being in any doubt.
    pub domains_seq: u64,
    pub domains: usize,
    pub errors: Vec<String>,
}

/// One tick. Never propagates an error: the caller exits 0 regardless.
pub fn refresh(cfg: &FeedsConfig, out_dir: &Path) -> RefreshSummary {
    let mut sum = RefreshSummary {
        mode: "none".into(),
        ..Default::default()
    };

    if !cfg.enabled {
        sum.skipped = true;
        sum.reason = Some("feeds.enabled = false; leaving existing files alone".into());
        return sum;
    }

    if let Err(e) = std::fs::create_dir_all(out_dir) {
        sum.skipped = true;
        sum.reason = Some(format!("{}: {}", out_dir.display(), e));
        return sum;
    }

    let key = match cfg.verifying_key() {
        Ok(k) => k,
        Err(e) => {
            sum.skipped = true;
            sum.reason = Some(e);
            return sum;
        }
    };
    if key.is_none() && cfg.require_signature {
        sum.skipped = true;
        sum.reason = Some(format!(
            "no feed public key at {} and require_signature is on; \
             refusing to apply an unverifiable index",
            cfg.public_key_path
        ));
        return sum;
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(cfg.timeout_secs)))
        .user_agent(concat!(
            "moat-feeds/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/dlussier/omarchy-moat)"
        ))
        .build()
        .into();

    let mut state = State::load(out_dir);
    let base = cfg.base_url.trim_end_matches('/').to_string();

    // 1. the pointer, conditionally.
    let (pointer, etag) = match fetch_pointer(&agent, &base, &state.pointer_etag, cfg) {
        Ok(Some(p)) => p,
        Ok(None) => {
            // A 304 on the pointer means neither wing moved: both live in that
            // one document, and it is byte-identical to the one we already saw.
            sum.mode = "unchanged".into();
            sum.seq = state.seq;
            sum.packages = count_packages(out_dir);
            sum.domains_seq = state.domains_seq;
            sum.domains = count_domain_feed(out_dir);
            return sum;
        }
        Err(e) => {
            sum.skipped = true;
            sum.reason = Some(format!("pointer: {}", e));
            return sum;
        }
    };

    if pointer.version != 1 {
        sum.skipped = true;
        sum.reason = Some(format!(
            "pointer announces format version {}; this build understands 1. \
             Leaving the existing index in place.",
            pointer.version
        ));
        return sum;
    }

    // A sequence must never go backwards. pointer.json is not signed, so
    // replaying an old pointer -- with its old, perfectly valid artifact and
    // matching sha256 -- would otherwise roll the index back and silently drop
    // every package added since. That is the suppression attack the signature
    // exists to prevent, arriving through the one door it does not cover.
    if pointer.seq < state.seq {
        sum.skipped = true;
        sum.reason = Some(format!(
            "pointer went BACKWARDS: it offers seq {} and this machine already has {}. Refusing to roll the index back; keeping what is on disk.",
            pointer.seq, state.seq
        ));
        return sum;
    }

    // 2. the domain wing, before any early return below.
    //
    // The two wings share one pointer and move at completely different rates:
    // a quiet quarter-hour for packages is exactly when ThreatFox has changed.
    // Doing this after the `pointer.seq == state.seq` check would have pinned
    // the domain list to whenever a malicious package happened to be published.
    match refresh_domains(&agent, &base, &pointer, cfg, key.as_ref(), out_dir, &mut state) {
        Ok(n) => sum.domains = n,
        Err(e) => sum.errors.push(format!("domains: {}", e)),
    }
    sum.domains_seq = state.domains_seq;

    // 3. nothing new.
    let have_index = out_dir.join(PACKAGES_FILE).exists();
    if pointer.seq == state.seq && have_index {
        state.pointer_etag = etag;
        let _ = state.save(out_dir);
        sum.mode = "unchanged".into();
        sum.seq = state.seq;
        sum.packages = count_packages(out_dir);
        return sum;
    }

    // 4. delta if we can chain to it, full otherwise.
    let delta_path = if have_index && state.seq > 0 {
        pointer.deltas.get(&state.seq.to_string()).cloned()
    } else {
        None
    };

    let outcome = match &delta_path {
        Some(p) => apply_delta(
            &agent,
            &base,
            p,
            cfg,
            key.as_ref(),
            out_dir,
            state.seq,
            pointer.seq,
        ),
        None => apply_full(&agent, &base, &pointer, cfg, key.as_ref(), out_dir),
    };

    let mut outcome = match outcome {
        Ok(o) => o,
        Err(e) if delta_path.is_some() => {
            // A broken delta chain is a fall-back case, not a failure.
            sum.errors.push(format!("delta: {}; falling back to full", e));
            match apply_full(&agent, &base, &pointer, cfg, key.as_ref(), out_dir) {
                Ok(o) => o,
                Err(e) => {
                    sum.skipped = true;
                    sum.reason = Some(format!("full: {}", e));
                    return sum;
                }
            }
        }
        Err(e) => {
            sum.skipped = true;
            sum.reason = Some(format!("full: {}", e));
            return sum;
        }
    };
    outcome.mode = if delta_path.is_some() && sum.errors.is_empty() {
        "delta"
    } else {
        "full"
    }
    .into();

    // 5. commit.
    state.seq = pointer.seq;
    state.pointer_etag = etag;
    if let Err(e) = state.save(out_dir) {
        sum.errors.push(e);
    }
    if let Err(e) = write_meta(out_dir, &pointer, outcome.packages, &outcome.mode) {
        sum.errors.push(e);
    }

    sum.mode = outcome.mode;
    sum.seq = pointer.seq;
    sum.packages = outcome.packages;
    sum.added = outcome.added;
    sum.removed = outcome.removed;
    sum
}

struct Applied {
    mode: String,
    packages: usize,
    added: usize,
    removed: usize,
}

fn fetch_pointer(
    agent: &ureq::Agent,
    base: &str,
    etag: &str,
    cfg: &FeedsConfig,
) -> Result<Option<(Pointer, String)>, String> {
    let url = format!("{}/v1/pointer.json", base);
    let mut req = agent.get(&url);
    if !etag.is_empty() {
        req = req.header("If-None-Match", etag);
    }
    let mut resp = req.call().map_err(|e| e.to_string())?;
    if resp.status() == 304 {
        return Ok(None);
    }
    let new_etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp
        .body_mut()
        .with_config()
        .limit(cfg.max_pointer_bytes)
        .read_to_string()
        .map_err(|e| e.to_string())?;
    let p: Pointer = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    Ok(Some((p, new_etag)))
}

/// Fetch `path` and its detached signature, verify both, return the plain text.
fn fetch_verified(
    agent: &ureq::Agent,
    base: &str,
    path: &str,
    cfg: &FeedsConfig,
    key: Option<&[u8; 32]>,
    expect_sha256: Option<&str>,
) -> Result<String, String> {
    let url = format!("{}{}", base, path);
    let gz = agent
        .get(&url)
        .call()
        .map_err(|e| e.to_string())?
        .body_mut()
        .with_config()
        .limit(cfg.max_artifact_bytes)
        .read_to_vec()
        .map_err(|e| e.to_string())?;

    // Signature first: it is the check that matters, so nothing else runs
    // before it succeeds.
    if let Some(k) = key {
        let sig = agent
            .get(&format!("{}.sig", url))
            .call()
            .map_err(|e| format!("signature: {}", e))?
            .body_mut()
            .with_config()
            .limit(4096)
            .read_to_vec()
            .map_err(|e| format!("signature: {}", e))?;
        verify_ed25519(k, &gz, &sig)?;
    } else if cfg.require_signature {
        return Err("no public key available".into());
    }

    if let Some(want) = expect_sha256 {
        let got = crate::util::sha256_hex(&gz);
        if !got.eq_ignore_ascii_case(want) {
            return Err(format!("sha256 mismatch: pointer said {}, got {}", want, got));
        }
    }

    let mut text = String::new();
    use std::io::Read;
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut text)
        .map_err(|e| format!("gunzip: {}", e))?;
    Ok(text)
}

fn verify_ed25519(key: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    // Accept a raw 64-byte signature or its hex/base64 text form, so the
    // aggregator can publish whichever is convenient.
    let raw: Vec<u8> = if sig.len() == 64 {
        sig.to_vec()
    } else {
        let s = std::str::from_utf8(sig)
            .map_err(|_| "signature is neither 64 raw bytes nor text".to_string())?
            .trim();
        let s = s
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .unwrap_or("");
        crate::util::from_hex(s)
            .or_else(|| crate::util::from_base64(s))
            .ok_or_else(|| "signature is not decodable".to_string())?
    };
    let sig: [u8; 64] = raw
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(key).map_err(|e| format!("bad public key: {}", e))?;
    vk.verify(msg, &Signature::from_bytes(&sig))
        .map_err(|_| "SIGNATURE DID NOT VERIFY".to_string())
}

/// Fetch, verify and install the published domain list.
///
/// Never fatal to the package refresh. The six scanners read `packages.txt`
/// before every install and that path has worked for a year; a new feed wing
/// does not get to break it. Every failure here leaves the file that is on disk
/// exactly where it is -- a stale domain list still matches yesterday's C2.
///
/// @returns the number of entries now on disk.
#[allow(clippy::too_many_arguments)]
fn refresh_domains(
    agent: &ureq::Agent,
    base: &str,
    pointer: &Pointer,
    cfg: &FeedsConfig,
    key: Option<&[u8; 32]>,
    out_dir: &Path,
    state: &mut State,
) -> Result<usize, String> {
    let Some(d) = pointer.domains.as_ref() else {
        // An aggregator that does not publish one. Not an error, and in
        // particular not a reason to delete a list we already have.
        return Ok(count_domain_feed(out_dir));
    };

    // The same rollback guard the package wing has, for the same reason:
    // pointer.json is not signed, so replaying an old pointer with its old but
    // perfectly valid artifact would roll the list back to before whichever
    // domains the attacker cares about were added. The signature cannot see
    // this; only a sequence that never decreases can.
    if d.seq < state.domains_seq {
        return Err(format!(
            "pointer offers domain seq {} and this machine already has {}; refusing to roll back",
            d.seq, state.domains_seq
        ));
    }

    let have = out_dir.join(DOMAINS_FEED_FILE).exists();
    if d.seq == state.domains_seq && have {
        return Ok(count_domain_feed(out_dir));
    }

    let text = fetch_verified(agent, base, &d.artifact, cfg, key, Some(&d.sha256))?;

    // The sequence is inside the signed bytes. Without this check a fresh
    // pointer can serve a stale artifact whose signature is genuine.
    match header_u64(&text, "# seq ") {
        Some(seq) if seq == d.seq => {}
        Some(seq) => {
            return Err(format!(
                "pointer says domain seq {} but the signed artifact says {}; refusing it",
                d.seq, seq
            ))
        }
        None => return Err("the domain artifact does not state its own seq; refusing it".into()),
    }

    let entries = text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();
    if entries == 0 {
        return Err("domain list parsed to zero entries; refusing to install it".into());
    }

    crate::util::atomic_write(&out_dir.join(DOMAINS_FEED_FILE), text.as_bytes(), 0o644)
        .map_err(|e| format!("{}: {}", DOMAINS_FEED_FILE, e))?;
    state.domains_seq = d.seq;
    Ok(entries)
}

fn count_domain_feed(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join(DOMAINS_FEED_FILE))
        .map(|t| {
            t.lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .count()
        })
        .unwrap_or(0)
}

fn apply_full(
    agent: &ureq::Agent,
    base: &str,
    pointer: &Pointer,
    cfg: &FeedsConfig,
    key: Option<&[u8; 32]>,
    out_dir: &Path,
) -> Result<Applied, String> {
    let text = fetch_verified(
        agent,
        base,
        &pointer.artifact,
        cfg,
        key,
        Some(&pointer.sha256),
    )?;
    // The artifact states its own sequence INSIDE the signed bytes. The
    // pointer is unsigned, so this is what stops a fresh-looking pointer from
    // serving an old artifact whose signature is genuine.
    match header_u64(&text, "# seq ") {
        Some(seq) if seq == pointer.seq => {}
        Some(seq) => {
            return Err(format!(
                "pointer says seq {} but the signed artifact says {}; refusing it",
                pointer.seq, seq
            ))
        }
        None => {
            return Err("the artifact does not state its own seq; refusing it".into());
        }
    }
    let index = parse_index(&text)?;
    let n = index.len();
    write_index(out_dir, &index)?;
    Ok(Applied {
        mode: "full".into(),
        packages: n,
        added: n,
        removed: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_delta(
    agent: &ureq::Agent,
    base: &str,
    path: &str,
    cfg: &FeedsConfig,
    key: Option<&[u8; 32]>,
    out_dir: &Path,
    from_seq: u64,
    to_seq: u64,
) -> Result<Applied, String> {
    let current = std::fs::read_to_string(out_dir.join(PACKAGES_FILE))
        .map_err(|e| format!("{}: {}", PACKAGES_FILE, e))?;
    let mut index = parse_index(&current)?;
    let text = fetch_verified(agent, base, path, cfg, key, None)?;

    // A delta is only meaningful between the two sequences it names, and both
    // are inside the signed bytes. Applying one to the wrong base would corrupt
    // the index quietly -- entries removed that were never added, and no
    // signature failure to show for it.
    match (header_u64(&text, "# from "), header_u64(&text, "# to ")) {
        (Some(f), Some(t)) if f == from_seq && t == to_seq => {}
        (Some(f), Some(t)) => {
            return Err(format!(
                "delta is {}->{} but this machine needs {}->{}",
                f, t, from_seq, to_seq
            ))
        }
        _ => return Err("delta does not state the sequences it spans".into()),
    }

    let (mut added, mut removed) = (0usize, 0usize);
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split('\t');
        let op = f.next().unwrap_or("");
        let eco = f.next().unwrap_or("");
        let name = f.next().unwrap_or("");
        if eco.is_empty() || name.is_empty() {
            return Err(format!("delta line {}: malformed", n + 1));
        }
        let k = format!("{}\t{}", eco, name);
        match op {
            "+" => {
                let spec = f.next().unwrap_or("");
                if spec.is_empty() {
                    return Err(format!("delta line {}: '+' with no spec", n + 1));
                }
                if index.insert(k, spec.to_string()).is_none() {
                    added += 1;
                }
            }
            "-" => {
                if index.remove(&k).is_some() {
                    removed += 1;
                }
            }
            other => return Err(format!("delta line {}: unknown op {:?}", n + 1, other)),
        }
    }

    let n = index.len();
    write_index(out_dir, &index)?;
    Ok(Applied {
        mode: "delta".into(),
        packages: n,
        added,
        removed,
    })
}

/// `ecosystem\tname` -> spec.
type Index = BTreeMap<String, String>;

fn parse_index(text: &str) -> Result<Index, String> {
    let mut out = Index::new();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.splitn(3, '\t');
        let (eco, name, spec) = (f.next(), f.next(), f.next());
        match (eco, name, spec) {
            (Some(e), Some(nm), Some(s)) if !e.is_empty() && !nm.is_empty() && !s.is_empty() => {
                out.insert(format!("{}\t{}", e, nm), s.to_string());
            }
            _ => return Err(format!("index line {}: malformed", n + 1)),
        }
    }
    if out.is_empty() {
        return Err("index parsed to zero entries; refusing to install it".into());
    }
    Ok(out)
}

fn write_index(dir: &Path, index: &Index) -> Result<(), String> {
    let mut body = String::with_capacity(index.len() * 32 + 128);
    body.push_str("# moat-packages v1\n");
    body.push_str(&format!("# generated {}\n", crate::util::now_rfc3339()));
    body.push_str(&format!("# entries {}\n", index.len()));
    for (k, v) in index {
        body.push_str(k);
        body.push('\t');
        body.push_str(v);
        body.push('\n');
    }
    crate::util::atomic_write(&dir.join(PACKAGES_FILE), body.as_bytes(), 0o644)
        .map(|_| ())
        .map_err(|e| format!("{}: {}", PACKAGES_FILE, e))
}

fn write_meta(dir: &Path, pointer: &Pointer, packages: usize, mode: &str) -> Result<(), String> {
    let meta = serde_json::json!({
        "updated": crate::util::now_rfc3339(),
        "seq": pointer.seq,
        "generated": pointer.generated,
        "packages": packages,
        "mode": mode,
        "source": "malicious-package index (OSSF malicious-packages + DataDog dataset)",
        "hash_feed": "operator-supplied; abuse.ch was dropped, see docs/PACKAGE-FEED.md",
        "domain_feed_seq": pointer.domains.as_ref().map(|d| d.seq).unwrap_or(0),
        "domain_feed": pointer.domains.as_ref().map(|d| d.entries).unwrap_or(0),
        "domain_feed_source": "ThreatFox (abuse.ch), gated and signed by the aggregator",
    });
    crate::util::atomic_write(
        &dir.join(META_FILE),
        format!("{}\n", serde_json::to_string_pretty(&meta).unwrap_or_default()).as_bytes(),
        0o644,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// A `# key value` header line from the top of a signed artifact or delta.
/// Only the comment block is scanned: a body line can contain anything.
fn header_u64(text: &str, prefix: &str) -> Option<u64> {
    text.lines()
        .take_while(|l| l.starts_with('#'))
        .find_map(|l| l.strip_prefix(prefix))
        .and_then(|v| v.trim().parse().ok())
}

fn count_packages(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join(PACKAGES_FILE))
        .map(|t| {
            t.lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .count()
        })
        .unwrap_or(0)
}

/// Where `moat-feeds` and the daemon agree the config lives.
pub fn default_config_path() -> PathBuf {
    std::env::var_os("MOAT_FEEDS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/moat/feeds.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(pairs: &[(&str, &str, &str)]) -> String {
        let mut s = String::from("# moat-packages v1\n");
        for (e, n, sp) in pairs {
            s.push_str(&format!("{}\t{}\t{}\n", e, n, sp));
        }
        s
    }

    #[test]
    fn a_domain_hit_walks_parent_domains_and_names_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("domains.txt"), "# c2\nEvil.Example.\nexact.only.test\n").unwrap();
        let f = Feeds::load(dir.path());
        assert_eq!(f.meta.domains, 2);
        let entry = |n: &str| f.domain_hit(n).map(|h| h.entry);
        assert_eq!(entry("cdn.evil.example").as_deref(), Some("evil.example"));
        assert_eq!(entry("EVIL.example.").as_deref(), Some("evil.example"));
        assert_eq!(entry("exact.only.test").as_deref(), Some("exact.only.test"));
        assert_eq!(
            f.domain_hit("cdn.evil.example").unwrap().source,
            crate::feeds::DomainSource::Operator
        );
        assert!(f.domain_hit("notevil.example").is_none(), "the walk is on label boundaries");
        assert!(f.domain_hit("example").is_none(), "one label is never a match");
        assert!(f.domain_hit("only.test").is_none(), "a subdomain entry does not cover its parent");
        assert!(Feeds::default().domain_hit("evil.example").is_none());
    }

    // --- a real server, because the fetch path had no test at all -----------
    //
    // Everything interesting about `refresh` happens over HTTP: the pointer,
    // the detached signature, the sha256, the sequence inside the signed bytes
    // and the rollback guard. None of it could be reached from a unit test, so
    // none of it was covered. This is a two-route server on a loopback port --
    // enough to answer a pointer and a pair of artifacts, and enough to lie in
    // the specific ways the client is supposed to refuse.

    use std::io::{BufRead, BufReader, Write};
    use std::sync::mpsc;

    struct Server {
        base: String,
        _stop: mpsc::Sender<()>,
    }

    /// Routes are absolute paths -> (content type, body).
    fn serve(routes: std::collections::HashMap<String, Vec<u8>>) -> Server {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if rx.try_recv() != Err(mpsc::TryRecvError::Empty) {
                    return;
                }
                let Ok(mut stream) = stream else { return };
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = routes.get(&path);
                let head = match &body {
                    Some(b) => format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\netag: \"x\"\r\nconnection: close\r\n\r\n",
                        b.len()
                    ),
                    None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string(),
                };
                let _ = stream.write_all(head.as_bytes());
                if let Some(b) = body {
                    let _ = stream.write_all(b);
                }
                let _ = stream.flush();
            }
        });
        Server { base, _stop: tx }
    }

    fn gz(text: &str) -> Vec<u8> {
        use std::io::Write as _;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(text.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    struct Keys {
        signing: ed25519_dalek::SigningKey,
        pub_hex: String,
    }

    fn keys() -> Keys {
        use ed25519_dalek::SigningKey;
        // Deterministic: a test that fails should fail the same way twice.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pub_hex = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        Keys { signing, pub_hex }
    }

    fn sign(k: &Keys, bytes: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        k.signing.sign(bytes).to_bytes().to_vec()
    }

    fn domain_artifact(seq: u64, rows: &[&str]) -> String {
        let mut s = format!(
            "# moat-domains v1\n# generated 2026-09-11T00:00:00Z\n# entries {}\n# seq {}\n",
            rows.len(),
            seq
        );
        for r in rows {
            s.push_str(r);
            s.push('\n');
        }
        s
    }

    const ROWS: &[&str] = &[
        "evil.example\tAsyncRAT\t100\t-\t2026-01-02",
        "hacked.example\tClearFake\t90\tc\t2026-03-04",
    ];

    /// A server publishing package seq `pseq` and domain seq `dseq`.
    fn feed_server(k: &Keys, pseq: u64, dseq: Option<u64>, rows: &[&str]) -> (Server, String) {
        let mut routes = std::collections::HashMap::new();

        let pkg = format!("# moat-packages v1\n# seq {}\nnpm\tevil\t*\n", pseq);
        let pkg_gz = gz(&pkg);
        let pkg_sha = crate::util::sha256_hex(&pkg_gz);
        let pkg_path = format!("/v1/packages-{}-{}.txt.gz", pseq, &pkg_sha[..12]);
        routes.insert(format!("{}.sig", pkg_path), sign(k, &pkg_gz));
        routes.insert(pkg_path.clone(), pkg_gz.clone());

        let mut pointer = serde_json::json!({
            "version": 1, "seq": pseq, "generated": "2026-09-11T00:00:00Z",
            "entries": 1, "artifact": pkg_path, "sha256": pkg_sha,
            "bytes": pkg_gz.len(), "deltas": {},
        });

        let mut dom_path = String::new();
        if let Some(dseq) = dseq {
            let dom = domain_artifact(dseq, rows);
            let dom_gz = gz(&dom);
            let dom_sha = crate::util::sha256_hex(&dom_gz);
            dom_path = format!("/v1/domains-{}-{}.txt.gz", dseq, &dom_sha[..12]);
            routes.insert(format!("{}.sig", dom_path), sign(k, &dom_gz));
            routes.insert(dom_path.clone(), dom_gz.clone());
            pointer["domains"] = serde_json::json!({
                "seq": dseq, "generated": "2026-09-11T00:00:00Z", "entries": rows.len(),
                "artifact": dom_path, "sha256": dom_sha, "bytes": dom_gz.len(),
            });
        }
        routes.insert(
            "/v1/pointer.json".into(),
            serde_json::to_vec_pretty(&pointer).unwrap(),
        );
        (serve(routes), dom_path)
    }

    fn cfg_for(server: &Server, k: &Keys) -> FeedsConfig {
        FeedsConfig {
            base_url: server.base.clone(),
            public_key: k.pub_hex.clone(),
            timeout_secs: 5,
            ..Default::default()
        }
    }

    #[test]
    fn the_published_domain_list_is_fetched_verified_and_installed() {
        let k = keys();
        let dir = tempfile::tempdir().unwrap();
        let (server, _) = feed_server(&k, 1, Some(3), ROWS);
        let sum = refresh(&cfg_for(&server, &k), dir.path());

        assert!(sum.errors.is_empty(), "{:?}", sum.errors);
        assert_eq!(sum.domains_seq, 3);
        assert_eq!(sum.domains, 2);

        let f = Feeds::load(dir.path());
        assert_eq!(f.meta.domain_feed, 2);
        assert_eq!(f.meta.domain_feed_seq, 3);

        // Suffix matching works off the fetched list, with its metadata.
        let hit = f.domain_hit("cdn.evil.example").expect("a parent-domain match");
        assert_eq!(hit.entry, "evil.example");
        assert_eq!(hit.source, DomainSource::Feed);
        let info = hit.info.unwrap();
        assert_eq!(info.family, "AsyncRAT");
        assert_eq!(info.confidence, 100);
        assert!(!info.compromised);

        let hacked = f.domain_hit("hacked.example").unwrap();
        assert!(hacked.info.as_ref().unwrap().compromised);
        assert!(
            hacked.evidence("hacked.example", &f.meta).contains("legitimate site that was compromised"),
            "the alert has to say which kind of entry this is: {}",
            hacked.evidence("hacked.example", &f.meta)
        );
    }

    #[test]
    fn a_refresh_never_touches_the_operators_own_domain_file() {
        let k = keys();
        let dir = tempfile::tempdir().unwrap();
        // The one invariant this module has always promised. The published list
        // has forty-eight thousand names in it; writing it into the operator's
        // file would eat whatever they had put there.
        std::fs::write(dir.path().join("domains.txt"), "# mine\nlab.internal\n").unwrap();

        let (server, _) = feed_server(&k, 1, Some(1), ROWS);
        let sum = refresh(&cfg_for(&server, &k), dir.path());
        assert!(sum.errors.is_empty(), "{:?}", sum.errors);

        assert_eq!(
            std::fs::read_to_string(dir.path().join("domains.txt")).unwrap(),
            "# mine\nlab.internal\n"
        );
        let f = Feeds::load(dir.path());
        assert_eq!(f.meta.domains, 1);
        assert_eq!(f.meta.domain_feed, 2);
        assert_eq!(f.domains_known(), 3);
    }

    #[test]
    fn an_operator_entry_wins_over_the_published_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("domains.txt"), "evil.example\n").unwrap();
        std::fs::write(
            dir.path().join(DOMAINS_FEED_FILE),
            domain_artifact(1, ROWS),
        )
        .unwrap();
        let f = Feeds::load(dir.path());
        // Both lists cover it; the alert should point at the file the reader
        // can actually go and edit.
        let hit = f.domain_hit("evil.example").unwrap();
        assert_eq!(hit.source, DomainSource::Operator);
        assert_eq!(hit.source.file(), "feeds/domains.txt");
        assert!(hit.info.is_none());
        // And the one only the feed knows still matches.
        assert_eq!(f.domain_hit("hacked.example").unwrap().source, DomainSource::Feed);
    }

    #[test]
    fn a_pointer_replaying_an_older_domain_sequence_is_refused() {
        let k = keys();
        let dir = tempfile::tempdir().unwrap();
        let (server, _) = feed_server(&k, 1, Some(5), ROWS);
        assert_eq!(refresh(&cfg_for(&server, &k), dir.path()).domains_seq, 5);
        drop(server);

        // pointer.json is not signed, so an old pointer with its old but
        // perfectly valid artifact is a replay the signature cannot see.
        // Dropping back to seq 2 would lose every domain added since.
        let (old, _) = feed_server(&k, 1, Some(2), &["only.example\tx\t100\t-\t"]);
        let sum = refresh(&cfg_for(&old, &k), dir.path());
        assert!(
            sum.errors.iter().any(|e| e.contains("refusing to roll back")),
            "{:?}",
            sum.errors
        );
        let f = Feeds::load(dir.path());
        assert_eq!(f.meta.domain_feed_seq, 5, "the good list is still installed");
        assert!(f.domain_hit("evil.example").is_some());
    }

    #[test]
    fn a_domain_artifact_whose_signature_is_wrong_is_not_installed() {
        let k = keys();
        let dir = tempfile::tempdir().unwrap();

        // A complete, correct feed in every respect except one: the domain
        // artifact's detached signature was made with a different key. The
        // pointer resolves, the sha256 matches, the sequence inside the bytes
        // is right. Only the signature is a lie, and it is the only check that
        // is supposed to matter.
        let liar = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut routes = std::collections::HashMap::new();

        let pkg = "# moat-packages v1\n# seq 1\nnpm\tevil\t*\n";
        let pkg_gz = gz(pkg);
        let pkg_sha = crate::util::sha256_hex(&pkg_gz);
        let pkg_path = format!("/v1/packages-1-{}.txt.gz", &pkg_sha[..12]);
        routes.insert(format!("{}.sig", pkg_path), sign(&k, &pkg_gz));
        routes.insert(pkg_path.clone(), pkg_gz.clone());

        let dom = domain_artifact(1, ROWS);
        let dom_gz = gz(&dom);
        let dom_sha = crate::util::sha256_hex(&dom_gz);
        let dom_path = format!("/v1/domains-1-{}.txt.gz", &dom_sha[..12]);
        routes.insert(dom_path.clone(), dom_gz.clone());
        {
            use ed25519_dalek::Signer;
            routes.insert(format!("{}.sig", dom_path), liar.sign(&dom_gz).to_bytes().to_vec());
        }

        routes.insert(
            "/v1/pointer.json".into(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1, "seq": 1, "generated": "2026-09-11T00:00:00Z",
                "entries": 1, "artifact": pkg_path, "sha256": pkg_sha,
                "bytes": pkg_gz.len(), "deltas": {},
                "domains": {
                    "seq": 1, "generated": "2026-09-11T00:00:00Z", "entries": ROWS.len(),
                    "artifact": dom_path, "sha256": dom_sha, "bytes": dom_gz.len(),
                },
            }))
            .unwrap(),
        );
        let server = serve(routes);

        let sum = refresh(&cfg_for(&server, &k), dir.path());
        assert!(
            !dir.path().join(DOMAINS_FEED_FILE).exists(),
            "an unverifiable domain list must not be written"
        );
        assert!(
            sum.errors.iter().any(|e| e.contains("SIGNATURE DID NOT VERIFY")),
            "and it must say why: {:?}",
            sum.errors
        );
        // The package index is signed correctly and must still install: a
        // domain failure is not a package failure.
        assert_eq!(sum.packages, 1);
        assert_eq!(sum.seq, 1);
    }

    /// A feed whose pointer and artifact are each internally consistent but
    /// disagree with each other. `mangle` gets the artifact text to publish.
    fn feed_with_domain_artifact(k: &Keys, claimed_seq: u64, body: String) -> Server {
        let mut routes = std::collections::HashMap::new();
        let pkg = "# moat-packages v1\n# seq 1\nnpm\tevil\t*\n";
        let pkg_gz = gz(pkg);
        let pkg_sha = crate::util::sha256_hex(&pkg_gz);
        let pkg_path = format!("/v1/packages-1-{}.txt.gz", &pkg_sha[..12]);
        routes.insert(format!("{}.sig", pkg_path), sign(k, &pkg_gz));
        routes.insert(pkg_path.clone(), pkg_gz.clone());

        let dom_gz = gz(&body);
        let dom_sha = crate::util::sha256_hex(&dom_gz);
        let dom_path = format!("/v1/domains-{}-{}.txt.gz", claimed_seq, &dom_sha[..12]);
        routes.insert(format!("{}.sig", dom_path), sign(k, &dom_gz));
        routes.insert(dom_path.clone(), dom_gz.clone());

        routes.insert(
            "/v1/pointer.json".into(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1, "seq": 1, "generated": "2026-09-11T00:00:00Z",
                "entries": 1, "artifact": pkg_path, "sha256": pkg_sha,
                "bytes": pkg_gz.len(), "deltas": {},
                "domains": {
                    "seq": claimed_seq, "generated": "2026-09-11T00:00:00Z", "entries": 2,
                    "artifact": dom_path, "sha256": dom_sha, "bytes": dom_gz.len(),
                },
            }))
            .unwrap(),
        );
        serve(routes)
    }

    #[test]
    fn a_fresh_pointer_serving_a_stale_signed_list_is_refused() {
        let k = keys();
        let dir = tempfile::tempdir().unwrap();

        // The attack the sequence-inside-the-signed-bytes exists for. Everything
        // verifies: the signature is genuine, the sha256 matches, the pointer
        // looks new. The artifact is an old one, so installing it would quietly
        // drop every domain added since seq 2 -- and nothing in the signature
        // can tell, because the old artifact really was signed by us.
        let server = feed_with_domain_artifact(&k, 9, domain_artifact(2, ROWS));
        let sum = refresh(&cfg_for(&server, &k), dir.path());

        assert!(!dir.path().join(DOMAINS_FEED_FILE).exists());
        assert!(
            sum.errors.iter().any(|e| e.contains("the signed artifact says 2")),
            "{:?}",
            sum.errors
        );
    }

    #[test]
    fn a_domain_list_with_no_entries_is_refused() {
        let k = keys();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DOMAINS_FEED_FILE), domain_artifact(1, ROWS)).unwrap();

        // A header-only artifact, correctly signed. Installing it would wipe
        // the list on every machine at once and look like a successful refresh.
        let server = feed_with_domain_artifact(&k, 2, domain_artifact(2, &[]));
        let sum = refresh(&cfg_for(&server, &k), dir.path());

        assert!(
            sum.errors.iter().any(|e| e.contains("zero entries")),
            "{:?}",
            sum.errors
        );
        assert!(
            Feeds::load(dir.path()).domain_hit("evil.example").is_some(),
            "the list that was on disk is still there"
        );
    }

    #[test]
    fn the_domain_list_moves_when_the_package_index_does_not() {
        let k = keys();
        let dir = tempfile::tempdir().unwrap();
        let (first, _) = feed_server(&k, 4, Some(1), ROWS);
        let a = refresh(&cfg_for(&first, &k), dir.path());
        assert_eq!(a.seq, 4);
        assert_eq!(a.domains_seq, 1);
        drop(first);

        // Same package sequence, new domain sequence. This is the common case
        // -- packages move a few times a day, ThreatFox moves constantly -- and
        // the `pointer.seq == state.seq` early return used to skip it entirely.
        let (second, _) = feed_server(
            &k,
            4,
            Some(2),
            &["evil.example\tAsyncRAT\t100\t-\t2026-01-02", "new.example\tVidar\t75\t-\t2026-09-10"],
        );
        let b = refresh(&cfg_for(&second, &k), dir.path());
        assert_eq!(b.mode, "unchanged", "packages did not move");
        assert_eq!(b.domains_seq, 2, "but the domain list did");
        assert_eq!(b.domains, 2);
        assert!(Feeds::load(dir.path()).domain_hit("new.example").is_some());
    }

    #[test]
    fn an_aggregator_that_publishes_no_domain_list_does_not_delete_ours() {
        let k = keys();
        let dir = tempfile::tempdir().unwrap();
        let (with, _) = feed_server(&k, 1, Some(1), ROWS);
        assert_eq!(refresh(&cfg_for(&with, &k), dir.path()).domains, 2);
        drop(with);

        // A rollback of the aggregator, or a mirror that has not caught up.
        // Absent is not the same as empty.
        let (without, _) = feed_server(&k, 2, None, &[]);
        let sum = refresh(&cfg_for(&without, &k), dir.path());
        assert!(sum.errors.is_empty(), "{:?}", sum.errors);
        assert_eq!(sum.domains, 2);
        assert!(Feeds::load(dir.path()).domain_hit("evil.example").is_some());
    }

    #[test]
    fn disabled_leaves_files_alone() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PACKAGES_FILE), idx(&[("npm", "x", "*")])).unwrap();
        let cfg = FeedsConfig {
            enabled: false,
            ..Default::default()
        };
        let sum = refresh(&cfg, dir.path());
        assert!(sum.skipped);
        assert!(std::fs::read_to_string(dir.path().join(PACKAGES_FILE))
            .unwrap()
            .contains("npm\tx\t*"));
    }

    #[test]
    fn missing_key_with_require_signature_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = FeedsConfig {
            public_key_path: dir.path().join("nope.pub").display().to_string(),
            ..Default::default()
        };
        let sum = refresh(&cfg, dir.path());
        assert!(sum.skipped);
        assert!(sum.reason.unwrap().contains("public key"));
        assert!(!dir.path().join(PACKAGES_FILE).exists());
    }

    #[test]
    fn index_round_trips() {
        let text = idx(&[
            ("npm", "--hiljson", "*"),
            ("npm", "@scope/pkg", ">=1.1.2"),
            ("crates.io", "append-only-vec", "=0.1.9"),
        ]);
        let i = parse_index(&text).unwrap();
        assert_eq!(i.len(), 3);
        assert_eq!(i.get("crates.io\tappend-only-vec").unwrap(), "=0.1.9");
        assert_eq!(i.get("npm\t@scope/pkg").unwrap(), ">=1.1.2");
    }

    #[test]
    fn a_name_containing_spaces_survives() {
        // Only the tab is structural; upstream names are otherwise arbitrary.
        let i = parse_index(&idx(&[("npm", "weird name", "*")])).unwrap();
        assert!(i.contains_key("npm\tweird name"));
    }

    #[test]
    fn empty_index_is_rejected() {
        // An index that parses to nothing would silently disarm every scanner.
        assert!(parse_index("# moat-packages v1\n").is_err());
        assert!(parse_index("").is_err());
    }

    #[test]
    fn malformed_index_line_is_rejected() {
        assert!(parse_index("npm\tonlytwo\n").is_err());
    }

    #[test]
    fn delta_applies_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let start = idx(&[("npm", "keep", "*"), ("npm", "drop", "*"), ("npm", "bump", "=1.0.0")]);
        let mut index = parse_index(&start).unwrap();

        let delta = "# moat-packages-delta v1\n\
                     # from 1\n# to 2\n\
                     +\tnpm\tnew\t*\n\
                     +\tnpm\tbump\t=1.0.0|=2.0.0\n\
                     -\tnpm\tdrop\n";
        let apply = |index: &mut Index| {
            for line in delta.lines() {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut f = line.split('\t');
                let op = f.next().unwrap();
                let eco = f.next().unwrap();
                let name = f.next().unwrap();
                let k = format!("{}\t{}", eco, name);
                match op {
                    "+" => {
                        index.insert(k, f.next().unwrap().to_string());
                    }
                    "-" => {
                        index.remove(&k);
                    }
                    _ => unreachable!(),
                }
            }
        };
        apply(&mut index);
        let once = index.clone();
        apply(&mut index);
        assert_eq!(once, index, "applying a delta twice must be a no-op");

        assert!(!index.contains_key("npm\tdrop"));
        assert_eq!(index.get("npm\tbump").unwrap(), "=1.0.0|=2.0.0");
        assert_eq!(index.get("npm\tnew").unwrap(), "*");
        assert_eq!(index.len(), 3);

        write_index(dir.path(), &index).unwrap();
        let back = parse_index(&std::fs::read_to_string(dir.path().join(PACKAGES_FILE)).unwrap())
            .unwrap();
        assert_eq!(back, index, "write then parse must round-trip");
    }

    #[test]
    fn cache_reports_counts_and_reloads_on_change() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PACKAGES_FILE), idx(&[("npm", "a", "*")])).unwrap();
        std::fs::write(dir.path().join(META_FILE), r#"{"seq":7,"packages":1}"#).unwrap();
        std::fs::write(dir.path().join("hashes.txt"), "AABB\n").unwrap();

        let mut f = Feeds::load(dir.path());
        assert_eq!(f.meta.seq, 7);
        assert_eq!(f.meta.packages, 1);
        assert!(f.hash_hit("aabb"), "operator-supplied hashes still match");
        assert!(!f.reload_if_changed(dir.path()));

        // An operator dropping in their own hashes must be noticed.
        std::fs::write(dir.path().join("hashes.txt"), "aabb\nccdd\n").unwrap();
        assert!(f.reload_if_changed(dir.path()));
        assert_eq!(f.meta.hashes, 2);
    }

    #[test]
    fn signature_verification_actually_rejects() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key().to_bytes();
        let msg = b"the index bytes";
        let sig = sk.sign(msg).to_bytes();

        assert!(verify_ed25519(&vk, msg, &sig).is_ok());
        assert!(verify_ed25519(&vk, b"tampered", &sig).is_err());

        let mut bad = sig;
        bad[0] ^= 0xff;
        assert!(verify_ed25519(&vk, msg, &bad).is_err());

        // A different key must not verify: this is the bucket-compromise case.
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        assert!(verify_ed25519(&other, msg, &sig).is_err());
    }

    #[test]
    fn public_key_reads_hex_and_base64_and_skips_comments() {
        let dir = tempfile::tempdir().unwrap();
        let raw = [3u8; 32];
        let hex = raw.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let p = dir.path().join("k.pub");

        std::fs::write(&p, format!("untrusted comment: moat feed\n{}\n", hex)).unwrap();
        let cfg = FeedsConfig {
            public_key_path: p.display().to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.verifying_key().unwrap().unwrap(), raw);

        std::fs::write(&p, format!("# a comment\n{}\n", crate::util::to_base64(&raw))).unwrap();
        assert_eq!(cfg.verifying_key().unwrap().unwrap(), raw);
    }

    /// The exact bytes `aggregator/scripts/keygen.mjs` writes. These two halves
    /// are built separately and only meet on the machine that deploys them, so
    /// the format they agree on has to be pinned by a test rather than by two
    /// people remembering the same thing. It was NOT agreed at first: keygen
    /// emitted a type tag and this parser rejected it, which would have read as
    /// "your key is broken" on day one.
    #[test]
    fn the_key_file_keygen_writes_is_the_key_file_this_reads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("feed-key.pub");
        let raw = [0x11u8; 32];
        std::fs::write(
            &p,
            format!(
                "# omarchy-moat package feed signing key\nmoat-feed-ed25519 {}\n",
                crate::util::to_base64(&raw)
            ),
        )
        .unwrap();
        let cfg = FeedsConfig {
            public_key_path: p.display().to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.verifying_key().unwrap().unwrap(), raw);
    }

    /// An ssh-ed25519 key is base64 too, and the same length class, so pasting
    /// one in has to be named rather than reported as a decode failure.
    #[test]
    fn a_key_of_the_wrong_kind_is_named_as_such() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("feed-key.pub");
        std::fs::write(&p, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample\n").unwrap();
        let cfg = FeedsConfig {
            public_key_path: p.display().to_string(),
            ..Default::default()
        };
        let e = cfg.verifying_key().unwrap_err();
        assert!(e.contains("ssh-ed25519"), "{}", e);
        assert!(e.contains("moat-feed-ed25519"), "{}", e);
    }

    #[test]
    fn headers_are_read_from_the_comment_block_only() {
        let t = "# moat-packages v1\n# seq 412\n# entries 3\nnpm\t# seq 999\t*\n";
        assert_eq!(header_u64(t, "# seq "), Some(412));
        assert_eq!(header_u64(t, "# entries "), Some(3));
        assert_eq!(header_u64(t, "# nope "), None);
        // Scanning stops at the first body line, so a package that happens to
        // be named `# seq 999` cannot forge a header.
        assert_eq!(header_u64("npm\t# seq 999\t*\n", "# seq "), None);
    }

    /// pointer.json is unsigned, so a replayed pointer plus its genuine old
    /// artifact would roll the index back and drop everything added since --
    /// suppression, arriving through the one door the signature does not cover.
    #[test]
    fn a_pointer_that_goes_backwards_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PACKAGES_FILE), idx(&[("npm", "keep", "*")])).unwrap();
        std::fs::write(dir.path().join(STATE_FILE), r#"{"seq":412,"pointer_etag":""}"#).unwrap();
        let s = State::load(dir.path());
        assert_eq!(s.seq, 412);
        // The comparison the refresh path makes.
        assert!(400u64 < s.seq, "an older sequence must be refused");
        assert!(!(412u64 < s.seq), "the same sequence is not a rollback");
        assert!(!(500u64 < s.seq), "and moving forward is fine");
    }

    /// A machine that installed moat before the feed existed keeps its own
    /// /etc/moat/feeds.toml on upgrade -- pacman writes a .pacnew and leaves the
    /// old file in place -- so it would carry a hostname that has never resolved
    /// and get an inert feed for ever, without being told. The bundle has to
    /// carry the feed, not ask for it.
    #[test]
    fn the_pre_deployment_placeholder_migrates_itself() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("feeds.toml");
        std::fs::write(&p, "base_url = \"https://feed.omarchy-moat.org\"\n").unwrap();
        let c = FeedsConfig::load(&p).unwrap();
        assert_eq!(c.base_url, DEFAULT_BASE_URL, "the dead placeholder is replaced");

        // A trailing slash is the same dead name.
        std::fs::write(&p, "base_url = \"https://feed.omarchy-moat.org/\"\n").unwrap();
        assert_eq!(FeedsConfig::load(&p).unwrap().base_url, DEFAULT_BASE_URL);
    }

    /// A DELIBERATE base_url is a preference and is left alone. Someone running
    /// their own mirror must not have it overwritten by an upgrade.
    #[test]
    fn a_real_base_url_is_never_second_guessed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("feeds.toml");
        std::fs::write(&p, "base_url = \"https://mirror.example.internal\"\n").unwrap();
        assert_eq!(
            FeedsConfig::load(&p).unwrap().base_url,
            "https://mirror.example.internal"
        );
    }

    /// The shipped config names the live feed, so a fresh install needs no
    /// edit at all -- which is the actual requirement.
    #[test]
    fn the_shipped_config_points_at_the_deployed_feed() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/feeds.toml");
        let c = FeedsConfig::load(&p).expect("etc/feeds.toml must parse");
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
        assert_eq!(c.public_key_path, DEFAULT_PUBLIC_KEY_PATH);
        assert!(c.require_signature);
    }

    #[test]
    fn shipped_feeds_toml_parses() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/feeds.toml");
        let c = FeedsConfig::load(&p).expect("etc/feeds.toml must parse");
        assert!(c.require_signature, "shipped config must verify signatures");
        assert!(!c.base_url.is_empty());
    }
}
