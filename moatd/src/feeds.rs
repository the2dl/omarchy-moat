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
pub const DEFAULT_BASE_URL: &str = "https://feed.omarchy-moat.org";

/// Shipped with the package; the private half never leaves the aggregator.
pub const DEFAULT_PUBLIC_KEY_PATH: &str = "/usr/share/moat/feed-key.pub";

/// Files the client owns. `hashes.txt`, `domains.txt` and `urls.txt` are *not*
/// in this list: nothing fetches them any more, they are operator-supplied, and
/// a refresh must never touch them.
const PACKAGES_FILE: &str = "packages.txt";
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
        match std::fs::read_to_string(path) {
            Ok(t) => toml::from_str(&t).map_err(|e| format!("{}: {}", path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FeedsConfig::default()),
            Err(e) => Err(format!("{}: {}", path.display(), e)),
        }
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
}

#[derive(Debug, Default)]
pub struct Feeds {
    pub hashes: HashSet<String>,
    pub domains: HashSet<String>,
    pub meta: FeedMeta,
    stamp: Option<Vec<(u64, u64)>>,
}

impl Feeds {
    pub fn load(dir: &Path) -> Feeds {
        let hashes = read_set(&dir.join("hashes.txt"));
        let domains = read_set(&dir.join("domains.txt"));
        let urls = read_set(&dir.join("urls.txt"));
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
            },
            hashes,
            domains,
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
}

fn stamp(dir: &Path) -> Option<Vec<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    // Watch the operator-supplied files too: they change without a refresh.
    for f in [PACKAGES_FILE, META_FILE, "hashes.txt", "domains.txt", "urls.txt"] {
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
            sum.mode = "unchanged".into();
            sum.seq = state.seq;
            sum.packages = count_packages(out_dir);
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

    // 2. nothing new.
    let have_index = out_dir.join(PACKAGES_FILE).exists();
    if pointer.seq == state.seq && have_index {
        state.pointer_etag = etag;
        let _ = state.save(out_dir);
        sum.mode = "unchanged".into();
        sum.seq = state.seq;
        sum.packages = count_packages(out_dir);
        return sum;
    }

    // 3. delta if we can chain to it, full otherwise.
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

    // 4. commit.
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

    #[test]
    fn shipped_feeds_toml_parses() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/feeds.toml");
        let c = FeedsConfig::load(&p).expect("etc/feeds.toml must parse");
        assert!(c.require_signature, "shipped config must verify signatures");
        assert!(!c.base_url.is_empty());
    }
}
