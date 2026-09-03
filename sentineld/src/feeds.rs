//! Threat feeds.
//!
//! Two halves:
//!
//! * the **cache** (`Feeds`), which sentineld memory-maps in the crudest way —
//!   a `HashSet` of sha256 strings — and reloads when the file mtime changes;
//! * the **fetcher**, run by `sentinel-feeds` from an hourly timer.
//!
//! abuse.ch has required an `Auth-Key` header on every endpoint since 2025. With
//! no key configured we log one line and exit 0, leaving the previous files in
//! place: a machine with no key must not lose the feed it already has, and the
//! timer must never fail hard (CONTRACT §6.7).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

// Endpoints, verified against the abuse.ch API docs (2026-09).
pub const MALWAREBAZAAR_URL: &str = "https://mb-api.abuse.ch/api/v1/";
pub const THREATFOX_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";
pub const URLHAUS_URL: &str = "https://urlhaus-api.abuse.ch/v1/urls/recent/";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeedsConfig {
    /// abuse.ch Auth-Key (https://auth.abuse.ch/). Empty disables fetching.
    pub auth_key: String,
    pub malwarebazaar: bool,
    pub threatfox: bool,
    pub urlhaus: bool,
    pub malwarebazaar_url: String,
    pub threatfox_url: String,
    pub urlhaus_url: String,
    /// ThreatFox window, 1..7 (the API refuses more).
    pub threatfox_days: u32,
    /// URLhaus `limit/N/`, max 1000.
    pub urlhaus_limit: u32,
    pub timeout_secs: u64,
    /// Cap on how many sha256 we keep; the file is read into memory.
    pub max_hashes: usize,
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            auth_key: String::new(),
            malwarebazaar: true,
            threatfox: true,
            urlhaus: true,
            malwarebazaar_url: MALWAREBAZAAR_URL.into(),
            threatfox_url: THREATFOX_URL.into(),
            urlhaus_url: URLHAUS_URL.into(),
            threatfox_days: 3,
            urlhaus_limit: 1000,
            timeout_secs: 30,
            max_hashes: 500_000,
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

    pub fn key(&self) -> Option<&str> {
        let k = self.auth_key.trim();
        if k.is_empty() || k == "PUT-YOUR-ABUSE-CH-AUTH-KEY-HERE" {
            None
        } else {
            Some(k)
        }
    }
}

// ------------------------------------------------------------------- the cache

#[derive(Debug, Default, Clone, Serialize)]
pub struct FeedMeta {
    pub updated: Option<String>,
    pub hashes: usize,
    pub domains: usize,
    pub urls: usize,
}

#[derive(Debug, Default)]
pub struct Feeds {
    pub hashes: HashSet<String>,
    pub domains: HashSet<String>,
    pub meta: FeedMeta,
    stamp: Option<(u64, u64)>,
}

impl Feeds {
    pub fn load(dir: &Path) -> Feeds {
        let hashes = read_set(&dir.join("hashes.txt"));
        let domains = read_set(&dir.join("domains.txt"));
        let urls = read_set(&dir.join("urls.txt"));
        let updated = std::fs::read_to_string(dir.join("meta.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| v.get("updated")?.as_str().map(str::to_string));
        Feeds {
            meta: FeedMeta {
                updated,
                hashes: hashes.len(),
                domains: domains.len(),
                urls: urls.len(),
            },
            hashes,
            domains,
            stamp: stamp(dir),
        }
    }

    /// mtime+size poll (default every 60 s): reload only when something moved.
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

fn stamp(dir: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(dir.join("hashes.txt")).ok()?;
    Some((m.mtime() as u64, m.size()))
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

// ----------------------------------------------------------------- the fetcher

#[derive(Debug, Default, Serialize)]
pub struct RefreshSummary {
    pub skipped: bool,
    pub reason: Option<String>,
    pub hashes: usize,
    pub domains: usize,
    pub urls: usize,
    pub errors: Vec<String>,
}

/// Fetch every enabled source and write the four files atomically.
/// Errors from individual sources are collected, never propagated: a
/// half-reachable network must still refresh what it can.
pub fn refresh(cfg: &FeedsConfig, out_dir: &Path) -> RefreshSummary {
    let mut sum = RefreshSummary::default();
    let Some(key) = cfg.key() else {
        sum.skipped = true;
        sum.reason = Some(
            "no abuse.ch auth_key in feeds.toml; get one at https://auth.abuse.ch/ \
             and set auth_key. Existing feed files are left untouched."
                .into(),
        );
        return sum;
    };

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(cfg.timeout_secs)))
        .user_agent(concat!("sentinel-feeds/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();

    let mut hashes: HashSet<String> = HashSet::new();
    let mut domains: HashSet<String> = HashSet::new();
    let mut urls: HashSet<String> = HashSet::new();

    if cfg.malwarebazaar {
        match post_form(
            &agent,
            &cfg.malwarebazaar_url,
            key,
            "query=get_recent&selector=time",
        ) {
            Ok(body) => collect_malwarebazaar(&body, &mut hashes, &mut sum.errors),
            Err(e) => sum.errors.push(format!("malwarebazaar: {}", e)),
        }
    }
    if cfg.threatfox {
        let days = cfg.threatfox_days.clamp(1, 7);
        let body = format!("{{\"query\":\"get_iocs\",\"days\":{}}}", days);
        match post_json(&agent, &cfg.threatfox_url, key, &body) {
            Ok(body) => collect_threatfox(&body, &mut hashes, &mut domains, &mut urls, &mut sum.errors),
            Err(e) => sum.errors.push(format!("threatfox: {}", e)),
        }
    }
    if cfg.urlhaus {
        let limit = cfg.urlhaus_limit.clamp(1, 1000);
        let url = format!("{}/limit/{}/", cfg.urlhaus_url.trim_end_matches('/'), limit);
        match get(&agent, &url, key) {
            Ok(body) => collect_urlhaus(&body, &mut domains, &mut urls, &mut sum.errors),
            Err(e) => sum.errors.push(format!("urlhaus: {}", e)),
        }
    }

    // A total failure must not blank the cache the daemon is using.
    if hashes.is_empty() && domains.is_empty() && urls.is_empty() {
        sum.skipped = true;
        sum.reason = Some("every source failed or returned nothing; keeping the previous files".into());
        return sum;
    }

    if hashes.len() > cfg.max_hashes {
        let keep: HashSet<String> = hashes.iter().take(cfg.max_hashes).cloned().collect();
        hashes = keep;
    }

    sum.hashes = hashes.len();
    sum.domains = domains.len();
    sum.urls = urls.len();

    if let Err(e) = write_all(out_dir, &hashes, &domains, &urls) {
        sum.errors.push(e);
    }
    sum
}

fn write_all(
    dir: &Path,
    hashes: &HashSet<String>,
    domains: &HashSet<String>,
    urls: &HashSet<String>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    write_set(&dir.join("hashes.txt"), hashes)?;
    write_set(&dir.join("domains.txt"), domains)?;
    write_set(&dir.join("urls.txt"), urls)?;
    let meta = serde_json::json!({
        "updated": crate::util::now_rfc3339(),
        "hashes": hashes.len(),
        "domains": domains.len(),
        "urls": urls.len(),
        "sources": ["malwarebazaar", "threatfox", "urlhaus"],
    });
    crate::util::atomic_write(
        &dir.join("meta.json"),
        format!("{}\n", serde_json::to_string_pretty(&meta).unwrap_or_default()).as_bytes(),
        0o644,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn write_set(path: &Path, set: &HashSet<String>) -> Result<(), String> {
    let mut v: Vec<&String> = set.iter().collect();
    v.sort();
    let mut body = String::with_capacity(v.len() * 65);
    for x in v {
        body.push_str(x);
        body.push('\n');
    }
    crate::util::atomic_write(path, body.as_bytes(), 0o644)
        .map(|_| ())
        .map_err(|e| format!("{}: {}", path.display(), e))
}

fn post_form(agent: &ureq::Agent, url: &str, key: &str, body: &str) -> Result<String, String> {
    agent
        .post(url)
        .header("Auth-Key", key)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body)
        .map_err(|e| e.to_string())?
        .body_mut()
        .read_to_string()
        .map_err(|e| e.to_string())
}

fn post_json(agent: &ureq::Agent, url: &str, key: &str, body: &str) -> Result<String, String> {
    agent
        .post(url)
        .header("Auth-Key", key)
        .header("Content-Type", "application/json")
        .send(body)
        .map_err(|e| e.to_string())?
        .body_mut()
        .read_to_string()
        .map_err(|e| e.to_string())
}

fn get(agent: &ureq::Agent, url: &str, key: &str) -> Result<String, String> {
    agent
        .get(url)
        .header("Auth-Key", key)
        .call()
        .map_err(|e| e.to_string())?
        .body_mut()
        .read_to_string()
        .map_err(|e| e.to_string())
}

// -------------------------------------------------------------- response shapes
// Parsers are separate from transport so they can be unit tested on canned
// bodies; the API shapes are documented at bazaar/threatfox/urlhaus .abuse.ch.

pub fn collect_malwarebazaar(body: &str, hashes: &mut HashSet<String>, errors: &mut Vec<String>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        errors.push("malwarebazaar: response was not JSON".into());
        return;
    };
    match v.get("query_status").and_then(|s| s.as_str()) {
        Some("ok") => {}
        Some(other) => {
            errors.push(format!("malwarebazaar: query_status={}", other));
            return;
        }
        None => {}
    }
    for item in array(&v, "data") {
        if let Some(h) = item.get("sha256_hash").and_then(|h| h.as_str()) {
            hashes.insert(h.to_ascii_lowercase());
        }
    }
}

pub fn collect_threatfox(
    body: &str,
    hashes: &mut HashSet<String>,
    domains: &mut HashSet<String>,
    urls: &mut HashSet<String>,
    errors: &mut Vec<String>,
) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        errors.push("threatfox: response was not JSON".into());
        return;
    };
    if let Some(status) = v.get("query_status").and_then(|s| s.as_str()) {
        if status != "ok" {
            errors.push(format!("threatfox: query_status={}", status));
            return;
        }
    }
    for item in array(&v, "data") {
        let Some(ioc) = item.get("ioc").and_then(|i| i.as_str()) else {
            continue;
        };
        match item.get("ioc_type").and_then(|t| t.as_str()).unwrap_or("") {
            "sha256_hash" => {
                hashes.insert(ioc.to_ascii_lowercase());
            }
            "domain" => {
                domains.insert(ioc.to_ascii_lowercase());
            }
            // `ip:port`; the port is not useful without the address family.
            "ip:port" => {
                let ip = ioc.rsplit_once(':').map(|(a, _)| a).unwrap_or(ioc);
                domains.insert(ip.trim_matches(['[', ']']).to_ascii_lowercase());
            }
            "url" => {
                urls.insert(ioc.to_string());
                if let Some(h) = host_of(ioc) {
                    domains.insert(h);
                }
            }
            _ => {}
        }
    }
}

pub fn collect_urlhaus(
    body: &str,
    domains: &mut HashSet<String>,
    urls: &mut HashSet<String>,
    errors: &mut Vec<String>,
) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        errors.push("urlhaus: response was not JSON".into());
        return;
    };
    if let Some(status) = v.get("query_status").and_then(|s| s.as_str()) {
        if status != "ok" {
            errors.push(format!("urlhaus: query_status={}", status));
            return;
        }
    }
    for item in array(&v, "urls") {
        if let Some(u) = item.get("url").and_then(|u| u.as_str()) {
            urls.insert(u.to_string());
            if let Some(h) = item
                .get("host")
                .and_then(|h| h.as_str())
                .map(|h| h.to_ascii_lowercase())
                .or_else(|| host_of(u))
            {
                domains.insert(h);
            }
        }
    }
}

fn array<'a>(v: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    v.get(key)
        .and_then(|d| d.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
}

/// Minimal host extraction; we never need a full URL parser here.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    let host = if host.starts_with('[') {
        host.split(']').next()?.trim_start_matches('[')
    } else {
        host.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Where `sentinel-feeds` and the daemon agree the config lives.
pub fn default_config_path() -> PathBuf {
    std::env::var_os("SENTINEL_FEEDS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/sentinel/feeds.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_key_skips_without_touching_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hashes.txt"), "deadbeef\n").unwrap();
        let sum = refresh(&FeedsConfig::default(), dir.path());
        assert!(sum.skipped);
        assert!(sum.reason.unwrap().contains("auth_key"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("hashes.txt")).unwrap(),
            "deadbeef\n"
        );
    }

    #[test]
    fn placeholder_key_counts_as_no_key() {
        let mut c = FeedsConfig {
            auth_key: "PUT-YOUR-ABUSE-CH-AUTH-KEY-HERE".into(),
            ..Default::default()
        };
        assert!(c.key().is_none());
        c.auth_key = "  real-key  ".into();
        assert_eq!(c.key(), Some("real-key"));
    }

    #[test]
    fn malwarebazaar_shape() {
        let body = r#"{"query_status":"ok","data":[
            {"sha256_hash":"AABBCC","file_name":"x"},
            {"sha256_hash":"ddeeff"}]}"#;
        let mut h = HashSet::new();
        let mut e = Vec::new();
        collect_malwarebazaar(body, &mut h, &mut e);
        assert!(e.is_empty());
        assert!(h.contains("aabbcc") && h.contains("ddeeff"));
    }

    #[test]
    fn malwarebazaar_error_status_is_reported() {
        let mut h = HashSet::new();
        let mut e = Vec::new();
        collect_malwarebazaar(r#"{"query_status":"unauthorized"}"#, &mut h, &mut e);
        assert!(h.is_empty());
        assert!(e[0].contains("unauthorized"));
    }

    #[test]
    fn threatfox_splits_by_ioc_type() {
        let body = r#"{"query_status":"ok","data":[
          {"ioc":"evil.example","ioc_type":"domain"},
          {"ioc":"1.2.3.4:8080","ioc_type":"ip:port"},
          {"ioc":"http://bad.example/a.bin","ioc_type":"url"},
          {"ioc":"ABC123","ioc_type":"sha256_hash"},
          {"ioc":"x","ioc_type":"md5_hash"}]}"#;
        let (mut h, mut d, mut u, mut e) = (HashSet::new(), HashSet::new(), HashSet::new(), Vec::new());
        collect_threatfox(body, &mut h, &mut d, &mut u, &mut e);
        assert!(e.is_empty());
        assert!(h.contains("abc123"));
        assert!(d.contains("evil.example"));
        assert!(d.contains("1.2.3.4"));
        assert!(d.contains("bad.example"));
        assert!(u.contains("http://bad.example/a.bin"));
        assert_eq!(h.len(), 1, "md5 is not usable against process.binary");
    }

    #[test]
    fn urlhaus_shape() {
        let body = r#"{"query_status":"ok","urls":[
          {"url":"http://1.2.3.4:8080/x.exe","host":"1.2.3.4"},
          {"url":"https://drop.example/y"}]}"#;
        let (mut d, mut u, mut e) = (HashSet::new(), HashSet::new(), Vec::new());
        collect_urlhaus(body, &mut d, &mut u, &mut e);
        assert!(e.is_empty());
        assert_eq!(u.len(), 2);
        assert!(d.contains("1.2.3.4") && d.contains("drop.example"));
    }

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("http://a.example/x").as_deref(), Some("a.example"));
        assert_eq!(host_of("https://u:p@b.example:8443/x").as_deref(), Some("b.example"));
        assert_eq!(host_of("http://[2001:db8::1]/x").as_deref(), Some("2001:db8::1"));
        assert_eq!(host_of("").as_deref(), None);
    }

    #[test]
    fn cache_reloads_only_on_change() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hashes.txt"), "AABB\n\n# comment\n").unwrap();
        let mut f = Feeds::load(dir.path());
        assert!(f.hash_hit("aabb"));
        assert!(f.hash_hit("AABB"), "lookups are case insensitive");
        assert_eq!(f.meta.hashes, 1);
        assert!(!f.reload_if_changed(dir.path()));
        std::fs::write(dir.path().join("hashes.txt"), "aabb\nccdd\n").unwrap();
        assert!(f.reload_if_changed(dir.path()));
        assert_eq!(f.meta.hashes, 2);
    }

    #[test]
    fn shipped_feeds_toml_parses() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/feeds.toml");
        let c = FeedsConfig::load(&p).expect("etc/feeds.toml must parse");
        assert!(c.key().is_none(), "shipped file must not carry a key");
        assert_eq!(c.malwarebazaar_url, MALWAREBAZAAR_URL);
    }
}
