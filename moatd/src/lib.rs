//! moatd — the userspace half of omarchy-moat.
//!
//! Tetragon (upstream, unmodified) does the kernel work and writes a JSON-lines
//! export file. Everything in this crate reads that file, keeps the context the
//! kernel cannot (ancestry, windows, hashes, hostnames), and turns matches into
//! *explainable* alerts that a developer can act on.
//!
//! Module map:
//!
//! | module      | job                                                            |
//! |-------------|----------------------------------------------------------------|
//! | `config`    | `/etc/moat/moat.toml` + every path override            |
//! | `render`    | `moatd render-policies`: `{{HOME}}` expansion + allowlist   |
//! | `policy`    | rendered-policy annotation loader (severity/title/why/…)        |
//! | `tail`      | rotation- and truncation-safe line tailer                       |
//! | `event`     | Tetragon protojson (snake_case) event structs                   |
//! | `proctable` | `exec_id` -> process, parent chain capped at 8                  |
//! | `allowlist` | `/etc/moat/allowlist.d/*.toml`, glob matching, appends      |
//! | `alert`     | the alert record of CONTRACT §4                                 |
//! | `explain`   | the `explain` block: what / why / evidence / if_expected / next |
//! | `selectors` | re-validating a kernel match against the policy's own filter    |
//! | `rules`     | userland rules Tetragon cannot express (incl. `pkgtree`)        |
//! | `provenance`| official / foreign / user / unknown, from the pacman database    |
//! | `context`   | interactive / pkg-install / service / unknown, from the ancestry |
//! | `scoring`   | the provenance and context adjustments of BASELINE §2 and §2b   |
//! | `rarity`    | decayed per-tuple counters: first_seen / rare / common           |
//! | `baseline`  | the learning window, proposals, and the noise guard             |
//! | `receipt`   | install receipts: what a package-manager subtree actually did   |
//! | `incident`  | the pre-kill snapshot of a high/critical alert                  |
//! | `chain`     | alerts in one process tree crossing families: one sequence      |
//! | `bundle`    | `bundle.md`, with every process string in a `DATA` fence        |
//! | `content`   | what is *in* a file a chain implicated: ELF, strings, entropy    |
//! | `analysis`  | the agent preamble and how `moatctl analyze` launches it        |
//! | `digest`    | the weekly summary and when it is due                           |
//! | `store`     | append-only `alerts.jsonl`, updates, receipts, rotation         |
//! | `control`   | the `/run/moat/control.sock` protocol of CONTRACT §5        |
//! | `engine`    | the run loop that wires all of the above together               |
//! | `feeds`     | abuse.ch feed fetch + local feed cache                          |
//! | `telemetry` | selectable telemetry classes and `telemetry.jsonl`              |
//! | `ship`      | `moat-ship`: NDJSON/syslog export, cursor, buffer, redaction    |

pub mod alert;
pub mod allowlist;
pub mod analysis;
pub mod baseline;
pub mod bundle;
pub mod chain;
pub mod config;
pub mod contain;
pub mod content;
pub mod context;
pub mod control;
pub mod digest;
pub mod engine;
pub mod event;
pub mod evidence;
pub mod explain;
pub mod feeds;
pub mod incident;
pub mod mtree;
pub mod policy;
pub mod receipt;
pub mod proctable;
pub mod provenance;
pub mod rarity;
pub mod render;
pub mod rules;
pub mod scoring;
pub mod selectors;
pub mod ship;
pub mod store;
pub mod tail;
pub mod telemetry;
pub mod triage;
pub mod util;

/// Version reported by `status` and written into every alert-adjacent artifact.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
