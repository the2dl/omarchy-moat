//! sentineld — the userspace half of omarchy-sentinel.
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
//! | `config`    | `/etc/sentinel/sentinel.toml` + every path override            |
//! | `render`    | `sentineld render-policies`: `{{HOME}}` expansion + allowlist   |
//! | `policy`    | rendered-policy annotation loader (severity/title/why/…)        |
//! | `tail`      | rotation- and truncation-safe line tailer                       |
//! | `event`     | Tetragon protojson (snake_case) event structs                   |
//! | `proctable` | `exec_id` -> process, parent chain capped at 8                  |
//! | `allowlist` | `/etc/sentinel/allowlist.d/*.toml`, glob matching, appends      |
//! | `alert`     | the alert record of CONTRACT §4                                 |
//! | `explain`   | the `explain` block: what / why / evidence / if_expected / next |
//! | `rules`     | userland `sentinel-x-*` rules Tetragon cannot express           |
//! | `store`     | append-only `alerts.jsonl`, updates, rotation                   |
//! | `control`   | the `/run/sentinel/control.sock` protocol of CONTRACT §5        |
//! | `engine`    | the run loop that wires all of the above together               |
//! | `feeds`     | abuse.ch feed fetch + local feed cache                          |

pub mod alert;
pub mod allowlist;
pub mod config;
pub mod control;
pub mod engine;
pub mod event;
pub mod explain;
pub mod feeds;
pub mod policy;
pub mod proctable;
pub mod render;
pub mod rules;
pub mod store;
pub mod tail;
pub mod util;

/// Version reported by `status` and written into every alert-adjacent artifact.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
