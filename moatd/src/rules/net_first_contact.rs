//! `moat-net-first-contact`.
//!
//! An outbound connection to a destination this machine has never talked to.
//!
//! On its own this is nothing, and it is deliberately `low` so it stays on the
//! timeline and never notifies. It exists to be the **second half of a
//! sequence**: a credential file read and then a connection to somewhere new,
//! from the same process tree, is exfiltration. `chain.rs` correlates the two
//! and the escalation ladder raises `cred -> net` to at least `high`.
//!
//! ## Why this rule exists at all
//!
//! On 2026-09-04 a simulated npm package received a command over a WebSocket
//! from a C2 on the LAN and rewrote its own installed source. Every rule that
//! could have seen the beacon missed it, each for a defensible reason:
//!
//! - `moat-net-suspicious-port-egress` excludes RFC1918 in-kernel, because a
//!   workstation talks to its LAN all day, and 4873 is not an unusual port.
//! - `moat-x-pkg-egress` fires only inside a package-install subtree. The
//!   payload ran at *import* time, from `node -e`, long after the install --
//!   which is the smarter play precisely because install time is what everyone
//!   watches.
//!
//! Widening either one was the obvious fix and the wrong one: alerting on all
//! interactive egress means every `curl`, browser tab and dev server. The thing
//! that actually separates a beacon from a build is not the port, the address
//! family or the context -- it is that nothing on this machine has ever spoken
//! to that host before, and that something else happened in the same breath.

use std::net::IpAddr;

use crate::event::HookHit;
use crate::explain::Finding;
use crate::rules::netmatch::{contains_any, is_always_local, parse_all, Cidr};
use crate::rules::{signal_meta, RuleCtx, UserRule};

pub const ID: &str = "moat-net-first-contact";

/// How recently a credential read must precede a connection for it to count as
/// the exfil context -- short enough that an unrelated read earlier in the same
/// terminal session does not couple to every later connection.
const EXFIL_WINDOW_SECS: u64 = 60;

#[derive(Default)]
pub struct NetFirstContact {
    compiled: Option<(Vec<String>, Vec<Cidr>)>,
    /// "Have I already said this?" for the exfil-override path, keyed
    /// `exe|ip:port`. See `rules::Said`, which is this idea shared.
    ///
    /// The novelty path reports a destination once because RARITY remembers it
    /// afterwards. The credential-context path had no such memory: it fires
    /// BECAUSE familiarity is being overridden, so nothing stopped it firing
    /// again on the next packet. Measured 2026-09-07: `kubectl`, which reads
    /// ~/.kube/config before every call, produced **84 reports of one address**
    /// in an afternoon -- while the card said "a destination is reported once
    /// and then never again".
    ///
    /// One report is all the override is for: it exists so the cred -> net
    /// chain can form, and a chain forms on the first step. The 84th says
    /// nothing the 1st did not.
    reported: Option<crate::rules::Said>,
}

impl NetFirstContact {
    /// The registry CIDRs, compiled once and rebuilt when config changes. Same
    /// list `pkg_egress` uses: a host you have named as your registry is not a
    /// discovery, however new it is.
    fn allowed(&mut self, cfg: &crate::config::Config) -> &[Cidr] {
        let want = &cfg.net.registry_cidrs;
        let stale = match &self.compiled {
            Some((seen, _)) => seen != want,
            None => true,
        };
        if stale {
            self.compiled = Some((want.clone(), parse_all(want).0));
        }
        &self.compiled.as_ref().expect("just set").1
    }
}

impl UserRule for NetFirstContact {
    fn id(&self) -> &'static str {
        ID
    }

    fn on_hook(&mut self, h: &HookHit, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some((ip_s, port)) = h.dest() else {
            return Vec::new();
        };
        let Ok(ip) = ip_s.parse::<IpAddr>() else {
            return Vec::new();
        };
        // Loopback is not "somewhere". The kernel policy already drops it; this
        // is the belt to that pair of braces, and it costs nothing.
        if is_always_local(&ip) {
            return Vec::new();
        }
        let Some(proc) = ctx.table.get(exec_id) else {
            return Vec::new();
        };

        {
            let nets = self.allowed(ctx.cfg);
            if contains_any(nets, &ip) {
                return Vec::new();
            }
        }

        // The whole discrimination. `rarity` is read-only here -- the engine
        // owns `observe`, so by the time this runs the tuple has NOT yet been
        // recorded for this event, and "have we seen it before" means exactly
        // that.
        // FAMILIAR, not merely seen -- and asked through the one shared
        // predicate, which `moat-x-pkg-egress` also calls. The reasoning lives
        // at `RarityStore::knows_destination`; duplicating it here is what let
        // the other call site keep the weak answer for two months.
        // Familiar /24 -> normally silent. BUT `knows_destination` answers at
        // /24 granularity (a CDN affordability choice), which means an exfil to
        // a brand-new host in a block this machine already talks to -- the
        // reputable-infra exfil, the realistic case -- is hidden. So a familiar
        // /24 only silences this when the session did NOT just read a
        // credential. A connection moments after a secret read is the exfil
        // context, and it fires even to a familiar block so the cred->net chain
        // can form. Bounded to the exfil case: an ordinary CDN contact with no
        // preceding cred read stays silent, so this adds no general noise.
        //
        // 2026-09-07: the credential override does NOT apply to a private
        // destination that is already familiar. A machine migration reads every
        // credential in $HOME and rsyncs it to one LAN host, so EVERY
        // connection is "moments after a secret read" -- 22 first-contact
        // reports for one host this machine had spoken to 86 times, welded into
        // a HIGH chain, and ssh contained mid-transfer.
        //
        // This is narrower than the 2026-09-04 mistake `netmatch::is_always_local`
        // records, and deliberately so: a NEW private host still fires on
        // novelty, which is what caught the 192.168.44.122 C2. What stops is
        // only the re-reporting of a destination this machine already knows.
        // Exfil to a familiar PUBLIC host after a credential read still fires,
        // because that is the realistic reputable-infra case.
        let familiar = ctx.rarity.knows_destination(&proc.exe, &ip_s, port, ctx.now);
        let exfil_context = ctx.session_read_cred_within(exec_id, EXFIL_WINDOW_SECS);
        let lan = crate::rules::netmatch::is_private(&ip);
        if familiar && (lan || !exfil_context) {
            return Vec::new();
        }
        // Report a familiar destination ONCE per exe, however many times the
        // credential override re-qualifies it. See `reported`: the override is
        // what makes the cred -> net chain form, and a chain forms on the first
        // step. Novelty is untouched -- rarity already remembers a genuinely new
        // destination after the first sighting, which is why that path never
        // needed this.
        if familiar {
            // Keyed by SESSION as well as destination.
            //
            // Without the session this was a global "already said", and a
            // second process tree using the same interpreter and the same
            // destination lost its network step entirely -- `return
            // Vec::new()` below means correlation never sees the event, not
            // merely that the badge stays quiet. That is the same trap
            // `explain::dedupe_key` records for dropping `pid`: two trees
            // doing one thing must stay two.
            //
            // Sessions, not exec_ids: a session is the unit the exfil gate
            // already reasons in (`session_read_cred_within`), and keying on
            // exec_id would re-report once per process, which is the noise
            // this exists to stop. An unknown session falls back to 0, which
            // groups the unknowns together rather than making each one novel.
            let sid = ctx.table.get(exec_id).and_then(|p| p.sid).unwrap_or(0);
            let key = format!("{}\u{1}{}\u{1}{}:{}", sid, proc.exe, ip_s, port);
            let said = self
                .reported
                .get_or_insert_with(|| crate::rules::Said::new(EXFIL_WINDOW_SECS * 10, 512));
            if !said.worth_saying(&key, ctx.now) {
                return Vec::new();
            }
        }

        let m = self.meta();
        let Some(mut f) = ctx.finding(ID, m, exec_id) else {
            return Vec::new();
        };
        f.net = Some(crate::alert::NetRef {
            dst_ip: ip_s.clone(),
            dst_port: port,
            // No DNS in the kernel and none in the export (NOTES gap 4): moat
            // genuinely does not know the name, and saying so is better than
            // implying it looked.
            domain: None,
        });
        f.extra_evidence = vec![
            format!("first connection from {} to {}:{} on this machine", proc.exe, ip_s, port),
            // Saying "reported once and never again" while reporting a
            // destination for the 22nd time is how a person concludes the rule
            // is broken. It is only true of the novelty path.
            if familiar {
                format!(
                    "{}:{} is NOT new to this machine -- this is reported because a credential \
                     was read in the same session within {} s, which is the shape an exfil \
                     takes. A familiar destination is otherwise reported once and never again.",
                    ip_s, port, EXFIL_WINDOW_SECS
                )
            } else {
                "a destination is reported once and then never again; this is a step in a \
                 sequence rather than a finding on its own"
                    .to_string()
            },
        ];
        vec![f]
    }

    fn enabled(&self, cfg: &crate::config::Config) -> bool {
        cfg.rules.net_first_contact
    }

    /// `tier: signal` — weak alone; exists to be a chain step (BASELINE §4).
    fn meta(&self) -> crate::policy::PolicyMeta {
        signal_meta(
            ID,
            "net",
            "low",
            "Outbound connection to somewhere new",
            "On its own this is nothing: the first time you use any service is a first \
             contact. It matters as the second half of a sequence -- a credential read \
             and then a connection somewhere new, from the same process tree.",
            "Constantly, for the first few days: every host you use is new once. Each \
             destination reports at most once and then goes quiet for good.",
            &[],
            &["ignore"],
            "exe",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::feeds::Feeds;
    use crate::event::{HookEvent, HookKind};
    use crate::proctable::ProcTable;
    use crate::rarity::{RarityStore, Tuple};
    use crate::rules::testkit::proc;

    fn table() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-node", 41201, "/usr/bin/node", "-e import('x')", None));
        t
    }

    fn run(r: &RarityStore, ip: &str, port: u16, cfg: &Config) -> Vec<Finding> {
        let t = table();
        let feeds = Feeds::default();
        let ctx = RuleCtx {
            rarity: r,
            cfg,
            table: &t,
            feeds: &feeds,
            homes: &[],
            now: 100,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
        };
        let ev = HookEvent {
            function_name: Some("tcp_connect".into()),
            args: vec![serde_json::json!({"sock_arg":{
                "family":"AF_INET","daddr":ip,"dport":port,
                "saddr":"192.168.1.20","sport":51234
            }})],
            policy_name: Some(ID.into()),
            ..Default::default()
        };
        let h = HookHit { kind: HookKind::Kprobe, ev: &ev };
        NetFirstContact::default().on_hook(&h, "e-node", &ctx)
    }

    #[test]
    fn a_destination_never_seen_before_reports_once() {
        let cfg = Config::default();
        let empty = RarityStore::default();
        // The 2026-09-04 C2: a LAN host nothing on this machine had contacted.
        assert_eq!(run(&empty, "192.168.44.122", 4873, &cfg).len(), 1);
        // Public destinations are judged the same way -- the point is novelty,
        // not which side of a NAT the host is on.
        assert_eq!(run(&empty, "185.220.101.55", 443, &cfg).len(), 1);
    }

    #[test]
    fn one_sighting_does_not_buy_silence() {
        // The hole this test used to assert as correct. It was called
        // `a_destination_seen_before_is_silent_forever`, and it was:
        // `has_seen` is true after ONE connection, so a payload's own first
        // packet silenced every beacon that followed it to that /24 -- no
        // privilege, no root, nothing to detect. The attacker trained the
        // detector with the attack.
        let cfg = Config::default();
        let mut once = RarityStore::default();
        once.observe(&Tuple::net("/usr/bin/node", "192.168.44.122", 4873, None), 1);
        assert_eq!(
            run(&once, "192.168.44.122", 4873, &cfg).len(),
            1,
            "one prior connection must not silence the rule"
        );

        // Nor does a burst: four connections inside ten seconds is what a
        // dropper does, not what familiarity looks like.
        let mut burst = RarityStore::default();
        for i in 0..8u64 {
            burst.observe(&Tuple::net("/usr/bin/node", "192.168.44.122", 4873, None), 100 + i);
        }
        assert_eq!(
            run(&burst, "192.168.44.122", 4873, &cfg).len(),
            1,
            "a burst cannot manufacture familiarity"
        );
    }

    #[test]
    fn a_genuinely_familiar_destination_is_quiet() {
        // The other half, and what keeps the rule affordable: your registry
        // and your NAS are used repeatedly over hours and go quiet, exactly as
        // the rule's own documentation promises.
        let mut seen = RarityStore::default();
        let t = Tuple::net("/usr/bin/node", "192.168.44.122", 4873, None);
        for i in 0..8u64 {
            seen.observe(&t, 1_000 + i * 1_800);
        }
        let now = 1_000 + 7 * 1_800;
        assert!(
            seen.is_familiar(&t, now),
            "used repeatedly across hours, this is a host the machine knows"
        );
    }

    #[test]
    fn a_familiar_private_destination_is_quiet_even_after_a_credential_read() {
        // The /24-familiarity exfil gap: a connection to a host the machine
        // already knows, moments after the same session read a secret, is the
        // reputable-infra exfil case and must still produce the net step so the
        // cred->net chain can form. 2026-09-06.
        use std::collections::HashMap;
        let cfg = Config::default();

        // A destination whose /24 is thoroughly familiar.
        let mut seen = RarityStore::default();
        let tup = Tuple::net("/usr/bin/node", "192.168.44.122", 4873, None);
        for i in 0..8u64 {
            seen.observe(&tup, 1_000 + i * 1_800);
        }
        let now = 1_000 + 7 * 1_800;
        assert!(seen.is_familiar(&tup, now), "precondition: the /24 is familiar");

        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-node", 41201, "/usr/bin/node", "-e x", None));
        t.set_session("e-node", Some(77), Some(0));
        let feeds = Feeds::default();

        let ev = HookEvent {
            function_name: Some("tcp_connect".into()),
            args: vec![serde_json::json!({"sock_arg":{
                "family":"AF_INET","daddr":"192.168.44.122","dport":4873,
                "saddr":"192.168.1.20","sport":51234
            }})],
            policy_name: Some(ID.into()),
            ..Default::default()
        };
        let h = HookHit { kind: HookKind::Kprobe, ev: &ev };

        // No cred read in the session: familiar -> silent.
        let none: HashMap<u32, u64> = HashMap::new();
        let quiet = RuleCtx {
            rarity: &seen, cfg: &cfg, table: &t, feeds: &feeds, homes: &[],
            now, mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED, cred_read_sessions: &none,
        };
        assert!(
            NetFirstContact::default().on_hook(&h, "e-node", &quiet).is_empty(),
            "familiar and no recent cred read: silent"
        );

        // Same session read a credential 10s ago: the exfil override fires it.
        let mut creds: HashMap<u32, u64> = HashMap::new();
        creds.insert(77u32, now - 10);
        let after_read = RuleCtx {
            rarity: &seen, cfg: &cfg, table: &t, feeds: &feeds, homes: &[],
            now, mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED, cred_read_sessions: &creds,
        };
        // 2026-09-07: a FAMILIAR PRIVATE destination no longer fires on the
        // exfil override. This is the deliberate hole, and it is this shape:
        // a machine migration reads every credential in $HOME and rsyncs to one
        // LAN host, so every connection is "moments after a secret read" and
        // the rule reported one known host 22 times, built a HIGH chain, and
        // contained ssh mid-transfer. The cost is stated in the test below it.
        assert!(
            NetFirstContact::default().on_hook(&h, "e-node", &after_read).is_empty(),
            "familiar AND private: the credential override does not apply"
        );
    }

    /// What the 2026-09-07 change gives up, and what it keeps. Both halves are
    /// asserted here so neither can be lost quietly.
    #[test]
    fn the_credential_override_still_covers_a_familiar_public_host() {
        use std::collections::HashMap;
        let cfg = Config::default();

        // A public destination this machine talks to constantly -- the
        // reputable-infra exfil case, which is the realistic one.
        let mut seen = RarityStore::default();
        let tup = Tuple::net("/usr/bin/node", "93.184.216.34", 443, None);
        for i in 0..8u64 {
            seen.observe(&tup, 1_000 + i * 1_800);
        }
        let now = 1_000 + 7 * 1_800;
        assert!(seen.is_familiar(&tup, now), "precondition: familiar");

        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-node", 41201, "/usr/bin/node", "-e x", None));
        t.set_session("e-node", Some(77), Some(0));
        let feeds = Feeds::default();
        let ev = HookEvent {
            function_name: Some("tcp_connect".into()),
            args: vec![serde_json::json!({"sock_arg":{
                "family":"AF_INET","daddr":"93.184.216.34","dport":443,
                "saddr":"192.168.1.20","sport":51234
            }})],
            policy_name: Some(ID.into()),
            ..Default::default()
        };
        let h = HookHit { kind: HookKind::Kprobe, ev: &ev };
        let mut creds: HashMap<u32, u64> = HashMap::new();
        creds.insert(77u32, now - 10);
        let ctx = RuleCtx {
            rarity: &seen, cfg: &cfg, table: &t, feeds: &feeds, homes: &[],
            now, mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED, cred_read_sessions: &creds,
        };
        let out = NetFirstContact::default().on_hook(&h, "e-node", &ctx);
        assert_eq!(out.len(), 1, "familiar but PUBLIC, after a cred read: still fires");
        assert!(
            out[0].extra_evidence[1].contains("NOT new to this machine"),
            "and it says why it fired despite being familiar: {:?}",
            out[0].extra_evidence
        );
    }

    /// 84 reports of ONE address, from a card that says "a destination is
    /// reported once and then never again".
    ///
    /// 2026-09-07, measured: `kubectl` reads ~/.kube/config before every call,
    /// so the credential override re-qualified a familiar cluster address on
    /// every single connection. The override exists so the cred -> net chain can
    /// form, and a chain forms on the FIRST step.
    #[test]
    fn the_credential_override_reports_a_destination_once_not_once_per_packet() {
        use std::collections::HashMap;
        let cfg = Config::default();

        let mut seen = RarityStore::default();
        let tup = Tuple::net("/usr/bin/kubectl", "162.209.114.112", 443, None);
        for i in 0..8u64 {
            seen.observe(&tup, 1_000 + i * 1_800);
        }
        let now = 1_000 + 7 * 1_800;
        assert!(seen.is_familiar(&tup, now), "precondition: familiar");

        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-kubectl", 41201, "/usr/bin/kubectl", "get pods", None));
        t.set_session("e-kubectl", Some(77), Some(0));
        let feeds = Feeds::default();
        let ev = HookEvent {
            function_name: Some("tcp_connect".into()),
            args: vec![serde_json::json!({"sock_arg":{
                "family":"AF_INET","daddr":"162.209.114.112","dport":443,
                "saddr":"192.168.1.20","sport":51234
            }})],
            policy_name: Some(ID.into()),
            ..Default::default()
        };
        let h = HookHit { kind: HookKind::Kprobe, ev: &ev };
        let mut creds: HashMap<u32, u64> = HashMap::new();
        creds.insert(77u32, now - 10);

        // One rule instance across the whole burst, as the daemon has.
        let mut rule = NetFirstContact::default();
        let mut fired = 0;
        for _ in 0..40 {
            let ctx = RuleCtx {
                rarity: &seen, cfg: &cfg, table: &t, feeds: &feeds, homes: &[],
                now, mode: "monitor",
                armed: &crate::rules::NO_RULES_ARMED, cred_read_sessions: &creds,
            };
            fired += rule.on_hook(&h, "e-kubectl", &ctx).len();
        }
        assert_eq!(fired, 1, "forty calls to one known address is one report, not forty");

        // A DIFFERENT SESSION reaching the SAME destination still reports.
        //
        // The memory was global (`exe|ip:port`) until 2026-09-08, so a second
        // process tree running the same interpreter to the same host lost its
        // network step for ten minutes -- and `on_hook` returning empty means
        // correlation never sees it, not merely that the badge stays quiet.
        // Two trees doing one thing must stay two; that is the same rule
        // `explain::dedupe_key` keeps `pid` for.
        {
            let mut t2 = ProcTable::new(8, 60);
            t2.observe(&proc("e-other", 41999, "/usr/bin/kubectl", "get pods", None));
            t2.set_session("e-other", Some(88), Some(0));
            let mut creds2: HashMap<u32, u64> = HashMap::new();
            creds2.insert(88u32, now - 10);
            let ctx = RuleCtx {
                rarity: &seen, cfg: &cfg, table: &t2, feeds: &feeds, homes: &[],
                now, mode: "monitor",
                armed: &crate::rules::NO_RULES_ARMED, cred_read_sessions: &creds2,
            };
            assert_eq!(
                rule.on_hook(&h, "e-other", &ctx).len(),
                1,
                "a second session must not inherit the first session's silence"
            );
        }

        // A DIFFERENT destination in the same session still reports: the memory
        // is per destination, not a mute button on the rule.
        let ev2 = HookEvent {
            function_name: Some("tcp_connect".into()),
            args: vec![serde_json::json!({"sock_arg":{
                "family":"AF_INET","daddr":"162.209.114.113","dport":443,
                "saddr":"192.168.1.20","sport":51235
            }})],
            policy_name: Some(ID.into()),
            ..Default::default()
        };
        let tup2 = Tuple::net("/usr/bin/kubectl", "162.209.114.113", 443, None);
        for i in 0..8u64 {
            seen.observe(&tup2, 1_000 + i * 1_800);
        }
        let ctx2 = RuleCtx {
            rarity: &seen, cfg: &cfg, table: &t, feeds: &feeds, homes: &[],
            now, mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED, cred_read_sessions: &creds,
        };
        assert_eq!(
            rule.on_hook(&HookHit { kind: HookKind::Kprobe, ev: &ev2 }, "e-kubectl", &ctx2).len(),
            1,
            "a different destination is a different fact and still reports"
        );
    }

    /// The 192.168.44.122 C2 is still caught: it was NEW, and novelty is
    /// untouched by the 2026-09-07 change.
    #[test]
    fn a_new_lan_host_still_reports_even_though_it_is_private() {
        let cfg = Config::default();
        let empty = RarityStore::default();
        assert_eq!(
            run(&empty, "192.168.44.122", 4873, &cfg).len(),
            1,
            "a LAN host never seen before is still a first contact"
        );
    }

    #[test]
    fn loopback_and_a_named_registry_never_report() {
        let cfg = Config::default();
        let empty = RarityStore::default();
        assert!(run(&empty, "127.0.0.1", 4873, &cfg).is_empty());
        let mut named = Config::default();
        named.net.registry_cidrs.push("192.168.44.0/24".into());
        assert!(
            run(&empty, "192.168.44.122", 4873, &named).is_empty(),
            "a host you have named as your registry is not a discovery"
        );
    }

    #[test]
    fn it_stays_low_so_it_never_interrupts_on_its_own() {
        // The whole design: this is a chain step, not a detection. If it ever
        // reaches the badge by itself it will be pure noise, because every host
        // anyone uses is new exactly once.
        assert_eq!(NetFirstContact::default().meta().severity, "low");
    }
}
