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
use crate::rules::{meta, RuleCtx, UserRule};

pub const ID: &str = "moat-net-first-contact";

#[derive(Default)]
pub struct NetFirstContact {
    compiled: Option<(Vec<String>, Vec<Cidr>)>,
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
        let tuple = crate::rarity::Tuple::net(&proc.exe, &ip_s, port, None);
        // FAMILIAR, not merely seen. `has_seen` is true after one connection,
        // so a payload's own first packet used to silence every beacon that
        // followed it -- the cheapest possible defeat of this rule, available
        // to any unprivileged process. `is_familiar` additionally wants the
        // sightings spread over real time, which an attacker who has just
        // arrived cannot manufacture.
        if ctx.rarity.is_familiar(&tuple, ctx.now) {
            return Vec::new();
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
            "a destination is reported once and then never again; this is a step in a \
             sequence rather than a finding on its own"
                .to_string(),
        ];
        vec![f]
    }

    fn enabled(&self, cfg: &crate::config::Config) -> bool {
        cfg.rules.net_first_contact
    }

    fn meta(&self) -> crate::policy::PolicyMeta {
        meta(
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
        let cfg = Config::default();
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
