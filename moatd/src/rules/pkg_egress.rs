//! `moat-x-pkg-egress`.
//!
//! Fills NOTES gap 4: the kernel sees addresses, never names, and the export
//! carries no hostname. So "npm may talk to the registry, not to anywhere else"
//! cannot be a policy. Here we take every connection made from inside a
//! package-manager subtree and flag the ones that are neither private nor in the
//! configured registry CIDR list.
//!
//! Because the allowlist is address-based and CDN address space moves, this
//! fires at **medium** by default (configurable) — it is a "look at this", not a
//! "you are owned".

use std::net::IpAddr;

use crate::config::Config;
use crate::event::HookHit;
use crate::explain::Finding;
use crate::alert::NetRef;
use crate::policy::PolicyMeta;
use crate::rules::netmatch::{contains_any, is_always_local, is_private, parse_all, Cidr};
use crate::rules::pkgtree;
use crate::rules::{meta, RuleCtx, UserRule};

pub const ID: &str = "moat-x-pkg-egress";

/// Has this machine never talked to this destination from this binary before?
///
/// The whole discrimination in one predicate, and it is
/// `RarityStore::knows_destination` -- the same one `moat-net-first-contact`
/// asks, because it is the same question. This used to be `has_seen`, which is
/// true after ONE sighting, so inside an install a payload's own first packet
/// silenced every connection that followed it to that /24. An internal registry
/// is contacted repeatedly over hours and goes quiet; a burst inside one install
/// cannot buy that.
fn first_contact(ctx: &RuleCtx, exe: &str, ip: &str, port: u16) -> bool {
    !ctx.rarity.knows_destination(exe, ip, port, ctx.now)
}

#[derive(Default)]
pub struct PkgEgress {
    compiled: Option<(Vec<String>, Vec<Cidr>)>,
}

impl PkgEgress {
    fn cidrs(&mut self, cfg: &Config) -> &[Cidr] {
        let want = &cfg.net.registry_cidrs;
        let stale = match &self.compiled {
            Some((src, _)) => src != want,
            None => true,
        };
        if stale {
            let (ok, bad) = parse_all(want);
            for b in bad {
                log::warn!("{}: ignoring unparseable registry CIDR {:?}", ID, b);
            }
            self.compiled = Some((want.clone(), ok));
        }
        &self.compiled.as_ref().expect("just set").1
    }
}

impl UserRule for PkgEgress {
    fn id(&self) -> &'static str {
        ID
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.pkg_egress
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            ID,
            "net",
            "medium",
            "Package install connected to a host outside the registry allowlist",
            "An install should talk to its registry and its CDN, nothing else. A connection \
             from inside the install tree to an unrelated address is how a malicious package \
             ships your tokens out, and it happens during `install`, before you ever run the code.",
            "Registries and mirrors whose address ranges are not in the list yet, telemetry \
             endpoints, and packages that download a prebuilt binary from their own host. Add \
             the CIDR to `net.registry_cidrs` in moat.toml once you recognise it.",
            &[],
            &["kill", "ignore"],
            "rule",
        )
    }

    fn on_hook(&mut self, h: &HookHit, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some((ip_s, port)) = h.dest() else {
            return Vec::new();
        };
        let Ok(ip) = ip_s.parse::<IpAddr>() else {
            return Vec::new();
        };
        // The subtree test is `pkgtree`'s, the same one the pkg-subtree rules
        // and the egress escalation use: one definition of "inside an install".
        let Some((pkg, why)) = pkgtree::pkg_root_with_reason(ctx.table, exec_id) else {
            return Vec::new();
        };
        let (pkg, why) = (pkg.clone(), why);
        // Loopback is always fine, whatever the config says: a local registry
        // proxy or a devcontainer registry is ordinary and lives on 127.0.0.1.
        if is_always_local(&ip) {
            return Vec::new();
        }
        // RFC1918 stays excluded by default, and should -- an internal
        // Artifactory, Nexus or PyPI mirror is how a great many real installs
        // work, and alerting on all LAN traffic would make this useless in the
        // environments that most need it.
        //
        // But "private" is not the same as "yours". A LAN address this machine
        // has never talked to before is not the registry you use every day, so
        // a first-contact destination is still worth one alert: on 2026-09-04 a
        // simulated npm package beaconed to a WebSocket C2 on 192.168.44.122
        // and the blanket exclusion said nothing. Your real registry becomes
        // `common` within a few installs and goes quiet; a beacon to a host
        // nobody has seen does not.
        if ctx.cfg.net.allow_private && is_private(&ip) && !first_contact(ctx, ctx.table.get(exec_id).map(|p| p.exe.as_str()).unwrap_or(""), &ip_s, port) {
            return Vec::new();
        }
        let allowed = {
            let nets = self.cidrs(ctx.cfg);
            contains_any(nets, &ip)
        };
        if allowed {
            return Vec::new();
        }

        let mut m = self.meta();
        m.severity = ctx.cfg.net.egress_severity.clone();
        let Some(mut f) = ctx.finding(ID, m, exec_id) else {
            return Vec::new();
        };
        f.hook = format!("userland: {} from a package install subtree", h.hook_name());
        f.net = Some(NetRef {
            dst_ip: ip_s.clone(),
            dst_port: port,
            // No DNS in the kernel and none in the export: we genuinely do not
            // know the name (NOTES gap 4).
            domain: None,
        });
        f.what_override = Some(format!(
            "A `{}` install connected to {}:{}, which is not a known package registry.",
            pkg.comm(),
            ip_s,
            port
        ));
        f.extra_evidence = vec![
            pkgtree::root_evidence(&pkg, &why),
            format!(
                "{} is neither private nor inside any of the {} configured registry CIDR(s)",
                ip_s,
                ctx.cfg.net.registry_cidrs.len()
            ),
            "no hostname is available: Tetragon reports addresses only".to_string(),
        ];
        vec![f]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HookEvent, HookKind, RawEvent};
    use crate::feeds::Feeds;
    use crate::proctable::ProcTable;
    use crate::rules::testkit::{cfg, proc, table_with_install};

    fn sock_event(daddr: &str, dport: u16) -> HookEvent {
        HookEvent {
            function_name: Some("tcp_connect".into()),
            args: vec![serde_json::json!({"sock_arg":{
                "family":"AF_INET","daddr":daddr,"dport":dport,"saddr":"192.168.1.20","sport":51234
            }})],
            policy_name: Some("moat-net-egress".into()),
            ..Default::default()
        }
    }

    fn run(table: &ProcTable, cfg: &Config, ev: &HookEvent, exec_id: &str) -> Vec<Finding> {
        let feeds = Feeds::default();
        let homes = vec!["/home/dan".to_string()];
        let ctx = RuleCtx {
            rarity: &crate::rarity::RarityStore::default(),
            cfg,
            table,
            feeds: &feeds,
            homes: &homes,
            now: 100,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
        };
        let h = HookHit {
            kind: HookKind::Kprobe,
            ev,
        };
        PkgEgress::default().on_hook(&h, exec_id, &ctx)
    }

    #[test]
    fn a_public_non_registry_address_fires() {
        let t = table_with_install();
        let f = run(&t, &cfg(), &sock_event("185.220.101.55", 4444), "e-node");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "medium");
        let net = f[0].net.as_ref().unwrap();
        assert_eq!(net.dst_ip, "185.220.101.55");
        assert_eq!(net.dst_port, 4444);
        assert!(net.domain.is_none());
    }

    #[test]
    fn the_registry_allowlist_silences_it() {
        let t = table_with_install();
        // 151.101.0.0/16 is in the shipped defaults (Fastly: npm, crates.io).
        assert!(run(&t, &cfg(), &sock_event("151.101.1.2", 443), "e-node").is_empty());
    }

    /// `run`, but with a rarity store that already knows some destinations.
    fn run_with_rarity(
        table: &ProcTable,
        cfg: &Config,
        rarity: &crate::rarity::RarityStore,
        ev: &HookEvent,
        exec_id: &str,
    ) -> Vec<Finding> {
        let feeds = Feeds::default();
        let homes = vec!["/home/dan".to_string()];
        let ctx = RuleCtx {
            rarity,
            cfg,
            table,
            feeds: &feeds,
            homes: &homes,
            now: 100,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
        };
        let h = HookHit {
            kind: HookKind::Kprobe,
            ev,
        };
        PkgEgress::default().on_hook(&h, exec_id, &ctx)
    }

    #[test]
    fn a_lan_host_is_flagged_but_loopback_never_is() {
        let t = table_with_install();
        // Loopback is unconditional: a local registry proxy or a devcontainer
        // registry on 127.0.0.1 is the ordinary case, and is what the old
        // `allow_private` default was really protecting.
        assert!(run(&t, &cfg(), &sock_event("127.0.0.1", 4873), "e-node").is_empty());
        let mut allowing = cfg();
        allowing.net.allow_private = true;
        assert!(run(&t, &allowing, &sock_event("127.0.0.1", 4873), "e-node").is_empty());

        // RFC1918 stays excluded -- an internal registry is how most real
        // installs work -- EXCEPT on first contact. A LAN host this machine has
        // never talked to is not the registry you use every day: on 2026-09-04
        // a simulated npm package beaconed to a WebSocket C2 on 192.168.44.122
        // and the blanket exclusion said nothing.
        //
        // `cfg()` builds an empty rarity store, so every destination is first
        // contact here; the "seen before" half is asserted below.
        assert_eq!(run(&t, &cfg(), &sock_event("192.168.44.122", 4873), "e-node").len(), 1);

        // The other half, and the reason the exclusion stays: a LAN host this
        // machine genuinely KNOWS is your internal registry, and it must stay
        // silent without anyone configuring anything. One alert on first
        // contact, then quiet forever.
        //
        // "Knows" is `knows_destination`, not "there is a counter": an internal
        // registry is contacted repeatedly across hours, which is what earns it.
        let mut known = cfg();
        let mut store = crate::rarity::RarityStore::default();
        let dst = crate::rarity::Tuple::net("/usr/bin/node", "192.168.44.122", 4873, None);
        for i in 0..8u64 {
            store.observe(&dst, 1_000 + i * 1_800);
        }
        assert!(
            run_with_rarity(&t, &known, &store, &sock_event("192.168.44.122", 4873), "e-node")
                .is_empty(),
            "an internal registry the machine knows is not reported again"
        );
        known.net.allow_private = true;

        // Naming it in registry_cidrs allows it without allowing the whole LAN.
        let mut named = cfg();
        named.net.registry_cidrs.push("192.168.44.0/24".into());
        assert!(run(&t, &named, &sock_event("192.168.44.122", 4873), "e-node").is_empty());
    }

    /// One sighting is not knowledge, here either.
    ///
    /// This rule asked `has_seen` long after `moat-net-first-contact` stopped:
    /// one question, two predicates, and the weaker one had no comment saying
    /// why it was weaker. Inside an install with `allow_private` on, a payload's
    /// own first connection to its C2 silenced every connection that followed
    /// it -- no privilege needed, and the attacker trained the detector with the
    /// attack. Both call sites now go through `knows_destination`.
    #[test]
    fn one_sighting_does_not_buy_silence_inside_an_install() {
        let t = table_with_install();
        let mut c = cfg();
        c.net.allow_private = true;
        let dst = crate::rarity::Tuple::net("/usr/bin/node", "192.168.44.122", 4873, None);

        let mut once = crate::rarity::RarityStore::default();
        once.observe(&dst, 1);
        assert_eq!(
            run_with_rarity(&t, &c, &once, &sock_event("192.168.44.122", 4873), "e-node").len(),
            1,
            "one prior connection must not silence the rule"
        );

        // Nor a burst: eight connections in eight seconds is what a payload
        // does inside one install, not what an internal registry looks like.
        let mut burst = crate::rarity::RarityStore::default();
        for i in 0..8u64 {
            burst.observe(&dst, 100 + i);
        }
        assert_eq!(
            run_with_rarity(&t, &c, &burst, &sock_event("192.168.44.122", 4873), "e-node").len(),
            1,
            "a burst inside one install cannot manufacture familiarity"
        );
    }

    #[test]
    fn outside_a_package_subtree_it_stays_quiet() {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-term", 41100, "/usr/bin/alacritty", "", None));
        t.observe(&proc("e-curl", 41400, "/usr/bin/curl", "https://x", Some("e-term")));
        assert!(run(&t, &cfg(), &sock_event("185.220.101.55", 443), "e-curl").is_empty());
    }

    #[test]
    fn severity_comes_from_config() {
        let t = table_with_install();
        let mut c = cfg();
        c.net.egress_severity = "high".into();
        let f = run(&t, &c, &sock_event("185.220.101.55", 4444), "e-node");
        assert_eq!(f[0].meta.severity, "high");
    }

    #[test]
    fn a_sockaddr_arg_from_the_lsm_hook_also_works() {
        let t = table_with_install();
        let ev = HookEvent {
            function_name: Some("socket_connect".into()),
            args: vec![serde_json::json!({"sockaddr_arg":{"family":"AF_INET","addr":"1.2.3.4","port":443}})],
            ..Default::default()
        };
        let f = run(&t, &cfg(), &ev, "e-node");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].net.as_ref().unwrap().dst_ip, "1.2.3.4");
    }

    #[test]
    fn the_sample_log_connection_is_caught() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sample.log"),
        )
        .unwrap();
        let mut t = ProcTable::new(8, 60);
        let mut hits = 0;
        for line in text.lines() {
            let Some(ev) = RawEvent::parse(line) else { continue };
            if let Some(e) = &ev.process_exec {
                t.on_exec(e);
            }
            if let Some(h) = ev.hook() {
                if let Some(p) = &h.ev.process {
                    let id = p.exec_id.clone().unwrap_or_default();
                    hits += run(&t, &cfg(), h.ev, &id).len();
                }
            }
        }
        assert_eq!(hits, 1, "only the 185.220.101.55:4444 connect should fire");
    }
}
