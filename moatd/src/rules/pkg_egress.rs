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
use crate::rules::netmatch::{contains_any, is_private, parse_all, Cidr};
use crate::rules::pkgtree;
use crate::rules::{meta, RuleCtx, UserRule};

pub const ID: &str = "moat-x-pkg-egress";

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
        if ctx.cfg.net.allow_private && is_private(&ip) {
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
            cfg,
            table,
            feeds: &feeds,
            homes: &homes,
            now: 100,
            mode: "monitor",
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

    #[test]
    fn private_addresses_are_allowed_by_default_but_configurable() {
        let t = table_with_install();
        assert!(run(&t, &cfg(), &sock_event("192.168.1.10", 8080), "e-node").is_empty());
        let mut c = cfg();
        c.net.allow_private = false;
        assert_eq!(run(&t, &c, &sock_event("192.168.1.10", 8080), "e-node").len(), 1);
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
