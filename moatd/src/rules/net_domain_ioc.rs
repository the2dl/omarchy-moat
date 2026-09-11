//! `moat-x-net-domain-ioc`.
//!
//! A connection to an address this machine resolved from a name on one of the
//! two domain lists -- the operator's `feeds/domains.txt` or the published
//! `feeds/domains-feed.txt`. The second half of NOTES gap 4: the kernel sees
//! addresses only, `names.rs` says which name was resolved to each, and this
//! is the feed match on top -- the way `moat-x-new-exec-ioc` matches a hash.
//!
//! Every net finding already gets its IOC set by `Daemon::enrich_names` when
//! the name is fed, so a first-contact or egress report to a fed domain scores
//! as an IOC on its own. This rule is for the connections nothing else
//! reports: a familiar /24, a registry CIDR, the fortieth beacon. It fires on
//! the connection, not on the lookup -- a lookup with no connection is a
//! weaker claim, and the user asked for evidence on alerts rather than a DNS
//! detector.
//!
//! `high`, not `critical` like the hash rule: a domain feed is a coarser
//! instrument. Parent-domain matching (`Feeds::domain_hit`) is how a feed of
//! registrable domains is meant to be read, and it is also how a shared host
//! or a sinkhole lands here. The alert carries the age of the resolution so
//! the reader can judge a CDN address that has since changed hands.

use std::net::IpAddr;

use crate::alert::{IocRef, NetRef};
use crate::config::Config;
use crate::event::HookHit;
use crate::explain::Finding;
use crate::policy::PolicyMeta;
use crate::rules::{meta, RuleCtx, Said, UserRule};

pub const ID: &str = "moat-x-net-domain-ioc";

/// One report per (exe, address) inside this window. A beacon reconnects
/// every few seconds; the row exists to say it happened, not to count.
const SAID_WINDOW_SECS: u64 = 600;

#[derive(Default)]
pub struct NetDomainIoc {
    said: Option<Said>,
}

impl UserRule for NetDomainIoc {
    fn id(&self) -> &'static str {
        ID
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.net_domain_ioc && cfg.names.enabled
    }

    fn meta(&self) -> PolicyMeta {
        meta(
            ID,
            "net",
            "high",
            "Connection to a domain on the local threat feed",
            "This address was reached after this machine resolved a name that is in the \
             local domain feed. The feed is operator-supplied (feeds/domains.txt) and the \
             name comes from systemd-resolved's own query stream, not from a reverse lookup.",
            "A shared host or CDN address that a fed domain also used, a sinkholed domain \
             being visited on purpose, or a feed entry broad enough to cover a legitimate \
             parent domain. About one published entry in five is a legitimate site that was \
             broken into rather than a domain registered to do harm, and the alert says so \
             when the feed does. The resolution's age is on the alert for the same judgement.",
            // No rotate list, and this used to hardcode browser/github/npm --
            // which is nonsense here. Those belong to a credential READ: they
            // answer "what did the program have in reach". A connection to a
            // fed domain says nothing was read; it says something talked to a
            // place the operator flagged. Rotating your GitHub token because a
            // process reached a bad domain is advice nobody can act on, and the
            // "what that program could read" section it drove is about the
            // wrong thing entirely. The finding is the connection.
            &[],
            &["kill", "ignore"],
            "exe",
        )
    }

    fn on_hook(&mut self, h: &HookHit, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        if ctx.feeds.domains_known() == 0 {
            return Vec::new();
        }
        let Some((ip_s, port)) = h.dest() else {
            return Vec::new();
        };
        let Ok(ip) = ip_s.parse::<IpAddr>() else {
            return Vec::new();
        };
        let Some(l) = ctx.names.lookup(&ip, ctx.now) else {
            return Vec::new();
        };
        let Some(hit) = ctx.feeds.domain_hit(&l.name) else {
            return Vec::new();
        };
        let Some(proc) = ctx.table.get(exec_id) else {
            return Vec::new();
        };
        let key = format!("{}\u{1}{}", proc.exe, ip_s);
        if !self
            .said
            .get_or_insert_with(|| Said::new(SAID_WINDOW_SECS, 512))
            .worth_saying(&key, ctx.now)
        {
            return Vec::new();
        }

        let Some(mut f) = ctx.finding(ID, self.meta(), exec_id) else {
            return Vec::new();
        };
        f.hook = h.hook_name();
        let mut net = NetRef::new(ip_s.clone(), port);
        net.domain = Some(l.name.clone());
        net.domain_age_secs = Some(l.age_secs);
        net.domain_cname = l.cname.clone();
        f.net = Some(net);
        f.ioc = Some(IocRef {
            source: "domain-feed".into(),
            matched: hit.matched(),
        });
        // The headline says what the list says about the name. A malware
        // family is the single most useful word available here, and when the
        // entry is a compromised legitimate site the sentence has to say so --
        // otherwise the reader goes hunting for an intrusion that is somebody
        // else's.
        let says = match (&hit.info, hit.source) {
            (Some(i), _) if i.compromised => format!(
                "{} -- a legitimate site reported as compromised and serving {}",
                hit.entry, i.family
            ),
            (Some(i), _) if i.family != "unknown" && !i.family.is_empty() => {
                format!("{} -- attributed to {}", hit.entry, i.family)
            }
            _ => hit.entry.clone(),
        };
        f.what_override = Some(format!(
            "{} connected to {}:{}, which this machine resolved from {} -- a name on the domain feed ({}).",
            proc.comm(),
            ip_s,
            port,
            l.name,
            says
        ));
        f.extra_evidence = vec![hit.evidence(&l.name, &ctx.feeds.meta)];
        vec![f]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::Feeds;
    use crate::names::{NameCache, Resolved};
    use crate::proctable::ProcTable;
    use crate::rules::testkit::{cfg, proc};
    use std::path::Path;

    fn feeds_with(dir: &Path, domain: &str) -> Feeds {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("domains.txt"), format!("# test\n{}\n", domain)).unwrap();
        Feeds::load(dir)
    }

    fn connect(ip: &str, port: u16) -> crate::event::HookEvent {
        serde_json::from_value(serde_json::json!({
            "policy_name": "moat-net-first-contact",
            "function_name": "security_socket_connect",
            "args": [{"sockaddr_arg": {"family": "AF_INET", "addr": ip, "port": port}}]
        }))
        .unwrap()
    }

    fn run(rule: &mut NetDomainIoc, t: &ProcTable, feeds: &Feeds, names: &NameCache, now: u64) -> Vec<Finding> {
        let cfg = cfg();
        let ctx = RuleCtx {
            rarity: &crate::rarity::RarityStore::default(),
            cfg: &cfg,
            table: t,
            feeds,
            homes: &[],
            now,
            mode: "monitor",
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
            names,
        };
        let ev = connect("45.9.148.99", 443);
        let hit = HookHit {
            kind: crate::event::HookKind::Lsm,
            ev: &ev,
        };
        rule.on_hook(&hit, "e1", &ctx)
    }

    fn resolved(question: &str, ip: &str) -> Resolved {
        Resolved {
            question: question.into(),
            answer_name: None,
            ip: ip.parse().unwrap(),
            ttl: Some(300),
        }
    }

    #[test]
    fn a_connection_to_a_fed_name_is_reported_with_the_name_and_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let feeds = feeds_with(&dir.path().join("feeds"), "evil.example");
        let mut names = NameCache::default();
        names.record(&resolved("cdn.evil.example", "45.9.148.99"), 90);
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 4242, "/usr/bin/curl", "https://cdn.evil.example/", None));

        let mut rule = NetDomainIoc::default();
        let f = run(&mut rule, &t, &feeds, &names, 100);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "high");
        // No rotation advice: a connection to a fed domain is not a credential
        // read, so it must not claim one was exposed. This drove a "rotate your
        // browser/github/npm creds" line and a "what that program could read"
        // section on a network egress alert.
        assert!(
            f[0].meta.rotate.is_empty(),
            "a domain-match must not recommend rotating anything: {:?}",
            f[0].meta.rotate
        );
        let net = f[0].net.as_ref().unwrap();
        assert_eq!(net.domain.as_deref(), Some("cdn.evil.example"));
        assert_eq!(net.domain_age_secs, Some(10));
        assert_eq!(f[0].ioc.as_ref().unwrap().matched, "domain:evil.example");
        assert!(f[0].what_override.as_ref().unwrap().contains("cdn.evil.example"));

        // The same program to the same address inside the window is said once.
        assert!(run(&mut rule, &t, &feeds, &names, 101).is_empty());
        assert_eq!(run(&mut rule, &t, &feeds, &names, 100 + SAID_WINDOW_SECS + 1).len(), 1);
    }

    #[test]
    fn a_published_entry_puts_the_malware_family_in_the_sentence() {
        let dir = tempfile::tempdir().unwrap();
        let feeds_dir = dir.path().join("feeds");
        std::fs::create_dir_all(&feeds_dir).unwrap();
        std::fs::write(
            feeds_dir.join("domains-feed.txt"),
            "# moat-domains v1\n# generated 2026-09-11T00:00:00Z\n# seq 7\n\
             evil.example\tCobalt Strike\t100\t-\t2026-01-02\n",
        )
        .unwrap();
        let feeds = Feeds::load(&feeds_dir);
        assert_eq!(feeds.meta.domain_feed, 1);

        let mut names = NameCache::default();
        names.record(&resolved("cdn.evil.example", "45.9.148.99"), 90);
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 4242, "/usr/bin/curl", "https://cdn.evil.example/", None));

        let f = run(&mut NetDomainIoc::default(), &t, &feeds, &names, 100);
        assert_eq!(f.len(), 1);
        let what = f[0].what_override.as_ref().unwrap();
        // The family is the single most useful word available, and a bare
        // "a name on the domain feed" throws it away.
        assert!(what.contains("Cobalt Strike"), "{}", what);
        let ev = &f[0].extra_evidence[0];
        assert!(ev.contains("feeds/domains-feed.txt"), "{}", ev);
        assert!(ev.contains("100% confidence"), "{}", ev);
        assert!(!ev.contains("compromised"), "{}", ev);
    }

    #[test]
    fn a_compromised_legitimate_site_is_described_as_one() {
        let dir = tempfile::tempdir().unwrap();
        let feeds_dir = dir.path().join("feeds");
        std::fs::create_dir_all(&feeds_dir).unwrap();
        std::fs::write(
            feeds_dir.join("domains-feed.txt"),
            "# moat-domains v1\n# seq 7\nbakery.example\tClearFake\t90\tc\t2026-03-04\n",
        )
        .unwrap();
        let feeds = Feeds::load(&feeds_dir);

        let mut names = NameCache::default();
        names.record(&resolved("bakery.example", "45.9.148.99"), 90);
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 4242, "/usr/bin/firefox", "", None));

        let f = run(&mut NetDomainIoc::default(), &t, &feeds, &names, 100);
        // Roughly one published entry in five is a real business whose site was
        // broken into. "Your browser reached a hacked bakery" and "your shell
        // reached a C2" are the same event to a suffix match and completely
        // different instructions to whoever is reading the alert.
        let what = f[0].what_override.as_ref().unwrap();
        assert!(what.contains("legitimate site reported as compromised"), "{}", what);
        assert!(f[0].extra_evidence[0].contains("registered to do harm"), "{}", f[0].extra_evidence[0]);
    }

    #[test]
    fn no_name_no_feed_or_no_hit_is_silent() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e1", 4242, "/usr/bin/curl", "", None));

        // Name known, but not fed.
        let feeds = feeds_with(&dir.path().join("feeds"), "evil.example");
        let mut names = NameCache::default();
        names.record(&resolved("www.google.com", "45.9.148.99"), 90);
        assert!(run(&mut NetDomainIoc::default(), &t, &feeds, &names, 100).is_empty());

        // Fed, but the address was never resolved from anything moat saw.
        assert!(run(&mut NetDomainIoc::default(), &t, &feeds, &NameCache::default(), 100).is_empty());

        // Fed and named, but the resolution is older than retention.
        let mut old = NameCache::new(60, 16);
        old.record(&resolved("evil.example", "45.9.148.99"), 0);
        assert!(run(&mut NetDomainIoc::default(), &t, &feeds, &old, 1_000).is_empty());

        // No feed at all.
        names.record(&resolved("evil.example", "45.9.148.99"), 90);
        assert!(run(&mut NetDomainIoc::default(), &t, &Feeds::default(), &names, 100).is_empty());
    }

    #[test]
    fn the_rule_is_off_when_names_are_off() {
        let mut c = cfg();
        assert!(NetDomainIoc::default().enabled(&c));
        c.names.enabled = false;
        assert!(!NetDomainIoc::default().enabled(&c), "no names, nothing to match: say so via `enabled`");
    }
}
