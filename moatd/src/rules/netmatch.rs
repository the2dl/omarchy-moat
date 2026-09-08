//! CIDR matching for the egress rule.
//!
//! Tetragon can exclude RFC1918 in-kernel (`NotDAddr`), but the registry
//! allowlist has to live here, and it is IPs only: there is no DNS in the
//! kernel and the export carries no hostname (NOTES gap 4).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

pub fn parse_cidr(s: &str) -> Option<Cidr> {
    let s = s.trim();
    let (addr_s, prefix_s) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let addr: IpAddr = addr_s.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_s {
        Some(p) => p.parse::<u8>().ok()?,
        None => max,
    };
    if prefix > max {
        return None;
    }
    Some(Cidr { addr, prefix })
}

pub fn parse_all(list: &[String]) -> (Vec<Cidr>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for s in list {
        match parse_cidr(s) {
            Some(c) => ok.push(c),
            None => bad.push(s.clone()),
        }
    }
    (ok, bad)
}

pub fn contains(net: &Cidr, ip: &IpAddr) -> bool {
    match (net.addr, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => bits_eq(&n.octets(), &i.octets(), net.prefix),
        (IpAddr::V6(n), IpAddr::V6(i)) => bits_eq(&n.octets(), &i.octets(), net.prefix),
        _ => false,
    }
}

pub fn contains_any(nets: &[Cidr], ip: &IpAddr) -> bool {
    nets.iter().any(|n| contains(n, ip))
}

fn bits_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Anything that never leaves the machine or the LAN. Loopback, RFC1918,
/// link-local, CGNAT, multicast and their v6 equivalents.
/// Addresses that are always fine to talk to from inside an install.
///
/// Loopback only. A local registry proxy, a devcontainer registry and a
/// `verdaccio` on 127.0.0.1 are ordinary and are the reason `allow_private`
/// existed at all -- but they live on loopback, not on the LAN. An install
/// reaching an arbitrary *LAN* host is a different thing entirely, and on
/// 2026-09-04 a simulated npm package beaconed to a WebSocket C2 on
/// 192.168.44.122 and moat said nothing, because "private" covered both.
pub fn is_always_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]) // 100.64/10 CGNAT
                || *v4 == Ipv4Addr::new(255, 255, 255, 255)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || v4_mapped(v6).map(|v| is_private(&IpAddr::V4(v))).unwrap_or(false)
        }
    }
}

fn v4_mapped(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        let o = v6.octets();
        Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_prefixes() {
        let n = parse_cidr("151.101.0.0/16").unwrap();
        assert!(contains(&n, &ip("151.101.1.2")));
        assert!(!contains(&n, &ip("151.102.1.2")));
        let n = parse_cidr("140.82.112.0/20").unwrap();
        assert!(contains(&n, &ip("140.82.113.4")));
        assert!(!contains(&n, &ip("140.82.128.1")));
    }

    #[test]
    fn a_bare_address_is_a_host_route() {
        let n = parse_cidr("1.2.3.4").unwrap();
        assert_eq!(n.prefix, 32);
        assert!(contains(&n, &ip("1.2.3.4")));
        assert!(!contains(&n, &ip("1.2.3.5")));
    }

    #[test]
    fn v6_prefixes_and_family_mismatch() {
        let n = parse_cidr("2606:4700::/32").unwrap();
        assert!(contains(&n, &ip("2606:4700:10::1")));
        assert!(!contains(&n, &ip("2606:4701::1")));
        assert!(!contains(&n, &ip("1.2.3.4")), "family mismatch never matches");
    }

    #[test]
    fn private_ranges() {
        for p in ["10.1.2.3", "192.168.0.5", "172.16.9.9", "127.0.0.1", "169.254.1.1", "100.64.0.1"] {
            assert!(is_private(&ip(p)), "{} should be private", p);
        }
        for p in ["1.1.1.1", "185.220.101.55", "151.101.1.2"] {
            assert!(!is_private(&ip(p)), "{} should be public", p);
        }
        assert!(is_private(&ip("::1")));
        assert!(is_private(&ip("fd00::1")));
        assert!(is_private(&ip("fe80::1")));
        assert!(is_private(&ip("::ffff:10.0.0.1")));
        assert!(!is_private(&ip("2001:db8::1")));
    }

    #[test]
    fn garbage_is_rejected_not_silently_allowed() {
        assert!(parse_cidr("not-an-ip").is_none());
        assert!(parse_cidr("10.0.0.0/33").is_none());
        let (ok, bad) = parse_all(&["10.0.0.0/8".into(), "nope".into()]);
        assert_eq!(ok.len(), 1);
        assert_eq!(bad, vec!["nope"]);
    }
}

#[cfg(test)]
mod shipped_registry_list {
    use super::{contains_any, parse_all, parse_cidr};

    /// Every CIDR moat ships for `net.registry_cidrs` must parse.
    #[test]
    fn the_shipped_registry_cidrs_all_parse() {
        let toml = include_str!("../../etc/moat.toml");
        let start = toml.find("registry_cidrs = [").expect("the key is shipped");
        let end = start + toml[start..].find(']').expect("the list closes");
        let cidrs: Vec<String> = toml[start..end]
            .lines()
            .filter_map(|l| l.split('"').nth(1).map(str::to_string))
            .collect();
        assert!(cidrs.len() >= 8, "read {} entries, the list is not that short", cidrs.len());
        let (ok, bad) = parse_all(&cidrs);
        assert!(bad.is_empty(), "unparseable shipped CIDRs: {:?}", bad);
        assert_eq!(ok.len(), cidrs.len());
    }

    /// node, npm and mise resolve AAAA first, so on a v6-capable network the
    /// registry is reached over v6 every time. A v4-only list is not a
    /// conservative list -- it is one that never matches.
    #[test]
    fn the_registry_is_recognised_over_ipv6() {
        let toml = include_str!("../../etc/moat.toml");
        let start = toml.find("registry_cidrs = [").unwrap();
        let end = start + toml[start..].find(']').unwrap();
        let cidrs: Vec<String> = toml[start..end]
            .lines()
            .filter_map(|l| l.split('"').nth(1).map(str::to_string))
            .collect();
        let (nets, _) = parse_all(&cidrs);

        // Seen live on 2026-09-08: `npx tsc` and `mise use -g npm:wrangler`.
        for addr in [
            "2606:4700::6810:722",  // Cloudflare, the npx tsc alert
            "2606:4700::6810:822",  // Cloudflare, one of the wrangler nine
            "2a04:4e42:4e::760",    // Fastly, registry.npmjs.org
        ] {
            let ip = addr.parse().expect("test address parses");
            assert!(
                contains_any(&nets, &ip),
                "{} is a package registry and the shipped list does not know it",
                addr
            );
        }
    }

    /// The list is an allowlist, so it must not quietly cover the internet.
    #[test]
    fn it_does_not_allow_somewhere_it_should_not() {
        let (nets, _) = parse_all(&[
            "104.16.0.0/12".to_string(),
            "2606:4700::/32".to_string(),
        ]);
        for addr in ["8.8.8.8", "2001:4860:4860::8888", "192.0.2.1"] {
            let ip = addr.parse().unwrap();
            assert!(!contains_any(&nets, &ip), "{} must not be inside the registry list", addr);
        }
        assert!(parse_cidr("2606:4700::/32").is_some());
    }
}
