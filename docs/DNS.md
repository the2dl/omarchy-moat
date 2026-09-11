# Name resolution: where a hostname can come from, and what moat records

An audit of how names get resolved on this machine, which of those paths moat
can read, and what it now writes on a network alert. Same shape as `LPE.md`:
what is covered, what is not, then the build.

Written 2026-09-10 against the machine moat is developed on: Omarchy, Arch,
systemd 261, kernel 7.1.9.

## The short version

Until today every network alert carried `{dst_ip, dst_port, domain}` with
`domain` always null. `NetRef` in `alert.rs` had the field and a comment saying
"No DNS anywhere in moat (NOTES gap 4)". `feeds/domains.txt` was read, counted
in `status.feeds.domains`, and matched against nothing.

The cheapest correct source of names on this machine is **systemd-resolved's
own query stream**, and it needs no kernel work at all. It sees every
resolution whichever way it arrived, cache hits included, and it says which
name was asked for and which addresses came back. It does not say which
process asked. So the artifact moat can honestly write is:

> the most recent name this machine resolved to that address, and how long
> before the connection it was resolved

-- evidence keyed by address, with its age, never attribution. That is what
`net.domain` now means, and when there is no such name the record says
`not recorded` in words and why, rather than leaving a null that reads as "the
connection had no name".

The domain feed then matches against those names, the way `feeds.rs` already
matches malicious package names and `moat-x-new-exec-ioc` matches hashes.

## What this machine actually does

Measured, not assumed.

```
resolvectl status
    resolv.conf mode: stub
    Current DNS Server: 9.9.9.9#dns.quad9.net       (global; not the one in use)
  Link 3 (wlp6s0)     DNS Servers: 192.168.44.1    DNS Domain: lan      -DNSOverTLS
  Link 5 (tailscale0) DNS Servers: 100.100.100.100 DNS Domain: tail8cbe89.ts.net ~*.in-addr.arpa

/etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf   nameserver 127.0.0.53
/etc/nsswitch.conf  hosts: mymachines mdns_minimal [NOTFOUND=return] resolve files myhostname dns
/etc/hosts          localhost only (two lines)
/etc/systemd/resolved.conf.d/20-docker-dns.conf   DNSStubListenerExtra=172.17.0.1
/etc/systemd/resolved.conf.d/10-disable-multicast.conf   LLMNR=no MulticastDNS=no

resolvectl statistics
    Total Transactions: 139032    Cache Hits: 90089    Cache Misses: 15878

ss -ulnp | grep :53     172.17.0.1:53  127.0.0.54:53  127.0.0.53%lo:53   (all resolved)
ss -uapn | grep :53     nothing in flight at the time of measuring
chromium / google-chrome "Local State"   dns_over_https: unset (system resolver)
firefox                 not installed
tailscale               MagicDNS on
```

What that means:

* **Every ordinary resolution goes through resolved.** `resolve` is ahead of
  `dns` in nsswitch, so glibc programs use `nss-resolve` over varlink and never
  send a packet to port 53 themselves. Programs with their own stub (Chrome,
  Go binaries, `curl` built against c-ares) read `/etc/resolv.conf` and send to
  `127.0.0.53`, which is also resolved. Docker's default bridge is pointed at
  resolved's extra stub on `172.17.0.1`. Tailscale's MagicDNS names are
  forwarded by resolved to `100.100.100.100`. One daemon sees all of it.
* **Most lookups never touch the wire.** 85% of transactions were cache hits.
  Anything that watches port 53 -- a kprobe, a packet capture -- misses those
  by construction. resolved's stream reports them.
* **The uplink is plaintext UDP 53** to `192.168.44.1`. DNS-over-TLS is off.
  That only matters for the kprobe option below, and it turns out not to
  matter much.
* **No browser here does DNS-over-HTTPS on its own** today. Chrome's
  automatic mode upgrades to DoH only when the system resolver is a known DoH
  provider; a LAN router is not one. This is a fact about this machine on this
  day, not a guarantee -- see "What it cannot see".

## Candidates, in order of how much they matter

### 1. systemd-resolved's monitor stream -- built

`resolvectl monitor --json=short` streamed, unprivileged, from this session:

```
{"state":"success","question":[{"class":1,"type":1,"name":"localhost"}, ...],
 "answer":[{"rr":{"key":{"class":1,"type":1,"name":"localhost"},"address":[127,0,0,1]}, ...}]}
{"state":"success","question":[{"class":1,"type":1,"name":"www.google.com"},{"class":1,"type":28,"name":"www.google.com"}],
 "answer":[{"rr":{"key":{"class":1,"type":1,"name":"www.google.com"},"address":[142,251,154,119]},
            "raw":"A3d3dwZnb29nbGUDY29tAAABAAEAAAEZAASO+5p3","ifindex":3}, ... 8 A + 8 AAAA]}
```

The `localhost` lines were repeated cache hits, which is the point: the stream
is every transaction resolved handled, not every packet it sent. The `raw`
field is the wire-format RR, base64, and carries the TTL (`0x119` = 281 s
above), which the CLI does not print but moat decodes.

The transport is varlink on `/run/systemd/resolve/io.systemd.Resolve.Monitor`:
one JSON object terminated by a NUL byte each way, method
`io.systemd.Resolve.Monitor.SubscribeQueryResults` with `"more": true`. The
socket is world-connectable, but the method is polkit-gated
(`org.freedesktop.resolve1.subscribe-query-results`, `auth_admin_keep` for an
active session). A raw subscribe from this user without declaring interactive
authentication came back `io.systemd.InteractiveAuthenticationRequired`; the
CLI succeeded because the session had an admin authorisation cached.

**moatd runs as uid 0, and systemd's varlink polkit path lets root through
without asking.** That is read from systemd's source, not measured here:
`sudo` wants a password in this session and there was no other way to run
anything as root. It is the one unmeasured step, and it is designed to be
measured on the first restart: `status.names.state` says `connected`, or it
says `refused: io.systemd.InteractiveAuthenticationRequired`, and
`moatctl status` prints that line. The unit's hardening permits the call
(`RestrictAddressFamilies=AF_UNIX`, `@system-service` covers `connect`).

Cost: one thread, one unix socket, a bounded map. No hook, no policy, no
`BPF_MAX_TRAMP_LINKS` slot, no Tetragon restart, nothing in the 19-second
window. It survives a resolved restart with backoff, and it says so in
`status` when it is not connected.

### 2. Tetragon watching port 53 -- not built, and here is what it would see

A kprobe on `udp_sendmsg` / `udp_recvmsg` with a `sock` argument filtered to
`DPort 53`, plus `char_buf` and `maxData` to capture the payload, is not
subject to the LSM cap (kprobes attach through their own mechanism), so the
budget is not the objection. On this machine it would see exactly two things:

* resolved's own uplink queries to `192.168.44.1` -- the 15% that missed the
  cache, with resolved as the process, so no attribution gain;
* stub clients sending to `127.0.0.53` -- the Chrome-style resolvers, which
  resolved reports anyway.

Both are already in the stream from §1, and the 85% of cache hits are not
visible to a kprobe at all. The remaining work would be a DNS wire-format
parser in moatd (labels, compression pointers, RR types) under a `maxData`
cap, and DoT/DoH defeat it entirely. Not worth it as a *source of names*.

Where it WOULD earn its keep is as a different signal: "a process sent UDP to
port 53 somewhere other than loopback, and it is not resolved" is a
resolver-bypass, and that is a cheap, quiet kprobe. That is a detection about
DNS behaviour, which is explicitly not what was asked for. Listed under
"What next".

### 3. `/etc/hosts` and the nsswitch path -- partial, and covered by §1 anyway

Two lines, both `localhost`. resolved reads `/etc/hosts` itself and serves
those entries, and they appear in its stream (the `localhost` transactions
above are exactly that). `mymachines` and `myhostname` are synthetic. There
is no separate reading of the file to do.

### 4. Reverse DNS -- a trap, agreed, not built

A PTR answers "what does the owner of this address call it", which is a
different question from "what name did this program ask for". For a CDN or a
cloud host the two are unrelated (`142.251.154.119` reverses to something in
`1e100.net`, whatever you looked up), and for a hostile host the PTR is set by
the attacker. It also makes moat a source of outbound queries of its own,
which a monitor should not be. `names.rs` ignores PTR questions in the
stream for the same reason: a PTR that resolved happened to answer for
someone else must not become the "name" on an alert.

## What it cannot see

Said on the record, not just here. Each of these leaves `domain` null and puts
a `name: not recorded -- ...` line in the evidence naming the possibilities.

| case | why | what the record says |
|---|---|---|
| a program connects to a literal address | nothing was resolved | not recorded |
| DNS-over-HTTPS or DoT inside the program | resolved never sees it | not recorded (the line names DoH) |
| a container with its own resolver | Docker's default bridge is pointed at resolved; a user-defined network's embedded DNS forwards to the host's uplink servers and is **UNVERIFIED** here | not recorded |
| the name was resolved more than `retain_secs` (6 h) ago | pruned; programs cache far past the TTL, hence hours, but not forever | not recorded, with the window named |
| the name was resolved before moatd started | the cache is in memory only | not recorded |
| resolved refused the subscription | polkit, or a hardening change | `status.names.state` says `refused: ...`; every net alert says the stream is unavailable |
| which PROCESS asked | resolved does not report the client | the name is keyed by address; the alert carries its age |

The last row is the honest limit of this artifact. On a shared address --
any CDN edge -- the name on the alert is the most recent one this machine
resolved to it, which may be another program's. The age is on the record so a
reader can weigh it, and the domain-feed rule is `high` rather than
`critical` for the same reason.

A cache hit inside the *program* -- a browser that resolved a name an hour ago
and is reconnecting -- is fine: resolved saw the original lookup and the cache
holds it for six hours.

## The build

All in moatd and the panel. No policy, no Tetragon change, no `check.py`
concern. Hook budget unchanged: `file_post_open` stays where it was.

### `names.rs` -- the reader and the cache

A thread connects to the monitor socket, subscribes, and turns each reply
into `Resolved { question, answer_name, ip, ttl }` -- every A/AAAA answer is
attributed to the *first question name*, which is what the program typed; the
answer RR's owner name is kept as `answer_name` when a CNAME chain ended
somewhere else. PTR questions and non-success states are dropped. A bounded
channel carries it to the daemon, which drains it on every pass of the loop
*before* the sensor's lines, so a resolution precedes its connection in the
cache the way it did on the wire.

`NameCache` is address -> the last four names, newest first, 8,192 addresses,
six-hour retention, pruned from `tick`. `status.names` reports the reader's
last word (`connected`, `refused: ...`, `unavailable: ...`, `off`), how many
addresses are held, and how many answers have been recorded.

### The record

`NetRef` gains `domain_age_secs` and `domain_cname`, both optional and absent
when there is no name, so an old reader sees the shape it always saw.
`Daemon::enrich_names` is the one place every net finding passes through: it
fills the three fields, writes one evidence line either way, and -- when the
name is in `feeds/domains.txt` -- sets `ioc: {source: "domain-feed", matched:
"domain:<entry>"}` so the existing scoring reads it as an IOC whichever rule
raised the alert. `summary`, `explain.what` and the hook evidence line print
`142.251.154.119:443 (www.google.com)` when there is a name.

The feed is not affected: `cmd_feed` already strips `explain`, and the two
new fields are skipped when null.

### `moat-x-net-domain-ioc` -- the feed match

A connection to an address the machine resolved from a fed name, for the
connections nothing else reports (a familiar /24, a registry CIDR). `high`.
One row per (program, address) per ten minutes. Off when `[names]` is off,
because then it has nothing to match, and it says so through `enabled` rather
than by staying silent. `Feeds::domain_hit` matches an entry and every
subdomain of it, down to two labels, and returns the *entry* so the alert
names the line of the file that fired. Feed entries are normalised the way the
names are (lowercase, no trailing dot).

### The panel and the CLI

`normalizeStatus` whitelists `names` (the sixth field to be added there on
purpose; the test says why). `EvidenceBlock` has a `resolved from` row that
always renders -- `www.google.com · resolved 12 s before`, or `not recorded`.
`chainStepDetail` prints the name beside the address. `moatctl show` prints
`network: ip:port (name, resolved N s before)` or `(name not recorded)`;
`moatctl status` prints the reader's state.

### Config

```toml
[names]
enabled = true
socket = "/run/systemd/resolve/io.systemd.Resolve.Monitor"
retain_secs = 21600
max_addresses = 8192

[rules]
net_domain_ioc = true
```

## What next

In the order they are worth doing.

1. **Measure the root subscribe.** Restart moatd, run `moatctl status`, read
   the `names` line. Everything above assumes `connected`; if it says
   `refused`, the fix is a polkit rule for uid 0 on
   `org.freedesktop.resolve1.subscribe-query-results`, shipped in the package.
2. **Persist the cache across restarts.** Six hours of names is lost on every
   moatd restart, and moatd restarts whenever Tetragon does. `state.json` is
   the place; the shape is small.
3. ~~**A keyless domain feed.**~~ **DONE (2026-09-11).** The aggregator now
   publishes one: ~48k domains from ThreatFox, gated, signed, and installed by
   `moat-feeds` into `feeds/domains-feed.txt` -- a separate file, because
   `domains.txt` stays the operator's and a refresh must never write it. The
   rule is live on a fresh install. `status.feeds.domain_feed` is the count;
   `feeds.domains` remains the operator's own. See `docs/DOMAIN-FEED.md`.
4. **Resolver bypass as a signal.** The kprobe from §2, reduced to "UDP to
   port 53, not loopback, not from resolved": one policy, no LSM slot, a
   Tetragon restart to test. It is about DNS behaviour rather than evidence,
   which is why it is here and not above.
5. **A lookup with no connection.** A fed name that resolves to NXDOMAIN (a
   sinkhole) never produces a connection and so never fires the rule. A
   lookup-only match is a weaker claim and was left out on purpose; it is a
   ten-line addition to `drain_names` if it turns out to be wanted.
