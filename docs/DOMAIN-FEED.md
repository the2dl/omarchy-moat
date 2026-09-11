# The domain feed

A signed list of malicious hostnames, published by the same aggregator as the
package index and installed by `moat-feeds`. ~48,000 domains, 604 KB on the
wire, refreshed every fifteen minutes.

This is the companion to `docs/DNS.md`. That document explains how moatd learns
the hostname behind a connection (systemd-resolved's own query stream, giving
`process → pid → domain`). This one is the list that name gets checked against.

## Why it exists

`feeds/domains.txt` has been read since the DNS work landed, and it is
operator-supplied. On a normal machine it is empty, so `moat-x-net-domain-ioc`
never fired: moat could name the domain behind a connection and then had
nothing to compare it to.

## Why ThreatFox

abuse.ch was removed from moat once before, because MalwareBazaar, ThreatFox
and URLhaus all wanted an `Auth-Key` and a key shipped inside a package is not
a key. That reasoning does not survive the aggregator — one key here would have
served the whole fleet — and it turns out not to apply either way: the JSON API
is authenticated, the **bulk exports are not**, and the bulk exports are what a
feed builder wants.

The reason for ThreatFox over a union of everything is that **it ages its own
IOCs out**. About 50k domains are live against ~106k rows in the full dump. A
domain blocklist that only ever grows is a false-positive generator with a
six-month fuse, and somebody else doing the expiry is the most valuable
property on offer.

## The two upstreams, and which one decides

| Endpoint | Size | Role | Read by |
| --- | --- | --- | --- |
| `threatfox.abuse.ch/downloads/hostfile/` | 1.6 MB plain text | **the corpus** | every tick |
| `threatfox.abuse.ch/export/csv/full/` | 3 MB zip → 23 MB CSV | metadata only | the daily job |

The hostfile is abuse.ch's own answer to *which of these are live right now*.
The CSV adds malware family, confidence and the compromised flag.

They are deliberately **not unioned**. The full CSV lists ~2.2k domains the
hostfile does not, and taking the union would make the published set oscillate
between 47.9k and 50k twice a day — a new sequence, a new artifact and a fresh
download for every machine, describing no real change. Membership is the
hostfile's call; the CSV only decorates it. A domain the hostfile has and the
CSV has not yet seen is published with family `unknown`.

The zip needs `aggregator/src/zip.js`: Workers have `DecompressionStream`, but
a zip carries a central directory after the payload and handing those trailing
bytes to an inflate stream is an error, not a no-op.

## The gates

Three, applied in this order, all in `gateDomains`.

### 1. Shared suffixes

The one that matters. moatd matches the feed **by suffix** — `Feeds::domain_hit`
walks a resolved name up through its parents, so an entry of `evil.example`
fires on `cdn.evil.example`. That is correct for a campaign rotating its
leftmost label, and catastrophic for an entry like `workers.dev`: one bad row
upstream and every Cloudflare Worker on the internet is an IOC on every machine
running moat.

The first version asked *is this a public suffix*, which the live feed
immediately showed was the wrong question. 56 entries tripped it and 50 were
`<random>.localto.net` tunnels — real, current C2 being thrown away. The PSL
lists `*.localto.net` so browsers isolate one tunnel from another, which makes
each one a public suffix by the letter of the algorithm and a single tenant's
host in the sense that matters here.

So the test is the wildcard **base**, not the wildcard instance:

| Entry | Verdict |
| --- | --- |
| `workers.dev` | exact PSL rule → shared ground, dropped |
| `compute-1.amazonaws.com` | base of `*.` → shared ground, dropped |
| `ec2-18-208-244-120.compute-1.amazonaws.com` | one instance → kept |
| `ratted.localto.net` | one tunnel → kept |

The cost, stated plainly: `*.kobe.jp` is a wildcard of the other kind, where
each instance really is a registry for the public, and an entry of
`osaka.kobe.jp` would get through and over-match. Nothing in the PSL
distinguishes the two cases; every wildcard hit in the live feed is the tenant
kind; losing 50 live C2 domains to guard against a row that has never appeared
is the worse trade.

**On live data this gate currently drops nothing.** That is what a prophylactic
guard should do. It exists for the day it stops being true upstream.

### 2. The never-list

A short list in `aggregator/src/domains.js` of names whose appearance would
break moat or the machine it runs on: the package mirrors, the registries the
six scanners front, GitHub, `feed.runts.net` itself, the resolvers. An alert
storm on the Arch mirror during an upgrade is the failure that would get the
whole feature switched off. Not a general top-sites allowlist — the suffix gate
does the structural work, and abuse.ch does not report bare registrable domains
of major services.

### 3. Confidence

`DOMAIN_MIN_CONFIDENCE`, default 50. Drops the ~147 entries ThreatFox scores at
49. An entry the hostfile has but the CSV snapshot has not yet seen has no
score and is published regardless — membership is the hostfile's call.

## Normalisation

Lowercased, root dot dropped, IPs and anything carrying a path, port or scheme
refused. `www.` is **not** stripped: `www.abc-network.it` is a real entry and
the bare domain is not, and stripping it would widen one host to a whole site
in a list matched by suffix.

Unicode entries are punycoded. ThreatFox reports what a human typed —
`bbautókozmetika.hu` — and what moatd sees off the wire is the A-label,
`xn--bbautkozmetika-pob.hu`. Left in Unicode those entries are not strict, they
are dead. Ten are in a typical day's feed.

## The artifact

`/v1/domains-<seq>-<sha12>.txt.gz`, detached ed25519 signature at `.sig`, same
key as the package index.

```
# moat-domains v1
# generated 2026-09-11T14:51:56Z
# entries 47755
# seq 1
# upstream 2026-09-11 14:38:15 UTC
# fields domain	family	confidence	flags	first_seen
evil.example	AsyncRAT	100	-	2026-01-02
bakery.example	ClearFake	90	c	2026-03-04
```

Sorted by domain. `flags` is a character set; `c` means a legitimate site
reported as compromised rather than a domain registered to do harm — about one
entry in five. `seq` is inside the signed bytes, because `pointer.json` is not
signed and without it a fresh-looking pointer could serve an old,
genuinely-signed artifact.

No deltas. The list is 604 KB gzipped and changes wholesale; the delta
machinery exists for the 1.6 MB package index.

### In `pointer.json`

```json
{
  "version": 1,
  "seq": 6, "artifact": "/v1/packages-6-….txt.gz", "…": "…",
  "domains": {
    "seq": 1,
    "generated": "2026-09-11T14:51:56Z",
    "entries": 47755,
    "artifact": "/v1/domains-1-b98c6ee67427.txt.gz",
    "sha256": "b98c…",
    "bytes": 603964,
    "source": { "name": "threatfox", "upstream": "…", "min_confidence": 50 }
  }
}
```

The two wings **publish independently and share this one document**, each
replacing only its own keys by reading what is live first. Sharing a sequence
would mean every ThreatFox change republishing the 1.6 MB package artifact and
all 48 deltas, and every package change republishing the domain list — two
feeds moving at completely different rates, each paying the other's bandwidth.

An older client ignores the `domains` block; an older aggregator does not send
one, and absent is **not** the same as empty — the client keeps the list it has.

## Client contract

`moat-feeds` installs it as `feeds/domains-feed.txt`.

**It is a separate file on purpose.** `domains.txt` is operator-supplied and
`feeds.rs` has always promised never to write it. The published list has 48,000
names in it; merging would eat whatever somebody had typed there. `Feeds` reads
both, and **an operator entry wins a tie** — a line on this machine is a
deliberate act, the feed is a wholesale import, and the alert should point at
the file the reader can actually go and edit.

Refusals, all of which leave the file on disk alone:

- signature does not verify (logged at error, not warn);
- `sha256` disagrees with the pointer;
- the artifact's own `# seq` disagrees with the pointer's — a fresh pointer
  serving a stale but genuinely-signed list;
- the pointer offers a sequence lower than the one installed (rollback);
- the list parses to zero entries.

The domain step runs **before** the package path's `pointer.seq == state.seq`
early return. That check passing is the common case, and it is exactly when
ThreatFox has moved; doing domains after it would pin the domain list to
whenever a malicious npm package happened to be published.

## What it looks like in an alert

The family is the most useful word available, and the compromised flag changes
the instruction entirely:

```
curl connected to 45.9.148.99:443, which this machine resolved from
cdn.evil.example -- a name on the domain feed (evil.example -- attributed to
Cobalt Strike).

  feed: cdn.evil.example matched entry evil.example of feeds/domains-feed.txt
  (47755 entries, published 2026-09-11T14:51:56Z); attributed to Cobalt Strike
  at 100% confidence; first reported 2026-01-02
```

versus

```
firefox connected to … -- a name on the domain feed (bakery.example -- a
legitimate site reported as compromised and serving ClearFake).
```

"Your browser reached a hacked bakery" and "your shell reached a C2" are the
same event to a suffix match and completely different instructions to whoever
is reading the alert.

The rule recommends rotating **nothing**. A connection to a fed domain is not a
credential read; see the comment in `rules/net_domain_ioc.rs`.

## Operating it

```
moatctl status | grep -A1 domains
curl -s https://feed.runts.net/healthz | jq .domains
curl -sX POST -H "Authorization: Bearer $TOKEN" \
  'https://feed.runts.net/admin/domains?full=1'
```

`/admin/domains` runs the wing alone — the lever for refreshing after changing
`DOMAIN_MIN_CONFIDENCE` or the never-list, without waiting for 04:17 and
without dragging the 44 MB package rebuild along. `?full=1` re-reads the CSV
dump for metadata.

**A domain failure can never fail a package tick.** The six scanners read
`packages.txt` before every install and that path has worked for a year;
`runDomainsSafely` catches everything and records it in `healthz.domains
.last_error`.

### The collapse floor

A published list that collapses is worse than one that is stale: every machine
quietly loses coverage and nothing looks broken. A truncated response, a
half-written upstream file and an outage behind a 200 all present the same way,
and the answer to all three is to keep what is published. Below half the
current entry count the run refuses and says so. A deliberate shrink still gets
through — it just takes two runs.

## Licensing

abuse.ch data is free for non-commercial use under their terms of use; moat
re-hosts a derived, filtered list. See <https://threatfox.abuse.ch/faq/#tos>.
