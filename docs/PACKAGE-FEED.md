# The malicious-package feed

`moat-feeds` used to fetch abuse.ch (MalwareBazaar / ThreatFox / URLhaus). All
three require an `Auth-Key`, so on a machine without a key the timer did nothing
and every scanner ran with no feed at all. That is now gone.

In its place: a **keyless malicious-package index**, refreshed on a short timer,
that the six scanners consult offline before an install runs.

    upstream                aggregator (Cloudflare)        each machine
    ---------------------   -----------------------        ---------------------
    ossf/malicious-packages  Worker cron, 15 min           moat-feeds (timer)
    DataDog/...-dataset  ->  normalize -> R2      ->        packages.txt
                             pointer + immutable            |
                             artifacts, edge-cached         v
                                                            moat-scan-* (offline)

Two properties matter and everything below serves them:

* **the scanners never touch the network.** They read one local file. That is
  what lets them run in the hot path of `npm install` without adding latency or
  leaking what you are installing.
* **a stale feed is not a broken feed.** Every failure mode leaves the previous
  `packages.txt` in place. The timer never fails hard (CONTRACT §6.7).

## Why an aggregator and not direct fetches

Fetching upstream directly from every machine was the first design. It was
dropped for three reasons, in order of weight:

1. **Bootstrap cost.** The OSSF repo is 479,084 files; its tarball is 44 MB.
   Every install paying that, and re-paying it whenever the delta path failed,
   is the kind of traffic that gets a project blocked.
2. **Client complexity.** Direct fetching means an OSV parser, a streaming
   tar+gzip reader, the GitHub compare API, and per-source ETag bookkeeping —
   in the daemon's own codebase. The aggregate reduces `moat-feeds` to: fetch a
   pointer, maybe fetch one file, verify, write.
3. **Upstream politeness.** One IP does 4 API calls an hour on behalf of every
   user, instead of every user doing their own.

The cost of the aggregator is that users now trust an artifact we publish. That
is what the signature below is for; without it this design would be a downgrade
in trust, not an improvement.

## Endpoints

Base URL is configurable (`base_url` in `feeds.toml`); paths are fixed.

| path | cache | notes |
|---|---|---|
| `/v1/pointer.json` | `public, max-age=60` | the only unpinned object |
| `/v1/packages-<seq>-<sha12>.txt.gz` | `public, max-age=31536000, immutable` | full index |
| `/v1/packages-<seq>-<sha12>.txt.gz.sig` | immutable | ed25519 detached signature |
| `/v1/delta-<from>-<to>-<sha12>.txt.gz` | immutable | incremental |
| `/v1/delta-<from>-<to>-<sha12>.txt.gz.sig` | immutable | |

Artifact names are content-addressed, so they are immutable and edge-cacheable
forever. `pointer.json` is the single mutable object and the only one a client
polls on every tick.

### `pointer.json`

```json
{
  "version": 1,
  "seq": 412,
  "generated": "2026-09-09T18:36:13Z",
  "entries": 241815,
  "artifact": "/v1/packages-412-9f3a1c2b4d5e.txt.gz",
  "sha256": "9f3a1c2b4d5e...",
  "bytes": 1584069,
  "deltas": {
    "411": "/v1/delta-411-412-a1b2c3d4e5f6.txt.gz",
    "410": "/v1/delta-410-412-b2c3d4e5f6a1.txt.gz"
  },
  "sources": {
    "ossf":    { "commit": "b568b3a323d3...", "fetched": "2026-09-09T18:30:02Z" },
    "datadog": { "etag": "\"d26cbd50...\"",   "fetched": "2026-09-09T18:30:04Z" }
  }
}
```

`deltas` holds the recent tail only (default: last 48 sequences). A client whose
`seq` is not listed falls back to the full artifact. A client with no `seq` at
all fetches the full artifact — this is the only path that transfers 1.6 MB.

## Artifact format — `moat-packages v1`

Plain text, gzipped, sorted, LF-terminated, UTF-8. Comment lines start with `#`.
Three tab-separated fields:

    <ecosystem>\t<name>\t<spec>

```
# moat-packages v1
# generated 2026-09-09T18:36:13Z
# entries 241815
crates.io	append-only-vec	=0.1.9
npm	@abacusmirror/react-fontawesome	>=1.1.2
npm	--hiljson	*
pypi	requestss	*
```

`ecosystem` is one of the canonical lowercase names below. `name` is verbatim
from upstream (npm scopes keep their `@`, and a name may contain almost
anything except a tab). Sort order is byte order over the whole line.

### The spec field

A spec is one or more **clauses** joined by `|`, meaning OR. A package matches
if any clause matches.

| clause | meaning |
|---|---|
| `*` | every version of this package is malicious |
| `=V` | exactly version `V` |
| `>=V` | `V` and everything after it |
| `>=I,<F` | introduced at `I`, fixed in `F` |
| `>=I,<=L` | introduced at `I`, last affected `L` |

`*` absorbs everything: if any source contributes `*`, the spec is exactly `*`.

This distinction is the whole point of the format and must not be flattened.
86% of upstream records are `*` — a package that exists only to be malicious.
But 32,866 name specific versions, and those include ordinarily-legitimate
packages that were compromised for one release. Matching those on name alone
would warn on every install of a popular package forever, which trains users to
ignore the warning.

Version comparison is per-ecosystem and is the consumer's problem. A consumer
that cannot compare versions for an ecosystem MUST still honour `*` and `=V`
(exact string equality), and SHOULD treat an uncomparable `>=`/range clause as
a match with reduced confidence rather than silently ignoring it.

### Ecosystems

| canonical | upstream spellings |
|---|---|
| `npm` | `npm` |
| `pypi` | `PyPI`, `pypi` |
| `crates.io` | `crates.io` |
| `go` | `Go` |
| `rubygems` | `RubyGems` |
| `nuget` | `NuGet` |
| `maven` | `Maven` |
| `packagist` | `Packagist` |
| `vscode` | `VSCode`, `VSCode:https://open-vsx.org`, Datadog `ide_extensions` |
| `ai-skills` | Datadog `ai-skills` |

An unknown ecosystem is dropped by the aggregator, counted, and reported in the
run log — never guessed at.

## Delta format — `moat-packages-delta v1`

Same three fields, with a leading one-character op column and no separate
header for removals:

```
# moat-packages-delta v1
# from 411
# to 412
+	npm	@aspect-adv-ui/consent-manager	*
+	npm	1cattunnel	*
-	npm	somewithdrawnpkg
```

`+` means "insert or replace this entry" — the spec is the complete new spec for
that key, not an addition to it. `-` means "remove this key"; the spec field is
absent. Applying a delta is therefore idempotent and order-independent within a
single delta file.

A client applies deltas strictly in sequence order. If any delta in the chain is
missing, it must fall back to the full artifact rather than skipping one.

## Signing

Every artifact and delta is signed with ed25519. The public key ships in the
package at `/usr/share/moat/feed-key.pub` and is pinned; the signature is a
detached `.sig` alongside each object.

`moat-feeds` MUST verify before writing anything to the feed directory, and MUST
leave the previous `packages.txt` untouched on any verification failure. A bad
signature is logged loudly and is the one condition that is *not* treated as a
routine stale-feed case.

Rationale: this file drives security warnings. Without a signature, control of
the bucket is control of what moat warns about — including the ability to
silently empty the list and suppress every warning. TLS alone authenticates the
CDN, not the contents.

The `sha256` in the pointer is an integrity check against truncation and cache
corruption. It is not a substitute for the signature.

## Client contract

Per tick, `moat-feeds`:

1. `GET /v1/pointer.json` with `If-None-Match`. On 304, stop — this is the
   common case and costs nothing.
2. If `pointer.seq == local seq`, stop.
3. If `pointer.deltas` contains the local seq, fetch that delta; else fetch the
   full artifact.
4. Verify the ed25519 signature, then the sha256.
5. Apply, and write `packages.txt` + `meta.json` atomically.

On any error at any step: log, leave the existing files alone, exit 0.

### Failure behaviour

| condition | behaviour |
|---|---|
| network unreachable | keep existing files, exit 0 |
| pointer malformed | keep existing files, exit 0 |
| delta chain broken | fall back to full artifact this tick |
| sha256 mismatch | discard download, keep existing files, log at warn |
| **signature invalid** | discard, keep existing files, log at **error** |
| aggregator serving a very old `seq` | apply it; staleness is visible in `moatctl status` |

## Cadence

The timer runs every 15 minutes with jitter. Upstream itself only moves every
1–2 hours (the OSSF ingest jobs), so a shorter tick does not produce fresher
data — it reduces the worst-case lag between an ingest landing and the machine
seeing it, from an hour to a few minutes. Because the common tick is a 304 on a
200-byte object, the cost of that is negligible.

Jitter is not optional. Without `RandomizedDelaySec`, every machine fires on the
quarter hour and the aggregate looks like a thundering herd.

## What was lost by dropping abuse.ch

`hashes.txt`, `domains.txt` and `urls.txt` are no longer fetched by anything.
The files are still **read** if present, so an operator can drop in their own
indicators, and `moat-x-new-exec-ioc` still matches against `hashes.txt`.

There is no keyless replacement for the sha256 feed: OSV malicious-package
records identify packages, not file hashes. This is a real reduction in what
moat detects, and it is the deliberate price of not requiring every user to
register for an API key to get any feed at all. `moatctl status` reports the
hash feed as operator-supplied so the distinction is visible rather than
implied.
