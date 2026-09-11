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
# entries 241813
# seq 412
crates.io	append-only-vec	=0.1.9
npm	@abacusmirror/react-fontawesome	>=1.1.2
npm	--hiljson	*
pypi	requestss	*
```

`ecosystem` is one of the canonical lowercase names below. `name` is verbatim
from upstream (npm scopes keep their `@`, and a name may contain almost
anything except a tab) — **except for `pypi`, see below**. Sort order is byte
order over the whole line.

`# seq` is required and is the artifact's own sequence number. It is inside the
signed bytes deliberately — see "Signing" below. A client MUST refuse an
artifact with no `# seq`, or one whose `# seq` disagrees with the pointer that
sent it there. Header lines are only recognised in the leading comment block,
so a package named `# seq 999` cannot forge one.

### PyPI names are normalized; every other ecosystem is verbatim

`pypi` names are emitted PEP 503 normalized — lowercased, with runs of `-`, `_`
and `.` collapsed to a single `-`:

    re.sub(r"[-_.]+", "-", name).lower()

PyPI treats those spellings as the same package, so the feed must carry exactly
one of them or a lookup cannot find it. Consumers binary-search this file in
byte order, which rules out normalizing at lookup time: the *feed* side has to
be canonical.

This is not hypothetical. 21 of the 12,166 PyPI records upstream carry
uppercase, `_` or `.` — `CalcBoxLite`, `M-AT-STAR-Tools`, `EZBEAMER`. Emitted
verbatim, `pip install calcboxlite` installs the malicious package and matches
nothing in the feed. Only the exact upstream spelling matched, which is the one
spelling a person is least likely to type.

Normalization can collide: two upstream records can fold to one key (it happens
twice today, `roblox-com` and `sentinelone`). Their clauses are merged with the
usual union, so `*` still absorbs.

**Every other ecosystem is left verbatim.** npm registry names are already
lowercase; crates.io, Go and Maven treat case and separators as significant, so
folding them would merge genuinely distinct packages.

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

### What the signature does not cover, and what makes up for it

Ed25519 is PureEdDSA: it hashes the message internally with SHA-512, so the
signature already covers every byte and there is nothing to pre-hash. The
`sha256` in the pointer is therefore **not** a tamper check — the signature is
verified first, over the same bytes. It catches truncation and cache
corruption, and binds the pointer to an artifact.

But that binding is only worth as much as the pointer, and **`pointer.json` is
not signed.** It is fetched on every tick, so a detached signature beside it
would double the cost of the one request that has to stay free. Instead the
facts that decide what a machine installs are carried inside the signed bytes:

* the full artifact states `# seq`;
* a delta states `# from` and `# to`.

A client cross-checks those against the pointer and refuses any mismatch. That
closes two attacks a bucket-level attacker would otherwise have, both of which
end in a machine running a stale index while every signature verifies:

| attack | what stops it |
|---|---|
| replay an old pointer + its genuine old artifact | the client refuses a `seq` lower than the one it holds |
| a fresh-looking pointer naming an old, validly-signed artifact | `# seq` inside the signed bytes disagrees with `pointer.seq` |
| apply a delta to the wrong base | `# from` disagrees with the local seq |

A stale index is a suppression attack: the packages added since are the ones a
warning would have been about.

Sequence numbers are therefore **monotonic per machine**. A client never moves
backwards, and an aggregator that needs to withdraw an artifact publishes a new
higher sequence rather than reverting to an old one.

## Client contract

Per tick, `moat-feeds`:

1. `GET /v1/pointer.json` with `If-None-Match`. On 304, stop — this is the
   common case and costs nothing.
2. If `pointer.seq < local seq`, refuse the pointer and stop: sequences never
   go backwards. If `pointer.seq == local seq`, stop.
3. If `pointer.deltas` contains the local seq, fetch that delta; else fetch the
   full artifact.
4. Verify the ed25519 signature, then the sha256, then that the signed bytes
   agree with the pointer — `# seq` for a full artifact, `# from`/`# to` for a
   delta.
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
| **`# seq` disagrees with the pointer** | discard, keep existing files, log at **error** |
| **pointer offers an older `seq`** | refuse the pointer, keep existing files |
| aggregator serving a very old `seq` | apply it; staleness is visible in `moatctl status` |

## When the aggregator publishes

Only when the folded index actually changed — decided by the diff against the
previous artifact, not by comparing artifact bytes. `generated` and `seq` both
live inside those bytes and move every run, so a byte comparison can never be
equal and would mint a new sequence on every quiet tick. That would change the
pointer every fifteen minutes, so no client would ever receive a 304 and the
delta window would roll over in half a day.

A tick where upstream moved but the fold is identical publishes nothing.

## Cadence

The timer runs every 15 minutes with jitter. Upstream itself only moves every
1–2 hours (the OSSF ingest jobs), so a shorter tick does not produce fresher
data — it reduces the worst-case lag between an ingest landing and the machine
seeing it, from an hour to a few minutes. Because the common tick is a 304 on a
200-byte object, the cost of that is negligible.

Jitter is not optional. Without `RandomizedDelaySec`, every machine fires on the
quarter hour and the aggregate looks like a thundering herd.

## A second wing: domains

Since 2026-09-11 the same aggregator publishes a second signed artifact, a
~48k-entry malicious-domain list built from ThreatFox, referenced from a
`domains` block in this same `pointer.json`. It has its own sequence and is
published independently: the two feeds move at completely different rates and
neither should pay the other's bandwidth. `moat-feeds` installs it as
`domains-feed.txt`, which is a fourth file and not a rewrite of the operator's
`domains.txt`. Format, gates and client contract: `docs/DOMAIN-FEED.md`.

That ThreatFox is usable at all revises the note below. It wanted an `Auth-Key`
and still does — for its JSON API. Its bulk exports are unauthenticated, and
one aggregator reading them serves the whole fleet.

## What was lost by dropping abuse.ch

`hashes.txt` and `urls.txt` are no longer fetched by anything (`domains.txt`
has a published companion again; see above). The files are still **read** if
present, so an operator can drop in their own indicators, and
`moat-x-new-exec-ioc` still matches against `hashes.txt`.

There is no keyless replacement for the sha256 feed: OSV malicious-package
records identify packages, not file hashes. This is a real reduction in what
moat detects, and it is the deliberate price of not requiring every user to
register for an API key to get any feed at all. `moatctl status` reports the
hash feed as operator-supplied so the distinction is visible rather than
implied.
