# moat feed aggregator

A Cloudflare Worker that turns two upstream malicious-package sources into the
signed, edge-cached artifacts `moat-feeds` consumes. The wire format, endpoint
paths, cache headers, clause grammar and ecosystem table are fixed by
[`../docs/PACKAGE-FEED.md`](../docs/PACKAGE-FEED.md); this is the producer side
of that contract and nothing here may drift from it.

    ossf/malicious-packages ──┐
                              ├─► Worker ──► R2 ──► caches.default ──► machines
    DataDog/…-dataset ────────┘   normalise    immutable artifacts
                                  + sign       + pointer.json

## What runs when

| cron | job | budget | what it does |
|---|---|---|---|
| `*/15 * * * *` | `runTick` | 30 s CPU | GitHub compare since the last known commit, fetch only the changed OSV files from `raw.githubusercontent.com`, conditional-GET the four Datadog manifests, refold, publish — then the domain wing off the 1.6 MB ThreatFox hostfile |
| `17 4 * * *` | `runFull` | 15 min CPU | stream the 44 MB / 479k-file tarball, rebuild from scratch, publish — then the domain wing, additionally re-reading the 23 MB ThreatFox CSV dump and the public suffix list |

Both crons end with the **domain wing** (`runDomains`), which publishes a
second, independently-sequenced artifact into the same `pointer.json`. It is
wrapped so that it can never fail a package run: the six scanners read
`packages.txt` before every install and that path is not allowed to break
because abuse.ch had a bad afternoon. `docs/DOMAIN-FEED.md` is the contract;
`/admin/domains` runs it alone.

A quiet quarter-hour for packages is the common case and is exactly when
ThreatFox has moved, so the domain step runs on those ticks too — including the
ones that return early having found nothing.

The 15-minute cron's interval is under an hour, which caps it at 30 s of CPU —
that is why it never touches the tarball. The daily cron's interval is over an
hour, which is what buys it 15 minutes. **Do not shorten the daily cron below
an hour**; it would silently drop to a 30 s budget and start failing.

Most ticks publish nothing. Upstream moves every 1–2 hours, and a tick that
finds no changed files (or finds changes that do not alter any entry) updates
its bookmark and leaves `seq` alone, so clients keep getting a 304 on the
pointer.

### The state the incremental path needs

`state/records.tsv.gz` holds one line per *(upstream record, affected package)*:

    <rid>\t<ecosystem>\t<name>\t<spec>

`rid` identifies the upstream record so a tick can delete exactly the lines a
changed or deleted file contributed. For OSSF it is a 64-bit hash of the
repo-relative path (which is what the compare API reports); for Datadog it is
`dd:<eco>`, since a manifest is always replaced wholesale.

This is what makes removals correct. A package key is usually contributed by
several records, so "this OSV file was deleted" does not mean "drop this
package" — you have to re-fold the remaining records to find out. The tick
streams the records file, drops the replaced ids, appends the fresh ones, and
folds the new index in the same pass. The daily rebuild regenerates the file
from scratch, so any drift self-heals within 24 hours.

`state/state.json` holds the sequence number, the source bookmarks, and the
last `DELTA_WINDOW` pairwise deltas. Neither state object is servable: `fetch()`
only answers `v1/pointer.json` and content-addressed `v1/` artifact names.

### Deltas

Each publish composes the rolling window of pairwise steps into one delta per
old sequence, so `pointer.deltas` maps *every* seq in the window directly to
the new one and a client never chains files. `+` carries the complete new spec
for a key, `-` carries just the key; applying is idempotent and
order-independent, which is what lets composition be "later op wins".

Objects the new pointer no longer references are pruned, with one sequence of
grace so a client mid-download of the previous round still finishes.

### The compare fallback

`files[]` in a GitHub compare response is capped at 300 entries and the compare
truncates past 250 commits. Either condition means the response may not list
every changed file, so the tick refuses to publish a partial update: it sets
`needs_rebuild` in the state and stands down until the daily rebuild has run.
It does not fetch any raw files first, and it does not touch the pointer.

In practice this triggers only if ticks have been failing for two days or more
(24 h of churn is ~149 files), which is exactly the case where you want the
authoritative rebuild rather than a patch.

## Setup

```sh
npm test                                   # no dependencies to install

npx wrangler r2 bucket create moat-feed
node scripts/keygen.mjs --out ./secrets    # writes feed-key (0600) + feed-key.pub
npx wrangler secret put FEED_SIGNING_KEY < ./secrets/feed-key
npx wrangler secret put GITHUB_TOKEN       # see below; strongly recommended
npx wrangler deploy
```

`secrets/feed-key.pub` is the file that ships in the package at
`/usr/share/moat/feed-key.pub`. Its format is one line:

    moat-feed-ed25519 <base64 of the 32-byte ed25519 public key>

Keep the private half out of the repo. Rotating it means shipping a new
`feed-key.pub` to every machine before the Worker starts signing with the new
key, so rotation is a package release, not a Worker deploy.

### GITHUB_TOKEN is close to required

The unauthenticated GitHub API limit is 60 requests/hour **per IP**, and a
Worker's egress IPs are shared with every other Cloudflare customer. A
fine-grained token with no scopes and no repository access is enough — it only
needs to identify the caller — and lifts the limit to 5000/hour. Without it,
expect ticks to fail with 403s at unpredictable times; the run logs say
`github rate limited … set GITHUB_TOKEN` when that happens.

Raw file fetches (`raw.githubusercontent.com`) and the codeload tarball do not
count against the API limit.

## `.dev.vars` will silently sign with the wrong key

`wrangler dev` reads `.dev.vars` **instead of** the deployed Worker secrets --
including `--remote`, where everything else about the run is real. On
2026-09-10 a leftover `.dev.vars` from local workerd testing held a throwaway
signing key, and a tick fired that way published a live artifact signed with it.

Nothing warned. The publish succeeded, the pointer advanced, R2 held a perfectly
well-formed artifact, and every client refused it with `SIGNATURE DID NOT VERIFY`
-- which is the system working, but the feed was broken until the next correctly
signed publish.

So: **delete `.dev.vars` before any `wrangler dev --remote` that can publish**,
and if a publish is ever refused by clients, check which key signed it before
looking anywhere else:

```sh
curl -s https://feed.runts.net/v1/pointer.json | jq -r .artifact | \
  xargs -I{} sh -c 'curl -s https://feed.runts.net{} -o /tmp/a.gz; curl -s https://feed.runts.net{}.sig -o /tmp/a.sig'
# then verify /tmp/a.gz against secrets/feed-key.pub
```

It is gitignored, so it will not follow a clone -- which is exactly why it
survives locally and surprises you.

## Seeding sequence 1

`seed/packages.txt.gz` is a pre-built `moat-packages v1` artifact (241,813
entries, 1,583,961 bytes) so the first publish does not have to wait for a
rebuild.

```sh
node scripts/seed.mjs --key ./secrets/feed-key --out build/seed
cd build/seed
for f in $(find . -type f | sed 's|^\./||'); do
  npx wrangler r2 object put "moat-feed/$f" --file "$f" --remote
done
```

That writes and signs `v1/packages-1-<sha12>.txt.gz`, `v1/pointer.json` and
`state/state.json`, laid out under `build/seed/` exactly as the R2 keys. The
script re-derives the sha256 and the entry count from the file itself and
refuses to seed anything that is not a valid v1 artifact.

Seeded that way, `state.needs_rebuild` is `true`: there is no records file and
no OSSF commit bookmark, so ticks stand down until the daily rebuild produces
both. If you have the corpus locally you can seed both at once and have ticks
work immediately:

```sh
node scripts/seed.mjs --key ./secrets/feed-key \
  --corpus /path/to/corpus \
  --commit "$(curl -s https://api.github.com/repos/ossf/malicious-packages/commits/main | jq -r .sha)"
```

where the corpus directory holds `ossf.tar.gz` and `m_npm.json`, `m_pypi.json`,
`m_ai-skills.json`, `m_ide_extensions.json`. The script refuses to proceed if
its rebuild disagrees with the seed artifact's entry count.

## Cost

| item | monthly |
|---|---|
| Workers Paid | $5.00 |
| R2 storage (~50 MB: a few artifacts, the delta window, the records file) | $0.00075, effectively free against the 10 GB tier |
| R2 Class A (writes): ~100 per changed tick × ~20/day | well inside the 1M free tier |
| R2 Class B (reads): served from `caches.default` after the first hit | inside the 1M free tier |
| egress | $0 — R2 has no egress charge, which is the whole reason for R2 here |

The Paid plan is required for two reasons, not one: cron CPU limits above the
free tier's, and R2 itself.

Client-side traffic is what keeps the read counts low: the common tick is a 304
on a ~600-byte `pointer.json`, and everything else is `immutable` and answered
by the edge.

## Verification status

Verified locally, in `npm test` (29 tests, all passing):

* **Normalisation is byte-identical to the reference normalizer on the real
  corpus** — 241,813 entries from 237,352 OSSF records and 50,438 Datadog
  records, 365 withdrawn by field (0 by path alone, so the field really is
  authoritative), 34 `fixed` ranges, 138 `last_affected`, 21 PyPI names
  normalised. That test is skipped unless `MOAT_CORPUS` points at a directory
  holding the tarball, the four manifests, and the reference `packages.txt`;
  the fixture tests around it always run.
* Streaming tar+gzip reader, including pax long paths (which the OSSF repo has)
  and GNU long names.
* Delta round trip: `apply(delta, old) == new`, byte-identical artifacts after
  applying; idempotent and order-independent; composed deltas equal applying
  the chain; the window keeps the last N sequences and drops older ones.
* The delta path canonicalises PyPI names identically to a full rebuild, and a
  tick's artifact is byte-identical to a rebuild over the same upstream files.
* The `>= 300` files and `> 250` commits fallbacks: no publish, no raw fetches,
  `needs_rebuild` set, and the next tick stands down until a rebuild clears it.
* Serving: the exact `Cache-Control` values from the contract, content types,
  ETag/`If-None-Match` 304s, 404 for unknown or state paths, 405 for non-GET.
* ed25519 signing and detached-signature verification, including rejection of a
  tampered artifact.
* Failure leaves the previous pointer untouched.

Measured at real-corpus scale with `node scripts/bench.mjs <corpus-dir>`:

| | CPU | peak JS heap | budget |
|---|---|---|---|
| full rebuild | 2.8 s wall / 5.7 s CPU-seconds across zlib threads | 66 MB | 15 min, 128 MB |
| tick, 149 changed files | 0.7 s | 62 MB | 30 s, 128 MB |

The full rebuild also completes with `--max-old-space-size=72`, so the headroom
is real rather than an artifact of node's default heap. Getting there is why
neither the records file nor the artifact text is ever materialised as a single
string: both stream through `CompressionStream` a batch at a time, and the
daily rebuild diffs against the previous artifact by merge join rather than
holding two 241k-entry maps.

**Not verified, because it needs a real deployment** (no Cloudflare credentials
were available):

* Anything about workerd specifically: that `crypto.subtle` there accepts
  `Ed25519` (the code falls back to the older `NODE-ED25519` name, but only one
  of those paths has been exercised, in node), and that workerd's memory
  accounting agrees with node's heap measurements above. The measured 66 MB
  against a 128 MB isolate is comfortable but not proven in place.
* `caches.default` behaviour, R2 binding semantics, cron dispatch, and the
  cron CPU limits. Tests use in-memory doubles for R2 and the cache, and stub
  every upstream fetch.
* Upstream response shapes are taken from the task's verified facts and from
  the GitHub API docs; no live call was made from this environment.

Run `npx wrangler dev --test-scheduled` and hit
`/__scheduled?cron=17+4+*+*+*` against a real bucket before trusting the first
production run.

## Layout

    src/index.js      the Worker: scheduled() for both crons, fetch() for serving
    src/normalize.js  ecosystem table, clause grammar, PEP 503, ordering, records
    src/build.js      full rebuild: tarball + manifests -> records + index
    src/tar.js        streaming tar reader (ustar, pax, GNU long names)
    src/delta.js      diff, serialise, parse, apply, compose
    src/gz.js         gzip/gunzip helpers over Compression/DecompressionStream
    src/sign.js       ed25519 via WebCrypto
    scripts/keygen.mjs         generate the signing keypair
    scripts/seed.mjs           build and sign the seq-1 objects locally
    scripts/normalize-local.mjs  run the normaliser over a local corpus
    scripts/bench.mjs          time and measure both cron paths at full scale
    seed/packages.txt.gz       the pre-built seq-1 artifact
