// omarchy-moat package-feed aggregator.
//
// Two crons:
//   */15 * * * *  runTick  — GitHub compare since the last commit, a handful of
//                            raw files, refold, publish. 30 s CPU budget.
//   17 4 * * *    runFull  — stream the 44 MB / 479k-file OSSF tarball and
//                            rebuild from scratch. 15 min CPU budget.
//
// fetch() serves the published objects out of R2 behind caches.default with the
// Cache-Control headers fixed by docs/PACKAGE-FEED.md.

import { buildFullRecords } from './build.js';
import {
  isOsvPath, osvContributions, datadogContributions, rid, ddRid, foldInto,
  collapse, newStats, sortedKeys, artifactLines, isoNow, DATADOG_MANIFESTS,
} from './normalize.js';
import {
  diffSorted, deltaLines, composeOps, opsToWire, opsFromWire, sortOps,
} from './delta.js';
import { gzipStrings, gunzipLines, sha256Hex } from './gz.js';
import { importSigner, signBytes } from './sign.js';
import {
  THREATFOX_HOSTFILE, THREATFOX_CSV_FULL, PSL_URL, DEFAULT_MIN_CONFIDENCE,
  newDomainStats, threatFoxMetadata, hostfileDomains, upstreamStamp, parsePsl,
  gateDomains, domainArtifactLines, metaTableLines, parseMetaTable, unzipCsvLines,
} from './domains.js';

const OSSF_REPO = 'ossf/malicious-packages';
const OSSF_TARBALL = `https://codeload.github.com/${OSSF_REPO}/tar.gz/refs/heads/main`;
const GH_API = 'https://api.github.com';
const DD_RAW = 'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/';

const POINTER_KEY = 'v1/pointer.json';
const STATE_KEY = 'state/state.json';
const RECORDS_KEY = 'state/records.tsv.gz';

// The domain wing keeps its own state and its own sequence. Sharing the package
// sequence would mean every ThreatFox change republishes the 1.6 MB package
// artifact and all 48 deltas, and every package change republishes the domain
// list -- two feeds moving at completely different rates, each paying the
// other's bandwidth.
const DOMAINS_STATE_KEY = 'state/domains.json';
const DOMAIN_META_KEY = 'state/domain-meta.tsv.gz';
const PSL_KEY = 'state/psl.txt.gz';

const IMMUTABLE = 'public, max-age=31536000, immutable';
const POINTER_CACHE = 'public, max-age=60';

// GitHub caps compare responses at 300 files and truncates past 250 commits.
// Either means we may be missing records, and the only correct answer is a full
// rebuild — never a silent partial update.
const COMPARE_FILE_CAP = 300;
const COMPARE_COMMIT_CAP = 250;

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; };

class RunLog {
  constructor(kind) { this.kind = kind; this.t0 = Date.now(); this.lines = []; }
  add(...a) { const m = a.map(String).join(' '); this.lines.push(m); console.log(`[${this.kind}] ${m}`); }
  done(extra = {}) {
    console.log(JSON.stringify({ run: this.kind, ms: Date.now() - this.t0, ...extra }));
  }
}

// --- upstream ---------------------------------------------------------------

function ghHeaders(env, accept = 'application/vnd.github+json') {
  const h = {
    'user-agent': env.USER_AGENT || 'omarchy-moat-aggregator/1',
    accept,
    'x-github-api-version': '2022-11-28',
  };
  if (env.GITHUB_TOKEN) h.authorization = `Bearer ${env.GITHUB_TOKEN}`;
  return h;
}

async function ghJson(env, url) {
  const res = await fetch(url, { headers: ghHeaders(env) });
  if (res.status === 403 || res.status === 429) {
    const reset = res.headers.get('x-ratelimit-reset');
    throw new Error(`github rate limited (${res.status}, reset ${reset}); set GITHUB_TOKEN`);
  }
  if (!res.ok) throw new Error(`github ${url} -> ${res.status}`);
  return res.json();
}

async function headCommit(env) {
  const j = await ghJson(env, `${GH_API}/repos/${OSSF_REPO}/commits/main`);
  return j.sha;
}

/** @returns {{changed: Array<{path:string,rawUrl:string}>, removed: string[], head: string}|{rebuild: string}} */
async function compareSince(env, base) {
  const j = await ghJson(env, `${GH_API}/repos/${OSSF_REPO}/compare/${base}...main`);
  const files = j.files || [];
  if ((j.total_commits || 0) > COMPARE_COMMIT_CAP) {
    return { rebuild: `compare truncated: ${j.total_commits} commits > ${COMPARE_COMMIT_CAP}` };
  }
  if (files.length >= COMPARE_FILE_CAP) {
    return { rebuild: `compare file list at the ${COMPARE_FILE_CAP}-file cap (${files.length})` };
  }
  const head = (j.commits && j.commits.length ? j.commits[j.commits.length - 1].sha : null)
    || (j.merge_base_commit && j.merge_base_commit.sha) || base;
  const changed = [];
  const removed = [];
  for (const f of files) {
    const path = f.filename;
    if (f.previous_filename && isOsvPath(f.previous_filename)) removed.push(f.previous_filename);
    if (!isOsvPath(path)) continue;
    if (f.status === 'removed') removed.push(path);
    else changed.push({ path, rawUrl: f.raw_url || `https://raw.githubusercontent.com/${OSSF_REPO}/${head}/${path}` });
  }
  return { changed, removed, head };
}

async function fetchAll(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = new Array(Math.min(limit, items.length)).fill(0).map(async () => {
    for (;;) {
      const k = i++;
      if (k >= items.length) return;
      out[k] = await fn(items[k]);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Conditional GET of the four Datadog manifests. */
async function fetchDatadog(env, etags = {}) {
  const out = [];
  for (const { eco, path } of DATADOG_MANIFESTS) {
    const headers = { 'user-agent': env.USER_AGENT || 'omarchy-moat-aggregator/1' };
    if (etags[eco]) headers['if-none-match'] = etags[eco];
    const res = await fetch(DD_RAW + path, { headers, cf: { cacheTtl: 0 } });
    if (res.status === 304) { out.push({ eco, changed: false, etag: etags[eco] }); continue; }
    if (!res.ok) throw new Error(`datadog ${path} -> ${res.status}`);
    out.push({ eco, changed: true, etag: res.headers.get('etag'), manifest: await res.json() });
  }
  return out;
}

// --- state ------------------------------------------------------------------

const emptyState = () => ({
  version: 1, seq: 0, generated: null, entries: 0, artifact: null, sha256: null,
  bytes: 0, sources: { ossf: {}, datadog: {} }, dd_etags: {}, steps: [],
  needs_rebuild: true, last: {},
});

async function loadState(env) {
  const obj = await env.FEED.get(STATE_KEY);
  if (!obj) return emptyState();
  try { return { ...emptyState(), ...(await obj.json()) }; }
  catch { return emptyState(); }
}

const saveState = (env, state) =>
  env.FEED.put(STATE_KEY, JSON.stringify(state), {
    httpMetadata: { contentType: 'application/json', cacheControl: 'no-store' },
  });

// --- publishing -------------------------------------------------------------

async function putSigned(env, signer, key, bytes, contentType) {
  await env.FEED.put(key, bytes, {
    httpMetadata: { contentType, cacheControl: IMMUTABLE },
  });
  const sig = await signBytes(signer, bytes);
  await env.FEED.put(key + '.sig', sig, {
    httpMetadata: { contentType: 'application/octet-stream', cacheControl: IMMUTABLE },
  });
}

/**
 * Publish a new sequence: full artifact, the delta window, pointer, state.
 * No-ops (returns null) when the artifact is byte-identical to the current one.
 */
async function publish(env, state, index, sources, log, statsExtra = {}) {
  const signer = await importSigner(env.FEED_SIGNING_KEY);
  const window = num(env.DELTA_WINDOW, 48);
  const keep = num(env.KEEP_ARTIFACTS, 4);
  const generated = isoNow();

  const keys = sortedKeys(index);

  // Whether anything actually changed is decided by the DIFF, not by comparing
  // artifact bytes. `generated` (and now `seq`) are inside those bytes and move
  // every run, so a byte comparison was never once true: the no-op branch was
  // dead, and a quiet tick still published a new sequence and a fresh 1.6 MB
  // artifact. That is the property the whole cache story rests on -- if the
  // pointer changes every 15 minutes, no client ever gets a 304.
  //
  // The merge join against the previous artifact is already being done for the
  // delta, and an empty op list is an exact answer, so this costs nothing.
  let stepOps = null;
  if (state.artifact) {
    const prev = await env.FEED.get(state.artifact.replace(/^\//, ''));
    if (prev) stepOps = await diffSorted(gunzipLines(prev.body), keys, index);
    else log.add('previous artifact missing from R2; publishing without a delta step');
  }

  if (stepOps && stepOps.length === 0) {
    log.add('index unchanged, keeping seq', state.seq);
    state.sources = sources;
    state.last = { kind: log.kind, at: generated, ...statsExtra };
    await saveState(env, state);
    return null;
  }

  const seq = state.seq + 1;
  const artGz = await gzipStrings(artifactLines(index, generated, keys, seq));
  const sha = await sha256Hex(artGz);
  const sha12 = sha.slice(0, 12);
  const artName = `packages-${seq}-${sha12}.txt.gz`;
  await putSigned(env, signer, 'v1/' + artName, artGz, 'application/gzip');
  log.add('published', artName, index.size, 'entries', artGz.length, 'bytes');

  // rolling window of pairwise steps, composed into one delta per old seq
  const steps = stepOps
    ? [...(state.steps || []), { from: state.seq, to: seq, ops: opsToWire(stepOps) }].slice(-window)
    : [];
  const deltas = {};
  let acc = [];
  for (let i = steps.length - 1; i >= 0; i--) {
    acc = composeOps(opsFromWire(steps[i].ops), acc);
    const bytes = await gzipStrings(deltaLines(steps[i].from, seq, acc));
    const dsha = (await sha256Hex(bytes)).slice(0, 12);
    const name = `delta-${steps[i].from}-${seq}-${dsha}.txt.gz`;
    await putSigned(env, signer, 'v1/' + name, bytes, 'application/gzip');
    deltas[String(steps[i].from)] = '/v1/' + name;
  }
  log.add('published', Object.keys(deltas).length, 'deltas');

  const pointer = {
    version: 1,
    seq,
    generated,
    entries: index.size,
    artifact: '/v1/' + artName,
    sha256: sha,
    bytes: artGz.length,
    deltas,
    sources,
  };
  await writePointer(env, pointer);

  Object.assign(state, {
    seq, generated, entries: index.size, artifact: '/v1/' + artName,
    sha256: sha, bytes: artGz.length, sources, steps, needs_rebuild: false,
    last: { kind: log.kind, at: generated, ...statsExtra },
  });
  await saveState(env, state);
  await prune(env, seq, keep, log);
  return pointer;
}

/**
 * Write pointer.json, carrying the other wing's half across untouched.
 *
 * The packages feed and the domains feed publish independently and each owns
 * part of this one document. Whichever writes last must not drop what the other
 * just put there, and neither can hold the whole thing in its own state without
 * the two copies drifting. So the rule is: read what is live, replace only your
 * own keys, write it back.
 *
 * @param {object|null} packages top-level package fields, or null to keep them
 * @param {object|null|undefined} domains the `domains` block, or undefined to keep it
 */
async function writePointer(env, packages, domains) {
  let current = {};
  const obj = await env.FEED.get(POINTER_KEY);
  if (obj) { try { current = await obj.json(); } catch { current = {}; } }

  const next = packages ? { ...packages } : { ...current };
  if (domains !== undefined) {
    if (domains) next.domains = domains;
    else delete next.domains;
  } else if (current.domains) {
    next.domains = current.domains;
  }
  next.version = 1;

  await env.FEED.put(POINTER_KEY, JSON.stringify(next, null, 2), {
    httpMetadata: { contentType: 'application/json', cacheControl: POINTER_CACHE },
  });
  return next;
}

const emptyDomainsState = () => ({
  version: 1, seq: 0, generated: null, entries: 0, artifact: null, sha256: null,
  bytes: 0, upstream: null, meta_refreshed: null, psl_refreshed: null,
  stats: {}, last_error: null,
});

async function loadDomainsState(env) {
  const obj = await env.FEED.get(DOMAINS_STATE_KEY);
  if (!obj) return emptyDomainsState();
  try { return { ...emptyDomainsState(), ...(await obj.json()) }; }
  catch { return emptyDomainsState(); }
}

const saveDomainsState = (env, s) =>
  env.FEED.put(DOMAINS_STATE_KEY, JSON.stringify(s, null, 2), {
    httpMetadata: { contentType: 'application/json', cacheControl: 'no-store' },
  });

/** Drop artifacts and deltas the pointer no longer references. One sequence of
 *  grace, so a client mid-download of the previous round still finishes. */
async function prune(env, seq, keep, log) {
  let cursor;
  const doomed = [];
  do {
    const listed = await env.FEED.list({ prefix: 'v1/', cursor, limit: 1000 });
    for (const o of listed.objects) {
      const base = o.key.slice(3).replace(/\.sig$/, '');
      let m = /^packages-(\d+)-/.exec(base);
      if (m && Number(m[1]) <= seq - keep) { doomed.push(o.key); continue; }
      m = /^delta-\d+-(\d+)-/.exec(base);
      if (m && Number(m[1]) < seq - 1) doomed.push(o.key);
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  for (let i = 0; i < doomed.length; i += 100) await env.FEED.delete(doomed.slice(i, i + 100));
  if (doomed.length) log.add('pruned', doomed.length, 'objects');
}

// --- the domain wing --------------------------------------------------------

const UA = (env) => env.USER_AGENT || 'omarchy-moat-aggregator/1';

async function fetchBytes(env, url, cap) {
  const res = await fetch(url, { headers: { 'user-agent': UA(env) } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (cap && buf.length > cap) throw new Error(`${url} returned ${buf.length} bytes, cap is ${cap}`);
  return buf;
}

const fetchText = async (env, url, cap) =>
  new TextDecoder().decode(await fetchBytes(env, url, cap));

/**
 * The public suffix list, refreshed daily and cached in R2.
 *
 * Cached rather than fetched every tick because it is 334 KB that changes a few
 * times a month, and because a tick that cannot reach publicsuffix.org must
 * still be able to publish. Missing entirely is the one case worth refusing on:
 * without the gate a single bad upstream row could widen the feed to an entire
 * public suffix, so `gateDomains` is never run with a null list.
 */
async function loadPsl(env, refresh, dstate, log) {
  // Fetch when asked to, and ALSO when there is nothing cached to fall back
  // on. Without that second clause the wing could never start: a tick does not
  // refresh, `gateDomains` is never run without the gate, so every tick threw
  // and the first working domain list would have had to wait for 04:17. A
  // feature that is inert until tomorrow looks exactly like a feature that
  // works, right up until somebody checks.
  const cachedPsl = await env.FEED.get(PSL_KEY);
  if (refresh || !cachedPsl) {
    try {
      const text = await fetchText(env, PSL_URL, 8 << 20);
      const psl = parsePsl(text);
      // An error page, a captive portal or a truncated body all parse to
      // something; none of them parse to a thousand rules. The real list has
      // over twelve thousand, so this only ever catches a body that is not the
      // list at all.
      if (psl.exact.size < 100) throw new Error(`only ${psl.exact.size} rules; refusing it`);
      await env.FEED.put(PSL_KEY, await gzipStrings([text]), {
        httpMetadata: { contentType: 'application/gzip', cacheControl: 'no-store' },
      });
      dstate.psl_refreshed = isoNow();
      log.add('psl refreshed:', psl.exact.size, 'rules,', psl.wild.size, 'wildcards');
      return psl;
    } catch (e) {
      log.add('psl refresh failed:', String(e), '- falling back to the cached copy');
    }
  }
  if (!cachedPsl) return null;
  let text = '';
  for await (const line of gunzipLines(cachedPsl.body)) text += line + '\n';
  return parsePsl(text);
}

/** The metadata table: rebuilt from the 23 MB CSV on the daily run, cached otherwise. */
async function loadDomainMeta(env, refresh, dstate, stats, log) {
  const cached = await env.FEED.get(DOMAIN_META_KEY);
  // Same bootstrap clause, for a different cost. Without it the first published
  // list is forty-eight thousand domains with no malware family against any of
  // them, replaced wholesale the next morning -- one wasted sequence and one
  // wasted download for every machine, to publish something we could have got
  // right the first time.
  if (refresh || !cached) {
    try {
      const zip = await fetchBytes(env, THREATFOX_CSV_FULL, 64 << 20);
      const meta = await threatFoxMetadata(unzipCsvLines(zip), stats);
      // Relative, not absolute. The question worth asking is "did the dump
      // collapse since yesterday", and the answer lives in the table already on
      // disk -- an absolute floor would have to be guessed, and would be wrong
      // the first time abuse.ch's corpus legitimately changed size. With
      // nothing cached there is nothing to compare against, and the publish
      // floor downstream still guards the output.
      if (cached) {
        const had = Number(cached.httpMetadata && cached.httpMetadata.domains) || 0;
        if (had > 0 && meta.size < Math.floor(had / 2)) {
          throw new Error(`dump holds ${meta.size} domains against ${had} cached; refusing it`);
        }
      }
      await env.FEED.put(DOMAIN_META_KEY, await gzipStrings(metaTableLines(meta)), {
        httpMetadata: {
          contentType: 'application/gzip', cacheControl: 'no-store',
          // Carried so the next run can compare sizes without inflating it.
          domains: String(meta.size),
        },
      });
      dstate.meta_refreshed = isoNow();
      log.add('domain metadata:', stats.csv_rows, 'rows ->', meta.size, 'domains');
      return meta;
    } catch (e) {
      log.add('domain metadata refresh failed:', String(e), '- falling back to the cached table');
    }
  }
  if (!cached) return new Map();
  return parseMetaTable(gunzipLines(cached.body));
}

/**
 * A content digest that ignores `generated` and `seq`.
 *
 * Both of those move on every run and both are inside the artifact, so hashing
 * the artifact bytes would say "changed" every fifteen minutes forever. The
 * package wing answers the same question with a merge join against the previous
 * artifact; this list is small enough that a digest of its own contents is
 * simpler and exact.
 */
async function domainContentSha(accepted) {
  const parts = [];
  for (const d of [...accepted.keys()].sort()) {
    const m = accepted.get(d);
    parts.push(`${d}\t${m.family}\t${m.confidence}\t${m.compromised ? 'c' : '-'}\n`);
  }
  return sha256Hex(new TextEncoder().encode(parts.join('')));
}

/**
 * Build and publish the domain list.
 *
 * `full` reads the 23 MB CSV for metadata and refreshes the public suffix list;
 * a tick reads only the 1.6 MB hostfile and reuses both from R2.
 */
export async function runDomains(env, log, { full = false } = {}) {
  const dstate = await loadDomainsState(env);
  const stats = newDomainStats();
  const minConfidence = num(env.DOMAIN_MIN_CONFIDENCE, DEFAULT_MIN_CONFIDENCE);

  const psl = await loadPsl(env, full, dstate, log);
  if (!psl) {
    throw new Error('no public suffix list available; refusing to build a domain feed without the gate');
  }
  const meta = await loadDomainMeta(env, full, dstate, stats, log);

  const hostText = await fetchText(env, THREATFOX_HOSTFILE, 32 << 20);
  const corpus = hostfileDomains(hostText, stats);
  const upstream = upstreamStamp(hostText);
  const accepted = gateDomains(corpus, meta, psl, minConfidence, stats);

  // A feed that collapses is worse than a feed that is stale: every machine
  // would quietly lose coverage and nothing would look broken. A truncated
  // response, a half-written upstream file or an outage behind a 200 all land
  // here, and the right answer to all three is to keep what is already
  // published. A deliberate shrink still gets through -- it just takes two runs.
  const floor = Math.floor(dstate.entries / 2);
  if (dstate.entries > 0 && accepted.size < floor) {
    const why = `upstream returned ${accepted.size} domains against ${dstate.entries} published; `
      + `below the ${floor} floor, keeping the existing list`;
    dstate.last_error = why;
    await saveDomainsState(env, dstate);
    log.add('domains REFUSED:', why);
    return null;
  }

  const contentSha = await domainContentSha(accepted);
  if (contentSha === dstate.content_sha && dstate.artifact) {
    dstate.upstream = upstream;
    dstate.last_error = null;
    dstate.stats = stats;
    await saveDomainsState(env, dstate);
    log.add('domains unchanged at seq', dstate.seq, `(${accepted.size} entries)`);
    return null;
  }

  const signer = await importSigner(env.FEED_SIGNING_KEY);
  const seq = dstate.seq + 1;
  const generated = isoNow();
  const gz = await gzipStrings(domainArtifactLines(accepted, generated, seq, { upstream }));
  const sha = await sha256Hex(gz);
  const name = `domains-${seq}-${sha.slice(0, 12)}.txt.gz`;
  await putSigned(env, signer, 'v1/' + name, gz, 'application/gzip');

  Object.assign(dstate, {
    seq, generated, entries: accepted.size, artifact: '/v1/' + name,
    sha256: sha, bytes: gz.length, upstream, content_sha: contentSha,
    stats, last_error: null,
  });
  await saveDomainsState(env, dstate);
  await writePointer(env, null, {
    seq, generated, entries: accepted.size, artifact: '/v1/' + name,
    sha256: sha, bytes: gz.length,
    source: { name: 'threatfox', upstream, min_confidence: minConfidence },
  });
  await pruneDomains(env, seq, num(env.KEEP_ARTIFACTS, 4), log);

  log.add('published', name, accepted.size, 'entries,', gz.length, 'bytes;',
    'dropped', stats.dropped_shared_suffix, 'shared-suffix,',
    stats.dropped_never, 'never-list,', stats.dropped_confidence, 'low-confidence;',
    stats.no_metadata, 'without metadata,', stats.compromised, 'compromised sites');
  return { seq, entries: accepted.size, stats };
}

async function pruneDomains(env, seq, keep, log) {
  let cursor;
  const doomed = [];
  do {
    const listed = await env.FEED.list({ prefix: 'v1/domains-', cursor, limit: 1000 });
    for (const o of listed.objects) {
      const m = /^v1\/domains-(\d+)-/.exec(o.key);
      if (m && Number(m[1]) <= seq - keep) doomed.push(o.key);
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  for (let i = 0; i < doomed.length; i += 100) await env.FEED.delete(doomed.slice(i, i + 100));
  if (doomed.length) log.add('pruned', doomed.length, 'domain objects');
}

/**
 * Run the domain wing without letting it take the package wing down with it.
 *
 * The packages feed is what the six scanners read before an install, and it has
 * worked for a year. abuse.ch going down, changing a column or serving a broken
 * zip must not stop a package tick from publishing.
 */
async function runDomainsSafely(env, log, opts) {
  try {
    return await runDomains(env, log, opts);
  } catch (err) {
    log.add('domains FAILED:', err && err.stack ? err.stack : err);
    try {
      const d = await loadDomainsState(env);
      d.last_error = String(err);
      await saveDomainsState(env, d);
    } catch { /* the error line in the log is the record that matters */ }
    return null;
  }
}

// --- the daily full rebuild -------------------------------------------------

export async function runFull(env, log = new RunLog('full')) {
  const state = await loadState(env);
  // Read the head sha *before* the tarball: if the tarball is newer, the next
  // compare re-delivers changes we already have, and both delta ops are
  // idempotent. The other order would lose records.
  const head = await headCommit(env);
  const dd = await fetchDatadog(env, {}); // unconditional: we need every manifest
  const res = await fetch(OSSF_TARBALL, { headers: ghHeaders(env, 'application/vnd.github+json') });
  if (!res.ok || !res.body) throw new Error(`tarball -> ${res.status}`);

  const ctx = {};
  const recordsGz = await gzipStrings(
    buildFullRecords(res.body, dd.map(({ eco, manifest }) => ({ eco, manifest })), ctx),
  );
  await env.FEED.put(RECORDS_KEY, recordsGz, {
    httpMetadata: { contentType: 'application/gzip', cacheControl: 'no-store' },
  });
  log.add('rebuilt', ctx.records, 'records ->', ctx.index.size, 'entries;',
    'dropped', ctx.stats.skipped_unknown_ecosystem, 'unknown-ecosystem,',
    ctx.stats.ossf_withdrawn_by_field, 'withdrawn');

  state.needs_rebuild = false; // a completed rebuild is what the flag waits for
  const now = isoNow();
  const etags = {};
  for (const d of dd) etags[d.eco] = d.etag;
  state.dd_etags = etags;
  const sources = {
    ossf: { commit: head, fetched: now },
    datadog: { etag: etags.npm || null, fetched: now },
  };
  const pointer = await publish(env, state, ctx.index, sources, log, { stats: ctx.stats });
  // Last, and never fatal: the domain wing reads a 23 MB CSV here, which is
  // affordable only in this job's 15-minute CPU budget.
  const domains = await runDomainsSafely(env, log, { full: true });
  log.done({
    seq: pointer ? pointer.seq : state.seq, entries: ctx.index.size, stats: ctx.stats,
    domains: domains ? domains.entries : null,
  });
  return pointer;
}

// --- the 15-minute incremental tick ----------------------------------------

export async function runTick(env, log = new RunLog('tick')) {
  const state = await loadState(env);
  if (state.needs_rebuild || !state.sources.ossf || !state.sources.ossf.commit) {
    log.add('needs_rebuild is set; waiting for the daily rebuild');
    const domains = await runDomainsSafely(env, log, { full: false });
    log.done({ skipped: 'needs_rebuild', domains: domains ? domains.entries : null });
    return null;
  }
  const recObj = await env.FEED.get(RECORDS_KEY);
  if (!recObj) {
    state.needs_rebuild = true;
    await saveState(env, state);
    log.add('records state missing; flagged for rebuild');
    const domains = await runDomainsSafely(env, log, { full: false });
    log.done({ skipped: 'no records', domains: domains ? domains.entries : null });
    return null;
  }

  const cmp = await compareSince(env, state.sources.ossf.commit);
  if (cmp.rebuild) {
    state.needs_rebuild = true;
    await saveState(env, state);
    log.add('FALLBACK to full rebuild:', cmp.rebuild);
    const domains = await runDomainsSafely(env, log, { full: false });
    log.done({ skipped: 'fallback', reason: cmp.rebuild, domains: domains ? domains.entries : null });
    return null;
  }
  const dd = await fetchDatadog(env, state.dd_etags || {});
  const ddChanged = dd.filter((d) => d.changed);

  if (!cmp.changed.length && !cmp.removed.length && !ddChanged.length) {
    state.sources.ossf.commit = cmp.head;
    state.sources.ossf.fetched = isoNow();
    await saveState(env, state);
    // A quiet quarter-hour for packages is the COMMON case, and it is exactly
    // when ThreatFox is most likely to have moved. Returning here without
    // touching the domain wing would have pinned it to the daily run.
    const domains = await runDomainsSafely(env, log, { full: false });
    log.done({ seq: state.seq, changed: 0, domains: domains ? domains.entries : null });
    return null;
  }
  log.add(cmp.changed.length, 'changed,', cmp.removed.length, 'removed OSV files;',
    ddChanged.length, 'datadog manifests changed');

  // ids whose old record lines are replaced wholesale
  const changedIds = new Set();
  for (const f of cmp.changed) changedIds.add(rid(f.path));
  for (const p of cmp.removed) changedIds.add(rid(p));
  for (const d of ddChanged) changedIds.add(ddRid(d.eco));

  const stats = newStats();
  const fresh = [];
  const bodies = await fetchAll(cmp.changed, 8, async (f) => {
    const res = await fetch(f.rawUrl, { headers: ghHeaders(env, 'application/vnd.github.raw') });
    if (!res.ok) throw new Error(`raw ${f.path} -> ${res.status}`);
    return res.text();
  });
  cmp.changed.forEach((f, i) => {
    let doc;
    try { doc = JSON.parse(bodies[i]); } catch { stats.ossf_unparsable++; return; }
    const id = rid(f.path);
    for (const c of osvContributions(doc, f.path, stats)) {
      fresh.push(`${id}\t${c.eco}\t${c.name}\t${collapse(c.clauses)}\n`);
    }
  });
  for (const d of ddChanged) {
    const id = ddRid(d.eco);
    for (const c of datadogContributions(d.eco, d.manifest, stats)) {
      fresh.push(`${id}\t${c.eco}\t${c.name}\t${collapse(c.clauses)}\n`);
    }
  }

  // One streaming pass: drop the replaced records, keep the rest, append the
  // fresh ones, and fold the new index as the lines go past.
  const index = new Map();
  let kept = 0;
  async function* rewrite() {
    for await (const line of gunzipLines(recObj.body)) {
      if (!line) continue;
      const t1 = line.indexOf('\t');
      if (t1 < 0 || changedIds.has(line.slice(0, t1))) continue;
      const t3 = line.lastIndexOf('\t');
      foldInto(index, line.slice(t1 + 1, t3), line.slice(t3 + 1));
      kept++;
      yield line + '\n';
    }
    for (const line of fresh) {
      const t1 = line.indexOf('\t');
      const t3 = line.lastIndexOf('\t');
      foldInto(index, line.slice(t1 + 1, t3), line.slice(t3 + 1, line.length - 1));
      yield line;
    }
  }
  const recordsGz = await gzipStrings(rewrite());
  await env.FEED.put(RECORDS_KEY, recordsGz, {
    httpMetadata: { contentType: 'application/gzip', cacheControl: 'no-store' },
  });
  log.add('records', kept, 'kept +', fresh.length, 'fresh ->', index.size, 'entries');

  const now = isoNow();
  const etags = { ...(state.dd_etags || {}) };
  for (const d of dd) if (d.etag) etags[d.eco] = d.etag;
  state.dd_etags = etags;
  const sources = {
    ossf: { commit: cmp.head, fetched: now },
    datadog: { etag: etags.npm || null, fetched: state.sources.datadog?.fetched || now },
  };
  if (ddChanged.length) sources.datadog.fetched = now;

  const pointer = await publish(env, state, index, sources, log, { stats });
  const domains = await runDomainsSafely(env, log, { full: false });
  log.done({
    seq: pointer ? pointer.seq : state.seq, entries: index.size, stats,
    domains: domains ? domains.entries : null,
  });
  return pointer;
}

// --- serving ----------------------------------------------------------------

const ARTIFACT_RE = /^v1\/(packages-\d+-[0-9a-f]{12}|domains-\d+-[0-9a-f]{12}|delta-\d+-\d+-[0-9a-f]{12})\.txt\.gz(\.sig)?$/;

function contentTypeFor(key) {
  if (key.endsWith('.sig')) return 'application/octet-stream';
  if (key.endsWith('.json')) return 'application/json';
  return 'application/gzip';
}

/// Length-independent comparison. A `===` on a secret leaks its prefix through
/// timing, which is a silly way to lose a key that guards a write endpoint.
function timingSafeEqual(a, b) {
  const ab = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

export async function serve(request, env, ctx) {
  const url = new URL(request.url);

  // An authenticated way to run what the cron is supposed to run.
  //
  // Cloudflare accepted both cron triggers, the dashboard lists them with a
  // next-run time, and on 2026-09-10 none of them ever fired: no tail event, no
  // R2 heartbeat written before any work, and state.json frozen for 90 minutes
  // across four boundaries with no deploy to blame. Whatever the cause, a feed
  // that only updates when somebody runs a command by hand is not a feed, so
  // the schedule can come from somewhere else.
  //
  // Guarded by a secret, because it does real work and writes to R2. Without
  // TRIGGER_TOKEN set it is closed entirely rather than open -- a missing
  // secret must not mean a public button.
  if (url.pathname === '/admin/tick' || url.pathname === '/admin/rebuild'
      || url.pathname === '/admin/domains') {
    if (request.method !== 'POST') {
      return new Response('method not allowed\n', { status: 405, headers: { allow: 'POST' } });
    }
    const want = env.TRIGGER_TOKEN;
    const got = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    if (!want || !got || !timingSafeEqual(got, want)) {
      return new Response('unauthorized\n', { status: 401 });
    }
    // /admin/domains runs the domain wing alone. It is the lever for the case
    // the package crons cannot serve: refreshing the list after changing
    // DOMAIN_MIN_CONFIDENCE or the never-list, without waiting for 04:17 and
    // without dragging the 44 MB package rebuild along with it. `?full=1` reads
    // the CSV dump for metadata rather than reusing the cached table.
    if (url.pathname === '/admin/domains') {
      const log = new RunLog('domains');
      const full = url.searchParams.get('full') === '1';
      try {
        const out = await runDomains(env, log, { full });
        log.done(out || { unchanged: true });
        return json({ ok: true, run: log.kind, result: out, lines: log.lines }, 'no-store');
      } catch (err) {
        log.add('FAILED:', err && err.stack ? err.stack : err);
        log.done({ error: String(err) });
        return json({ ok: false, run: log.kind, error: String(err), lines: log.lines }, 'no-store', 500);
      }
    }
    const full = url.pathname.endsWith('rebuild');
    const log = new RunLog(full ? 'full' : 'tick');
    try {
      await (full ? runFull : runTick)(env, log);
      return json({ ok: true, run: log.kind, lines: log.lines }, 'no-store');
    } catch (err) {
      log.add('FAILED:', err && err.stack ? err.stack : err);
      log.done({ error: String(err) });
      return json({ ok: false, run: log.kind, error: String(err), lines: log.lines }, 'no-store', 500);
    }
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('method not allowed\n', { status: 405, headers: { allow: 'GET, HEAD' } });
  }
  const key = url.pathname.replace(/^\//, '');

  if (key === 'healthz') {
    const state = await loadState(env);
    const d = await loadDomainsState(env);
    return json({
      seq: state.seq, entries: state.entries, generated: state.generated,
      needs_rebuild: !!state.needs_rebuild, sources: state.sources,
      domains: {
        seq: d.seq, entries: d.entries, generated: d.generated, upstream: d.upstream,
        meta_refreshed: d.meta_refreshed, psl_refreshed: d.psl_refreshed,
        last_error: d.last_error, stats: d.stats,
      },
    }, 'no-store');
  }

  const isPointer = key === POINTER_KEY;
  if (!isPointer && !ARTIFACT_RE.test(key)) return new Response('not found\n', { status: 404 });

  const inm = request.headers.get('if-none-match');
  const matches = (etag) => !!etag && !!inm
    && inm.split(',').some((t) => t.trim() === etag || t.trim() === 'W/' + etag);

  // only GET responses are cacheable; a HEAD goes straight to R2
  const cache = request.method === 'GET' ? caches.default : null;
  const cached = cache ? await cache.match(request) : undefined;
  if (cached) {
    // the edge normally answers conditionals itself; do it here too so a
    // direct-to-origin request still gets the cheap 304 the client expects
    if (matches(cached.headers.get('etag'))) {
      return new Response(null, { status: 304, headers: cached.headers });
    }
    return cached;
  }

  const obj = await env.FEED.get(key);
  if (!obj) return new Response('not found\n', { status: 404 });

  const headers = new Headers({
    'content-type': contentTypeFor(key),
    'cache-control': isPointer ? POINTER_CACHE : IMMUTABLE,
    etag: obj.httpEtag,
    'x-content-type-options': 'nosniff',
  });
  if (matches(obj.httpEtag)) return new Response(null, { status: 304, headers });
  headers.set('content-length', String(obj.size));
  if (request.method === 'HEAD') return new Response(null, { headers });
  const res = new Response(obj.body, { headers });
  ctx.waitUntil(cache.put(request, res.clone()));
  return res;
}

function json(body, cacheControl, status) {
  return new Response(JSON.stringify(body, null, 2) + '\n', {
    status: status || 200,
    headers: { 'content-type': 'application/json', 'cache-control': cacheControl },
  });
}

export default {
  fetch: serve,
  async scheduled(event, env, ctx) {
    // FIRST, before anything that can fail or be cut short.
    //
    // On 2026-09-10 no scheduled run was observed for over an hour after both
    // triggers were registered, and `wrangler tail` showed no invocation at
    // all. That leaves two very different diagnoses -- Cloudflare is not
    // dispatching the cron, or it dispatches and the run dies before it logs --
    // and every log line in this file happens after work that could be killed.
    // This one cannot be, so its presence or absence is the answer.
    console.log(`[cron] fired ${event.cron} at ${new Date().toISOString()}`);
    // And a heartbeat that does not depend on `wrangler tail` capturing
    // scheduled invocations -- an assumption that has never been tested here,
    // and which is currently the difference between "Cloudflare is not
    // dispatching" and "we cannot see that it is".
    try {
      await env.FEED.put('state/last-cron.txt',
        `${event.cron} ${new Date().toISOString()}\n`);
    } catch (e) {
      console.log('[cron] heartbeat write failed:', String(e));
    }
    const fullCron = env.FULL_CRON || '17 4 * * *';
    const run = event.cron === fullCron ? runFull : runTick;
    const log = new RunLog(event.cron === fullCron ? 'full' : 'tick');
    try {
      await run(env, log);
    } catch (err) {
      // A failed run must leave the previous pointer and artifacts untouched:
      // every write happens after the new artifact is fully built.
      log.add('FAILED:', err && err.stack ? err.stack : err);
      log.done({ error: String(err) });
      throw err;
    }
  },
};
