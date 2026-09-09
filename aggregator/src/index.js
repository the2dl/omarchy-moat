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

const OSSF_REPO = 'ossf/malicious-packages';
const OSSF_TARBALL = `https://codeload.github.com/${OSSF_REPO}/tar.gz/refs/heads/main`;
const GH_API = 'https://api.github.com';
const DD_RAW = 'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/';

const POINTER_KEY = 'v1/pointer.json';
const STATE_KEY = 'state/state.json';
const RECORDS_KEY = 'state/records.tsv.gz';

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
  await env.FEED.put(POINTER_KEY, JSON.stringify(pointer, null, 2), {
    httpMetadata: { contentType: 'application/json', cacheControl: POINTER_CACHE },
  });

  Object.assign(state, {
    seq, generated, entries: index.size, artifact: '/v1/' + artName,
    sha256: sha, bytes: artGz.length, sources, steps, needs_rebuild: false,
    last: { kind: log.kind, at: generated, ...statsExtra },
  });
  await saveState(env, state);
  await prune(env, seq, keep, log);
  return pointer;
}

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
  log.done({ seq: pointer ? pointer.seq : state.seq, entries: ctx.index.size, stats: ctx.stats });
  return pointer;
}

// --- the 15-minute incremental tick ----------------------------------------

export async function runTick(env, log = new RunLog('tick')) {
  const state = await loadState(env);
  if (state.needs_rebuild || !state.sources.ossf || !state.sources.ossf.commit) {
    log.add('needs_rebuild is set; waiting for the daily rebuild');
    log.done({ skipped: 'needs_rebuild' });
    return null;
  }
  const recObj = await env.FEED.get(RECORDS_KEY);
  if (!recObj) {
    state.needs_rebuild = true;
    await saveState(env, state);
    log.add('records state missing; flagged for rebuild');
    log.done({ skipped: 'no records' });
    return null;
  }

  const cmp = await compareSince(env, state.sources.ossf.commit);
  if (cmp.rebuild) {
    state.needs_rebuild = true;
    await saveState(env, state);
    log.add('FALLBACK to full rebuild:', cmp.rebuild);
    log.done({ skipped: 'fallback', reason: cmp.rebuild });
    return null;
  }
  const dd = await fetchDatadog(env, state.dd_etags || {});
  const ddChanged = dd.filter((d) => d.changed);

  if (!cmp.changed.length && !cmp.removed.length && !ddChanged.length) {
    state.sources.ossf.commit = cmp.head;
    state.sources.ossf.fetched = isoNow();
    await saveState(env, state);
    log.done({ seq: state.seq, changed: 0 });
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
  log.done({ seq: pointer ? pointer.seq : state.seq, entries: index.size, stats });
  return pointer;
}

// --- serving ----------------------------------------------------------------

const ARTIFACT_RE = /^v1\/(packages-\d+-[0-9a-f]{12}|delta-\d+-\d+-[0-9a-f]{12})\.txt\.gz(\.sig)?$/;

function contentTypeFor(key) {
  if (key.endsWith('.sig')) return 'application/octet-stream';
  if (key.endsWith('.json')) return 'application/json';
  return 'application/gzip';
}

export async function serve(request, env, ctx) {
  const url = new URL(request.url);
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('method not allowed\n', { status: 405, headers: { allow: 'GET, HEAD' } });
  }
  const key = url.pathname.replace(/^\//, '');

  if (key === 'healthz') {
    const state = await loadState(env);
    return json({
      seq: state.seq, entries: state.entries, generated: state.generated,
      needs_rebuild: !!state.needs_rebuild, sources: state.sources,
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

function json(body, cacheControl) {
  return new Response(JSON.stringify(body, null, 2) + '\n', {
    headers: { 'content-type': 'application/json', 'cache-control': cacheControl },
  });
}

export default {
  fetch: serve,
  async scheduled(event, env, ctx) {
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
