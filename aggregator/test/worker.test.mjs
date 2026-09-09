// Integration tests for the Worker itself: a full rebuild, an incremental
// tick, the delta a client would actually apply, signature verification, the
// serving headers, and the >=300-files compare fallback.
//
// Everything upstream is stubbed; R2 and caches.default are in-memory doubles.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import worker, { runFull, runTick, serve } from '../src/index.js';
import { FakeR2, makeTarGz, installFetch, installCaches } from './helpers.mjs';
import { parseArtifact, serializeArtifact } from '../src/normalize.js';
import { parseDelta, applyOps } from '../src/delta.js';
import { gunzipString } from '../src/gz.js';
import { importVerifier, verifyBytes, b64encode } from '../src/sign.js';

installCaches();

const SHA_A = 'a'.repeat(40);
const SHA_B = 'b'.repeat(40);

const osvDoc = (id, eco, name, extra = {}) => JSON.stringify({
  id, modified: '2026-01-01T00:00:00Z',
  affected: [{ package: { ecosystem: eco, name }, ...extra }],
});

const BASE_FILES = [
  { name: 'r-main/osv/malicious/npm/evil/MAL-0001.json', body: osvDoc('MAL-0001', 'npm', 'evil') },
  { name: 'r-main/osv/malicious/npm/doomed/MAL-0002.json', body: osvDoc('MAL-0002', 'npm', 'doomed') },
  { name: 'r-main/osv/malicious/pypi/requestss/MAL-0003.json', body: osvDoc('MAL-0003', 'PyPI', 'requestss', { versions: ['0.1'] }) },
];

const MANIFESTS = {
  npm: { '@scope/pkg': null },
  pypi: { badpy: ['1.0'] },
  'ai-skills': { 'evil-skill': null },
  ide_extensions: { 'some.ext': ['1.0'] },
};

async function newEnv() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const p8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return {
    env: { FEED: new FakeR2(), FEED_SIGNING_KEY: b64encode(p8.slice(16)), DELTA_WINDOW: '48', KEEP_ARTIFACTS: '4' },
    pub,
  };
}

function baseRoutes(overrides = []) {
  return [
    ...overrides,
    [/api\.github\.com\/repos\/.*\/commits\/main/, () => ({ body: { sha: SHA_A } })],
    [/codeload\.github\.com/, async () => new Response(await makeTarGz(BASE_FILES), { headers: { etag: '"tar1"' } })],
    [/raw\.githubusercontent\.com\/DataDog\/.*samples\/(\w[\w-]*)\/manifest\.json/, (url) => {
      const eco = /samples\/([\w-]+)\/manifest\.json/.exec(url)[1];
      return { body: MANIFESTS[eco], headers: { etag: `"dd-${eco}-1"` } };
    }],
  ];
}

const unzip = (bytes) => gunzipString(new ReadableStream({
  start(c) { c.enqueue(bytes); c.close(); },
}));

const readObj = async (env, key) => new Uint8Array(await (await env.FEED.get(key)).arrayBuffer());

async function pointerOf(env) {
  return JSON.parse(await (await env.FEED.get('v1/pointer.json')).text());
}

test('full rebuild publishes a signed seq 1 artifact and a pointer', async () => {
  const { env, pub } = await newEnv();
  const f = installFetch(baseRoutes());
  try {
    await runFull(env);
  } finally { f.restore(); }

  const p = await pointerOf(env);
  assert.equal(p.version, 1);
  assert.equal(p.seq, 1);
  assert.equal(p.entries, 7);
  assert.match(p.artifact, /^\/v1\/packages-1-[0-9a-f]{12}\.txt\.gz$/);
  assert.equal(p.artifact, `/v1/packages-1-${p.sha256.slice(0, 12)}.txt.gz`);
  assert.match(p.generated, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.deepEqual(p.deltas, {}); // nothing to diff against at seq 1
  assert.equal(p.sources.ossf.commit, SHA_A);
  assert.equal(p.sources.datadog.etag, '"dd-npm-1"');

  const gz = await readObj(env, p.artifact.slice(1));
  assert.equal(gz.length, p.bytes);
  const text = await gunzipString(new ReadableStream({ start(c) { c.enqueue(gz); c.close(); } }));
  assert.equal(text.split('\n')[0], '# moat-packages v1');
  assert.equal(text.split('\n')[2], '# entries 7');
  assert.ok(text.includes('\nnpm\tevil\t*\n'));
  assert.ok(text.includes('\npypi\trequestss\t=0.1\n'));
  assert.ok(text.includes('\nai-skills\tevil-skill\t*\n'));
  assert.ok(text.includes('\nvscode\tsome.ext\t=1.0\n'));

  // sha256 in the pointer is over the gzip bytes
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', gz));
  assert.equal([...digest].map((b) => b.toString(16).padStart(2, '0')).join(''), p.sha256);

  // detached ed25519 signature verifies against the published public key
  const sig = await readObj(env, p.artifact.slice(1) + '.sig');
  assert.equal(sig.length, 64);
  const v = await importVerifier(pub);
  assert.equal(await verifyBytes(v, sig, gz), true);
  const tampered = gz.slice();
  tampered[tampered.length >> 1] ^= 0x01;
  assert.equal(await verifyBytes(v, sig, tampered), false);
});

test('a tick with no upstream movement does not bump seq', async () => {
  const { env } = await newEnv();
  let f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }

  f = installFetch(baseRoutes([
    [/compare/, () => ({ body: { total_commits: 0, commits: [], files: [], merge_base_commit: { sha: SHA_A } } })],
    [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
  ]));
  try { await runTick(env); } finally { f.restore(); }
  assert.equal((await pointerOf(env)).seq, 1);
});

test('a record that changes without changing the index does not bump seq', async () => {
  // The case the byte-comparison no-op branch was meant to catch and never
  // did: upstream really did move -- the compare names a changed file, and the
  // file's own `modified` timestamp is newer -- but the folded index is
  // identical. Publishing here would mint a sequence, write a fresh artifact
  // and change the pointer, so every client's next tick would be a delta fetch
  // instead of a 304, for no new information at all.
  const { env } = await newEnv();
  let f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }
  const before = await pointerOf(env);

  // Same package, same spec, different `modified`.
  const touched = JSON.stringify({
    id: 'MAL-0001', modified: '2026-06-01T00:00:00Z',
    affected: [{ package: { ecosystem: 'npm', name: 'evil' } }],
  });
  f = installFetch(baseRoutes([
    [/api\.github\.com\/repos\/.*\/commits\/main/, () => ({ body: { sha: SHA_B } })],
    [/compare/, () => ({ body: {
      total_commits: 1, commits: [{ sha: SHA_B }],
      files: [{ status: 'modified', filename: 'osv/malicious/npm/evil/MAL-0001.json' }],
      merge_base_commit: { sha: SHA_A },
    } })],
    [/raw\.githubusercontent\.com\/.*MAL-0001\.json/, () => new Response(touched)],
    [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
  ]));
  try { await runTick(env); } finally { f.restore(); }

  const after = await pointerOf(env);
  assert.equal(after.seq, before.seq, 'no new sequence');
  assert.equal(after.artifact, before.artifact, 'and the pointer still names the same artifact');
  assert.equal(after.generated, before.generated, 'so a client 304s instead of refetching');
});

test('the signed artifact carries its own seq, and it matches the pointer', async () => {
  // pointer.json is NOT signed. Without seq inside the signed bytes, a pointer
  // could name a fresh sequence while serving an older, validly-signed
  // artifact: every signature checks out and the client installs a stale index,
  // losing whichever malicious packages were added since. The client
  // cross-checks these two, so they have to agree.
  const { env } = await newEnv();
  const f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }
  const p = await pointerOf(env);
  const text = await unzip(await readObj(env, p.artifact.slice(1)));
  const seqLine = text.split('\n').find((l) => l.startsWith('# seq '));
  assert.ok(seqLine, 'the artifact must state its own sequence');
  assert.equal(Number(seqLine.slice(6)), p.seq);
});

test('incremental tick applies adds, spec changes and removals', async () => {
  const { env, pub } = await newEnv();
  let f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }

  const p1 = await pointerOf(env);
  const gz1 = await readObj(env, p1.artifact.slice(1));
  const index1 = parseArtifact(await gunzipString(
    new ReadableStream({ start(c) { c.enqueue(gz1); c.close(); } })));

  const NEW_FILE = 'osv/malicious/npm/newbad/MAL-0004.json';
  const MOD_FILE = 'osv/malicious/pypi/requestss/MAL-0003.json';
  const DEL_FILE = 'osv/malicious/npm/doomed/MAL-0002.json';

  f = installFetch(baseRoutes([
    [/compare/, () => ({
      body: {
        total_commits: 3,
        commits: [{ sha: SHA_B }],
        files: [
          { filename: NEW_FILE, status: 'added', raw_url: 'https://raw.githubusercontent.com/ossf/x/' + SHA_B + '/' + NEW_FILE },
          { filename: MOD_FILE, status: 'modified', raw_url: 'https://raw.githubusercontent.com/ossf/x/' + SHA_B + '/' + MOD_FILE },
          { filename: DEL_FILE, status: 'removed' },
          { filename: 'README.md', status: 'modified' },
        ],
      },
    })],
    [new RegExp(NEW_FILE), () => ({ body: osvDoc('MAL-0004', 'npm', 'newbad') })],
    [new RegExp(MOD_FILE), () => ({ body: osvDoc('MAL-0003', 'PyPI', 'requestss', { versions: ['0.1', '0.2'] }) })],
    [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
  ]));
  try { await runTick(env); } finally { f.restore(); }

  const p2 = await pointerOf(env);
  assert.equal(p2.seq, 2);
  assert.equal(p2.entries, 7); // +newbad, -doomed
  assert.equal(p2.sources.ossf.commit, SHA_B);
  assert.deepEqual(Object.keys(p2.deltas), ['1']);
  assert.match(p2.deltas['1'], /^\/v1\/delta-1-2-[0-9a-f]{12}\.txt\.gz$/);

  const gz2 = await readObj(env, p2.artifact.slice(1));
  const text2 = await gunzipString(new ReadableStream({ start(c) { c.enqueue(gz2); c.close(); } }));
  const index2 = parseArtifact(text2);
  assert.equal(index2.get('npm\tnewbad'), '*');
  assert.equal(index2.get('pypi\trequestss'), '=0.1|=0.2');
  assert.equal(index2.has('npm\tdoomed'), false);

  // what a client does: fetch the delta for its seq, verify, apply
  const dgz = await readObj(env, p2.deltas['1'].slice(1));
  const dsig = await readObj(env, p2.deltas['1'].slice(1) + '.sig');
  assert.equal(await verifyBytes(await importVerifier(pub), dsig, dgz), true);
  const delta = parseDelta(await gunzipString(
    new ReadableStream({ start(c) { c.enqueue(dgz); c.close(); } })));
  assert.equal(delta.from, 1);
  assert.equal(delta.to, 2);
  assert.deepEqual(delta.ops.map((o) => o.op + ' ' + o.key).sort(), [
    '+ npm\tnewbad',
    '+ pypi\trequestss',
    '- npm\tdoomed',
  ]);
  const applied = applyOps(index1, delta.ops);
  assert.equal(serializeArtifact(applied, 'T'), serializeArtifact(index2, 'T'));
});

test('delta window keeps the last N sequences', async () => {
  const { env } = await newEnv();
  let f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }
  env.DELTA_WINDOW = '2';

  const seq1 = await pointerOf(env);
  const gz1 = await readObj(env, seq1.artifact.slice(1));
  const index1 = parseArtifact(await gunzipString(
    new ReadableStream({ start(c) { c.enqueue(gz1); c.close(); } })));

  for (let i = 0; i < 3; i++) {
    const path = `osv/malicious/npm/x${i}/MAL-1${i}.json`;
    f = installFetch(baseRoutes([
      [/compare/, () => ({
        body: {
          total_commits: 1, commits: [{ sha: SHA_B + i }],
          files: [{ filename: path, status: 'added', raw_url: 'https://raw.githubusercontent.com/ossf/x/h/' + path }],
        },
      })],
      [new RegExp(`x${i}`), () => ({ body: osvDoc(`MAL-1${i}`, 'npm', `x${i}`) })],
      [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
    ]));
    try { await runTick(env); } finally { f.restore(); }
  }

  const p = await pointerOf(env);
  assert.equal(p.seq, 4);
  assert.deepEqual(Object.keys(p.deltas).sort(), ['2', '3']); // window of 2
  assert.equal(p.entries, 10);

  // seq 1 is outside the window: a client on seq 1 must take the full artifact
  assert.equal(p.deltas['1'], undefined);

  // the composed 2->4 delta is what a client on seq 2 gets, and it must land
  // exactly on the seq-4 index
  const gz4 = await readObj(env, p.artifact.slice(1));
  const index4 = parseArtifact(await gunzipString(
    new ReadableStream({ start(c) { c.enqueue(gz4); c.close(); } })));
  const dgz = await readObj(env, p.deltas['2'].slice(1));
  const delta = parseDelta(await gunzipString(
    new ReadableStream({ start(c) { c.enqueue(dgz); c.close(); } })));
  assert.equal(delta.from, 2);
  assert.equal(delta.to, 4);
  // rebuild the seq-2 index from seq 1 the way a client would have
  const index2 = index1; // seq 2 is seq 1 plus npm/x0
  index2.set('npm\tx0', '*');
  assert.equal(serializeArtifact(applyOps(index2, delta.ops), 'T'), serializeArtifact(index4, 'T'));
});

test('compare at the 300-file cap falls back to a full rebuild', async () => {
  const { env } = await newEnv();
  let f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }
  const before = await pointerOf(env);

  const files = Array.from({ length: 300 }, (_, i) => ({
    filename: `osv/malicious/npm/p${i}/MAL-${i}.json`, status: 'added',
    raw_url: `https://raw.githubusercontent.com/ossf/x/h/osv/malicious/npm/p${i}/MAL-${i}.json`,
  }));
  f = installFetch(baseRoutes([
    [/compare/, () => ({ body: { total_commits: 9, commits: [{ sha: SHA_B }], files } })],
    [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
  ]));
  let fetched;
  try {
    assert.equal(await runTick(env), null);
    fetched = f.calls;
  } finally { f.restore(); }

  // nothing published, no raw files fetched, and the rebuild flag is set
  assert.deepEqual(await pointerOf(env), before);
  assert.equal(fetched.some((u) => u.includes('/osv/malicious/npm/p0/')), false);
  const state = JSON.parse(await (await env.FEED.get('state/state.json')).text());
  assert.equal(state.needs_rebuild, true);

  // and a later tick refuses to run until the daily rebuild clears the flag
  f = installFetch(baseRoutes([[/compare/, () => { throw new Error('must not be called'); }]]));
  try { assert.equal(await runTick(env), null); } finally { f.restore(); }

  // the daily rebuild clears it and publishes again
  f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }
  const after = JSON.parse(await (await env.FEED.get('state/state.json')).text());
  assert.equal(after.needs_rebuild, false);
});

test('compare truncated past 250 commits also falls back', async () => {
  const { env } = await newEnv();
  let f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }

  f = installFetch(baseRoutes([
    [/compare/, () => ({ body: { total_commits: 251, commits: [{ sha: SHA_B }], files: [] } })],
    [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
  ]));
  try { assert.equal(await runTick(env), null); } finally { f.restore(); }
  const state = JSON.parse(await (await env.FEED.get('state/state.json')).text());
  assert.equal(state.needs_rebuild, true);
});

test('serving: contract cache headers, 404s, 405s and 304s', async () => {
  const { env } = await newEnv();
  const f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }
  const p = await pointerOf(env);
  const ctx = { waitUntil() {} };
  const get = (path, init) => serve(new Request('https://feed.example' + path, init), env, ctx);

  const ptr = await get('/v1/pointer.json');
  assert.equal(ptr.status, 200);
  assert.equal(ptr.headers.get('cache-control'), 'public, max-age=60');
  assert.equal(ptr.headers.get('content-type'), 'application/json');
  assert.equal(JSON.parse(await ptr.text()).seq, 1);

  const art = await get(p.artifact);
  assert.equal(art.status, 200);
  assert.equal(art.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal(art.headers.get('content-type'), 'application/gzip');
  assert.equal(Number(art.headers.get('content-length')), p.bytes);

  const sig = await get(p.artifact + '.sig');
  assert.equal(sig.status, 200);
  assert.equal(sig.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal(sig.headers.get('content-type'), 'application/octet-stream');

  const etag = ptr.headers.get('etag');
  const nm = await get('/v1/pointer.json', { headers: { 'if-none-match': etag } });
  assert.equal(nm.status, 304);

  assert.equal((await get('/v1/packages-1-zzzzzzzzzzzz.txt.gz')).status, 404);
  assert.equal((await get('/v1/../state/state.json')).status, 404);
  assert.equal((await get('/state/state.json')).status, 404);
  assert.equal((await get('/v1/pointer.json', { method: 'POST' })).status, 405);

  const head = await get(p.artifact, { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal(await head.text(), '');

  const health = await get('/healthz');
  assert.equal(health.headers.get('cache-control'), 'no-store');
  assert.equal(JSON.parse(await health.text()).entries, 7);
});

test('scheduled() routes the two crons to the two jobs', async () => {
  const { env } = await newEnv();
  const ctx = { waitUntil() {} };
  let f = installFetch(baseRoutes());
  try {
    await worker.scheduled({ cron: '17 4 * * *' }, env, ctx);
  } finally { f.restore(); }
  assert.equal((await pointerOf(env)).seq, 1);

  // the 15-minute cron takes the tick path, which uses the compare API
  let sawCompare = false;
  f = installFetch(baseRoutes([
    [/compare/, () => { sawCompare = true; return { body: { total_commits: 0, commits: [], files: [], merge_base_commit: { sha: SHA_A } } }; }],
    [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
  ]));
  try {
    await worker.scheduled({ cron: '*/15 * * * *' }, env, ctx);
  } finally { f.restore(); }
  assert.equal(sawCompare, true);
});

test('a failing run leaves the previous pointer intact', async () => {
  const { env } = await newEnv();
  let f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }
  const before = await pointerOf(env);

  f = installFetch([[/codeload/, () => ({ status: 500, body: 'boom' })],
    ...baseRoutes()]);
  try {
    await assert.rejects(worker.scheduled({ cron: '17 4 * * *' }, env, { waitUntil() {} }));
  } finally { f.restore(); }
  assert.deepEqual(await pointerOf(env), before);
});

test('the delta path canonicalises pypi names, and does not drift from a rebuild', async () => {
  const { env } = await newEnv();
  let f = installFetch(baseRoutes());
  try { await runFull(env); } finally { f.restore(); }

  const p1 = await pointerOf(env);
  const index1 = parseArtifact(await unzip(await readObj(env, p1.artifact.slice(1))));

  const ADDED = 'osv/malicious/pypi/calcboxlite/MAL-0007.json';
  const COLLIDE = 'osv/malicious/pypi/requestss/MAL-0008.json';
  const extra = [
    { name: 'r-main/' + ADDED, body: osvDoc('MAL-0007', 'PyPI', 'CalcBoxLite') },
    { name: 'r-main/' + COLLIDE, body: osvDoc('MAL-0008', 'PyPI', 'REQUESTSS', { versions: ['0.5'] }) },
  ];

  f = installFetch(baseRoutes([
    [/compare/, () => ({
      body: {
        total_commits: 2, commits: [{ sha: SHA_B }],
        files: [ADDED, COLLIDE].map((filename) => ({
          filename, status: 'added',
          raw_url: 'https://raw.githubusercontent.com/ossf/x/' + SHA_B + '/' + filename,
        })),
      },
    })],
    [new RegExp(ADDED), () => ({ body: extra[0].body })],
    [new RegExp(COLLIDE), () => ({ body: extra[1].body })],
    [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
  ]));
  try { await runTick(env); } finally { f.restore(); }

  const p2 = await pointerOf(env);
  const tickText = await unzip(await readObj(env, p2.artifact.slice(1)));
  const index2 = parseArtifact(tickText);
  assert.equal(index2.get('pypi\tcalcboxlite'), '*');
  assert.equal(index2.has('pypi\tCalcBoxLite'), false);
  // the collision folded onto the existing key rather than adding a second one
  assert.equal(index2.get('pypi\trequestss'), '=0.1|=0.5');
  assert.equal(index2.has('pypi\tREQUESTSS'), false);

  // the delta a client applies lands exactly on the tick's artifact
  const dgz = await readObj(env, p2.deltas['1'].slice(1));
  const delta = parseDelta(await unzip(dgz));
  assert.deepEqual(delta.ops.map((o) => o.op + ' ' + o.key).sort(),
    ['+ pypi\tcalcboxlite', '+ pypi\trequestss']);
  assert.equal(serializeArtifact(applyOps(index1, delta.ops), 'T'),
    serializeArtifact(index2, 'T'));

  // and a full rebuild over the same upstream files produces the same artifact:
  // the incremental path must not drift from the authoritative one
  const { env: env2 } = await newEnv();
  f = installFetch([
    [/api\.github\.com\/repos\/.*\/commits\/main/, () => ({ body: { sha: SHA_B } })],
    [/codeload\.github\.com/, async () => new Response(await makeTarGz([...BASE_FILES, ...extra]))],
    ...baseRoutes(),
  ]);
  try { await runFull(env2); } finally { f.restore(); }
  const pf = await pointerOf(env2);
  const fullText = await unzip(await readObj(env2, pf.artifact.slice(1)));
  // `# generated` and `# seq` are both expected to differ -- the tick reached
  // this content as sequence 2, the rebuild as sequence 1. What must not drift
  // is the folded content itself.
  const strip = (t) => t.split('\n')
    .filter((l) => !l.startsWith('# generated') && !l.startsWith('# seq'))
    .join('\n');
  assert.equal(strip(tickText), strip(fullText));
  assert.equal(pf.sha256.length, 64);
});
