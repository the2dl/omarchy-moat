// The domain wing: the public suffix gate, the never-list, the confidence
// floor, the collapse floor, and the shared pointer.
//
// Everything upstream is stubbed. The zip fixture is built here rather than
// checked in, so the test exercises src/zip.js against a real deflate stream.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { runDomains, runFull, serve } from '../src/index.js';
import { FakeR2, installFetch, installCaches } from './helpers.mjs';
import { unzipFirstEntry, unzipLines } from '../src/zip.js';
import { gunzipString, concatBytes } from '../src/gz.js';
import { importVerifier, verifyBytes, b64encode } from '../src/sign.js';
import {
  normalizeDomain, parsePsl, isSharedSuffix, parseCsvLine, hostfileDomains,
  gateDomains, upstreamStamp, newDomainStats, NEVER,
} from '../src/domains.js';

installCaches();

// --- fixtures ---------------------------------------------------------------

const PSL_TEXT = [
  '// ===BEGIN ICANN DOMAINS===',
  'com', 'net', 'org', 'dev', 'app', 'it', 'uk', 'co.uk',
  '// ===BEGIN PRIVATE DOMAINS===',
  'workers.dev', 'pages.dev', 'github.io', 'vercel.app',
  '*.compute.amazonaws.com', '*.localto.net',
  '!city.kobe.jp', 'kobe.jp', '*.kobe.jp',
  // Enough rules to clear loadPsl's "is this the list at all" floor.
  ...Array.from({ length: 120 }, (_, i) => `pad${i}.example`),
].join('\n');

const csvRow = (o) => [
  o.firstSeen || '2026-09-01 10:00:00', o.id || '1', o.ioc, o.type || 'domain',
  o.threat || 'botnet_cc', o.malware || 'win.thing', 'None', o.printable || 'Thing',
  '', String(o.confidence === undefined ? 100 : o.confidence),
  o.compromised ? 'True' : 'False', 'None', o.tags || 'a,b,c', '0', 'reporter',
].map((f) => `"${f}"`).join(', ');

const CSV_HEADER = [
  '################################################################',
  '# ThreatFox IOCs: full dump - CSV format                       #',
  '# Last updated: 2026-09-11 14:18:03 UTC                        #',
  '################################################################',
  '#',
  '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"',
];

const csvText = (rows) => CSV_HEADER.concat(rows.map(csvRow)).join('\r\n') + '\r\n';

const hostfileText = (domains, stamp = '2026-09-11 14:18:03 UTC') => [
  '################################################################',
  '# ThreatFox IOCs: host file                                    #',
  `# Last updated: ${stamp}                        #`,
  '################################################################',
  '#',
  ...domains.map((d) => `127.0.0.1\t${d}`),
].join('\n') + '\n';

/** A single-entry zip with a real deflate payload, so src/zip.js is exercised. */
async function makeZip(name, body) {
  const enc = new TextEncoder();
  const raw = enc.encode(body);
  const cs = new CompressionStream('deflate-raw');
  const w = cs.writable.getWriter();
  const chunks = [];
  const pump = (async () => {
    const r = cs.readable.getReader();
    for (;;) { const { value, done } = await r.read(); if (done) break; chunks.push(value); }
  })();
  await w.write(raw);
  await w.close();
  await pump;
  const deflated = concatBytes(chunks);

  const nameBytes = enc.encode(name);
  const local = new Uint8Array(30 + nameBytes.length);
  const dv = new DataView(local.buffer);
  dv.setUint32(0, 0x04034b50, true);
  dv.setUint16(4, 20, true);        // version needed
  dv.setUint16(6, 0, true);         // flags: no data descriptor
  dv.setUint16(8, 8, true);         // deflate
  dv.setUint32(18, deflated.length, true);
  dv.setUint32(22, raw.length, true);
  dv.setUint16(26, nameBytes.length, true);
  local.set(nameBytes, 30);
  // A central directory the reader must not feed to the inflater.
  const cd = new Uint8Array(46 + nameBytes.length);
  new DataView(cd.buffer).setUint32(0, 0x02014b50, true);
  cd.set(nameBytes, 46);
  return concatBytes([local, deflated, cd]);
}

async function newEnv(extra = {}) {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const p8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return {
    env: {
      FEED: new FakeR2(), FEED_SIGNING_KEY: b64encode(p8.slice(16)),
      DELTA_WINDOW: '48', KEEP_ARTIFACTS: '4', ...extra,
    },
    pub,
  };
}

function routes({ hostfile, csv, psl = PSL_TEXT }) {
  return [
    [/publicsuffix\.org/, () => ({ body: psl })],
    [/threatfox\.abuse\.ch\/downloads\/hostfile/, () => ({ body: hostfile })],
    [/threatfox\.abuse\.ch\/export\/csv\/full/, async () => new Response(await makeZip('full.csv', csv))],
  ];
}

const quietLog = () => ({ kind: 'domains', lines: [], add(...a) { this.lines.push(a.map(String).join(' ')); }, done() {} });

const artifactText = async (env, path) =>
  gunzipString((await env.FEED.get(path.replace(/^\//, ''))).body);

const entriesOf = (text) => new Map(
  text.split('\n').filter((l) => l && !l.startsWith('#'))
    .map((l) => { const f = l.split('\t'); return [f[0], { family: f[1], confidence: f[2], flags: f[3] }]; }),
);

// --- unit: normalisation ----------------------------------------------------

test('a domain is normalised, and anything that is not a hostname is refused', () => {
  assert.equal(normalizeDomain('  EVIL.Example.COM. '), 'evil.example.com');
  assert.equal(normalizeDomain('www.abc-network.it'), 'www.abc-network.it');
  // www is deliberately kept: stripping it would widen a one-host entry to a
  // whole site, and the client matches the feed by suffix.
  assert.equal(normalizeDomain('WWW.evil.com'), 'www.evil.com');

  for (const bad of [
    'http://evil.com/x', 'evil.com/path', 'evil.com:443', '1.2.3.4', 'localhost',
    'user@evil.com', 'evil .com', '', '#comment', 'a..b', '-bad.com', 'x'.repeat(70) + '.com',
    'axr7hs51.$unp2idvalk.digital', '\u05DDv',
  ]) {
    assert.equal(normalizeDomain(bad), null, `${JSON.stringify(bad)} should be refused`);
  }
});

test('a Unicode entry is punycoded, because that is the form DNS carries', () => {
  // ThreatFox reports what a human typed; moatd sees the A-label off the wire.
  // Left as Unicode these entries can never match anything.
  assert.equal(normalizeDomain('ker\u00F3.hu'), 'xn--ker-ina.hu');
  assert.equal(normalizeDomain('sapzq.KER\u00D3.hu'), 'sapzq.xn--ker-ina.hu');
  assert.equal(normalizeDomain('bbaut\u00F3kozmetika.hu'), 'xn--bbautkozmetika-pob.hu');
});

// --- unit: the gate that matters --------------------------------------------

test('a shared suffix is told apart from one tenant sitting on one', () => {
  const psl = parsePsl(PSL_TEXT);

  // Names anybody can register under: dropping these is the whole point.
  for (const s of ['com', 'co.uk', 'workers.dev', 'github.io', 'vercel.app',
                   'compute.amazonaws.com', 'localto.net']) {
    assert.equal(isSharedSuffix(s, psl), true, `${s} is shared ground`);
  }

  // Ordinary registrable names.
  for (const s of ['evil.com', 'fukimo.workers.dev', 'mine.github.io', 'evil.co.uk']) {
    assert.equal(isSharedSuffix(s, psl), false, `${s} is somebody's name`);
  }

  // The correction the live feed forced. `*.localto.net` makes every tunnel a
  // public suffix by the letter of the PSL algorithm, and 50 of these were
  // real, current C2 in today's data. One tenant's host is not shared ground.
  assert.equal(isSharedSuffix('ratted.localto.net', psl), false);
  assert.equal(isSharedSuffix('eu-west-1.compute.amazonaws.com', psl), false);

  // !city.kobe.jp beats *.kobe.jp
  assert.equal(isSharedSuffix('kobe.jp', psl), true);
  assert.equal(isSharedSuffix('city.kobe.jp', psl), false);
});

test('a bad upstream row naming a whole shared suffix never reaches the artifact', () => {
  // This is the one that would matter. moatd matches the feed by suffix, so an
  // entry of `workers.dev` would turn every Cloudflare Worker on the internet
  // into an IOC on every machine running moat.
  const psl = parsePsl(PSL_TEXT);
  const stats = newDomainStats();
  const corpus = new Set([
    'workers.dev', 'fukimo.workers.dev', 'github.io', 'evil.com',
    'localto.net', 'ratted.localto.net',
  ]);
  const out = gateDomains(corpus, new Map(), psl, 50, stats);

  assert.equal(out.has('workers.dev'), false);
  assert.equal(out.has('github.io'), false);
  assert.equal(out.has('localto.net'), false);
  assert.equal(out.has('fukimo.workers.dev'), true, 'the specific subdomain is still an IOC');
  assert.equal(out.has('ratted.localto.net'), true, 'and so is one tenant of a tunnel service');
  assert.equal(out.has('evil.com'), true);
  assert.equal(stats.dropped_shared_suffix, 3);
});

test('the never-list keeps the machine able to update itself', () => {
  const psl = parsePsl(PSL_TEXT);
  const stats = newDomainStats();
  const out = gateDomains(
    new Set(['github.com', 'registry.npmjs.org', 'feed.runts.net', 'evil.com']),
    new Map(), psl, 50, stats,
  );
  assert.deepEqual([...out.keys()], ['evil.com']);
  assert.equal(stats.dropped_never, 3);
  for (const d of ['github.com', 'registry.npmjs.org', 'feed.runts.net']) {
    assert.ok(NEVER.has(d));
  }
});

test('a domain below the confidence floor is dropped, one without metadata is kept', () => {
  const psl = parsePsl(PSL_TEXT);
  const stats = newDomainStats();
  const meta = new Map([
    ['sure.com', { family: 'AsyncRAT', confidence: 100, compromised: false, firstSeen: '2026-01-01' }],
    ['unsure.com', { family: 'Maybe', confidence: 49, compromised: false, firstSeen: '2026-01-01' }],
  ]);
  const out = gateDomains(new Set(['sure.com', 'unsure.com', 'fresh.com']), meta, psl, 50, stats);

  assert.deepEqual([...out.keys()].sort(), ['fresh.com', 'sure.com']);
  assert.equal(stats.dropped_confidence, 1);
  // In the hostfile but not yet in the CSV snapshot: abuse.ch says it is live,
  // and membership is the hostfile's call.
  assert.equal(out.get('fresh.com').family, 'unknown');
  assert.equal(stats.no_metadata, 1);
});

// --- unit: parsing ----------------------------------------------------------

test('a CSV field holding commas is not split on them', () => {
  const f = parseCsvLine('"2026-09-11 14:18:03", "1912301", "fukimo.workers.dev", "domain", "botnet_cc", "php.shin", "None", "Shin", "", "50", "True", "None", "Cloudflare,GIF,PHP,webshell", "0", "xscon"');
  assert.equal(f.length, 15);
  assert.equal(f[2], 'fukimo.workers.dev');
  assert.equal(f[9], '50');
  assert.equal(f[10], 'True');
  assert.equal(f[12], 'Cloudflare,GIF,PHP,webshell', 'the tag list is one field');
});

test('the hostfile banner yields the upstream timestamp and no domains', () => {
  const stats = newDomainStats();
  const text = hostfileText(['a.com', 'b.com', 'not a domain'], '2026-09-11 14:18:03 UTC');
  const out = hostfileDomains(text, stats);
  assert.deepEqual([...out].sort(), ['a.com', 'b.com']);
  assert.equal(stats.hostfile_rejected, 1);
  assert.equal(upstreamStamp(text), '2026-09-11 14:18:03 UTC');
});

test('a zip is read to its last byte and no further', async () => {
  const body = 'line one\r\nline two\r\nline three\r\n';
  const zip = await makeZip('x.csv', body);
  const { name, size } = unzipFirstEntry(zip);
  assert.equal(name, 'x.csv');
  assert.equal(size, body.length);
  const lines = [];
  for await (const l of unzipLines(zip)) lines.push(l);
  // Trailing central-directory bytes would make this throw, not merely append.
  assert.deepEqual(lines, ['line one', 'line two', 'line three']);
});

test('a zip with a data descriptor is refused rather than guessed at', async () => {
  const zip = await makeZip('x.csv', 'hello\r\n');
  new DataView(zip.buffer).setUint16(6, 0x08, true);
  assert.throws(() => unzipFirstEntry(zip), /data descriptor/);
});

// --- integration ------------------------------------------------------------

test('a run publishes a signed domain artifact the pointer can be checked against', async () => {
  const { env, pub } = await newEnv();
  const f = installFetch(routes({
    hostfile: hostfileText(['evil.com', 'bad.workers.dev', 'hacked.co.uk', 'github.com', 'workers.dev']),
    csv: csvText([
      { ioc: 'evil.com', printable: 'AsyncRAT', confidence: 100 },
      { ioc: 'hacked.co.uk', printable: 'ClearFake', confidence: 90, compromised: true },
      { ioc: 'bad.workers.dev', printable: 'Quasar RAT', confidence: 75 },
      { ioc: 'http://evil.com/payload.bin', type: 'url', printable: 'Ignored' },
    ]),
  }));
  try {
    const out = await runDomains(env, quietLog(), { full: true });
    assert.equal(out.entries, 3, 'github.com and workers.dev are gated out');

    const pointer = await (await env.FEED.get('v1/pointer.json')).json();
    assert.equal(pointer.domains.seq, 1);
    assert.equal(pointer.domains.entries, 3);
    assert.equal(pointer.domains.source.name, 'threatfox');
    assert.equal(pointer.domains.source.upstream, '2026-09-11 14:18:03 UTC');

    const gz = (await env.FEED.get(pointer.domains.artifact.slice(1))).bytes
      || new Uint8Array(await (await env.FEED.get(pointer.domains.artifact.slice(1))).arrayBuffer());
    const sig = new Uint8Array(await (await env.FEED.get(pointer.domains.artifact.slice(1) + '.sig')).arrayBuffer());
    const v = await importVerifier(pub);
    assert.equal(await verifyBytes(v, sig, gz), true, 'the artifact is signed');

    const text = await artifactText(env, pointer.domains.artifact);
    assert.match(text, /^# moat-domains v1\n/);
    assert.match(text, /^# seq 1$/m, 'the sequence is inside the signed bytes');

    const rows = entriesOf(text);
    assert.deepEqual([...rows.keys()], ['bad.workers.dev', 'evil.com', 'hacked.co.uk'], 'sorted');
    assert.equal(rows.get('evil.com').family, 'AsyncRAT');
    assert.equal(rows.get('hacked.co.uk').flags, 'c', 'a compromised legitimate site is flagged');
    assert.equal(rows.get('evil.com').flags, '-');
    // The url-type row contributes nothing: its host is a site with one bad
    // path, not a malicious domain.
    assert.equal(rows.size, 3);
  } finally { f.restore(); }
});

test('a second run with the same upstream does not mint a new sequence', async () => {
  const { env } = await newEnv();
  const hostfile = hostfileText(['evil.com', 'other.com']);
  const csv = csvText([{ ioc: 'evil.com' }, { ioc: 'other.com' }]);
  const f = installFetch(routes({ hostfile, csv }));
  try {
    await runDomains(env, quietLog(), { full: true });
    const first = await (await env.FEED.get('state/domains.json')).json();
    assert.equal(first.seq, 1);

    // `generated` moves every run and lives inside the artifact, so comparing
    // artifact bytes would say "changed" forever. The content digest is what
    // makes a quiet day cost a client nothing.
    const again = await runDomains(env, quietLog(), { full: false });
    assert.equal(again, null);
    const second = await (await env.FEED.get('state/domains.json')).json();
    assert.equal(second.seq, 1, 'the sequence did not move');
  } finally { f.restore(); }
});

test('an upstream that collapses is refused, and the published list survives', async () => {
  const { env } = await newEnv();
  const many = Array.from({ length: 40 }, (_, i) => `evil${i}.com`);
  const f = installFetch(routes({ hostfile: hostfileText(many), csv: csvText(many.map((d) => ({ ioc: d }))) }));
  try {
    await runDomains(env, quietLog(), { full: true });
  } finally { f.restore(); }
  const before = await (await env.FEED.get('state/domains.json')).json();
  assert.equal(before.entries, 40);

  // A truncated response, a half-written upstream file and an outage behind a
  // 200 all look like this, and the right answer to all three is to keep what
  // is already published.
  const g = installFetch(routes({ hostfile: hostfileText(['evil0.com']), csv: csvText([]) }));
  try {
    const out = await runDomains(env, quietLog(), { full: false });
    assert.equal(out, null);
  } finally { g.restore(); }

  const after = await (await env.FEED.get('state/domains.json')).json();
  assert.equal(after.seq, before.seq, 'no new sequence');
  assert.equal(after.entries, 40, 'the published entry count is untouched');
  assert.match(after.last_error, /below the 20 floor/);
  const pointer = await (await env.FEED.get('v1/pointer.json')).json();
  assert.equal(pointer.domains.entries, 40, 'clients still see the good list');
});

test('the first tick after a deploy can build the list on its own', async () => {
  // The wing has nothing cached and the tick does not refresh. If it only ever
  // read the cache it would throw here, every fifteen minutes, until the daily
  // job ran -- which reads as "deployed and working" from every angle except
  // the one where somebody fetches the pointer.
  const { env } = await newEnv();
  const f = installFetch(routes({
    hostfile: hostfileText(['evil.com', 'other.com']),
    csv: csvText([{ ioc: 'evil.com', printable: 'AsyncRAT' }, { ioc: 'other.com' }]),
  }));
  try {
    const out = await runDomains(env, quietLog(), { full: false });
    assert.equal(out.entries, 2);
  } finally { f.restore(); }

  const pointer = await (await env.FEED.get('v1/pointer.json')).json();
  assert.equal(pointer.domains.seq, 1);
  const rows = entriesOf(await artifactText(env, pointer.domains.artifact));
  // And with metadata, not forty-eight thousand rows of "unknown" to be
  // replaced wholesale the next morning.
  assert.equal(rows.get('evil.com').family, 'AsyncRAT');
  assert.ok(await env.FEED.get('state/psl.txt.gz'), 'the list was cached for next time');
  assert.ok(await env.FEED.get('state/domain-meta.tsv.gz'));
});

test('a run without a public suffix list refuses to build rather than build ungated', async () => {
  const { env } = await newEnv();
  const f = installFetch([
    [/publicsuffix\.org/, () => ({ body: 'x', status: 500 })],
    [/threatfox\.abuse\.ch\/downloads\/hostfile/, () => ({ body: hostfileText(['workers.dev']) })],
    [/threatfox\.abuse\.ch\/export\/csv\/full/, async () => new Response(await makeZip('f.csv', csvText([])))],
  ]);
  try {
    await assert.rejects(() => runDomains(env, quietLog(), { full: true }), /public suffix list/);
    assert.equal(await env.FEED.get('v1/pointer.json'), null, 'nothing was published');
  } finally { f.restore(); }
});

test('the two wings share pointer.json without overwriting each other', async () => {
  const { env } = await newEnv();
  const f = installFetch(routes({
    hostfile: hostfileText(['evil.com']), csv: csvText([{ ioc: 'evil.com' }]),
  }));
  try {
    await runDomains(env, quietLog(), { full: true });
  } finally { f.restore(); }

  // Now a package run, which owns the top level of the same document.
  const { installFetch: _u } = await import('./helpers.mjs');
  const pkg = installFetch([
    [/api\.github\.com\/repos\/.*\/commits\/main/, () => ({ body: { sha: 'a'.repeat(40) } })],
    [/codeload\.github\.com/, async () => {
      const { makeTarGz } = await import('./helpers.mjs');
      return new Response(await makeTarGz([{
        name: 'r-main/osv/malicious/npm/evil/MAL-0001.json',
        body: JSON.stringify({ id: 'MAL-0001', modified: '2026-01-01T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'evil' } }] }),
      }]));
    }],
    [/raw\.githubusercontent\.com\/DataDog\//, () => ({ body: {}, headers: { etag: '"dd1"' } })],
    // the domain wing runs at the end of runFull too
    [/publicsuffix\.org/, () => ({ body: PSL_TEXT })],
    [/threatfox\.abuse\.ch\/downloads\/hostfile/, () => ({ body: hostfileText(['evil.com']) })],
    [/threatfox\.abuse\.ch\/export\/csv\/full/, async () => new Response(await makeZip('f.csv', csvText([{ ioc: 'evil.com' }]))) ],
  ]);
  try {
    await runFull(env, quietLog());
  } finally { pkg.restore(); }

  const pointer = await (await env.FEED.get('v1/pointer.json')).json();
  assert.ok(pointer.artifact.startsWith('/v1/packages-'), 'the package half is there');
  assert.ok(pointer.domains, 'the domain half survived the package publish');
  assert.equal(pointer.domains.entries, 1);
  assert.equal(pointer.domains.seq, 1, 'and was not republished for no reason');
});

test('a domain artifact is servable; a made-up one is not', async () => {
  const { env } = await newEnv();
  const f = installFetch(routes({ hostfile: hostfileText(['evil.com']), csv: csvText([{ ioc: 'evil.com' }]) }));
  try { await runDomains(env, quietLog(), { full: true }); } finally { f.restore(); }

  const pointer = await (await env.FEED.get('v1/pointer.json')).json();
  const ctx = { waitUntil() {} };
  const ok = await serve(new Request('https://feed.test' + pointer.domains.artifact), env, ctx);
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('content-type'), 'application/gzip');
  assert.equal(ok.headers.get('cache-control'), 'public, max-age=31536000, immutable');

  const sig = await serve(new Request('https://feed.test' + pointer.domains.artifact + '.sig'), env, ctx);
  assert.equal(sig.status, 200);

  const nope = await serve(new Request('https://feed.test/v1/domains-9-ffffffffffff.txt.gz'), env, ctx);
  assert.equal(nope.status, 404);
  const junk = await serve(new Request('https://feed.test/v1/domains-1-notahash.txt.gz'), env, ctx);
  assert.equal(junk.status, 404);
});

test('healthz reports the domain wing', async () => {
  const { env } = await newEnv();
  const f = installFetch(routes({ hostfile: hostfileText(['evil.com']), csv: csvText([{ ioc: 'evil.com' }]) }));
  try { await runDomains(env, quietLog(), { full: true }); } finally { f.restore(); }
  const res = await serve(new Request('https://feed.test/healthz'), env, { waitUntil() {} });
  const body = await res.json();
  assert.equal(body.domains.seq, 1);
  assert.equal(body.domains.entries, 1);
  assert.equal(body.domains.upstream, '2026-09-11 14:18:03 UTC');
  assert.equal(body.domains.last_error, null);
});
