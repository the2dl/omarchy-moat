#!/usr/bin/env node
// Measure both cron paths at real-corpus scale, outside Cloudflare, so the
// 128 MB / 30 s / 15 min budgets can be checked before deploying.
//
//   node scripts/bench.mjs <corpus-dir> [changed-file-count]
//
// The corpus directory is the one scripts/normalize-local.mjs takes.
// Numbers are node's, not workerd's: treat peak heapUsed as the signal and
// node's RSS as an over-estimate (it includes the allocator's slack).

import { createReadStream, readFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import { join } from 'node:path';

import { runFull, runTick } from '../src/index.js';
import { FakeR2, installFetch, installCaches } from '../test/helpers.mjs';
import { b64encode } from '../src/sign.js';

const dir = process.argv[2];
const changedCount = Number(process.argv[3] || 149); // 24h of OSSF churn
if (!dir) { console.error('usage: bench.mjs <corpus-dir> [changed-file-count]'); process.exit(2); }

installCaches();

const manifests = Object.fromEntries([['npm', 'm_npm.json'], ['pypi', 'm_pypi.json'],
  ['ai-skills', 'm_ai-skills.json'], ['ide_extensions', 'm_ide_extensions.json']]
  .map(([eco, f]) => [eco, readFileSync(join(dir, f), 'utf8')]));

const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const seed = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey)).slice(16);
const env = { FEED: new FakeR2(), FEED_SIGNING_KEY: b64encode(seed) };

const routes = (extra = []) => [
  ...extra,
  [/api\.github\.com\/repos\/.*\/commits\/main/, () => ({ body: { sha: 'a'.repeat(40) } })],
  [/codeload\.github\.com/, () => new Response(Readable.toWeb(createReadStream(join(dir, 'ossf.tar.gz'))))],
  [/samples\/([\w-]+)\/manifest\.json/, (u) => ({ body: manifests[/samples\/([\w-]+)\//.exec(u)[1]], headers: { etag: '"x"' } })],
];

async function measure(label, fn) {
  let peak = 0;
  const t = setInterval(() => { const h = process.memoryUsage().heapUsed; if (h > peak) peak = h; }, 5);
  const cpu0 = process.cpuUsage();
  const t0 = Date.now();
  await fn();
  const cpu = process.cpuUsage(cpu0);
  clearInterval(t);
  const h = process.memoryUsage().heapUsed; if (h > peak) peak = h;
  console.log(`${label}: wall ${Date.now() - t0} ms, cpu ${((cpu.user + cpu.system) / 1000).toFixed(0)} ms, `
    + `peak heapUsed ${(peak / 1048576).toFixed(0)} MB, rss ${(process.memoryUsage().rss / 1048576).toFixed(0)} MB`);
}

let f = installFetch(routes());
await measure('full rebuild', () => runFull(env));
f.restore();

// a tick that touches `changedCount` OSV files, the way 24h of churn looks
const files = Array.from({ length: changedCount }, (_, i) => ({
  filename: `osv/malicious/npm/bench${i}/MAL-B${i}.json`, status: 'added',
  raw_url: `https://raw.githubusercontent.com/ossf/malicious-packages/h/osv/malicious/npm/bench${i}/MAL-B${i}.json`,
}));
f = installFetch(routes([
  [/compare/, () => ({ body: { total_commits: 40, commits: [{ sha: 'b'.repeat(40) }], files } })],
  [/osv\/malicious\/npm\/bench(\d+)\//, (u) => ({
    body: JSON.stringify({
      id: 'MAL-B', affected: [{ package: { ecosystem: 'npm', name: 'bench' + /bench(\d+)\//.exec(u)[1] } }],
    }),
  })],
  [/raw\.githubusercontent\.com\/DataDog/, () => new Response(null, { status: 304 })],
]));
await measure(`tick (${changedCount} changed files)`, () => runTick(env));
f.restore();

const state = JSON.parse(await (await env.FEED.get('state/state.json')).text());
console.log(`seq ${state.seq}, ${state.entries} entries, artifact ${state.bytes} bytes`);
