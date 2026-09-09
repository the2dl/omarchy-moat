#!/usr/bin/env node
// Run the Worker's normalisation over a local corpus, outside Cloudflare.
//
//   node scripts/normalize-local.mjs <corpus-dir> [out.txt] [--seq N]
//
// --seq writes a `# seq N` header. The seed needs `--seq 1`; without it the
// output is a plain normalisation, comparable to the Python reference.
//
// <corpus-dir> holds ossf.tar.gz and the four Datadog manifests
// (m_npm.json, m_pypi.json, m_ai-skills.json, m_ide_extensions.json).
// This is what test/normalize.test.mjs uses to prove equivalence with the
// reference normalizer.

import { createReadStream, readFileSync, writeFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import { join } from 'node:path';
import { buildFull } from '../src/build.js';
import { serializeArtifact, isoNow } from '../src/normalize.js';

export async function buildFromDir(dir) {
  const ossf = Readable.toWeb(createReadStream(join(dir, 'ossf.tar.gz')));
  const datadog = [
    ['npm', 'm_npm.json'], ['pypi', 'm_pypi.json'],
    ['ai-skills', 'm_ai-skills.json'], ['ide_extensions', 'm_ide_extensions.json'],
  ].map(([eco, f]) => ({ eco, manifest: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
  return buildFull(ossf, datadog);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = process.argv[2];
  if (!dir) { console.error('usage: normalize-local.mjs <corpus-dir> [out.txt]'); process.exit(2); }
  const t0 = Date.now();
  const { records, index, stats } = await buildFromDir(dir);
  const seqIdx = process.argv.indexOf('--seq');
  const seq = seqIdx >= 0 ? Number(process.argv[seqIdx + 1]) : undefined;
  const text = serializeArtifact(index, isoNow(), seq);
  if (process.argv[3]) writeFileSync(process.argv[3], text);
  console.error('entries:', index.size, 'records:', records.length,
    'ms:', Date.now() - t0, 'rss MB:', (process.memoryUsage().rss / 1048576).toFixed(0));
  console.error('stats:', stats);
}
