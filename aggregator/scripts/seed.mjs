#!/usr/bin/env node
// Build the seq-1 objects locally so the first publish does not need a Worker
// rebuild. Everything it writes goes under --out, laid out exactly as the R2
// keys, so uploading is a plain recursive copy.
//
//   node scripts/seed.mjs --key ./feed-key [--artifact seed/packages.txt.gz]
//                         [--out build/seed] [--corpus DIR --commit SHA]
//
// Without --corpus the state is marked needs_rebuild, so the 15-minute tick
// stands down until the daily rebuild has produced state/records.tsv.gz.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { createReadStream } from 'node:fs';
import { Readable } from 'node:stream';

import { importSigner, signBytes } from '../src/sign.js';
import { sha256Hex, gzipStrings, gunzipString } from '../src/gz.js';
import { isoNow, parseArtifact } from '../src/normalize.js';
import { buildFullRecords } from '../src/build.js';

const argv = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = argv.indexOf('--' + name);
  return i >= 0 ? argv[i + 1] : dflt;
};

const keyFile = flag('key');
const artifactPath = flag('artifact', 'seed/packages.txt.gz');
const outDir = flag('out', 'build/seed');
const corpus = flag('corpus');
const commit = flag('commit');

const secret = process.env.FEED_SIGNING_KEY || (keyFile && readFileSync(keyFile, 'utf8'));
if (!secret) {
  console.error('need --key <file> or FEED_SIGNING_KEY in the environment');
  process.exit(2);
}

const write = (rel, bytes) => {
  const p = join(outDir, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, bytes);
  console.log('  ' + p + '  (' + bytes.length + ' bytes)');
};

const artGz = new Uint8Array(readFileSync(artifactPath));
const sha = await sha256Hex(artGz);
const generated = isoNow();

// sanity-check the seed really is a moat-packages v1 artifact
const text = await gunzipString(new ReadableStream({ start(c) { c.enqueue(artGz); c.close(); } }));
if (!text.startsWith('# moat-packages v1\n')) throw new Error('not a moat-packages v1 artifact');
const entries = parseArtifact(text).size;
const declared = Number(/^# entries (\d+)$/m.exec(text)[1]);
if (entries !== declared) throw new Error(`header says ${declared} entries, body has ${entries}`);
// The sequence lives inside the signed bytes, and these bytes are uploaded
// verbatim -- there is no re-serialisation step to add it later. A seed
// without it is signed correctly and rejected by every client, which is a
// confusing way to start. Checked here so the bootstrap cannot regress
// silently when the artifact is regenerated.
const seqLine = /^# seq (\d+)$/m.exec(text);
if (!seqLine) {
  throw new Error('seed artifact has no `# seq` header; regenerate it with '
    + '`node scripts/normalize-local.mjs <corpus> <out.txt> --seq 1` and gzip it');
}
if (Number(seqLine[1]) !== 1) {
  throw new Error(`seed artifact declares seq ${seqLine[1]}; the seed must be seq 1`);
}

const signer = await importSigner(secret.trim());
const name = `packages-1-${sha.slice(0, 12)}.txt.gz`;

console.log('seeding seq 1 from', artifactPath, `(${entries} entries)`);
write('v1/' + name, artGz);
write('v1/' + name + '.sig', await signBytes(signer, artGz));

let records = null;
if (corpus) {
  if (!commit) { console.error('--corpus also needs --commit <ossf sha>'); process.exit(2); }
  const dd = [['npm', 'm_npm.json'], ['pypi', 'm_pypi.json'],
    ['ai-skills', 'm_ai-skills.json'], ['ide_extensions', 'm_ide_extensions.json']]
    .map(([eco, f]) => ({ eco, manifest: JSON.parse(readFileSync(join(corpus, f), 'utf8')) }));
  const ctx = {};
  records = await gzipStrings(buildFullRecords(
    Readable.toWeb(createReadStream(join(corpus, 'ossf.tar.gz'))), dd, ctx));
  if (ctx.index.size !== entries) {
    throw new Error(`corpus rebuild has ${ctx.index.size} entries, seed artifact has ${entries}`);
  }
  write('state/records.tsv.gz', records);
}

const sources = {
  ossf: { commit: commit || null, fetched: generated },
  datadog: { etag: null, fetched: generated },
};

const pointer = {
  version: 1, seq: 1, generated, entries,
  artifact: '/v1/' + name, sha256: sha, bytes: artGz.length,
  deltas: {}, sources,
};
write('v1/pointer.json', Buffer.from(JSON.stringify(pointer, null, 2)));

const state = {
  version: 1, seq: 1, generated, entries,
  artifact: '/v1/' + name, sha256: sha, bytes: artGz.length,
  sources, dd_etags: {}, steps: [],
  needs_rebuild: !(records && commit),
  last: { kind: 'seed', at: generated },
};
write('state/state.json', Buffer.from(JSON.stringify(state)));

console.log(`
upload (bucket name from wrangler.toml):

  cd ${outDir}
  for f in $(find . -type f | sed 's|^\\./||'); do
    npx wrangler r2 object put "moat-feed/$f" --file "$f" --remote
  done

state.needs_rebuild = ${state.needs_rebuild}${state.needs_rebuild
  ? '  (the 15-minute tick stands down until the daily rebuild runs)'
  : ''}`);
