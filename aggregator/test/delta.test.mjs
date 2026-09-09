import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  diffIndexes, diffSorted, serializeDelta, parseDelta, applyOps, composeOps,
} from '../src/delta.js';
import { sortedKeys, artifactLines, serializeArtifact } from '../src/normalize.js';

const idx = (o) => new Map(Object.entries(o));
const clone = (m) => new Map(m);

const OLD = idx({
  'npm\t1cattunnel': '*',
  'npm\t@scope/thing': '=1.0.0',
  'npm\tzzz': '*',
  'pypi\trequestss': '*',
  'crates.io\tappend-only-vec': '=0.1.9',
});
const NEW = idx({
  'npm\t1cattunnel': '*',                       // unchanged
  'npm\t@scope/thing': '=1.0.0|=1.0.1',         // spec changed
  'npm\t@aspect-adv-ui/consent-manager': '*',   // added
  'pypi\trequestss': '*',
  'crates.io\tappend-only-vec': '=0.1.9',
  // npm\tzzz removed
});

test('delta serialisation matches the contract grammar', () => {
  const text = serializeDelta(411, 412, diffIndexes(OLD, NEW));
  assert.equal(text.split('\n')[0], '# moat-packages-delta v1');
  assert.equal(text.split('\n')[1], '# from 411');
  assert.equal(text.split('\n')[2], '# to 412');
  const body = text.split('\n').slice(3).filter(Boolean);
  assert.deepEqual(body, [
    '+\tnpm\t@aspect-adv-ui/consent-manager\t*',
    '+\tnpm\t@scope/thing\t=1.0.0|=1.0.1',
    '-\tnpm\tzzz',
  ]);
  // removals carry no spec field
  assert.equal(body[2].split('\t').length, 3);
});

test('apply(delta, old) == new', () => {
  const round = parseDelta(serializeDelta(411, 412, diffIndexes(OLD, NEW)));
  assert.equal(round.from, 411);
  assert.equal(round.to, 412);
  const applied = applyOps(clone(OLD), round.ops);
  assert.deepEqual([...applied].sort(), [...NEW].sort());
  // and the artifact it produces is identical, byte for byte
  assert.equal(serializeArtifact(applied, 'T'), serializeArtifact(NEW, 'T'));
});

test('applying a delta is idempotent and order-independent', () => {
  const ops = parseDelta(serializeDelta(1, 2, diffIndexes(OLD, NEW))).ops;
  const once = applyOps(clone(OLD), ops);
  const twice = applyOps(applyOps(clone(OLD), ops), ops);
  const reversed = applyOps(clone(OLD), [...ops].reverse());
  assert.deepEqual([...once].sort(), [...twice].sort());
  assert.deepEqual([...once].sort(), [...reversed].sort());
});

test('a delta over a no-op change is empty', () => {
  assert.deepEqual(diffIndexes(OLD, clone(OLD)), []);
});

test('diffSorted (merge join) agrees with diffIndexes', async () => {
  const oldLines = [...artifactLines(OLD, 'T')].map((l) => l.slice(0, -1));
  const keys = sortedKeys(NEW);
  const merged = await diffSorted(oldLines, keys, NEW);
  assert.deepEqual(merged, diffIndexes(OLD, NEW));
  assert.deepEqual([...applyOps(clone(OLD), merged)].sort(), [...NEW].sort());
});

test('diffSorted handles empty sides', async () => {
  const empty = new Map();
  assert.deepEqual(await diffSorted([], sortedKeys(NEW), NEW), diffIndexes(empty, NEW));
  const oldLines = [...artifactLines(OLD, 'T')].map((l) => l.slice(0, -1));
  assert.deepEqual(await diffSorted(oldLines, [], empty), diffIndexes(OLD, empty));
});

test('composed deltas equal applying the chain in order', () => {
  const MID = idx({ ...Object.fromEntries(OLD), 'npm\tmid': '*', 'npm\tzzz': '=3' });
  const a = diffIndexes(OLD, MID);
  const b = diffIndexes(MID, NEW);
  const composed = composeOps(a, b);
  assert.deepEqual([...applyOps(clone(OLD), composed)].sort(), [...NEW].sort());
  assert.deepEqual(
    [...applyOps(applyOps(clone(OLD), a), b)].sort(),
    [...applyOps(clone(OLD), composed)].sort(),
  );
  // a key added then removed composes to a single removal
  assert.ok(composed.every((o) => o.key !== 'npm\tmid' || o.op === '-'));
});

test('a client applying delta chains 1..N lands on the same index', () => {
  // three sequences, each with adds, removes and spec changes
  const s1 = idx({ 'npm\ta': '*', 'npm\tb': '=1' });
  const s2 = idx({ 'npm\ta': '*', 'npm\tb': '=1|=2', 'npm\tc': '*' });
  const s3 = idx({ 'npm\tb': '=1|=2', 'npm\tc': '=9', 'pypi\td': '*' });
  const d12 = parseDelta(serializeDelta(1, 2, diffIndexes(s1, s2))).ops;
  const d23 = parseDelta(serializeDelta(2, 3, diffIndexes(s2, s3))).ops;
  const chained = applyOps(applyOps(clone(s1), d12), d23);
  assert.deepEqual([...chained].sort(), [...s3].sort());
  // the composed 1->3 delta a client would actually be served
  const d13 = parseDelta(serializeDelta(1, 3, composeOps(d12, d23))).ops;
  assert.deepEqual([...applyOps(clone(s1), d13)].sort(), [...s3].sort());
});
