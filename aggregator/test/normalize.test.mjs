import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, createReadStream } from 'node:fs';
import { Readable } from 'node:stream';
import { join } from 'node:path';

import {
  clausesFromAffected, collapse, osvContributions, datadogContributions,
  newStats, serializeArtifact, cmpLineKeys, canonicalName, ECO,
} from '../src/normalize.js';
import { buildFull } from '../src/build.js';
import { makeTarGz } from './helpers.mjs';

const stream = (bytes) => new ReadableStream({ start(c) { c.enqueue(bytes); c.close(); } });

test('clause derivation matches the reference grammar', () => {
  const s = newStats();
  assert.deepEqual(clausesFromAffected({ versions: ['1.0.0', '1.0.1'] }, s).sort(), ['=1.0.0', '=1.0.1']);
  assert.deepEqual(clausesFromAffected({}, s), ['*']);
  assert.equal(s.affected_without_version_info, 1);

  // introduced 0 with no fix is "every version"
  assert.deepEqual(clausesFromAffected({ ranges: [{ events: [{ introduced: '0' }] }] }, s), ['*']);
  // a range with no usable event is also "every version"
  assert.deepEqual(clausesFromAffected({ ranges: [{ events: [{}] }] }, s), ['*']);
  // introduced only
  assert.deepEqual(clausesFromAffected({ ranges: [{ events: [{ introduced: '1.2.3' }] }] }, s), ['>=1.2.3']);
  // fixed wins over last_affected, and defaults introduced to 0
  assert.deepEqual(
    clausesFromAffected({ ranges: [{ events: [{ fixed: '2.0.0' }, { last_affected: '1.9' }] }] }, s),
    ['>=0,<2.0.0'],
  );
  assert.deepEqual(
    clausesFromAffected({ ranges: [{ events: [{ introduced: '1.0' }, { last_affected: '1.9' }] }] }, s),
    ['>=1.0,<=1.9'],
  );
  assert.equal(s.range_with_fixed, 1);
  assert.equal(s.range_with_last_affected, 1);

  // versions and ranges combine, and numbers are stringified as str() does
  assert.deepEqual(
    clausesFromAffected({ versions: [1], ranges: [{ events: [{ introduced: '2' }] }] }, s).sort(),
    ['=1', '>=2'],
  );
});

test('pypi names are PEP 503 normalized and nothing else is', () => {
  assert.equal(canonicalName('pypi', 'CalcBoxLite'), 'calcboxlite');
  assert.equal(canonicalName('pypi', 'M-AT-STAR-Tools'), 'm-at-star-tools');
  assert.equal(canonicalName('pypi', 'Zope.Interface__x'), 'zope-interface-x');
  assert.equal(canonicalName('pypi', 'already-fine'), 'already-fine');
  // every other ecosystem is verbatim: folding them would merge distinct packages
  for (const eco of ['npm', 'crates.io', 'go', 'maven', 'rubygems', 'nuget', 'packagist', 'vscode', 'ai-skills']) {
    assert.equal(canonicalName(eco, 'Foo_Bar.Baz'), 'Foo_Bar.Baz');
  }

  const s = newStats();
  const out = osvContributions({
    affected: [{ package: { ecosystem: 'PyPI', name: 'Calc_Box.Lite' }, versions: ['1.0'] }],
  }, 'osv/malicious/pypi/x/MAL-1.json', s);
  assert.deepEqual(out.map((c) => c.name), ['calc-box-lite']);
  assert.equal(s.pypi_names_normalized, 1);

  // datadog manifests go through the same canonicalisation
  const s2 = newStats();
  assert.deepEqual(datadogContributions('pypi', { 'Some_Pkg': null }, s2).map((c) => c.name), ['some-pkg']);
  assert.equal(s2.pypi_names_normalized, 1);
});

test('normalisation collisions merge with the usual union', () => {
  const s = newStats();
  const out = osvContributions({
    affected: [
      { package: { ecosystem: 'PyPI', name: 'Roblox.Com' }, versions: ['1.0'] },
      { package: { ecosystem: 'PyPI', name: 'roblox-com' }, versions: ['2.0'] },
    ],
  }, 'p.json', s);
  assert.deepEqual(out.map((c) => c.name), ['roblox-com', 'roblox-com']);
  const index = new Map();
  for (const c of out) {
    const key = c.eco + '\t' + c.name;
    index.set(key, index.has(key) ? collapse([index.get(key), ...c.clauses]) : collapse(c.clauses));
  }
  assert.equal(index.get('pypi\troblox-com'), '=1.0|=2.0');
});

test('* absorbs every other clause', () => {
  assert.equal(collapse(['=1.0.0', '*', '>=2']), '*');
  assert.equal(collapse(['=1.0.0', '=0.9']), '=0.9|=1.0.0');
  assert.equal(collapse(['=1', '=1']), '=1');
});

test('unknown ecosystems are dropped and counted, never guessed', () => {
  const s = newStats();
  const out = osvContributions({
    affected: [
      { package: { ecosystem: 'Hackage', name: 'x' } },
      { package: { ecosystem: 'PyPI', name: 'y' } },
      { package: { ecosystem: 'npm' } },
    ],
  }, 'osv/malicious/x.json', s);
  assert.deepEqual(out.map((c) => c.eco + '/' + c.name), ['pypi/y']);
  assert.equal(s.skipped_unknown_ecosystem, 2);
  assert.equal(s.ossf_records, 1);
});

test('every canonical ecosystem in the contract is mapped', () => {
  assert.deepEqual([...new Set(Object.values(ECO))].sort(),
    ['ai-skills', 'crates.io', 'go', 'maven', 'npm', 'nuget', 'packagist', 'pypi', 'rubygems', 'vscode']);
  assert.equal(ECO['VSCode:https://open-vsx.org'], 'vscode');
  assert.equal(ECO.ide_extensions, 'vscode');
});

test('withdrawn is decided by the OSV field, not the path', () => {
  const s = newStats();
  assert.deepEqual(osvContributions(
    { withdrawn: '2026-01-01T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'w' } }] },
    'osv/malicious/npm/w/MAL-1.json', s), []);
  assert.equal(s.ossf_withdrawn_by_field, 1);
  assert.equal(s.ossf_withdrawn_by_path_only, 0);
  // path is only a belt-and-braces second gate; on the real corpus it catches 0
  assert.deepEqual(osvContributions(
    { affected: [{ package: { ecosystem: 'npm', name: 'w' } }] },
    'osv/withdrawn/npm/w/MAL-1.json', s), []);
  assert.equal(s.ossf_withdrawn_by_path_only, 1);
});

test('datadog manifests: null and [] mean every version', () => {
  const s = newStats();
  const out = datadogContributions('npm', { a: null, b: [], c: ['1.0.0'] }, s);
  assert.deepEqual(out.map((c) => c.name + ':' + collapse(c.clauses)), ['a:*', 'b:*', 'c:=1.0.0']);
  assert.equal(s.datadog_records, 3);
});

test('key ordering equals a byte sort over whole lines', () => {
  assert.ok(cmpLineKeys('npm\tfoo', 'npm\tfoobar') < 0);
  assert.ok(cmpLineKeys('npm\tb', 'npm\ta') > 0);
  // a name continuing with a byte below tab sorts before the shorter line,
  // because the shorter line continues with the tab before its spec
  assert.ok(cmpLineKeys('npm\tfoo', 'npm\tfoo') > 0);
});

test('end-to-end fixture: tarball + manifests -> artifact', async () => {
  const files = [
    {
      name: 'x-main/osv/malicious/npm/evil/MAL-0001.json',
      body: JSON.stringify({ id: 'MAL-0001', affected: [{ package: { ecosystem: 'npm', name: 'evil' } }] }),
    },
    {
      name: 'x-main/osv/malicious/pypi/requestss/MAL-0002.json',
      body: JSON.stringify({ id: 'MAL-0002', affected: [{ package: { ecosystem: 'PyPI', name: 'Request_ss' }, versions: ['0.1', '0.2'] }] }),
    },
    {
      // a long path, so the pax branch of the tar reader is exercised
      name: 'x-main/osv/malicious/crates.io/' + 'a'.repeat(90) + '/MAL-0003.json',
      body: JSON.stringify({ id: 'MAL-0003', affected: [{ package: { ecosystem: 'crates.io', name: 'append-only-vec' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0.1.9' }, { fixed: '0.1.10' }] }] }] }),
    },
    {
      name: 'x-main/osv/withdrawn/npm/gone/MAL-0004.json',
      body: JSON.stringify({ id: 'MAL-0004', withdrawn: '2026-01-01T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'gone' } }] }),
    },
    {
      name: 'x-main/osv/malicious/hackage/nope/MAL-0005.json',
      body: JSON.stringify({ id: 'MAL-0005', affected: [{ package: { ecosystem: 'Hackage', name: 'nope' } }] }),
    },
    { name: 'x-main/README.md', body: 'ignored' },
    { name: 'x-main/osv/malicious/npm/broken/MAL-0006.json', body: '{not json' },
  ];
  const { index, stats } = await buildFull(stream(await makeTarGz(files)), [
    { eco: 'npm', manifest: { evil: ['9.9.9'], '@scope/pkg': null } },
    { eco: 'ide_extensions', manifest: { 'some.ext': ['1.0'] } },
  ]);
  assert.equal(stats.ossf_unparsable, 1);
  assert.equal(stats.skipped_unknown_ecosystem, 1);
  assert.equal(stats.ossf_withdrawn_by_field, 1);

  const expected = [
    '# moat-packages v1',
    '# generated 2026-09-09T18:36:13Z',
    '# entries 5',
    'crates.io\tappend-only-vec\t>=0.1.9,<0.1.10',
    'npm\t@scope/pkg\t*',
    'npm\tevil\t*', // OSV says every version; * absorbs Datadog's =9.9.9
    'pypi\trequest-ss\t=0.1|=0.2', // PEP 503: Request_ss -> request-ss
    'vscode\tsome.ext\t=1.0',
    '',
  ].join('\n');
  assert.equal(serializeArtifact(index, '2026-09-09T18:36:13Z'), expected);
});

// The full-corpus equivalence check. Point MOAT_CORPUS at a directory holding
// ossf.tar.gz, m_npm.json, m_pypi.json, m_ai-skills.json, m_ide_extensions.json
// and packages.txt (the reference normalizer's output).
const corpus = process.env.MOAT_CORPUS;
test('byte-identical to the reference normalizer on the real corpus',
  { skip: corpus && existsSync(join(corpus, 'ossf.tar.gz')) ? false : 'set MOAT_CORPUS to a corpus directory' },
  async () => {
    const dd = [['npm', 'm_npm.json'], ['pypi', 'm_pypi.json'],
      ['ai-skills', 'm_ai-skills.json'], ['ide_extensions', 'm_ide_extensions.json']]
      .map(([eco, f]) => ({ eco, manifest: JSON.parse(readFileSync(join(corpus, f), 'utf8')) }));
    const { index, stats } = await buildFull(
      Readable.toWeb(createReadStream(join(corpus, 'ossf.tar.gz'))), dd);

    assert.equal(index.size, 241813); // two PEP 503 collisions fold
    assert.equal(stats.ossf_records, 237352);
    assert.equal(stats.datadog_records, 50438);
    assert.equal(stats.ossf_withdrawn_by_field, 365);
    assert.equal(stats.range_with_fixed, 34);
    assert.equal(stats.range_with_last_affected, 138);
    assert.equal(stats.pypi_names_normalized, 21);

    const reference = readFileSync(join(corpus, 'packages.txt'), 'utf8');
    const generated = /^# generated (.*)$/m.exec(reference)[1];
    assert.equal(serializeArtifact(index, generated), reference);
  });
