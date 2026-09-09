// moat-packages v1 normalisation.
//
// A faithful port of the reference normalizer (scratchpad/normalize.py) that
// was validated against the real corpus: 241,815 entries from 237,352 OSSF
// records + 50,438 Datadog records. test/normalize.test.mjs asserts this
// module reproduces that output byte for byte.

/** OSV / Datadog ecosystem spellings -> moat canonical name (PACKAGE-FEED.md). */
export const ECO = {
  npm: 'npm',
  PyPI: 'pypi',
  pypi: 'pypi',
  'crates.io': 'crates.io',
  Go: 'go',
  RubyGems: 'rubygems',
  NuGet: 'nuget',
  Maven: 'maven',
  Packagist: 'packagist',
  VSCode: 'vscode',
  'VSCode:https://open-vsx.org': 'vscode',
  ide_extensions: 'vscode',
  'ai-skills': 'ai-skills',
};

export const DATADOG_MANIFESTS = [
  { eco: 'npm', path: 'samples/npm/manifest.json' },
  { eco: 'pypi', path: 'samples/pypi/manifest.json' },
  { eco: 'ai-skills', path: 'samples/ai-skills/manifest.json' },
  { eco: 'ide_extensions', path: 'samples/ide_extensions/manifest.json' },
];

export function newStats() {
  return {
    ossf_records: 0,
    ossf_withdrawn_by_field: 0,
    ossf_withdrawn_by_path_only: 0,
    ossf_unparsable: 0,
    datadog_records: 0,
    range_with_fixed: 0,
    range_with_last_affected: 0,
    affected_without_version_info: 0,
    skipped_unknown_ecosystem: 0,
    skipped_malformed_name: 0,
    pypi_names_normalized: 0,
  };
}

const bump = (s, k) => { if (s) s[k] = (s[k] || 0) + 1; };

// --- ordering ---------------------------------------------------------------
//
// The artifact is sorted in byte order over the whole line (PACKAGE-FEED.md).
// For strings with no surrogate pair, JS `<` is already UTF-8 byte order; only
// astral characters need the slower code-point walk.
const SURROGATE = /[\uD800-\uDFFF]/;

export function cmpBytes(a, b) {
  if (a === b) return 0;
  if (!SURROGATE.test(a) && !SURROGATE.test(b)) return a < b ? -1 : 1;
  const ai = a[Symbol.iterator](), bi = b[Symbol.iterator]();
  for (;;) {
    const x = ai.next(), y = bi.next();
    if (x.done) return y.done ? 0 : -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0), cy = y.value.codePointAt(0);
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

/**
 * Compare two index keys (`eco\tname`) as if each were followed by the `\t`
 * that separates it from the spec, so ordering matches a byte sort over whole
 * artifact lines without having to materialise them.
 */
export function cmpLineKeys(a, b) {
  const c = cmpBytes(a, b);
  if (c !== 0) {
    // the only case where key order and line order can disagree is a strict
    // prefix, where the shorter line continues with a tab (0x09).
    if (c < 0 && b.length > a.length && b.startsWith(a)) {
      const next = b.charCodeAt(a.length);
      return next < 9 ? 1 : -1;
    }
    if (c > 0 && a.length > b.length && a.startsWith(b)) {
      const next = a.charCodeAt(b.length);
      return next < 9 ? -1 : 1;
    }
  }
  return c;
}

// --- clause derivation ------------------------------------------------------

/**
 * Clauses for one OSV `affected` entry.
 *
 *   *          every version
 *   =V         exactly V
 *   >=V        introduced at V, no fix known
 *   >=I,<F     introduced I, fixed F
 *   >=I,<=L    introduced I, last affected L
 *
 * @returns {string[]} unique, unsorted
 */
export function clausesFromAffected(a, stats) {
  const out = new Set();
  const versions = a && a.versions;
  if (Array.isArray(versions) && versions.length) {
    for (const v of versions) out.add('=' + String(v));
  }
  const ranges = (a && a.ranges) || [];
  for (const r of ranges) {
    let intro = null, fixed = null, last = null;
    for (const ev of (r && r.events) || []) {
      if (ev && 'introduced' in ev) intro = String(ev.introduced);
      if (ev && 'fixed' in ev) fixed = String(ev.fixed);
      if (ev && 'last_affected' in ev) last = String(ev.last_affected);
    }
    if (fixed) {
      bump(stats, 'range_with_fixed');
      out.add('>=' + (intro || '0') + ',<' + fixed);
    } else if (last) {
      bump(stats, 'range_with_last_affected');
      out.add('>=' + (intro || '0') + ',<=' + last);
    } else if (intro === null || intro === '0') {
      out.add('*');
    } else {
      out.add('>=' + intro);
    }
  }
  if (out.size === 0) {
    bump(stats, 'affected_without_version_info');
    out.add('*'); // advisory names the package but no range: assume all
  }
  return [...out];
}

/** Collapse a clause list to a spec: `*` absorbs everything. */
export function collapse(clauses) {
  for (const c of clauses) if (c === '*') return '*';
  return [...new Set(clauses)].sort(cmpBytes).join('|');
}

const PEP503 = /[-_.]+/g;

/**
 * PyPI names are case- and separator-insensitive (PEP 503), so the feed must
 * carry ONE spelling or a lookup cannot find them: consumers binary-search the
 * artifact in byte order, which rules out normalising at lookup time.
 * `CalcBoxLite` emitted verbatim meant `pip install calcboxlite` — the same
 * package — matched nothing.
 *
 * Every other ecosystem is left verbatim: npm registry names are already
 * lowercase, and crates.io, Go and Maven treat case and separators as
 * significant, so folding them would merge genuinely distinct packages.
 */
export function canonicalName(eco, name) {
  return eco === 'pypi' ? name.replace(PEP503, '-').toLowerCase() : name;
}

/** A name must survive a tab-separated, LF-terminated line. */
function nameOk(name) {
  return typeof name === 'string' && name.length > 0 &&
    name.indexOf('\t') < 0 && name.indexOf('\n') < 0 && name.indexOf('\r') < 0;
}

/**
 * The (ecosystem, name, clauses) contributions of one OSV document.
 * Returns [] for a withdrawn or unusable record.
 *
 * @param {object} doc parsed OSV JSON
 * @param {string} path repo-relative path, only used for the withdrawn-by-path
 *        belt-and-braces check the reference normalizer also performs
 */
export function osvContributions(doc, path, stats) {
  // Trust the record, not the path: withdrawn records carry a `withdrawn` field.
  if (doc && doc.withdrawn) { bump(stats, 'ossf_withdrawn_by_field'); return []; }
  if (path && ('/' + path).includes('/osv/withdrawn/')) {
    bump(stats, 'ossf_withdrawn_by_path_only');
    return [];
  }
  bump(stats, 'ossf_records');
  const out = [];
  for (const a of (doc && doc.affected) || []) {
    const p = (a && a.package) || {};
    const eco = ECO[p.ecosystem || ''];
    if (!eco || !p.name) { bump(stats, 'skipped_unknown_ecosystem'); continue; }
    const name = canonicalName(eco, p.name);
    if (name !== p.name) bump(stats, 'pypi_names_normalized');
    if (!nameOk(name)) { bump(stats, 'skipped_malformed_name'); continue; }
    out.push({ eco, name, clauses: clausesFromAffected(a, stats) });
  }
  return out;
}

/** Contributions of one Datadog manifest: {"pkg": null | ["1.0.0", ...]}. */
export function datadogContributions(ecoRaw, manifest, stats) {
  const out = [];
  for (const [raw, vers] of Object.entries(manifest || {})) {
    bump(stats, 'datadog_records');
    const eco = ECO[ecoRaw];
    if (!eco || !raw) { bump(stats, 'skipped_unknown_ecosystem'); continue; }
    const name = canonicalName(eco, raw);
    if (name !== raw) bump(stats, 'pypi_names_normalized');
    if (!nameOk(name)) { bump(stats, 'skipped_malformed_name'); continue; }
    const clauses = (!vers || vers.length === 0)
      ? ['*']
      : vers.map((v) => '=' + String(v));
    out.push({ eco, name, clauses });
  }
  return out;
}

// --- the records state file -------------------------------------------------
//
// `state/records.tsv.gz` holds one line per (source record, affected package):
//
//     <rid>\t<eco>\t<name>\t<spec>
//
// `rid` identifies the upstream record so an incremental tick can delete
// exactly the lines a changed or removed upstream file contributed, without
// re-reading the 44 MB tarball. For OSSF it is a 64-bit hash of the repo path;
// for Datadog it is `dd:<eco>`, since a manifest is always replaced wholesale.

/** 64-bit FNV-1a-ish hash of a path, 16 hex chars. Collision risk at 300k
 *  records is ~2e-9; a collision would only mean one record outlives its
 *  upstream deletion until the next full rebuild. */
export function rid(path) {
  let h1 = 0x811c9dc5, h2 = 0x9e3779b9;
  for (let i = 0; i < path.length; i++) {
    const c = path.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193);
    h2 = Math.imul(h2 ^ c, 0x85ebca6b);
  }
  h2 = Math.imul(h2 ^ path.length, 0x27d4eb2f);
  return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
}

export const ddRid = (eco) => 'dd:' + eco;

/** The OSSF files we care about, matching the reference normalizer's filter.
 *  Works for both tarball member names (`<root>/osv/...`) and repo-relative
 *  paths (`osv/...`). */
export function isOsvPath(name) {
  return name.endsWith('.json') && ('/' + name).includes('/osv/');
}

export function recordLine(id, c) {
  return id + '\t' + c.eco + '\t' + c.name + '\t' + collapse(c.clauses);
}

/** Fold one contribution into the index. */
export function foldInto(index, key, spec) {
  const prev = index.get(key);
  if (prev === undefined) index.set(key, spec);
  else if (prev === '*' || spec === '*') index.set(key, '*');
  else if (prev !== spec) index.set(key, mergeSpecs(prev, spec));
}

/**
 * Fold record lines into the package index.
 * @param {Iterable<string>} lines
 * @param {Map<string,string>} [into] key `eco\tname` -> spec
 */
export function foldRecords(lines, into = new Map()) {
  for (const line of lines) {
    if (!line) continue;
    const t1 = line.indexOf('\t');
    const t2 = line.indexOf('\t', t1 + 1);
    const t3 = line.indexOf('\t', t2 + 1);
    if (t1 < 0 || t2 < 0 || t3 < 0) continue;
    foldInto(into, line.slice(t1 + 1, t3), line.slice(t3 + 1));
  }
  return into;
}

export function mergeSpecs(a, b) {
  if (a === '*' || b === '*') return '*';
  return collapse(a.split('|').concat(b.split('|')));
}

// --- artifact serialisation -------------------------------------------------

export function sortedKeys(index) {
  const keys = new Array(index.size);
  let i = 0;
  for (const key of index.keys()) keys[i++] = key;
  keys.sort(cmpLineKeys);
  return keys;
}

/** The artifact, line by line, without ever holding it whole.
 *  Pass `keys` when you already sorted them (the publisher needs them twice). */
export function* artifactLines(index, generated, keys) {
  yield '# moat-packages v1\n';
  yield '# generated ' + generated + '\n';
  yield '# entries ' + index.size + '\n';
  for (const key of (keys || sortedKeys(index))) yield key + '\t' + index.get(key) + '\n';
}

export function serializeArtifact(index, generated) {
  let out = '';
  for (const l of artifactLines(index, generated)) out += l;
  return out;
}

/** Parse a full artifact back into an index map (used to diff against R2). */
export function parseArtifact(text) {
  const index = new Map();
  let pos = 0;
  while (pos < text.length) {
    let nl = text.indexOf('\n', pos);
    if (nl < 0) nl = text.length;
    const line = text.slice(pos, nl);
    pos = nl + 1;
    if (!line || line.charCodeAt(0) === 35 /* # */) continue;
    const t = line.lastIndexOf('\t');
    if (t < 0) continue;
    index.set(line.slice(0, t), line.slice(t + 1));
  }
  return index;
}

export const isoNow = (d = new Date()) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
