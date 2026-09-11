// The domain wing: a signed list of malicious hostnames, built from ThreatFox.
//
// # Why this feed exists at all
//
// moatd learns the hostname behind a connection from systemd-resolved (see
// docs/DNS.md), which gives it `process -> pid -> domain`. Until now the thing
// it checked that name against was `feeds/domains.txt`, an OPERATOR-supplied
// file -- which on a normal machine is empty, so the rule never fired. This
// publishes the list that makes it fire.
//
// # Why ThreatFox, and why no API key
//
// abuse.ch was dropped from moat once before because all three of its feeds
// wanted an `Auth-Key`, and a key shipped in a package is not a key. That
// reasoning does not survive the aggregator: one key here would have served the
// whole fleet. It turns out not to be needed either way -- the JSON API is
// authenticated, but the BULK EXPORTS are not, and the bulk exports are what a
// feed builder wants. Both endpoints below answer 200 with no credential.
//
// The reason ThreatFox and not a union of everything: it ages its own IOCs out.
// Roughly 50k domains are live at any time, against ~106k rows in the full
// dump, and a domain blocklist that only ever grows is a false-positive
// generator with a six-month fuse. Somebody else doing the expiry is the
// single most valuable property on offer.
//
// # The two sources, and which one is authoritative
//
//   downloads/hostfile/   plain text, 1.6 MB, ~48k domains. This is abuse.ch's
//                         own answer to "which of these are live right now",
//                         and it is THE CORPUS. Cheap enough for the 15-minute
//                         tick.
//   export/csv/full/      a 3 MB zip holding 23 MB of CSV. Carries malware
//                         family, confidence and the compromised flag. This is
//                         METADATA ONLY, read on the daily run.
//
// They are deliberately not unioned. The full CSV lists ~2.2k domains the
// hostfile does not, and taking the union would make the published set oscillate
// between the daily run and the tick -- a new sequence, a new artifact and a
// fresh download for every machine, twice a day, describing no real change.
// The hostfile decides membership; the CSV only decorates it. A domain the
// hostfile has and the CSV has not yet seen is published with family `unknown`,
// which is honest and costs nothing.

import { unzipLines } from './zip.js';

export const THREATFOX_HOSTFILE = 'https://threatfox.abuse.ch/downloads/hostfile/';
export const THREATFOX_CSV_FULL = 'https://threatfox.abuse.ch/export/csv/full/';
export const PSL_URL = 'https://publicsuffix.org/list/public_suffix_list.dat';

/** Below this, ThreatFox is telling us it is not sure. */
export const DEFAULT_MIN_CONFIDENCE = 50;

/**
 * Hostnames that must never reach a client no matter who reports them.
 *
 * This is NOT a general top-sites allowlist -- the public suffix gate below
 * does the structural work, and abuse.ch does not report bare registrable
 * domains of major services. It is the short list of names whose appearance
 * would break moat itself or the machine it runs on: an alert storm on the
 * package mirror during an upgrade is the failure mode that would get the whole
 * feature turned off.
 */
export const NEVER = new Set([
  // moat's own plumbing
  'feed.runts.net', 'runts.net',
  // Arch / Omarchy
  'archlinux.org', 'mirror.archlinux.org', 'geo.mirror.pkgbuild.com',
  'aur.archlinux.org', 'omarchy.org', 'manjaro.org',
  // the registries the scanners front
  'registry.npmjs.org', 'npmjs.com', 'pypi.org', 'files.pythonhosted.org',
  'crates.io', 'static.crates.io', 'rubygems.org', 'packagist.org', 'proxy.golang.org',
  // source hosts and the CDNs everything above sits on
  'github.com', 'api.github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com',
  'codeload.github.com', 'gitlab.com', 'cloudflare.com', 'abuse.ch', 'threatfox.abuse.ch',
  // name resolution itself
  'publicsuffix.org', 'one.one.one.one', 'dns.google', 'cloudflare-dns.com',
]);

// --------------------------------------------------------------- normalisation

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const LABEL_OK = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/;

/**
 * Lowercase, drop the root dot, and reject anything that is not a hostname.
 *
 * Note what is NOT done: `www.` is not stripped. `www.abc-network.it` is a
 * real ThreatFox entry and the bare domain is not -- stripping it would widen
 * the entry from one host to a whole site, which is the wrong direction for a
 * list matched by suffix.
 *
 * @returns {string|null}
 */
export function normalizeDomain(raw) {
  if (typeof raw !== 'string') return null;
  let d = raw.trim().toLowerCase();
  if (!d || d.startsWith('#')) return null;
  while (d.endsWith('.')) d = d.slice(0, -1);
  if (!d || d.length > 253) return null;
  // A URL, a port or a path means the row was not a bare domain.
  if (/[/\\:@\s?#]/.test(d)) return null;
  if (IPV4.test(d)) return null;

  // Punycode, because that is the form the name arrives in.
  //
  // ThreatFox reports what a human typed -- `bbautokozmetika.hu` shows up as
  // `bbautókozmetika.hu`. What moatd sees is a DNS query, and DNS carries the
  // A-label: `xn--bbautkozmetika-pob.hu`. Comparing one against the other never
  // matches, so a Unicode entry left as-is is not a strict entry, it is a dead
  // one. Ten of them are in today's feed.
  if (/[^\x00-\x7f]/.test(d)) {
    let ascii = null;
    try { ascii = new URL('https://' + d).hostname; } catch { return null; }
    if (!ascii || /[^\x00-\x7f]/.test(ascii)) return null;
    d = ascii.toLowerCase();
  }

  const labels = d.split('.');
  if (labels.length < 2) return null;
  for (const l of labels) {
    if (!l || l.length > 63 || !LABEL_OK.test(l)) return null;
  }
  return d;
}

// --------------------------------------------------------- the public suffix gate

/**
 * Parse publicsuffix.org's list into the three rule sets it actually has.
 *
 * @returns {{exact: Set<string>, wild: Set<string>, except: Set<string>}}
 */
export function parsePsl(text) {
  const exact = new Set();
  const wild = new Set();
  const except = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('//')) continue;
    const rule = line.split(/\s/)[0].toLowerCase();
    if (!rule) continue;
    if (rule.startsWith('!')) except.add(rule.slice(1));
    else if (rule.startsWith('*.')) wild.add(rule.slice(2));
    else exact.add(rule);
  }
  return { exact, wild, except };
}

/**
 * Is `domain` a name under which UNRELATED parties register?
 *
 * This is the gate that matters, and it is worth being precise about why.
 * moatd matches the feed by SUFFIX: `Feeds::domain_hit` walks a resolved name
 * up through its parents, so an entry of `evil.example` fires on
 * `cdn.evil.example`. That is correct for a campaign rotating its leftmost
 * label, and catastrophic for an entry like `workers.dev` -- one bad row
 * upstream and every Cloudflare Worker on the internet is an IOC.
 *
 * # Why this is not simply "is it a public suffix"
 *
 * It was, and that was wrong, and the live feed said so: 56 entries tripped it
 * and 50 of them were `<random>.localto.net` tunnels -- real, current C2 that
 * would have been silently thrown away. The PSL lists `*.localto.net` so that
 * browsers isolate one tunnel from another, which makes each
 * `ratted.localto.net` a public suffix by the letter of the algorithm and, in
 * the sense that matters here, a single tenant's host: nobody unrelated
 * registers beneath it. `ec2-18-208-244-120.compute-1.amazonaws.com` is one
 * EC2 instance, for the same reason.
 *
 * So the test is the wildcard BASE, not the wildcard instance:
 *
 *   workers.dev                             exact rule -> shared, drop
 *   compute-1.amazonaws.com                 base of `*.` -> shared, drop
 *   ec2-18-208-244-120.compute-1.amazonaws.com   one instance -> keep
 *   ratted.localto.net                      one tunnel -> keep
 *
 * The cost of that choice, stated plainly: `*.kobe.jp` is a wildcard of the
 * other kind, where each instance really is a registry for the public. An
 * entry of `osaka.kobe.jp` would get through and over-match. Nothing in the
 * PSL distinguishes the two cases, every wildcard hit in the live feed is the
 * tenant kind, and losing 50 live C2 domains to guard against a row that has
 * never appeared is the worse trade.
 */
export function isSharedSuffix(domain, psl) {
  if (!psl) return false;
  if (psl.except.has(domain)) return false;
  return psl.exact.has(domain) || psl.wild.has(domain);
}

// ------------------------------------------------------------------- upstream

/**
 * One line of abuse.ch CSV: `"a", "b", "c"`, quoted, `, `-separated, and tags
 * hold commas. A split on `,` gets this wrong on roughly one row in six.
 */
export function parseCsvLine(line) {
  const out = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"') {
        if (line[i + 1] === '"') { field += '"'; i++; }
        else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { out.push(field.trim()); field = ''; }
    else field += c;
  }
  out.push(field.trim());
  return out;
}

// Column order of export/csv/full, from the `#` header row abuse.ch ships.
const C_FIRST_SEEN = 0;
const C_IOC = 2;
const C_TYPE = 3;
const C_THREAT = 4;
const C_PRINTABLE = 7;
const C_CONFIDENCE = 9;
const C_COMPROMISED = 10;
const MIN_COLUMNS = 11;

export const newDomainStats = () => ({
  csv_rows: 0, csv_domains: 0, csv_malformed: 0,
  hostfile_lines: 0, hostfile_domains: 0, hostfile_rejected: 0,
  dropped_shared_suffix: 0, dropped_never: 0, dropped_confidence: 0,
  no_metadata: 0, compromised: 0,
});

/**
 * Build the metadata table from the full CSV dump.
 *
 * Only `ioc_type == domain` is taken. The 12k `url` rows also carry a hostname,
 * and it is tempting free coverage -- but a URL IOC is usually a legitimate
 * site with one malicious path on it, so promoting its host to a domain IOC
 * would alert on the whole site. abuse.ch draws that line itself by not putting
 * those hosts in the hostfile, and this follows it.
 *
 * @returns {Promise<Map<string, {family:string, confidence:number, compromised:boolean, firstSeen:string}>>}
 */
export async function threatFoxMetadata(lines, stats) {
  const meta = new Map();
  for await (const line of lines) {
    if (!line || line.startsWith('#')) continue;
    stats.csv_rows++;
    const f = parseCsvLine(line);
    if (f.length < MIN_COLUMNS) { stats.csv_malformed++; continue; }
    if (f[C_TYPE] !== 'domain') continue;
    const domain = normalizeDomain(f[C_IOC]);
    if (!domain) { stats.csv_malformed++; continue; }
    const confidence = Number(f[C_CONFIDENCE]);
    const rec = {
      family: f[C_PRINTABLE] && f[C_PRINTABLE] !== 'None' ? f[C_PRINTABLE] : (f[C_THREAT] || 'unknown'),
      confidence: Number.isFinite(confidence) ? confidence : 0,
      compromised: f[C_COMPROMISED] === 'True',
      firstSeen: (f[C_FIRST_SEEN] || '').slice(0, 10),
    };
    // Rows repeat a domain across campaigns. Keep the most confident, and on a
    // tie the newest -- the alert quotes one family and it should be the one
    // abuse.ch is surest about.
    const prev = meta.get(domain);
    if (!prev || rec.confidence > prev.confidence
        || (rec.confidence === prev.confidence && rec.firstSeen > prev.firstSeen)) {
      meta.set(domain, rec);
    }
    stats.csv_domains++;
  }
  return meta;
}

/** The hostfile is `127.0.0.1<TAB>domain` with a `#` banner. */
export function hostfileDomains(text, stats) {
  const out = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    stats.hostfile_lines++;
    const parts = line.split(/\s+/);
    const domain = normalizeDomain(parts.length > 1 ? parts[1] : parts[0]);
    if (!domain) { stats.hostfile_rejected++; continue; }
    out.add(domain);
  }
  stats.hostfile_domains = out.size;
  return out;
}

/** `# Last updated: 2026-09-11 14:18:03 UTC` out of either export's banner. */
export function upstreamStamp(text) {
  const m = /^#\s*Last updated:\s*(.+?)\s*#*\s*$/m.exec(text.slice(0, 4096));
  return m ? m[1].trim() : null;
}

// -------------------------------------------------------------------- the gate

/**
 * Turn the corpus plus the metadata into the map that gets published.
 *
 * @returns {Map<string, {family:string, confidence:number, compromised:boolean, firstSeen:string}>}
 */
export function gateDomains(corpus, meta, psl, minConfidence, stats) {
  const out = new Map();
  for (const domain of corpus) {
    if (NEVER.has(domain)) { stats.dropped_never++; continue; }
    if (isSharedSuffix(domain, psl)) { stats.dropped_shared_suffix++; continue; }
    const m = meta.get(domain);
    if (!m) {
      // In the hostfile but not yet in the CSV snapshot: abuse.ch considers it
      // live, and membership is the hostfile's call. Publish it unadorned
      // rather than silently dropping a fresh IOC for want of a label.
      stats.no_metadata++;
      out.set(domain, { family: 'unknown', confidence: 0, compromised: false, firstSeen: '' });
      continue;
    }
    if (m.confidence && m.confidence < minConfidence) { stats.dropped_confidence++; continue; }
    if (m.compromised) stats.compromised++;
    out.set(domain, m);
  }
  return out;
}

// --------------------------------------------------------------- the artifact

/**
 * `domain \t family \t confidence \t flags \t first-seen`, sorted by domain.
 *
 * Sorted because the client bisects it and because an unsorted artifact would
 * hash differently on every run for no reason. `flags` is a character set, `c`
 * meaning a compromised legitimate site -- moat says so in the alert, since
 * "your browser reached a hacked bakery" and "your shell reached a C2" want
 * very different responses from the person reading it.
 */
export function* domainArtifactLines(accepted, generated, seq, source) {
  yield '# moat-domains v1\n';
  yield '# generated ' + generated + '\n';
  yield '# entries ' + accepted.size + '\n';
  // Inside the signed bytes, for the same reason the package artifact carries
  // it: pointer.json is not signed, so without this a stale-but-validly-signed
  // artifact can be served under a fresh pointer.
  yield '# seq ' + seq + '\n';
  if (source && source.upstream) yield '# upstream ' + source.upstream + '\n';
  yield '# fields domain\tfamily\tconfidence\tflags\tfirst_seen\n';
  for (const domain of [...accepted.keys()].sort()) {
    const m = accepted.get(domain);
    const flags = m.compromised ? 'c' : '-';
    const family = m.family.replace(/[\t\n]/g, ' ');
    yield `${domain}\t${family}\t${m.confidence}\t${flags}\t${m.firstSeen}\n`;
  }
}

/** The metadata table as it is cached in R2 between runs. */
export function* metaTableLines(meta) {
  for (const domain of [...meta.keys()].sort()) {
    const m = meta.get(domain);
    yield `${domain}\t${m.family.replace(/[\t\n]/g, ' ')}\t${m.confidence}\t${m.compromised ? 'c' : '-'}\t${m.firstSeen}\n`;
  }
}

export async function parseMetaTable(lines) {
  const meta = new Map();
  for await (const line of lines) {
    if (!line) continue;
    const f = line.split('\t');
    if (f.length < 5) continue;
    meta.set(f[0], {
      family: f[1], confidence: Number(f[2]) || 0,
      compromised: f[3] === 'c', firstSeen: f[4],
    });
  }
  return meta;
}

export async function* unzipCsvLines(bytes) {
  yield* unzipLines(bytes);
}
