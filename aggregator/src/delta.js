// moat-packages-delta v1 — see PACKAGE-FEED.md.
//
//   +\t<eco>\t<name>\t<spec>   insert or replace; spec is the complete new spec
//   -\t<eco>\t<name>           remove
//
// Applying a delta is idempotent and order-independent within one file.

import { cmpLineKeys } from './normalize.js';

/** @typedef {{op:'+'|'-', key:string, spec?:string}} Op */

export function sortOps(ops) {
  ops.sort((a, b) => cmpLineKeys(a.key, b.key));
  return ops;
}

/**
 * Diff a sorted stream of old artifact lines against the new index, by merge
 * join. Never builds a second 241k-entry map, which is what lets the daily
 * rebuild diff against the previous artifact inside the isolate.
 *
 * @param {AsyncIterable<string>|Iterable<string>} oldLines artifact lines (comments ok)
 * @param {string[]} newKeys keys of newIndex, sorted with cmpLineKeys
 * @param {Map<string,string>} newIndex
 * @returns {Promise<Op[]>}
 */
export async function diffSorted(oldLines, newKeys, newIndex) {
  const ops = [];
  let j = 0;
  const flushNew = (upto) => {
    while (j < upto) {
      const k = newKeys[j++];
      ops.push({ op: '+', key: k, spec: newIndex.get(k) });
    }
  };
  for await (const line of oldLines) {
    if (!line || line.charCodeAt(0) === 35) continue;
    const t = line.lastIndexOf('\t');
    if (t < 0) continue;
    const key = line.slice(0, t);
    const spec = line.slice(t + 1);
    // emit every new key that sorts before this old key
    while (j < newKeys.length && cmpLineKeys(newKeys[j], key) < 0) {
      const k = newKeys[j++];
      ops.push({ op: '+', key: k, spec: newIndex.get(k) });
    }
    if (j < newKeys.length && newKeys[j] === key) {
      const ns = newIndex.get(key);
      if (ns !== spec) ops.push({ op: '+', key, spec: ns });
      j++;
    } else {
      ops.push({ op: '-', key });
    }
  }
  flushNew(newKeys.length);
  return ops;
}

/** Diff two in-memory indexes. Used by tests and by small, restricted diffs. */
export function diffIndexes(oldIndex, newIndex) {
  const ops = [];
  for (const [key, spec] of newIndex) {
    const prev = oldIndex.get(key);
    if (prev !== spec) ops.push({ op: '+', key, spec });
  }
  for (const key of oldIndex.keys()) {
    if (!newIndex.has(key)) ops.push({ op: '-', key });
  }
  return sortOps(ops);
}

export function* deltaLines(from, to, ops) {
  yield '# moat-packages-delta v1\n';
  yield '# from ' + from + '\n';
  yield '# to ' + to + '\n';
  for (const o of ops) {
    yield o.op === '-' ? '-\t' + o.key + '\n' : '+\t' + o.key + '\t' + o.spec + '\n';
  }
}

export function serializeDelta(from, to, ops) {
  let out = '';
  for (const l of deltaLines(from, to, ops)) out += l;
  return out;
}

export function parseDelta(text) {
  const out = { from: null, to: null, ops: [] };
  for (const line of text.split('\n')) {
    if (!line) continue;
    if (line.charCodeAt(0) === 35) {
      const m = /^#\s+(from|to)\s+(\d+)$/.exec(line);
      if (m) out[m[1]] = Number(m[2]);
      continue;
    }
    const op = line[0];
    if (line[1] !== '\t') continue;
    const rest = line.slice(2);
    if (op === '-') out.ops.push({ op: '-', key: rest });
    else if (op === '+') {
      const t = rest.lastIndexOf('\t');
      if (t < 0) continue;
      out.ops.push({ op: '+', key: rest.slice(0, t), spec: rest.slice(t + 1) });
    }
  }
  return out;
}

/** Apply ops to an index map in place. */
export function applyOps(index, ops) {
  for (const o of ops) {
    if (o.op === '-') index.delete(o.key);
    else index.set(o.key, o.spec);
  }
  return index;
}

/**
 * Compose S->M with M->N into S->N. Later ops win, which is exactly the
 * semantics of applying the two deltas in sequence.
 */
export function composeOps(a, b) {
  const m = new Map();
  for (const o of a) m.set(o.key, o);
  for (const o of b) m.set(o.key, o);
  return sortOps([...m.values()]);
}

/** Wire form used inside state.json — arrays are a third the size of objects. */
export const opsToWire = (ops) => ops.map((o) => (o.op === '-' ? ['-', o.key] : ['+', o.key, o.spec]));
export const opsFromWire = (w) => (w || []).map((a) => (a[0] === '-' ? { op: '-', key: a[1] } : { op: '+', key: a[1], spec: a[2] }));
