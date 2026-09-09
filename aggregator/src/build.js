// Full rebuild: OSSF tarball + Datadog manifests -> records + package index.

import { untarGz } from './tar.js';
import {
  isOsvPath, osvContributions, datadogContributions, rid, ddRid,
  recordLine, foldInto, newStats, collapse,
} from './normalize.js';

const DEC = new TextDecoder();

/**
 * Stream the records file for a full rebuild, folding the package index as it
 * goes. Yields newline-terminated record lines straight into a gzip sink; the
 * lines are never accumulated in an array, which is the difference between
 * fitting in a 128 MB isolate and not.
 *
 * @param {ReadableStream<Uint8Array>|null} ossfTarGz codeload tarball stream
 * @param {Array<{eco:string, manifest:object}>} datadog parsed manifests
 * @param {{index: Map<string,string>, stats: object, records: number}} ctx
 *        filled in as a side effect; read it after the sink drains.
 */
export async function* buildFullRecords(ossfTarGz, datadog, ctx) {
  ctx.index = ctx.index || new Map();
  ctx.stats = ctx.stats || newStats();
  ctx.records = 0;
  const emit = (id, c) => {
    const spec = collapse(c.clauses);
    foldInto(ctx.index, c.eco + '\t' + c.name, spec);
    ctx.records++;
    return id + '\t' + c.eco + '\t' + c.name + '\t' + spec + '\n';
  };

  if (ossfTarGz) {
    for await (const entry of untarGz(ossfTarGz, isOsvPath)) {
      // strip the tarball root so the record id matches the repo-relative path
      // the GitHub compare API reports.
      const path = entry.name.slice(entry.name.indexOf('/') + 1);
      let doc;
      try {
        doc = JSON.parse(DEC.decode(entry.body));
      } catch {
        ctx.stats.ossf_unparsable++;
        continue;
      }
      const id = rid(path);
      for (const c of osvContributions(doc, path, ctx.stats)) yield emit(id, c);
    }
  }
  for (const { eco, manifest } of datadog) {
    const id = ddRid(eco);
    for (const c of datadogContributions(eco, manifest, ctx.stats)) yield emit(id, c);
  }
}

/** Convenience wrapper for tests and the local CLI: materialises the records. */
export async function buildFull(ossfTarGz, datadog) {
  const ctx = {};
  const records = [];
  for await (const line of buildFullRecords(ossfTarGz, datadog, ctx)) {
    records.push(line.slice(0, -1));
  }
  return { records, index: ctx.index, stats: ctx.stats };
}

export { recordLine };
