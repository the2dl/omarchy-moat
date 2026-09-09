// Test doubles: an in-memory R2 bucket, a tar+gzip writer, and a fetch stub.

import { concatBytes } from '../src/gz.js';

const ENC = new TextEncoder();

// --- tar writer (enough of ustar + pax to exercise src/tar.js) --------------

function octal(n, len) {
  const s = n.toString(8);
  return s.padStart(len - 1, '0') + '\0';
}

function header(name, size, type = '0') {
  const h = new Uint8Array(512);
  const put = (str, off) => h.set(ENC.encode(str), off);
  put(name.slice(0, 100), 0);
  put(octal(0o644, 8), 100);
  put(octal(0, 8), 108);
  put(octal(0, 8), 116);
  put(octal(size, 12), 124);
  put(octal(0, 12), 136);
  h.fill(32, 148, 156);           // checksum field as spaces while summing
  h[156] = type.charCodeAt(0);
  put('ustar\0' + '00', 257);
  let sum = 0;
  for (const b of h) sum += b;
  put(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

function pad(n) { return new Uint8Array((512 - (n % 512)) % 512); }

/**
 * @param {Array<{name:string, body:string, pax?:boolean}>} files
 * @returns {Promise<Uint8Array>} gzipped tar
 */
export async function makeTarGz(files) {
  const parts = [];
  for (const f of files) {
    const body = ENC.encode(f.body);
    if (f.pax || f.name.length > 100) {
      // pax record: "<len> path=<name>\n", where <len> counts itself
      const rec = `path=${f.name}\n`;
      let total = rec.length + 2;
      while (String(total).length + 1 + rec.length !== total) total = String(total).length + 1 + rec.length;
      const payload = ENC.encode(`${total} ${rec}`);
      parts.push(header('PaxHeader/x', payload.length, 'x'), payload, pad(payload.length));
      parts.push(header('short-stand-in', body.length, '0'), body, pad(body.length));
    } else {
      parts.push(header(f.name, body.length, '0'), body, pad(body.length));
    }
  }
  parts.push(new Uint8Array(1024)); // two zero blocks
  const tar = concatBytes(parts);
  const cs = new CompressionStream('gzip');
  const w = cs.writable.getWriter();
  const chunks = [];
  const pump = (async () => {
    const r = cs.readable.getReader();
    for (;;) { const { value, done } = await r.read(); if (done) break; chunks.push(value); }
  })();
  await w.write(tar);
  await w.close();
  await pump;
  return concatBytes(chunks);
}

// --- in-memory R2 -----------------------------------------------------------

const toBytes = (v) => {
  if (typeof v === 'string') return ENC.encode(v);
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  throw new Error('unsupported body ' + typeof v);
};

export class FakeR2 {
  constructor() { this.objects = new Map(); this.n = 0; }

  async put(key, body, opts = {}) {
    const bytes = toBytes(body);
    this.objects.set(key, { bytes, meta: opts.httpMetadata || {}, etag: `"${++this.n}"` });
    return { key, size: bytes.length };
  }

  async get(key) {
    const o = this.objects.get(key);
    if (!o) return null;
    return {
      key,
      size: o.bytes.length,
      httpEtag: o.etag,
      httpMetadata: o.meta,
      get body() {
        return new ReadableStream({ start(c) { c.enqueue(o.bytes); c.close(); } });
      },
      arrayBuffer: async () => o.bytes.buffer.slice(o.bytes.byteOffset, o.bytes.byteOffset + o.bytes.length),
      text: async () => new TextDecoder().decode(o.bytes),
      json: async () => JSON.parse(new TextDecoder().decode(o.bytes)),
    };
  }

  async delete(keys) {
    for (const k of [].concat(keys)) this.objects.delete(k);
  }

  async list({ prefix = '', limit = 1000 } = {}) {
    const objects = [...this.objects.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .slice(0, limit)
      .map(([k, o]) => ({ key: k, size: o.bytes.length }));
    return { objects, truncated: false, cursor: undefined };
  }
}

/** Minimal caches.default so serve() can run under node --test. */
export function installCaches() {
  const store = new Map();
  globalThis.caches = {
    default: {
      async match(req) { return store.get(new URL(req.url).pathname) || undefined; },
      async put(req, res) { store.set(new URL(req.url).pathname, res); },
    },
  };
  return store;
}

/**
 * Route-table fetch stub.
 * @param {Array<[RegExp, (url:string, init:object)=>Response|object]>} routes
 */
export function installFetch(routes) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    calls.push(url);
    for (const [re, fn] of routes) {
      if (re.test(url)) {
        const out = await fn(url, init);
        if (out instanceof Response) return out;
        return new Response(
          typeof out.body === 'string' || out.body instanceof Uint8Array ? out.body : JSON.stringify(out.body),
          { status: out.status || 200, headers: out.headers || {} },
        );
      }
    }
    throw new Error('unstubbed fetch: ' + url);
  };
  return { calls, restore() { globalThis.fetch = real; } };
}

export const osv = (id, eco, name, extra = {}) => JSON.stringify({
  id, modified: '2026-01-01T00:00:00Z',
  affected: [{ package: { ecosystem: eco, name }, ...extra }],
});
