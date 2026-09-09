// gzip helpers built on the platform's Compression/DecompressionStream, so the
// same code runs in workerd and in node --test.
//
// The rebuild never materialises the 6.8 MB artifact text or the 13 MB records
// text as a single string: both are produced line-batch by line-batch straight
// into a CompressionStream, and consumed back out line by line. That is what
// keeps the full rebuild inside a 128 MB isolate.

export function concatBytes(chunks, total) {
  if (total === undefined) { total = 0; for (const c of chunks) total += c.length; }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

const BATCH = 1 << 18; // 256 KiB of text per write

/**
 * gzip an iterable of strings (already newline-terminated as needed).
 * @returns {Promise<Uint8Array>} the complete gzip member
 */
export async function gzipStrings(source) {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  const chunks = [];
  let total = 0;
  const pump = (async () => {
    const r = cs.readable.getReader();
    for (;;) {
      const { value, done } = await r.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
  })();
  const enc = new TextEncoder();
  let buf = '';
  for await (const s of source) {
    buf += s;
    if (buf.length >= BATCH) { await writer.write(enc.encode(buf)); buf = ''; }
  }
  if (buf) await writer.write(enc.encode(buf));
  await writer.close();
  await pump;
  return concatBytes(chunks, total);
}

/** @param {Uint8Array} bytes @returns {ReadableStream<Uint8Array>} */
export function bytesToStream(bytes) {
  return new ReadableStream({
    start(c) { c.enqueue(bytes); c.close(); },
  });
}

/** Yield the lines of a gzipped text stream without ever holding it whole. */
export async function* gunzipLines(stream) {
  const r = stream
    .pipeThrough(new DecompressionStream('gzip'))
    .pipeThrough(new TextDecoderStream())
    .getReader();
  let tail = '';
  for (;;) {
    const { value, done } = await r.read();
    if (done) break;
    let text = tail + value;
    let pos = 0;
    for (;;) {
      const nl = text.indexOf('\n', pos);
      if (nl < 0) break;
      yield text.slice(pos, nl);
      pos = nl + 1;
    }
    tail = text.slice(pos);
    text = null;
  }
  if (tail) yield tail;
}

export async function gunzipString(stream) {
  const r = stream.pipeThrough(new DecompressionStream('gzip')).getReader();
  const chunks = [];
  for (;;) {
    const { value, done } = await r.read();
    if (done) break;
    chunks.push(value);
  }
  return new TextDecoder().decode(concatBytes(chunks));
}

export async function streamToBytes(stream) {
  const r = stream.getReader();
  const chunks = [];
  for (;;) {
    const { value, done } = await r.read();
    if (done) break;
    chunks.push(value);
  }
  return concatBytes(chunks);
}

export async function sha256Hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  let s = '';
  for (const b of d) s += b.toString(16).padStart(2, '0');
  return s;
}
