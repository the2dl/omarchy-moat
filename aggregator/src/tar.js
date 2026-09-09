// Streaming tar + gzip reader.
//
// Buffers one member at a time, never the whole archive. Used for the 44 MB /
// 479k-file OSSF tarball, where buffering is not an option inside a 128 MB
// isolate.
//
// Handles: ustar name/prefix, GNU 'L' long names, pax 'x' extended headers
// (git archive emits these for paths over 100 bytes, which the OSSF repo has),
// and base-256 sizes. Everything else is skipped.

class ByteReader {
  constructor(stream) {
    this.reader = stream.getReader();
    this.chunks = [];
    this.len = 0;
    this.eof = false;
  }

  async #fill(n) {
    while (this.len < n && !this.eof) {
      const { value, done } = await this.reader.read();
      if (done) { this.eof = true; break; }
      if (value && value.length) { this.chunks.push(value); this.len += value.length; }
    }
  }

  // Exactly n bytes, or null at end of stream.
  async read(n) {
    if (n === 0) return new Uint8Array(0);
    await this.#fill(n);
    if (this.len < n) return null;
    const first = this.chunks[0];
    if (first.length >= n) {
      const out = first.subarray(0, n);
      if (first.length === n) this.chunks.shift();
      else this.chunks[0] = first.subarray(n);
      this.len -= n;
      return out;
    }
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const c = this.chunks[0];
      const take = Math.min(c.length, n - off);
      out.set(c.subarray(0, take), off);
      if (take === c.length) this.chunks.shift();
      else this.chunks[0] = c.subarray(take);
      off += take;
      this.len -= take;
    }
    return out;
  }

  async skip(n) {
    let left = n;
    while (left > 0) {
      const got = await this.read(Math.min(left, 1 << 16));
      if (got === null) return false;
      left -= got.length;
    }
    return true;
  }

  async cancel() { try { await this.reader.cancel(); } catch { /* already closed */ } }
}

const DEC = new TextDecoder();

function cstr(buf, off, len) {
  let end = off;
  const limit = off + len;
  while (end < limit && buf[end] !== 0) end++;
  return DEC.decode(buf.subarray(off, end));
}

function octal(buf, off, len) {
  // base-256 extension: high bit of the first byte set
  if (buf[off] & 0x80) {
    let v = buf[off] & 0x7f;
    for (let i = off + 1; i < off + len; i++) v = v * 256 + buf[i];
    return v;
  }
  const s = cstr(buf, off, len).trim();
  if (!s) return 0;
  const v = parseInt(s, 8);
  return Number.isFinite(v) ? v : 0;
}

function isZeroBlock(b) {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false;
  return true;
}

function parsePax(bytes) {
  // records are "<len> <key>=<value>\n"
  const text = DEC.decode(bytes);
  const out = {};
  let i = 0;
  while (i < text.length) {
    const sp = text.indexOf(' ', i);
    if (sp < 0) break;
    const len = parseInt(text.slice(i, sp), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const rec = text.slice(sp + 1, i + len - 1); // drop trailing \n
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

/**
 * Iterate the regular files of a gzip-compressed tar stream.
 *
 * @param {ReadableStream<Uint8Array>} gzStream
 * @param {(name:string)=>boolean} [want] cheap path filter; when it returns
 *        false the member body is skipped without being buffered.
 * @yields {{name: string, size: number, body: Uint8Array}}
 */
export async function* untarGz(gzStream, want = () => true) {
  yield* untar(gzStream.pipeThrough(new DecompressionStream('gzip')), want);
}

export async function* untar(tarStream, want = () => true) {
  const r = new ByteReader(tarStream);
  let longName = null;
  let paxName = null;
  let sawZero = false;
  try {
    for (;;) {
      const head = await r.read(512);
      if (head === null) return;
      if (isZeroBlock(head)) {
        if (sawZero) return; // two zero blocks: end of archive
        sawZero = true;
        continue;
      }
      sawZero = false;

      const type = String.fromCharCode(head[156] || 0x30);
      const size = octal(head, 124, 12);
      const pad = (512 - (size % 512)) % 512;

      let name = cstr(head, 0, 100);
      const prefix = cstr(head, 345, 155);
      if (prefix) name = prefix + '/' + name;
      if (longName !== null) { name = longName; longName = null; }
      if (paxName !== null) { name = paxName; paxName = null; }

      if (type === 'L') {                       // GNU long name
        const body = await r.read(size);
        if (body === null) return;
        longName = cstr(body, 0, body.length);
        await r.skip(pad);
        continue;
      }
      if (type === 'x' || type === 'X') {       // pax extended header
        const body = await r.read(size);
        if (body === null) return;
        const rec = parsePax(body);
        if (rec.path) paxName = rec.path;
        await r.skip(pad);
        continue;
      }
      if (type === 'g' || type === 'K') {       // global pax / long link: ignore
        await r.skip(size + pad);
        continue;
      }
      // head[156] === 0 (old tar) is normalised to '0' above, so a regular
      // file is exactly type '0'. Everything else (dir '5', symlink '2', ...)
      // is skipped.
      if (type !== '0') { await r.skip(size + pad); continue; }

      if (!want(name)) {
        await r.skip(size + pad);
        continue;
      }
      const body = await r.read(size);
      if (body === null) return;
      await r.skip(pad);
      yield { name, size, body };
    }
  } finally {
    await r.cancel();
  }
}
