// Just enough ZIP to read abuse.ch's bulk exports.
//
// ThreatFox publishes its full dumps as single-entry zips (23 MB of CSV inside
// 3 MB on the wire). Workers have `DecompressionStream('deflate-raw')`, which
// is the whole of the decompression job -- what is missing is the six fields of
// the local file header that say where the deflate stream starts and, more
// importantly, where it STOPS.
//
// The stopping point is not optional. A zip carries a central directory after
// the last entry, and handing those trailing bytes to an inflate stream is an
// error, not a no-op: node rejects it outright with
// ERR_TRAILING_JUNK_AFTER_STREAM_END. Slicing to `compressed_size` is what
// makes the same code work in both runtimes.

const LOCAL_SIG = 0x04034b50;
const FLAG_DATA_DESCRIPTOR = 0x08;
const METHOD_DEFLATE = 8;
const METHOD_STORE = 0;

/**
 * Read the first entry of a zip held in memory.
 *
 * Deliberately not streaming: these archives are ~3 MB, and the alternative is
 * either a Range request for the central directory (a second round trip, and
 * one more thing the upstream has to support) or trusting a data descriptor we
 * cannot see until after we have already inflated past it.
 *
 * @param {Uint8Array} bytes the complete archive
 * @returns {{name: string, size: number, stream: ReadableStream<Uint8Array>}}
 */
export function unzipFirstEntry(bytes) {
  if (bytes.length < 30) throw new Error(`zip too short: ${bytes.length} bytes`);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const sig = dv.getUint32(0, true);
  if (sig !== LOCAL_SIG) {
    throw new Error(`not a zip: first four bytes are 0x${sig.toString(16)}`);
  }
  const flags = dv.getUint16(6, true);
  const method = dv.getUint16(8, true);
  const csize = dv.getUint32(18, true);
  const usize = dv.getUint32(22, true);
  const nameLen = dv.getUint16(26, true);
  const extraLen = dv.getUint16(28, true);
  const start = 30 + nameLen + extraLen;
  const name = new TextDecoder().decode(bytes.subarray(30, 30 + nameLen));

  // Bit 3 means the sizes live in a data descriptor AFTER the payload, so the
  // header's zeros are not a length. Finding the real end would mean scanning
  // for the descriptor signature, which can legitimately occur inside
  // compressed data. abuse.ch does not write these; refuse rather than guess.
  if (flags & FLAG_DATA_DESCRIPTOR) {
    throw new Error(`zip entry ${name} uses a data descriptor; sizes are not in the header`);
  }
  if (csize === 0xffffffff || usize === 0xffffffff) {
    throw new Error(`zip entry ${name} is zip64; not supported`);
  }
  if (start + csize > bytes.length) {
    throw new Error(
      `zip entry ${name} claims ${csize} bytes from ${start} but the archive is ${bytes.length}`,
    );
  }

  const body = bytes.subarray(start, start + csize);
  if (method === METHOD_STORE) {
    return {
      name,
      size: usize,
      stream: new ReadableStream({ start(c) { c.enqueue(body); c.close(); } }),
    };
  }
  if (method !== METHOD_DEFLATE) {
    throw new Error(`zip entry ${name} uses compression method ${method}; only store and deflate`);
  }

  const ds = new DecompressionStream('deflate-raw');
  const w = ds.writable.getWriter();
  // Not awaited: the reader on the other side is what drains it, and awaiting a
  // write of 3 MB before anyone reads would deadlock on the stream's backpressure.
  w.write(body).then(() => w.close(), () => {});
  return { name, size: usize, stream: ds.readable };
}

/** Lines of the first zip entry, `\r` trimmed -- these exports are CRLF. */
export async function* unzipLines(bytes) {
  const { stream } = unzipFirstEntry(bytes);
  const r = stream.pipeThrough(new TextDecoderStream()).getReader();
  let tail = '';
  for (;;) {
    const { value, done } = await r.read();
    if (done) break;
    const text = tail + value;
    let pos = 0;
    for (;;) {
      const nl = text.indexOf('\n', pos);
      if (nl < 0) break;
      const end = nl > pos && text.charCodeAt(nl - 1) === 13 ? nl - 1 : nl;
      yield text.slice(pos, end);
      pos = nl + 1;
    }
    tail = text.slice(pos);
  }
  if (tail) yield tail.charCodeAt(tail.length - 1) === 13 ? tail.slice(0, -1) : tail;
}
