// Detached ed25519 signatures over each published object.
//
// The signing key lives in the `FEED_SIGNING_KEY` Worker secret as base64. Both
// forms scripts/keygen.mjs can emit are accepted: a 32-byte raw seed or a
// 48-byte PKCS#8 blob. The public half ships to clients at
// /usr/share/moat/feed-key.pub and is pinned there.

const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);
const SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export function b64decode(s) {
  const bin = atob(s.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64encode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// workerd exposes ed25519 as "Ed25519"; older builds only know "NODE-ED25519".
const ALGS = [{ name: 'Ed25519' }, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }];

async function importAny(format, bytes, usages) {
  let last;
  for (const alg of ALGS) {
    try {
      return { key: await crypto.subtle.importKey(format, bytes, alg, false, usages), alg };
    } catch (e) { last = e; }
  }
  throw new Error('ed25519 unavailable in this runtime: ' + (last && last.message));
}

/** @param {string} secret base64 of a 32-byte seed or a 48-byte PKCS#8 blob */
export async function importSigner(secret) {
  if (!secret) throw new Error('FEED_SIGNING_KEY is not set');
  let raw = b64decode(secret);
  if (raw.length === 32) {
    const p8 = new Uint8Array(PKCS8_PREFIX.length + 32);
    p8.set(PKCS8_PREFIX, 0);
    p8.set(raw, PKCS8_PREFIX.length);
    raw = p8;
  }
  if (raw.length !== 48) throw new Error('FEED_SIGNING_KEY must be a 32-byte seed or 48-byte PKCS#8, got ' + raw.length);
  return importAny('pkcs8', raw, ['sign']);
}

/** @param {string|Uint8Array} pub base64 or bytes of the 32-byte public key */
export async function importVerifier(pub) {
  let raw = typeof pub === 'string' ? b64decode(pub) : pub;
  if (raw.length === 32) {
    const spki = new Uint8Array(SPKI_PREFIX.length + 32);
    spki.set(SPKI_PREFIX, 0);
    spki.set(raw, SPKI_PREFIX.length);
    raw = spki;
  }
  return importAny('spki', raw, ['verify']);
}

export async function signBytes(signer, data) {
  const sig = await crypto.subtle.sign(signer.alg, signer.key, data);
  return new Uint8Array(sig);
}

export async function verifyBytes(verifier, sig, data) {
  return crypto.subtle.verify(verifier.alg, verifier.key, sig, data);
}

/** Parse /usr/share/moat/feed-key.pub: `moat-feed-ed25519 <base64>`. */
export function parsePubFile(text) {
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const parts = t.split(/\s+/);
    return b64decode(parts[parts.length - 1]);
  }
  throw new Error('no key found in public key file');
}
