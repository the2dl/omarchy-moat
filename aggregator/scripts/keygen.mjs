#!/usr/bin/env node
// Generate the feed signing keypair.
//
//   node scripts/keygen.mjs [--out DIR]
//
// Prints the secret to stdout and the public half in the format clients pin at
// /usr/share/moat/feed-key.pub. With --out, writes feed-key (secret, 0600) and
// feed-key.pub next to each other instead of printing the secret.

import { writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const args = process.argv.slice(2);
const outIdx = args.indexOf('--out');
const out = outIdx >= 0 ? args[outIdx + 1] : null;

const b64 = (u8) => Buffer.from(u8).toString('base64');

const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
const seed = pkcs8.slice(16);                       // the 32-byte private seed
const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));

const pubFile = `# omarchy-moat package feed signing key\nmoat-feed-ed25519 ${b64(pub)}\n`;

if (out) {
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'feed-key'), b64(seed) + '\n', { mode: 0o600 });
  chmodSync(join(out, 'feed-key'), 0o600);
  writeFileSync(join(out, 'feed-key.pub'), pubFile);
  console.log(`wrote ${join(out, 'feed-key')} (secret, 0600)`);
  console.log(`wrote ${join(out, 'feed-key.pub')}`);
  console.log('\nupload the secret:');
  console.log(`  npx wrangler secret put FEED_SIGNING_KEY < ${join(out, 'feed-key')}`);
  console.log('ship the public half in the package at /usr/share/moat/feed-key.pub');
} else {
  console.log('# FEED_SIGNING_KEY (Worker secret; base64 of the 32-byte ed25519 seed)');
  console.log(b64(seed));
  console.log('\n# /usr/share/moat/feed-key.pub');
  process.stdout.write(pubFile);
}
