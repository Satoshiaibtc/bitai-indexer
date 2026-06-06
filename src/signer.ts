// ed25519 signing for snapshot authenticity.
//
// The signature provides authenticity and integrity: it proves the
// snapshot was produced by the holder of the signing key and has not
// been altered in transit. Clients pin the corresponding public key
// and reject any snapshot that fails verification.
//
// Key lifecycle:
//   * `npm run keygen` → generates a 32-byte seed, writes it 0600 to
//     SIGNING_KEY_PATH, prints the PUBLIC key hex. Paste that pubkey
//     into the web client (hardcoded verify key).
//   * runtime → loads the seed, signs sha256(snapshot bytes).

import { readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { SIGNING_KEY_PATH } from "./config";

function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}
function unhex(s: string): Uint8Array {
  const clean = s.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Load the 32-byte signing seed from disk. Throws if missing — the
 *  indexer must not start without a key (it would publish unsigned
 *  snapshots the web client rejects). */
export function loadSigningKey(): Uint8Array {
  const seedHex = readFileSync(SIGNING_KEY_PATH, "utf8").trim();
  const seed = unhex(seedHex);
  if (seed.length !== 32) {
    throw new Error(`signing key at ${SIGNING_KEY_PATH} is ${seed.length} bytes, expected 32`);
  }
  return seed;
}

/** ed25519 public key (hex) for a given seed — what the web client
 *  hardcodes as its verify key. */
export function publicKeyHex(seed: Uint8Array): string {
  return hex(ed25519.getPublicKey(seed));
}

/** Sign a message, returning the 64-byte signature as hex. */
export function signHex(seed: Uint8Array, msg: Uint8Array): string {
  return hex(ed25519.sign(msg, seed));
}

/** Generate + persist a fresh signing key, print the public key.
 *  Refuses to overwrite an existing key (rotating is deliberate, not
 *  accidental — delete the file by hand first if you really mean to). */
function keygen(): void {
  try {
    readFileSync(SIGNING_KEY_PATH);
    console.error(
      `✗ refusing to overwrite existing key at ${SIGNING_KEY_PATH}\n` +
      `  (delete it manually first if you intend to rotate — note this\n` +
      `   invalidates every client carrying the old hardcoded pubkey)`,
    );
    process.exit(1);
  } catch {
    // ENOENT — good, no key yet.
  }
  const seed = new Uint8Array(randomBytes(32));
  mkdirSync(dirname(SIGNING_KEY_PATH), { recursive: true });
  writeFileSync(SIGNING_KEY_PATH, hex(seed), { mode: 0o600 });
  chmodSync(SIGNING_KEY_PATH, 0o600);
  console.log("✓ signing key written to", SIGNING_KEY_PATH, "(mode 0600)");
  console.log("");
  console.log("PUBLIC KEY (hardcode this into the web client):");
  console.log("  " + publicKeyHex(seed));
}

// CLI: `tsx src/signer.ts --keygen`
if (process.argv.includes("--keygen")) {
  keygen();
}
