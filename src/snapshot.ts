// Snapshot writer — serialize the registry, sign it, write three
// files atomically into the directory Caddy serves:
//
//   latest.bin   — serializeRegistry(reg) output (JSON text, the
//                  EXACT format the web client's deserializeRegistry
//                  reads). Despite the .bin name it's UTF-8 JSON.
//   latest.sig   — ed25519 signature (hex) over latest.bin's bytes.
//   latest.json  — descriptor the web reads FIRST: schema version,
//                  tip height/hash, sha256, signed_at, counts. Lets
//                  the client fail-fast on schema mismatch / staleness
//                  before downloading the (larger) .bin.
//
// Atomicity: each file is written to a .tmp sibling then renamed.
// POSIX rename(2) is atomic on the same filesystem, so a client
// fetching mid-write never sees a torn file. We write .bin + .sig
// BEFORE .json so a client that reads .json (the trigger) is
// guaranteed the .bin/.sig it points at already exist.

import { writeFileSync, renameSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2";
import {
  serializeRegistry,
  REGISTRY_SCHEMA_VERSION,
  type TokenRegistry,
} from "../lib/token-registry";
import { signHex, publicKeyHex } from "./signer";
import { SNAPSHOT_DIR } from "./config";

export const INDEXER_VERSION = "0.1.0";

function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** Atomic single-file write: tmp → rename. */
function atomicWrite(path: string, data: string | Uint8Array): void {
  const tmp = path + ".tmp";
  writeFileSync(tmp, data);
  renameSync(tmp, path);
}

interface SnapshotDescriptor {
  schema_version: number;
  indexer_version: string;
  /** Registry's last fully-scanned block (snapshot's notion of tip). */
  tip_height: number;
  tip_hash: string;
  /** Actual chain tip at write time — lets the client compute lag. */
  chain_tip: number;
  /** sha256(latest.bin) hex — integrity cross-check. */
  registry_sha256: string;
  /** ed25519 signature (hex) over latest.bin bytes. Duplicated in
   *  latest.sig; embedded here too so a single descriptor fetch has
   *  everything for verification once .bin is downloaded. */
  signature: string;
  /** Signing pubkey (hex). The web client ALSO hardcodes this and
   *  must check the two match — the field is a convenience/debug aid,
   *  never the trust root. */
  pubkey: string;
  signed_at: string;
  tokens_count: number;
  utxos_count: number;
  mints_count: number;
}

/** Serialize + sign + atomically publish the registry snapshot.
 *  `chainTip` is the live chain height (for the lag field). */
export function writeSnapshot(
  reg: TokenRegistry,
  chainTip: number,
  seed: Uint8Array,
): SnapshotDescriptor {
  mkdirSync(SNAPSHOT_DIR, { recursive: true });

  const binText = serializeRegistry(reg);
  const binBytes = new TextEncoder().encode(binText);
  const sig = signHex(seed, binBytes);
  const sha = hex(sha256(binBytes));

  let mintsCount = 0;
  for (const t of Object.values(reg.tokens)) mintsCount += t.mints_done;

  const descriptor: SnapshotDescriptor = {
    schema_version: REGISTRY_SCHEMA_VERSION,
    indexer_version: INDEXER_VERSION,
    tip_height: reg.last_scanned_height,
    tip_hash: reg.last_scanned_hash,
    chain_tip: chainTip,
    registry_sha256: sha,
    signature: sig,
    pubkey: publicKeyHex(seed),
    signed_at: new Date().toISOString(),
    tokens_count: Object.keys(reg.tokens).length,
    utxos_count: Object.keys(reg.token_utxos).length,
    mints_count: mintsCount,
  };

  // Order matters: payload + sig first, descriptor (the read trigger)
  // last, so a client never sees a descriptor pointing at a missing
  // or stale .bin.
  atomicWrite(join(SNAPSHOT_DIR, "latest.bin"), binText);
  atomicWrite(join(SNAPSHOT_DIR, "latest.sig"), sig);
  atomicWrite(join(SNAPSHOT_DIR, "latest.json"), JSON.stringify(descriptor, null, 2));

  return descriptor;
}
