// bitai-indexer — runtime configuration.
//
// Everything is overridable via environment variables so the same
// binary runs in dev (point at a local regtest) and prod (a dedicated
// mainnet node) without code edits. The defaults below match the
// production server layout documented in deploy/.

import { readFileSync } from "node:fs";
import { GENESIS_H0_MAINNET } from "../lib/token-registry";

/** The single hardcoded treasury / service-fee address. EVERY
 *  consensus-valid DEPLOY / MINT / TRANSFER pays a flat 546-sat
 *  output here, so this address's tx history is the complete,
 *  authoritative list of protocol activity. The indexer fee-gates
 *  on "tx has an output paying this address" — txs that skip the
 *  fee are invisible to the index (same rule the web client's
 *  fast-sync enforces). Mirrors SERVICE_FEE_ADDRESS in
 *  the web client's deploy module — must stay in lockstep. */
export const TREASURY_ADDRESS =
  process.env.BITAI_TREASURY ??
  "bc1pkqxlx42eswn0dev5m4nmg26y0xyasmfx4jx53573kkttzvzs4nrqf4xt6t";

/** Protocol genesis — no DEPLOY/MINT/TRANSFER below this height is
 *  ever indexed. Imported from the web lib so the indexer and the
 *  browser can NEVER disagree on the floor (the #1 consistency
 *  edge: a mismatch makes the browser's sample-verify reject the
 *  snapshot forever). */
export const GENESIS_H0 = Number(process.env.BITAI_GENESIS ?? GENESIS_H0_MAINNET);

/** Bitcoin Core JSON-RPC endpoint (local node). */
export const RPC_URL = process.env.BITAI_RPC_URL ?? "http://127.0.0.1:8332";

/** Cookie-file path. bitcoind writes `__cookie__:<random>` here on
 *  startup; we read it for RPC auth so no static password ever
 *  touches disk in our config. Overridable to a user:pass pair via
 *  BITAI_RPC_USER / BITAI_RPC_PASS if the node uses static auth. */
export const RPC_COOKIE_PATH =
  process.env.BITAI_RPC_COOKIE ?? "/var/lib/bitcoind/.cookie";

/** Resolve RPC credentials: explicit user/pass env wins, else read
 *  the cookie file. Returns `{ user, pass }`. Throws if neither is
 *  available (fail-fast — the indexer is useless without RPC). */
export function rpcAuth(): { user: string; pass: string } {
  const u = process.env.BITAI_RPC_USER;
  const p = process.env.BITAI_RPC_PASS;
  if (u && p) return { user: u, pass: p };
  const cookie = readFileSync(RPC_COOKIE_PATH, "utf8").trim();
  const idx = cookie.indexOf(":");
  if (idx < 0) throw new Error(`malformed cookie file at ${RPC_COOKIE_PATH}`);
  return { user: cookie.slice(0, idx), pass: cookie.slice(idx + 1) };
}

/** ZMQ block-hash publisher (set via bitcoin.conf
 *  zmqpubhashblock=tcp://127.0.0.1:28332). The indexer subscribes
 *  here for instant new-block notifications instead of polling. */
export const ZMQ_HASHBLOCK = process.env.BITAI_ZMQ_HASHBLOCK ?? "tcp://127.0.0.1:28332";

/** Output directory Caddy serves over HTTPS. The indexer writes
 *  latest.bin / latest.sig / latest.json here atomically. */
export const SNAPSHOT_DIR = process.env.BITAI_SNAPSHOT_DIR ?? "/var/www/registry";

/** ed25519 signing key (32-byte seed, hex). Lives ONLY on the
 *  server; the matching public key is hardcoded into the web client.
 *  Generated once via `npm run keygen`. */
export const SIGNING_KEY_PATH =
  process.env.BITAI_SIGNING_KEY ?? "/etc/bitai-indexer/signing.key";

/** MiniLM model + tokenizer. The indexer runs the full 16-gate mint
 *  verifier (gate 13 = AI inference), so it needs the same model the
 *  web client uses. They default to a local model/ directory (see
 *  README). SHA-256 is verified at load against the
 *  golden constants in miniml-node.ts. */
export const MODEL_PATH =
  process.env.BITAI_MODEL ?? "./model/all-MiniLM-L6-v2-int8.onnx";
export const TOKENIZER_PATH =
  process.env.BITAI_TOKENIZER ?? "./model/tokenizer.json";

/** Where to persist the registry between restarts so a crash doesn't
 *  force a full genesis→tip re-walk. JSON (serializeRegistry output). */
export const REGISTRY_STATE_PATH =
  process.env.BITAI_REGISTRY_STATE ?? "/var/lib/bitai-indexer/registry.json";

/** How many blocks to hold behind the chain tip before indexing one.
 *
 *  Default 0 — index the tip the instant the local node connects it.
 *
 *  The browser fast-sync keeps 6 because it reads PUBLIC Esplora servers
 *  whose by-address index is eventually-consistent: a freshly-mined
 *  block's txs aren't queryable for a few blocks, so it must wait. THIS
 *  indexer reads a LOCAL Bitcoin Core node via getblock, which is
 *  authoritative the instant a block connects — there is no such delay,
 *  so a non-zero lag would be pure dead latency (~10 min/block).
 *
 *  Reorg safety no longer depends on this lag: the scanner detects
 *  reorgs by prev-hash and rewinds through the registry's 200-block undo
 *  journal (scan.ts → rewindToCommonAncestor), re-deriving from genesis
 *  if a reorg ever runs deeper than the journal. Set BITAI_SAFETY_LAG>0
 *  only if you deliberately want a confirmation cushion. The web client
 *  still applies a 6-block display collapse, so any snapshot within 6 of
 *  the tip (including 0) reads as "synced" in the UI. */
export const SAFETY_LAG_BLOCKS = Number(process.env.BITAI_SAFETY_LAG ?? 0);
