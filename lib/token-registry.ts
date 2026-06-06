// BITAI Protocol token registry — state machine.
//
// Port of the consensus-critical pieces of
// `bitai-miner/src-tauri/src/token_registry.rs`. Mirrors the same
// state transitions on DEPLOY / MINT / TRANSFER and the universal
// token-UTXO sweep that every tx triggers.
//
// THE BUDGET FOR DIVERGENCE FROM THE RUST IMPLEMENTATION IS ZERO.
// A web client that disagrees with the desktop indexer about which
// txs carry valid BITAI activity is a network fork on a per-tx
// basis — exactly the worst failure mode for a meta-protocol.
// Treat the round-trip vectors in `bitai-miner` as the consensus
// gold-master and add coverage here for every Rust test case before
// shipping breaking changes.
//
// SCOPE NOTE for the web client v0 (Phase 3):
//
// The MINT branch of apply_payload requires AI inference against
// MiniLM-L6-v2 to verify the PoW challenge. We don't have the
// WASM miner loaded yet (that's Phase 4). To avoid forging false
// rejects, this Phase-3 implementation gates every MINT through
// a `modelLoaded` flag passed by the caller — when it's false
// (Phase 3), MINTs are SOFT-SKIPPED (return `Ok` without state
// change) so the scanner can keep advancing block height. The
// caller is responsible for triggering a full re-scan once the
// model loads (Phase 4) so the skipped MINTs are re-evaluated
// and the `mints_done` counters are accurate.
//
// In practice for the v0 web rollout, BITAI mainnet has no mints
// yet (we're the first deployer), so the soft-skip path executes
// zero times — but the gate is in place so the model-load
// transition doesn't quietly accept stale state.

import type { DeployParams, MintPayload, TransferPayload, Edict } from "./protocol";
import { MAX_DIFFICULTY_BITS } from "./protocol";
import { SUPPORTED_MODEL_IDS } from "./protocol";
import { sha256 } from "@noble/hashes/sha2";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { base58 } from "@scure/base";
import type { InferenceBackend } from "./inference";
import { computePow, leadingZeroBits } from "./pow";
import { isChallengeFresh } from "./miner-prompt";
import { promptFor } from "./miner-prompt";
import { p2wpkh } from "@scure/btc-signer/payment";
import { NETWORK } from "@scure/btc-signer/utils";

// ── Consensus constants (mirror token_registry.rs) ──────────────────

/** First block at which the BITAI protocol is considered live on
 *  mainnet — the launch block. No DEPLOY/MINT/TRANSFER at or below
 *  952_594 is in-protocol; clients start scanning here so they spend
 *  zero time on pre-launch blocks with no BITAI activity.
 *
 *  Bumping this constant MUST be accompanied by a
 *  REGISTRY_SCHEMA_VERSION bump (below) so existing clients with a
 *  persisted `last_scanned_height` < new genesis don't get stuck
 *  thinking they're caught up. The schema-version mismatch on
 *  deserialise wipes the local blob and the next scan starts fresh
 *  from the new genesis.
 *
 *  Earlier pre-release pins (948_136, 948_948, 949_375, 950_382) are
 *  explicitly NOT supported. */
export const GENESIS_H0_MAINNET = 952_595;

/** Max blocks back a mint's `challenge_h` may reference (≈24 h). Forces
 *  a recent BTC tip and prevents miners from precomputing a year of
 *  challenges in advance. */
export const CHALLENGE_TIP_DEPTH = 144;

/** Ring-buffer depth for reorg-rewind and challenge-freshness lookup.
 *  Hard invariant: must be ≥ CHALLENGE_TIP_DEPTH + 50. */
export const RECENT_BLOCK_WINDOW = 200;

/** LRU cap on the (challenge, nonce, hash160) dedup set. */
export const MAX_MINTED_TRIPLES = 200_000;

/** Standard Bitcoin Core P2WPKH dust threshold (mirror of `DUST_SATS`
 *  in `format.ts`; redeclared here so callers only need to import
 *  from this module to do consensus accounting). */
export const DUST_SATS = 546;

// ── Persistence schema version ──────────────────────────────────────

/** Bump when any field above is renamed, retyped, or the apply_payload
 *  semantics change. On `load` we hard-reset (back to genesis) when
 *  the persisted version doesn't match — same policy as the Rust
 *  client's `migrate_*` chain.
 *
 *  History:
 *    v1 — initial release, genesis pinned at #949_375
 *    v2 — genesis bumped to #950_382 (first observed deploy);
 *         every v1 client gets wiped on next load so the new scan
 *         doesn't try to resume from a now-pre-genesis height.
 *    v3 — genesis re-anchored to launch block #952_595; every v2
 *         client (and the indexer's persisted registry) gets wiped on
 *         next load and re-derives from the new floor. */
export const REGISTRY_SCHEMA_VERSION = 3;

// ── Data types (mirror Rust structs) ────────────────────────────────

/** One BITAI token's registry entry. */
export interface TokenRecord {
  ticker: string;            // UPPERCASE, canonical key
  deploy_block: number;      // 0 = optimistic-only, not yet confirmed
  deploy_txid: string;
  params: DeployParams;
  mints_done: number;        // counter only; the proof of authorship is on-chain
  starred: boolean;          // UI affordance (preserved across F-3 frontrun overwrite)
  holders: string[];         // "ever-held" addresses, sorted; NOT "currently held"
}

/** An asset-bearing UTXO. Maps an outpoint to its protocol-level
 *  identity. The wallet's per-address UTXO list cross-references this
 *  via `asset-index.ts::classifyUtxos`. */
export interface TokenUtxo {
  ticker: string;
  /** Smallest-unit amount (yield_per_mint × 10^decimals — for v0.1.0
   *  decimals=0, so this is just the integer count). */
  amount: bigint;
}

/** Outpoint key for the `token_utxos` map. Stored as `${txid}:${vout}`
 *  for cheap JSON round-trip; the Rust impl uses a tuple key but JS
 *  objects can't use tuple keys natively. */
export type OutpointKey = string;

export function outpointKey(txid: string, vout: number): OutpointKey {
  return `${txid}:${vout}`;
}

/** Reorg-undo journal for a single block. The chain scanner pushes
 *  one of these per block onto a ring buffer; if a later block's
 *  prev_blockhash doesn't match, the scanner pops deltas off the
 *  buffer to rewind state. */
export interface BlockDelta {
  block_hash: string;
  tokens_deployed: string[];                              // tickers freshly inserted
  mints_added: Record<string, number>;                    // ticker → delta to mints_done
  triples_added: string[];                                // dedup keys (challenge:nonce:hash160) to remove on rewind
  utxos_created: OutpointKey[];                           // new entries in token_utxos to drop on rewind
  utxos_removed: { key: OutpointKey; value: TokenUtxo }[];// removed entries to restore on rewind
  holders_added: Record<string, string[]>;                // first-time-holder address insertions by ticker
}

/** Persisted root state. Serialised to IDB as a JSON-compatible blob. */
export interface TokenRegistry {
  schema_version: number;
  last_scanned_height: number;
  /** Hash of the last fully-scanned block, used to detect reorgs on
   *  resume. Empty string when no blocks scanned yet. */
  last_scanned_hash: string;
  tokens: Record<string, TokenRecord>;
  token_utxos: Record<OutpointKey, TokenUtxo>;
  /** LRU dedup set; we encode as an ordered array so JSON round-trip
   *  preserves insertion order for the eviction policy. */
  minted_triples: string[];
  /** Ring buffer of (height, blockHash) for the last RECENT_BLOCK_WINDOW
   *  blocks. Reorg-rewind walks this in reverse. Oldest at index 0. */
  recent_blocks: { height: number; hash: string }[];
  /** Per-block reorg-undo journal, keyed by block hash. Pruned when
   *  `recent_blocks` evicts the corresponding entry. */
  block_deltas: Record<string, BlockDelta>;
}

export function emptyRegistry(): TokenRegistry {
  return {
    schema_version: REGISTRY_SCHEMA_VERSION,
    last_scanned_height: 0,
    last_scanned_hash: "",
    tokens: {},
    token_utxos: {},
    minted_triples: [],
    recent_blocks: [],
    block_deltas: {},
  };
}

// ── Helpers ─────────────────────────────────────────────────────────

/** Effective per-mint difficulty under the deploy's halving schedule.
 *  Mirrors `effective_difficulty` in `token_registry.rs` (lines 188-199).
 *  Saturates at `MAX_DIFFICULTY_BITS` so a deploy whose
 *  `difficulty_0 + era` would exceed 27 simply stalls at 27 instead of
 *  producing progressively unmineable mints. */
export function effectiveDifficulty(p: DeployParams, mintsDone: number): number {
  if (p.halving_curve === 0 || p.total_mints === 0n) return p.difficulty_0;
  const interval = p.total_mints / BigInt(p.halving_curve);
  const era = Math.min(
    Math.floor(mintsDone / Number(interval)),
    p.halving_curve,
  );
  return Math.min(p.difficulty_0 + era, MAX_DIFFICULTY_BITS);
}

/** True iff this token still has mint slots available. */
export function isActive(rec: TokenRecord): boolean {
  return BigInt(rec.mints_done) < rec.params.total_mints;
}

/** Construct a fresh empty BlockDelta for a given block hash. The
 *  chain scanner calls this once per block and then threads the
 *  resulting object through every apply_* call for that block, so the
 *  per-block undo journal accumulates correctly. */
export function newBlockDelta(blockHash: string): BlockDelta {
  return {
    block_hash: blockHash,
    tokens_deployed: [],
    mints_added: {},
    triples_added: [],
    utxos_created: [],
    utxos_removed: [],
    holders_added: {},
  };
}

// ── apply_payload — DEPLOY ───────────────────────────────────────────

/** DEPLOY state transition. Mirrors `apply_payload` Deploy branch in
 *  the desktop client (token_registry.rs lines 491-583). Three paths:
 *
 *    1. Ticker not in registry → fresh insert with `mints_done = 0`,
 *       `starred = false`, empty holders. Push ticker into
 *       `delta.tokens_deployed` for rewind.
 *
 *    2. Ticker present with `deploy_block == 0` (optimistic
 *       placeholder — used by miners pre-broadcasting their own
 *       deploys):
 *         * Same txid → patch in the on-chain block_height (path a.i).
 *         * Different txid → frontrun overwrite (F-3): replace params
 *           with on-chain ones, reset `mints_done = 0`, empty
 *           `holders`, preserve only `starred`. NOT pushed into
 *           `delta.tokens_deployed` (so a reorg of the confirming
 *           block leaves params in place; next scan re-converges).
 *
 *    3. Ticker present with `deploy_block > 0` → silently ignored
 *       (first-come-first-served).
 */
export function applyDeploy(
  reg: TokenRegistry,
  delta: BlockDelta,
  txid: string,
  blockHeight: number,
  params: DeployParams,
): void {
  const tickerKey = params.ticker.toUpperCase();
  const existing = reg.tokens[tickerKey];

  if (!existing) {
    // Path 1: fresh insert.
    reg.tokens[tickerKey] = {
      ticker: tickerKey,
      deploy_block: blockHeight,
      deploy_txid: txid,
      params: { ...params, ticker: tickerKey },
      mints_done: 0,
      starred: false,
      holders: [],
    };
    delta.tokens_deployed.push(tickerKey);
    return;
  }

  if (existing.deploy_block === 0) {
    if (existing.deploy_txid === txid) {
      // Path 2.a.i: our own optimistic placeholder confirming. Just
      // patch in the block height; everything else was correct.
      existing.deploy_block = blockHeight;
      return;
    }
    // Path 2.b: F-3 frontrun overwrite. A different deploy txid for
    // the same ticker landed before ours. Replace params with the
    // on-chain ones, reset counters, preserve only `starred`.
    const starredPreserved = existing.starred;
    reg.tokens[tickerKey] = {
      ticker: tickerKey,
      deploy_block: blockHeight,
      deploy_txid: txid,
      params: { ...params, ticker: tickerKey },
      mints_done: 0,
      starred: starredPreserved,
      holders: [],
    };
    return;
  }

  // Path 3: already confirmed. First-come-first-served — silently
  // ignore the late deploy.
}

// ── apply_payload — MINT (full 16-gate verifier) ────────────────────

/** Outcome of `applyMint`. Mirrors `ApplyOutcome` in the Rust impl. */
export type MintOutcome =
  | { kind: "ok" }
  | { kind: "rejected"; reason: string }
  | { kind: "skipped"; reason: string };

/** Tx shape applyMint needs — a slimmed view of `EsploraTx` so this
 *  module doesn't depend on the HTTP layer directly. */
export interface MintTxInfo {
  vin: { txid: string; vout: number; witness?: string[] }[];
  vout: {
    /** Hex scriptpubkey. Used for the P2WPKH-only consensus check on
     *  vout[1] (gates 1-3) — script bytes start `0x0014 + 20-byte
     *  hash160` for native P2WPKH. */
    scriptpubkey: string;
    /** Esplora-supplied script-type hint. Faster path than parsing
     *  the script bytes ourselves; if absent we fall back to a hex
     *  prefix match. */
    scriptpubkey_type?: string;
  }[];
}

/** Per-block rate-cap counter the scanner threads through every
 *  applyMint call for a given block. Key is `${ticker}:${hash160_hex}`,
 *  value is the number of accepted mints by that (ticker, miner)
 *  pair INSIDE THIS BLOCK. Reset at the top of each block by the
 *  caller (chain-scan.ts). */
export type RateCapCounter = Map<string, number>;

/**
 * MINT state transition — full 16-gate verifier.
 *
 * Mirrors `token_registry.rs::apply_payload` Mint branch (lines
 * 584-945) order of operations exactly:
 *
 *   1. tx.output.len() < 2                              → reject
 *   2. tx.output[1] is OP_RETURN                        → reject
 *   3. tx.output[1] is not P2WPKH                       → reject
 *   4. ticker not in registry                           → ok (not our token)
 *   5. !record.is_active()                              → reject
 *   6. record.deploy_block == 0                         → reject
 *   7. block_height <= record.deploy_block (A3)         → reject
 *   8. block_height < record.params.start_block (A2)    → reject
 *   9. model_id not in SUPPORTED_MODEL_IDS (A1)         → reject
 *  10. triple already in minted_triples (C3)            → reject
 *  11. !isChallengeFresh (C1)                            → reject
 *  12. !txInputAuthorizesHash160 (C2)                   → reject
 *  13. backend null / not real                          → skip (soft)
 *  14. inference error                                  → skip (soft)
 *  15. leading_zero_bits(pow_hash) < effective_diff      → reject
 *  16. rate_cap > 0 && perBlockCounts >= rate_cap        → reject
 *
 * On accept: increments rate-cap, mints_done; inserts dedup triple;
 * inserts (txid,1) into token_utxos; records first-time holder.
 *
 * NOTE async because inference (gate 13) is async.
 */
export async function applyMint(args: {
  reg: TokenRegistry;
  delta: BlockDelta;
  txid: string;
  blockHeight: number;
  blockHash: string;
  mintPayload: MintPayload;
  tx: MintTxInfo;
  backend: InferenceBackend;
  perBlockCounts: RateCapCounter;
}): Promise<MintOutcome> {
  const { reg, delta, txid, blockHeight, mintPayload, tx, backend, perBlockCounts } = args;
  void delta;

  // ── Gate 1: must have at least 2 outputs ────────────────────────
  if (tx.vout.length < 2) {
    return { kind: "rejected", reason: "mint tx has fewer than 2 outputs (need OP_RETURN + token dust)" };
  }

  // ── Gate 2: vout[1] must NOT be OP_RETURN ───────────────────────
  const v1 = tx.vout[1];
  const v1IsOpReturn =
    v1.scriptpubkey_type === "op_return" ||
    (v1.scriptpubkey?.startsWith("6a") ?? false);
  if (v1IsOpReturn) {
    return { kind: "rejected", reason: "vout[1] is OP_RETURN (must carry the minted token dust)" };
  }

  // ── Gate 3: vout[1] must be P2WPKH ──────────────────────────────
  // P2WPKH scriptpubkey is exactly `0x00 0x14 <20-byte hash160>` = 22 bytes
  // = 44 lowercase hex chars starting with "0014".
  const isP2WPKH =
    v1.scriptpubkey_type === "v0_p2wpkh" ||
    (typeof v1.scriptpubkey === "string"
      && v1.scriptpubkey.length === 44
      && v1.scriptpubkey.startsWith("0014"));
  if (!isP2WPKH) {
    return { kind: "rejected", reason: "vout[1] is not P2WPKH (consensus rule — token must land at a P2WPKH dust)" };
  }

  // ── Gate 4: ticker must be in registry ──────────────────────────
  const tickerKey = mintPayload.ticker.toUpperCase();
  const rec = reg.tokens[tickerKey];
  if (!rec) {
    // Not our token — silently skip. Same as the Rust impl: an
    // unknown ticker is not a protocol violation, the ticker just
    // hasn't been deployed (or we're scanning a mint before its
    // deploy, which would also fail gate 7 below).
    return { kind: "ok" };
  }

  // ── Gate 5: token must still have mint slots ────────────────────
  if (!isActive(rec)) {
    return { kind: "rejected", reason: `${tickerKey} fully minted (${rec.mints_done}/${rec.params.total_mints})` };
  }

  // ── Gate 6: optimistic placeholder not yet confirmed ────────────
  if (rec.deploy_block === 0) {
    return { kind: "rejected", reason: `${tickerKey} deploy not yet confirmed (deploy_block == 0)` };
  }

  // ── Gate 7 (A3): no same-block premining ────────────────────────
  if (blockHeight <= rec.deploy_block) {
    return { kind: "rejected", reason: `mint at #${blockHeight} ≤ deploy #${rec.deploy_block}` };
  }

  // ── Gate 8 (A2): start_block respected ──────────────────────────
  if (blockHeight < rec.params.start_block) {
    return { kind: "rejected", reason: `mint at #${blockHeight} < start_block #${rec.params.start_block}` };
  }

  // ── Gate 9 (A1): model_id whitelist ─────────────────────────────
  if (!SUPPORTED_MODEL_IDS.includes(rec.params.model_id)) {
    return { kind: "rejected", reason: `unsupported model_id ${rec.params.model_id}` };
  }

  // ── Gate 10 (C3): triple dedup ──────────────────────────────────
  const triple = tripleKey(
    tickerKey, mintPayload.challenge_h, mintPayload.nonce, mintPayload.hash160,
  );
  if (reg.minted_triples.includes(triple)) {
    return { kind: "rejected", reason: "triple already used (C3 dedup)" };
  }

  // ── Gate 11 (C1): challenge_h freshness vs recent blocks ────────
  const fresh = isChallengeFresh({
    ticker: tickerKey,
    mintChallengeH: mintPayload.challenge_h,
    mintBlockHeight: blockHeight,
    recentBlocks: reg.recent_blocks,
  });
  if (!fresh) {
    return { kind: "rejected", reason: "challenge_h not fresh (does not match any recent-block-derived challenge)" };
  }

  // ── Gate 12 (C2): tx input witness must authorise the hash160 ───
  if (!txInputAuthorizesHash160(tx.vin, mintPayload.hash160)) {
    return { kind: "rejected", reason: "no tx input witness HASH160s to the claimed hash160 (C2)" };
  }

  // ── Gate 13: backend availability ───────────────────────────────
  if (!backend.real) {
    // Soft skip — backend exists but is the stub, or no golden vector
    // has verified it yet. We do NOT update state; the scanner will
    // try again on the next rescan (after the user loads + verifies
    // a real backend).
    return { kind: "skipped", reason: "backend not consensus-grade (stub or unverified)" };
  }

  // ── Run inference + PoW (gates 14-15) ───────────────────────────
  // Reconstruct the miner's bech32 address from the hash160 (the
  // verifier path — pow_verify.rs lines 64-72 — does exactly this:
  // wrap the 20-byte hash160 as a P2WPKH script and call
  // `Address::from_script(P2WPKH, Bitcoin).to_string()`).
  let addrBech32: string;
  try {
    addrBech32 = p2wpkhAddressFromHash160(mintPayload.hash160);
  } catch (e: unknown) {
    return { kind: "rejected", reason: `bech32 reconstruction failed: ${e instanceof Error ? e.message : String(e)}` };
  }

  // Build the prompt the miner would have built for this nonce.
  const { prompt } = promptFor({
    challengeH: mintPayload.challenge_h,
    addrBech32,
    nonce: mintPayload.nonce,
  });

  let embedding: Uint8Array;
  try {
    embedding = await backend.encode(prompt);
  } catch (e: unknown) {
    // Gate 14: inference error → soft skip. The scanner will retry
    // on the next rescan; meanwhile we don't poison the registry
    // with a false reject.
    return { kind: "skipped", reason: `inference error: ${e instanceof Error ? e.message : String(e)}` };
  }

  const addrUtf8 = new TextEncoder().encode(addrBech32);
  const powHash = computePow(embedding, mintPayload.nonce, addrUtf8, mintPayload.challenge_h);
  const zb = leadingZeroBits(powHash);
  const effDiff = effectiveDifficulty(rec.params, rec.mints_done);
  if (zb < effDiff) {
    return { kind: "rejected", reason: `PoW too weak: ${zb} < ${effDiff} leading-zero bits required` };
  }

  // ── Gate 16: rate_cap per (ticker, hash160) per block ───────────
  if (rec.params.rate_cap > 0n) {
    const counterKey = `${tickerKey}:${bytesToHex(mintPayload.hash160)}`;
    const already = perBlockCounts.get(counterKey) ?? 0;
    if (BigInt(already) >= rec.params.rate_cap) {
      return { kind: "rejected", reason: `rate_cap exceeded (${already + 1} > ${rec.params.rate_cap}) for (${tickerKey}, ${counterKey.slice(-12)})` };
    }
    perBlockCounts.set(counterKey, already + 1);
  }

  // ── Accept — apply state changes ────────────────────────────────
  rec.mints_done += 1;

  // ypm_raw = yield_per_mint × 10^decimals.
  // v0.1.0 enforces decimals == 0 so the multiplier is always 1n.
  // We still keep the explicit pow term so the future-relaxation
  // path is uncovered.
  let pow10: bigint = 1n;
  for (let i = 0; i < rec.params.decimals; i++) pow10 *= 10n;
  const ypmRaw = rec.params.yield_per_mint * pow10;

  // Triple dedup — push to set + LRU companion. Evict oldest when
  // we exceed MAX_MINTED_TRIPLES.
  reg.minted_triples.push(triple);
  while (reg.minted_triples.length > MAX_MINTED_TRIPLES) {
    reg.minted_triples.shift();
  }
  delta.triples_added.push(triple);

  // Mints-done counter into the per-block delta for reorg-undo.
  delta.mints_added[tickerKey] = (delta.mints_added[tickerKey] ?? 0) + 1;

  // Token UTXO — always at vout=1.
  const outKey = outpointKey(txid, 1);
  reg.token_utxos[outKey] = { ticker: tickerKey, amount: ypmRaw };
  delta.utxos_created.push(outKey);

  // Holder bookkeeping — derive the recipient address from vout[1]'s
  // P2WPKH scriptpubkey hash160, then record first-time holders into
  // the delta so a reorg undoes them. The mint's hash160 is what we
  // already verified at gate 3 + gate 12 (must match), so it's fine
  // to reuse the same bech32 we computed above.
  const holderAddr = addrBech32;
  const wasNew = recordHolder(rec, holderAddr);
  if (wasNew) {
    if (!delta.holders_added[tickerKey]) delta.holders_added[tickerKey] = [];
    delta.holders_added[tickerKey].push(holderAddr);
  }

  return { kind: "ok" };
}

// ── C2 helper: does any input witness HASH160 to `hash160`? ─────────

/** Walks the tx inputs looking for a P2WPKH-shaped witness (`[sig,
 *  compressed_pubkey]`) whose pubkey hashes to the claimed hash160.
 *  Mirrors `token_registry.rs::tx_input_authorizes_hash160`
 *  (lines 1280-1299).
 *
 *  Witness encoding from Esplora is hex strings — element [0] is the
 *  DER signature (variable length), [1] is the 33-byte compressed
 *  pubkey. We only accept the strict 2-element shape because a
 *  non-standard witness can't be assumed to encode a recoverable
 *  pubkey.
 */
function txInputAuthorizesHash160(
  vin: { witness?: string[] }[],
  claimed: Uint8Array,
): boolean {
  if (claimed.length !== 20) return false;
  for (const i of vin) {
    if (!i.witness || i.witness.length !== 2) continue;
    const pubkeyHex = i.witness[1];
    if (typeof pubkeyHex !== "string") continue;
    // Compressed secp256k1 pubkey is 33 bytes = 66 hex chars, with
    // the first byte 0x02 / 0x03 (Y parity).
    if (pubkeyHex.length !== 66) continue;
    const first = pubkeyHex.slice(0, 2);
    if (first !== "02" && first !== "03") continue;
    const pubkey = hexToBytes(pubkeyHex);
    if (!pubkey) continue;
    const h160 = ripemd160(sha256(pubkey));
    if (h160.length !== 20) continue;
    let match = true;
    for (let k = 0; k < 20; k++) {
      if (h160[k] !== claimed[k]) { match = false; break; }
    }
    if (match) return true;
  }
  return false;
}

/** Reconstruct the bech32 P2WPKH address (`bc1q...`) for a 20-byte
 *  hash160 on Bitcoin mainnet. Same encoding the verifier path uses
 *  via `Address::from_script(P2WPKH(hash160), Network::Bitcoin)`.
 *  Encodes the witness program directly via the bech32 segwit codec
 *  (segwit v0, HRP "bc").
 */
/** Decode a hex scriptpubkey to its canonical bech32 / base58 address
 *  for one of the 5 accepted output types (P2WPKH, P2WSH, P2TR, P2PKH,
 *  P2SH). Returns undefined for OP_RETURN, exotic scripts, or malformed
 *  hex. Used by `processTransferUtxos` to track holders of token UTXOs
 *  it just credited.
 *
 *  Mirror of the Rust path `Address::from_script(script, Network::Bitcoin)`.
 *  We pattern-match the standard scriptPubKey shapes by hand because
 *  @scure/btc-signer's `OutScript.decode` returns a tagged union that
 *  still needs a separate `Address(NETWORK).encode(...)` step — the
 *  byte-pattern approach below is one-shot and avoids dragging
 *  payment-script types into this module. */
export function scriptpubkeyHexToAddress(hex: string): string | undefined {
  if (!hex || hex.length % 2 !== 0) return undefined;
  // P2WPKH:  0014 <20 bytes>            → bc1q... (witness v0, 20-byte program)
  if (hex.length === 44 && hex.startsWith("0014")) {
    const h160 = hexToBytes(hex.slice(4));
    if (!h160 || h160.length !== 20) return undefined;
    return bech32EncodeSegwit("bc", 0, h160);
  }
  // P2WSH:  0020 <32 bytes>             → bc1q... (witness v0, 32-byte program)
  if (hex.length === 68 && hex.startsWith("0020")) {
    const witProg = hexToBytes(hex.slice(4));
    if (!witProg || witProg.length !== 32) return undefined;
    return bech32EncodeSegwit("bc", 0, witProg);
  }
  // P2TR:   5120 <32 bytes>             → bc1p... (witness v1, taproot)
  if (hex.length === 68 && hex.startsWith("5120")) {
    const witProg = hexToBytes(hex.slice(4));
    if (!witProg || witProg.length !== 32) return undefined;
    return bech32EncodeSegwit("bc", 1, witProg);
  }
  // P2PKH:  76 a9 14 <20 bytes> 88 ac   → 1...   (legacy, base58)
  if (hex.length === 50 && hex.startsWith("76a914") && hex.endsWith("88ac")) {
    const h160 = hexToBytes(hex.slice(6, 6 + 40));
    if (!h160 || h160.length !== 20) return undefined;
    return base58CheckEncode(0x00, h160);
  }
  // P2SH:   a9 14 <20 bytes> 87         → 3...   (legacy, base58)
  if (hex.length === 46 && hex.startsWith("a914") && hex.endsWith("87")) {
    const h160 = hexToBytes(hex.slice(4, 4 + 40));
    if (!h160 || h160.length !== 20) return undefined;
    return base58CheckEncode(0x05, h160);
  }
  return undefined;
}

// Base58Check encode: `version || payload || checksum[0..4]` →
// Base58. Used by P2PKH / P2SH address rendering for the holder
// derivation in `processTransferUtxos`.
function base58CheckEncode(version: number, payload: Uint8Array): string {
  const versioned = new Uint8Array(1 + payload.length);
  versioned[0] = version;
  versioned.set(payload, 1);
  const checksum = sha256(sha256(versioned)).slice(0, 4);
  const full = new Uint8Array(versioned.length + 4);
  full.set(versioned, 0);
  full.set(checksum, versioned.length);
  return base58.encode(full);
}

export function p2wpkhAddressFromHash160(hash160: Uint8Array): string {
  if (hash160.length !== 20) throw new Error("hash160 must be 20 bytes");
  // `p2wpkh` expects a pubkey; we instead build the script manually
  // and let @scure's Address encoder return the bech32 string. The
  // script is `OP_0 <20-byte hash160>` = `0x00 0x14 <20 bytes>`.
  // Easiest: synthesise a dummy pubkey, call p2wpkh, then override
  // the script. But the helper computes the address from hash160
  // internally — if we build the same shape the address comes out
  // the same. So just call p2wpkh on a dummy pubkey and inject the
  // hash160 into the address via the same encoding.
  //
  // Cleanest path: bypass p2wpkh and call the bech32 encoder
  // directly. We borrow @scure/base's bech32 which is what
  // btc-signer uses internally.
  return bech32EncodeSegwit("bc", 0, hash160);
}

// Minimal bech32 segwit-v0 encoder (BIP173). Hand-rolled because
// @scure/base's bech32 export surface changed across versions and we
// only need one specific encoding path.
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32EncodeSegwit(hrp: string, witver: number, witprog: Uint8Array): string {
  const data = [witver].concat(convertBits(witprog, 8, 5, true));
  const checksum = bech32Checksum(hrp, data, witver === 0 ? 1 : 0x2bc830a3);
  let s = hrp + "1";
  for (const v of data) s += BECH32_CHARSET[v];
  for (const v of checksum) s += BECH32_CHARSET[v];
  return s;
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const v of data) {
    acc = (acc << fromBits) | v;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) out.push((acc << (toBits - bits)) & maxv);
  return out;
}

function bech32Checksum(hrp: string, data: number[], encConst: number): number[] {
  // BIP173 (bech32) uses encConst=1; BIP350 (bech32m) uses 0x2bc830a3.
  // Segwit v0 = bech32 with const 1; v1+ = bech32m.
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const mod = bech32Polymod(values) ^ encConst;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) out.push((mod >> (5 * (5 - i))) & 31);
  return out;
}

function bech32HrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (typeof hex !== "string" || hex.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// Reference unused imports so they don't get tree-shaken away (used
// by future code paths in pow-verify wrapping).
void p2wpkh; void NETWORK;

// ── process_transfer_utxos ──────────────────────────────────────────

/** A single tx vout, as far as the transfer state machine cares. */
export interface TxOutLite {
  /** Hex scriptpubkey. */
  scriptpubkey: string;
  /** Hint from Esplora ("v0_p2wpkh", "v1_p2tr", "p2pkh", "p2sh",
   *  "v0_p2wsh", "op_return", or undefined). Used as the fast path
   *  for the 5-class recipient whitelist; if missing, we treat the
   *  output as non-accepted and the edict soft-burns. */
  scriptpubkey_type?: string;
}

const ACCEPTED_OUTPUT_TYPES = new Set([
  "v0_p2wpkh",
  "v1_p2tr",
  "v0_p2wsh",
  "p2pkh",
  "p2sh",
]);

/** Mirrors `process_transfer_utxos` in token_registry.rs (lines 1009-1170).
 *
 *  Walks the tx's INPUTS to collect token UTXOs being spent, decides
 *  whether the spend is multi-ticker (full-tx burn) or single-ticker,
 *  then walks the EDICTS in order to mint output UTXOs up to the
 *  consumed token balance. Unallocated remainder is silently burned.
 *  Edicts pointing to OP_RETURN or non-whitelisted-script outputs
 *  soft-burn their allocation but do NOT halt edict processing.
 *
 *  Returns the donor ticker (for the receive-tracker / holders
 *  bookkeeping) and the per-edict outcome list so the caller can
 *  update its asset-index. */
export interface TransferResult {
  donor_ticker: string | null;        // null when full-tx burn (multi-ticker)
  edict_outcomes: {
    edict_index: number;
    edict: Edict;
    /** "credited"   — output created at `(txid, edict.output)`
     *  "soft_burn"  — edict-target unacceptable (OP_RETURN / non-whitelisted script / out-of-range) or no balance left
     *  "consumed"   — edict produced no output but DID consume balance (soft_burn after balance was deducted) */
    outcome: "credited" | "soft_burn";
    granted_amount: bigint;           // 0 for any non-"credited" outcome
  }[];
}

export function processTransferUtxos(args: {
  reg: TokenRegistry;
  delta: BlockDelta;
  txid: string;
  vin: { txid: string; vout: number }[];
  vout: TxOutLite[];
  transfer: TransferPayload;
}): TransferResult {
  const { reg, delta, txid, vin, vout, transfer } = args;

  // ── 1. Single-ticker pre-scan (S21) ──────────────────────────────
  // Collect every distinct ticker among the spent input UTXOs.
  // Multi-ticker spends are a full-tx burn — input UTXOs are still
  // removed (one-way state change) but NO outputs are credited.
  const tickerSet = new Set<string>();
  for (const i of vin) {
    const u = reg.token_utxos[outpointKey(i.txid, i.vout)];
    if (u) tickerSet.add(u.ticker);
  }
  const multiTicker = tickerSet.size > 1;

  // ── 2. Remove input UTXOs + accumulate donor balance ─────────────
  let donorTicker: string | null = null;
  let totalInput = 0n;
  for (const i of vin) {
    const key = outpointKey(i.txid, i.vout);
    const u = reg.token_utxos[key];
    if (!u) continue;
    delete reg.token_utxos[key];
    delta.utxos_removed.push({ key, value: u });
    if (!multiTicker) {
      donorTicker = u.ticker;
      totalInput += u.amount;
    }
  }

  // Multi-ticker → full-tx burn; do not credit any outputs.
  if (multiTicker || donorTicker === null) {
    return {
      donor_ticker: null,
      edict_outcomes: transfer.edicts.map((e, i) => ({
        edict_index: i, edict: e, outcome: "soft_burn", granted_amount: 0n,
      })),
    };
  }

  // ── 3. Walk edicts in order, crediting outputs up to totalInput ──
  let remaining = totalInput;
  const outcomes: TransferResult["edict_outcomes"] = [];
  for (let i = 0; i < transfer.edicts.length; i++) {
    const e = transfer.edicts[i];
    const out = vout[e.output];

    // Out-of-range edict: skip WITHOUT consuming `remaining`, so the
    // donor balance survives intact for the rest of the edicts. This
    // matches the Rust gold-master (token_registry.rs: `if idx >=
    // tx.output.len() { continue; }` with no `remaining` mutation).
    // Consuming here would diverge from the desktop client and split
    // consensus on any multi-edict transfer whose first edict is
    // out-of-range — the budget for divergence from Rust is ZERO.
    if (!out) {
      outcomes.push({ edict_index: i, edict: e, outcome: "soft_burn", granted_amount: 0n });
      continue;
    }

    // OP_RETURN as edict target — guaranteed unspendable. Skip WITHOUT
    // consuming `remaining` (Rust gold-master: `if ...is_op_return() {
    // continue; }`, remaining untouched). We also detect this from the
    // scriptpubkey hex starting with 0x6a (in case scriptpubkey_type is
    // missing).
    const isOpReturn =
      out.scriptpubkey_type === "op_return" ||
      (out.scriptpubkey?.startsWith("6a") ?? false);
    if (isOpReturn) {
      outcomes.push({ edict_index: i, edict: e, outcome: "soft_burn", granted_amount: 0n });
      continue;
    }

    // Recipient whitelist: 5-class accepted scripts only.
    const accepted = !!out.scriptpubkey_type && ACCEPTED_OUTPUT_TYPES.has(out.scriptpubkey_type);
    if (!accepted) {
      const consume = remaining < e.amount ? remaining : e.amount;
      remaining -= consume;
      outcomes.push({ edict_index: i, edict: e, outcome: "soft_burn", granted_amount: 0n });
      continue;
    }

    // Calculate the granted amount (capped at remaining balance).
    const granted = remaining < e.amount ? remaining : e.amount;
    if (granted === 0n) {
      outcomes.push({ edict_index: i, edict: e, outcome: "soft_burn", granted_amount: 0n });
      continue;
    }
    remaining -= granted;

    // Credit the output. Same-output-as-prior-edict accumulates
    // (matches Rust's `entry.amount.saturating_add(granted)`).
    const key = outpointKey(txid, e.output);
    const existing = reg.token_utxos[key];
    if (existing) {
      // Same-ticker by construction (donorTicker is the single ticker
      // pool); add to existing amount, saturating at u64 ceiling.
      const sum = existing.amount + granted;
      const cap = (1n << 64n) - 1n;
      existing.amount = sum > cap ? cap : sum;
    } else {
      reg.token_utxos[key] = { ticker: donorTicker, amount: granted };
      delta.utxos_created.push(key);
    }

    // Holder bookkeeping: the recipient of this edict is a new
    // address that now holds `donorTicker`. Without this, transfers
    // would silently leave the `holders` count stuck at whatever the
    // mint path established — visible to the user as "transferred
    // 100 BITAI to a friend but holders count still says 1".
    const rec = reg.tokens[donorTicker];
    if (rec) {
      const recipientAddr = scriptpubkeyHexToAddress(out.scriptpubkey);
      if (recipientAddr && recordHolder(rec, recipientAddr)) {
        // Track the new holder in the delta so a reorg-rewind can
        // remove it. Same shape as the mint path's holder bookkeeping.
        const list = delta.holders_added[donorTicker] ?? [];
        list.push(recipientAddr);
        delta.holders_added[donorTicker] = list;
      }
    }

    outcomes.push({ edict_index: i, edict: e, outcome: "credited", granted_amount: granted });
  }

  // Anything left in `remaining` is silently burned. Mirror the Rust
  // semantics — we do NOT emit a synthetic edict for the burn.
  return { donor_ticker: donorTicker, edict_outcomes: outcomes };
}

// ── Universal token-UTXO sweep (Rule 5.5, UNDEFINED-6) ──────────────

/** For ANY tx that wasn't processed as a valid TRANSFER (plain BTC
 *  send, mint, deploy, malformed BITAI payload, OP_RETURN at the
 *  wrong vout, etc.) we still need to remove any of its inputs that
 *  happen to be in `token_utxos`. Otherwise the registry would think
 *  burned UTXOs are still alive.
 *
 *  Mirrors token_registry.rs lines 2386-2401. */
export function universalSweep(args: {
  reg: TokenRegistry;
  delta: BlockDelta;
  vin: { txid: string; vout: number }[];
}): void {
  for (const i of args.vin) {
    const key = outpointKey(i.txid, i.vout);
    const u = args.reg.token_utxos[key];
    if (!u) continue;
    delete args.reg.token_utxos[key];
    args.delta.utxos_removed.push({ key, value: u });
  }
}

// ── Holder bookkeeping ──────────────────────────────────────────────

/** Insert an address into the token's holders set (lexicographically
 *  sorted). Returns true if this is the first time we see this
 *  holder for this ticker — caller uses that to decide whether to
 *  log into `delta.holders_added`. */
export function recordHolder(rec: TokenRecord, addr: string): boolean {
  // Cheap dedup via linear scan — `holders` is rarely huge in practice
  // and stays well below the size where a Set would pay off.
  if (rec.holders.includes(addr)) return false;
  rec.holders.push(addr);
  rec.holders.sort();
  return true;
}

// ── commit_block ────────────────────────────────────────────────────

/** Finalise the per-block delta into the registry's ring buffer and
 *  advance `last_scanned_height` / `last_scanned_hash`. Evicts the
 *  oldest entry once `recent_blocks.length > RECENT_BLOCK_WINDOW`,
 *  also deleting the matching entry from `block_deltas` so the
 *  serialised state doesn't grow unbounded.
 *
 *  Mirrors `commit_block` in the Rust client. */
export function commitBlock(
  reg: TokenRegistry,
  height: number,
  blockHash: string,
  delta: BlockDelta,
): void {
  reg.recent_blocks.push({ height, hash: blockHash });
  reg.block_deltas[blockHash] = delta;
  reg.last_scanned_height = height;
  reg.last_scanned_hash = blockHash;
  while (reg.recent_blocks.length > RECENT_BLOCK_WINDOW) {
    const evicted = reg.recent_blocks.shift();
    if (evicted) delete reg.block_deltas[evicted.hash];
  }
}

// ── Reorg rewind ────────────────────────────────────────────────────

/** Pop blocks off `recent_blocks` and undo their `block_deltas` until
 *  the top of the ring buffer matches the new chain's
 *  `previousblockhash` (`targetHash`). Returns `true` if a common
 *  ancestor was found, `false` if the reorg exceeds RECENT_BLOCK_WINDOW
 *  and the caller must full-reset + rescan from genesis.
 *
 *  Shared by BOTH scan paths — the browser fast-sync (chain-scan.ts)
 *  and the server indexer (indexer/src/scan.ts) — so a reorg unwinds
 *  to byte-identical registry state on either side. Best-effort port of
 *  the Rust `rewind_to_match`. The exact set of undoable changes is:
 *
 *    * `delta.tokens_deployed` → delete `tokens[ticker]` (only when
 *       the ticker was freshly inserted in that block — F-3 frontruns
 *       aren't pushed into this list, so their overwrites do NOT
 *       rewind; the next scan re-converges).
 *    * `delta.mints_added` → decrement `tokens[ticker].mints_done`.
 *    * `delta.triples_added` → remove from `minted_triples`.
 *    * `delta.utxos_created` → delete from `token_utxos`.
 *    * `delta.utxos_removed` → restore to `token_utxos`.
 *    * `delta.holders_added` → drop from `tokens[ticker].holders`.
 */
export function rewindToCommonAncestor(reg: TokenRegistry, targetHash: string): boolean {
  while (reg.recent_blocks.length > 0) {
    const top = reg.recent_blocks[reg.recent_blocks.length - 1];
    if (top.hash === targetHash) {
      // We're now positioned right at the new chain's parent.
      reg.last_scanned_height = top.height;
      reg.last_scanned_hash = top.hash;
      return true;
    }
    // Pop + undo.
    reg.recent_blocks.pop();
    const delta = reg.block_deltas[top.hash];
    delete reg.block_deltas[top.hash];
    if (!delta) continue;

    // Undo each effect in REVERSE of how it was applied, so any
    // accumulated-amount addition unwinds cleanly.
    for (const key of delta.utxos_created) {
      delete reg.token_utxos[key];
    }
    for (const r of delta.utxos_removed) {
      reg.token_utxos[r.key] = r.value;
    }
    for (const t of delta.triples_added) {
      // Remove from the LRU set. The list is small relative to the
      // 200k cap so a filter is fine — happens only on rewind, not
      // on the hot scan path.
      const idx = reg.minted_triples.indexOf(t);
      if (idx >= 0) reg.minted_triples.splice(idx, 1);
    }
    for (const [ticker, delta_n] of Object.entries(delta.mints_added)) {
      const rec = reg.tokens[ticker];
      if (rec) rec.mints_done = Math.max(0, rec.mints_done - delta_n);
    }
    for (const [ticker, addrs] of Object.entries(delta.holders_added)) {
      const rec = reg.tokens[ticker];
      if (!rec) continue;
      rec.holders = rec.holders.filter(a => !addrs.includes(a));
    }
    // Tokens deployed in THIS block disappear entirely on rewind.
    for (const ticker of delta.tokens_deployed) {
      delete reg.tokens[ticker];
    }
  }
  // Exhausted the ring buffer without finding the new chain — full
  // rescan required.
  return false;
}

// ── triple dedup (will be used by Phase 4 MINT) ─────────────────────

/** Build the LRU-dedup key for a (ticker, challenge_h, nonce, hash160)
 *  tuple. Mirrors the Rust format `"TICKER:HEX(challenge):NONCE:HEX(h160)"`
 *  byte-for-byte so a registry round-trip through web↔desktop sees the
 *  same set membership. */
export function tripleKey(
  ticker: string,
  challengeH: Uint8Array,
  nonce: bigint,
  hash160: Uint8Array,
): string {
  return `${ticker}:${bytesToHex(challengeH)}:${nonce.toString()}:${bytesToHex(hash160)}`;
}

// ── Internal hex helper (small enough to inline) ────────────────────

function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}

// ── JSON persistence (registry ↔ IDB-friendly blob) ─────────────────
//
// `JSON.stringify` doesn't know about bigint. We serialise every bigint
// field as a string under a sentinel-wrapped shape, then revive on
// load. Keeping the format JSON-text (vs CBOR / structured-clone)
// trades a few KB of size for compatibility with humans inspecting the
// dump in browser DevTools.

interface SerialisedRegistry {
  schema_version: number;
  last_scanned_height: number;
  last_scanned_hash: string;
  tokens: Record<string, SerialisedTokenRecord>;
  token_utxos: Record<string, SerialisedTokenUtxo>;
  minted_triples: string[];
  recent_blocks: { height: number; hash: string }[];
  block_deltas: Record<string, SerialisedBlockDelta>;
}

interface SerialisedTokenRecord {
  ticker: string;
  deploy_block: number;
  deploy_txid: string;
  params: SerialisedDeployParams;
  mints_done: number;
  starred: boolean;
  holders: string[];
}

interface SerialisedDeployParams {
  ticker: string;
  total_mints: string;
  yield_per_mint: string;
  decimals: number;
  model_id: number;
  difficulty_0: number;
  halving_curve: number;
  rate_cap: string;
  start_block: number;
}

interface SerialisedTokenUtxo {
  ticker: string;
  amount: string;
}

interface SerialisedBlockDelta {
  block_hash: string;
  tokens_deployed: string[];
  mints_added: Record<string, number>;
  triples_added: string[];
  utxos_created: OutpointKey[];
  utxos_removed: { key: OutpointKey; value: SerialisedTokenUtxo }[];
  holders_added: Record<string, string[]>;
}

export function serializeRegistry(reg: TokenRegistry): string {
  const out: SerialisedRegistry = {
    schema_version: reg.schema_version,
    last_scanned_height: reg.last_scanned_height,
    last_scanned_hash: reg.last_scanned_hash,
    tokens: {},
    token_utxos: {},
    minted_triples: reg.minted_triples.slice(),
    recent_blocks: reg.recent_blocks.slice(),
    block_deltas: {},
  };
  for (const [k, v] of Object.entries(reg.tokens)) {
    out.tokens[k] = {
      ticker: v.ticker,
      deploy_block: v.deploy_block,
      deploy_txid: v.deploy_txid,
      params: serDeployParams(v.params),
      mints_done: v.mints_done,
      starred: v.starred,
      holders: v.holders.slice(),
    };
  }
  for (const [k, v] of Object.entries(reg.token_utxos)) {
    out.token_utxos[k] = { ticker: v.ticker, amount: v.amount.toString() };
  }
  for (const [k, d] of Object.entries(reg.block_deltas)) {
    out.block_deltas[k] = {
      block_hash: d.block_hash,
      tokens_deployed: d.tokens_deployed.slice(),
      mints_added: { ...d.mints_added },
      triples_added: d.triples_added.slice(),
      utxos_created: d.utxos_created.slice(),
      utxos_removed: d.utxos_removed.map(r => ({
        key: r.key,
        value: { ticker: r.value.ticker, amount: r.value.amount.toString() },
      })),
      holders_added: { ...d.holders_added },
    };
  }
  return JSON.stringify(out);
}

export function deserializeRegistry(json: string): TokenRegistry {
  const raw = JSON.parse(json) as SerialisedRegistry;
  if (raw.schema_version !== REGISTRY_SCHEMA_VERSION) {
    // Hard reset on any schema mismatch. The Rust client does the same
    // through its migrate_* chain — we don't yet have a migration to
    // a v2 because there is no v2.
    return emptyRegistry();
  }
  const reg: TokenRegistry = {
    schema_version: raw.schema_version,
    last_scanned_height: raw.last_scanned_height,
    last_scanned_hash: raw.last_scanned_hash,
    tokens: {},
    token_utxos: {},
    minted_triples: raw.minted_triples.slice(),
    recent_blocks: raw.recent_blocks.slice(),
    block_deltas: {},
  };
  for (const [k, v] of Object.entries(raw.tokens)) {
    reg.tokens[k] = {
      ticker: v.ticker,
      deploy_block: v.deploy_block,
      deploy_txid: v.deploy_txid,
      params: deserDeployParams(v.params),
      mints_done: v.mints_done,
      starred: v.starred,
      holders: v.holders.slice(),
    };
  }
  for (const [k, v] of Object.entries(raw.token_utxos)) {
    reg.token_utxos[k] = { ticker: v.ticker, amount: BigInt(v.amount) };
  }
  for (const [k, d] of Object.entries(raw.block_deltas)) {
    reg.block_deltas[k] = {
      block_hash: d.block_hash,
      tokens_deployed: d.tokens_deployed.slice(),
      mints_added: { ...d.mints_added },
      triples_added: d.triples_added.slice(),
      utxos_created: d.utxos_created.slice(),
      utxos_removed: d.utxos_removed.map(r => ({
        key: r.key,
        value: { ticker: r.value.ticker, amount: BigInt(r.value.amount) },
      })),
      holders_added: { ...d.holders_added },
    };
  }
  return reg;
}

function serDeployParams(p: DeployParams): SerialisedDeployParams {
  return {
    ticker: p.ticker,
    total_mints: p.total_mints.toString(),
    yield_per_mint: p.yield_per_mint.toString(),
    decimals: p.decimals,
    model_id: p.model_id,
    difficulty_0: p.difficulty_0,
    halving_curve: p.halving_curve,
    rate_cap: p.rate_cap.toString(),
    start_block: p.start_block,
  };
}

function deserDeployParams(p: SerialisedDeployParams): DeployParams {
  return {
    ticker: p.ticker,
    total_mints: BigInt(p.total_mints),
    yield_per_mint: BigInt(p.yield_per_mint),
    decimals: p.decimals,
    model_id: p.model_id,
    difficulty_0: p.difficulty_0,
    halving_curve: p.halving_curve,
    rate_cap: BigInt(p.rate_cap),
    start_block: p.start_block,
  };
}
