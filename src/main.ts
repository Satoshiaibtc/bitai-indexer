// bitai-indexer entry point.
//
// Lifecycle:
//   1. Load ed25519 signing key (fail-fast if absent).
//   2. Load + verify the MiniLM model (sha256 + golden vector) so the
//      16-gate mint verifier is consensus-grade.
//   3. Load the persisted registry (or start empty at genesis).
//   4. Backfill: walk blocks from last-scanned+1 → chain tip (lag 0 by
//      default — a local node is authoritative the instant a block
//      connects, so there's no reason to wait).
//   5. Go live: on every ZMQ new-block notification, re-run the same
//      catch-up so a freshly-confirmed mint lands in the snapshot within
//      seconds of its block. Reorgs are detected by prev-hash and unwound
//      through the registry's 200-block undo journal (scan.ts walkRange);
//      a reorg deeper than the journal re-derives from genesis.
//
// "Instant" comes from ZMQ push: bitcoind notifies us the moment a
// block connects, instead of us polling on a timer.

import { readFileSync } from "node:fs";
import { writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { Subscriber } from "zeromq";
import {
  serializeRegistry,
  deserializeRegistry,
  emptyRegistry,
  REGISTRY_SCHEMA_VERSION,
  RECENT_BLOCK_WINDOW,
  type TokenRegistry,
} from "../lib/token-registry";
import { MinilmNodeBackend } from "./miniml-node";
import { loadSigningKey } from "./signer";
import { writeSnapshot } from "./snapshot";
import { walkRange } from "./scan";
import { getBlockCount } from "./rpc";
import {
  GENESIS_H0,
  SAFETY_LAG_BLOCKS,
  MODEL_PATH,
  TOKENIZER_PATH,
  REGISTRY_STATE_PATH,
  ZMQ_HASHBLOCK,
} from "./config";

function log(msg: string): void {
  console.log(`[bitai-indexer ${new Date().toISOString()}] ${msg}`);
}

// ── Registry persistence (JSON via the web lib's serializer) ────────
function loadRegistryState(): TokenRegistry {
  try {
    const reg = deserializeRegistry(readFileSync(REGISTRY_STATE_PATH, "utf8"));
    if (reg.schema_version !== REGISTRY_SCHEMA_VERSION) {
      log(`persisted registry schema ${reg.schema_version} != ${REGISTRY_SCHEMA_VERSION}; starting fresh`);
      return emptyRegistry();
    }
    return reg;
  } catch {
    return emptyRegistry();
  }
}
function saveRegistryState(reg: TokenRegistry): void {
  mkdirSync(dirname(REGISTRY_STATE_PATH), { recursive: true });
  const tmp = REGISTRY_STATE_PATH + ".tmp";
  writeFileSync(tmp, serializeRegistry(reg));
  renameSync(tmp, REGISTRY_STATE_PATH);
}

const CHECKPOINT_EVERY = 200; // persist registry state every N blocks during backfill

/** Bring the registry up to (chain tip − SAFETY_LAG), persist, and
 *  publish a fresh snapshot. Idempotent + reused for both the initial
 *  backfill and every live ZMQ tick. */
async function catchUp(
  reg: TokenRegistry,
  backend: MinilmNodeBackend,
  seed: Uint8Array,
): Promise<void> {
  const chainTip = await getBlockCount();
  const safeTip = chainTip - SAFETY_LAG_BLOCKS;
  let from = Math.max(GENESIS_H0, reg.last_scanned_height + 1);

  if (from > safeTip) {
    // Already caught up — still refresh the snapshot so its chain_tip /
    // signed_at advance (lets clients see the indexer is alive).
    writeSnapshot(reg, chainTip, seed);
    return;
  }

  log(`scanning blocks ${from} → ${safeTip} (chain tip ${chainTip})`);
  let sinceSave = 0;
  let totalApplied = 0;
  const onBlock = async (h: number, applied: number) => {
    totalApplied += applied;
    if (applied > 0) log(`  block ${h}: applied ${applied} protocol tx(s)`);
    if (++sinceSave >= CHECKPOINT_EVERY) {
      saveRegistryState(reg);
      sinceSave = 0;
      log(`  checkpoint @ ${h} (${Object.keys(reg.tokens).length} tokens)`);
    }
  };

  // walkRange rewinds the undo journal on a reorg. If the reorg is
  // deeper than the journal it returns hardReset (registry wiped) and we
  // re-derive from genesis — cheap for this small post-genesis range.
  // Bounded so a pathological reorg storm can't spin forever; the next
  // ZMQ tick (or systemd restart) retries.
  for (let guard = 0; ; guard++) {
    const { hardReset } = await walkRange(reg, from, safeTip, backend, onBlock);
    if (!hardReset) break;
    if (guard >= 3) throw new Error("repeated reorg hard-resets — aborting pass, will retry on next block");
    log(`reorg deeper than ${RECENT_BLOCK_WINDOW}-block undo journal — re-deriving registry from genesis`);
    saveRegistryState(reg); // reg already emptied by walkRange
    from = GENESIS_H0;
  }
  saveRegistryState(reg);
  const d = writeSnapshot(reg, chainTip, seed);
  log(
    `snapshot published: tip #${d.tip_height}, ${d.tokens_count} tokens, ` +
    `${d.mints_count} mints, ${d.utxos_count} token-utxos ` +
    `(applied ${totalApplied} this pass)`,
  );
}

async function main(): Promise<void> {
  log(`starting — genesis ${GENESIS_H0}, safety lag ${SAFETY_LAG_BLOCKS}`);

  const seed = loadSigningKey();
  log("signing key loaded");

  const backend = new MinilmNodeBackend(MODEL_PATH, TOKENIZER_PATH);
  await backend.init();
  if (!backend.real) throw new Error("MiniLM backend failed golden-vector check — refusing to index");
  log(`MiniLM backend ready (${backend.name}) — golden vector verified`);

  const reg = loadRegistryState();
  log(`registry loaded: last_scanned #${reg.last_scanned_height}, ${Object.keys(reg.tokens).length} tokens`);

  // Initial backfill.
  await catchUp(reg, backend, seed);

  // Go live on ZMQ. Any new-block notification triggers a catch-up;
  // querying getblockcount inside catchUp naturally coalesces bursts
  // (two blocks arriving back-to-back → one walk covering both).
  const sock = new Subscriber();
  sock.connect(ZMQ_HASHBLOCK);
  sock.subscribe("hashblock");
  log(`subscribed to ZMQ ${ZMQ_HASHBLOCK} — live`);

  for await (const _frames of sock) {
    try {
      await catchUp(reg, backend, seed);
    } catch (e) {
      // A transient RPC blip shouldn't kill the daemon; the next block
      // notification (or systemd restart) retries.
      log(`catch-up error (will retry on next block): ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}

main().catch((e) => {
  log(`fatal: ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
  process.exit(1);
});
