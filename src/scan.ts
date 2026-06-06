// Block-walk scanner — the indexer's core.
//
// Discovery vs. application:
//   * DISCOVERY is a block-walk: the local node has every block from
//     genesis to tip, so we fetch each one (getblock verbosity 2) and
//     look at its txs. This is how we find treasury-paying txs without
//     an address index (stock Core has none).
//   * APPLICATION matches the web client's fast-sync EXACTLY: we only
//     act on txs that pay the treasury fee (the "only fee-paid txs are
//     indexed" rule), decode their vout[0] BITAI OP_RETURN, and apply
//     deploy / mint / transfer via the SAME token-registry functions
//     the browser uses. Non-fee txs are skipped entirely — no sweep,
//     same as fast-sync.
//
// The ONE intentional divergence from browser fast-sync: mints run the
// full 16-gate `applyMint` (the server has the MiniLM model loaded), so
// a fee-paid mint with invalid PoW is REJECTED here. The browser's
// fast-sync trusts the fee without re-checking PoW; its sample-verify
// (which DOES re-run the gate) therefore agrees with this snapshot, and
// the snapshot is strictly more correct than a naive fast-sync.

import {
  applyDeploy,
  applyMint,
  processTransferUtxos,
  commitBlock,
  newBlockDelta,
  rewindToCommonAncestor,
  emptyRegistry,
  scriptpubkeyHexToAddress,
  type TokenRegistry,
  type TxOutLite,
  type RateCapCounter,
} from "../lib/token-registry";
import { extractOpReturnData, hexToBytes } from "../lib/op-return";
import { decode, MAGIC, ProtocolError } from "../lib/protocol";
import type { InferenceBackend } from "../lib/inference";
import type { EsploraTx } from "./types";
import { getFullBlock, getBlockHash, type FullBlock } from "./rpc";
import { TREASURY_ADDRESS, GENESIS_H0 } from "./config";

/** True iff any output pays the treasury address. This is the
 *  fee-gate: a tx that doesn't pay the treasury is invisible to the
 *  index (matches the web fast-sync's treasury-address-only view). */
function paysTreasury(tx: EsploraTx): boolean {
  for (const v of tx.vout) {
    if (v.scriptpubkey_type === "op_return") continue;
    if (scriptpubkeyHexToAddress(v.scriptpubkey) === TREASURY_ADDRESS) return true;
  }
  return false;
}

/** Does vout[0] carry a BITAI-magic OP_RETURN? Returns the decoded
 *  payload, or null if not BITAI / not parseable. */
function decodeBitai(tx: EsploraTx): ReturnType<typeof decode> | null {
  const v0 = tx.vout[0];
  if (!v0 || v0.scriptpubkey_type !== "op_return") return null;
  const scriptBytes = hexToBytes(v0.scriptpubkey);
  if (!scriptBytes) return null;
  const payload = extractOpReturnData(scriptBytes);
  if (!payload || payload.length < MAGIC.length) return null;
  for (let i = 0; i < MAGIC.length; i++) if (payload[i] !== MAGIC[i]) return null;
  try {
    return decode(payload);
  } catch (e) {
    if (e instanceof ProtocolError) return null;
    throw e;
  }
}

/** Apply one fully-loaded block to the registry. Mutates `reg`.
 *  Returns the count of BITAI protocol txs applied (for logging). */
export async function applyBlock(
  reg: TokenRegistry,
  block: FullBlock,
  backend: InferenceBackend,
): Promise<number> {
  // Genesis floor — defensive; backfill never fetches below genesis.
  if (block.height < GENESIS_H0) {
    reg.last_scanned_height = block.height;
    reg.last_scanned_hash = block.hash;
    return 0;
  }

  const delta = newBlockDelta(block.hash);
  const perBlockCounts: RateCapCounter = new Map();
  let applied = 0;

  for (const tx of block.txs) {
    // Fee-gate: only treasury-paying txs are protocol-relevant.
    if (!paysTreasury(tx)) continue;
    const decoded = decodeBitai(tx);
    if (!decoded) continue; // paid the treasury but no BITAI payload (donation / stray)

    if (decoded.kind === "deploy") {
      applyDeploy(reg, delta, tx.txid, block.height, decoded.params);
      applied++;
    } else if (decoded.kind === "mint") {
      await applyMint({
        reg,
        delta,
        txid: tx.txid,
        blockHeight: block.height,
        blockHash: block.hash,
        mintPayload: decoded.mint,
        tx: {
          vin: tx.vin.map((v) => ({ txid: v.txid, vout: v.vout, witness: v.witness })),
          vout: tx.vout.map((v) => ({
            scriptpubkey: v.scriptpubkey,
            scriptpubkey_type: v.scriptpubkey_type,
          })),
        },
        backend,
        perBlockCounts,
      });
      applied++;
    } else if (decoded.kind === "transfer") {
      const voutLite: TxOutLite[] = tx.vout.map((v) => ({
        scriptpubkey: v.scriptpubkey,
        scriptpubkey_type: v.scriptpubkey_type,
      }));
      processTransferUtxos({
        reg,
        delta,
        txid: tx.txid,
        vin: tx.vin.map((i) => ({ txid: i.txid, vout: i.vout })),
        vout: voutLite,
        transfer: decoded.transfer,
      });
      applied++;
    }
  }

  commitBlock(reg, block.height, block.hash, delta);
  return applied;
}

/** Walk blocks [from, to] inclusive, applying each. Calls `onBlock`
 *  after every block so the caller can checkpoint / report progress.
 *  Sequential by design: the registry state machine is order-
 *  dependent (reorg detection compares prev-hash chains), and a local
 *  node serves blocks fast enough that pipelining isn't worth the
 *  complexity for the indexer's small post-genesis range.
 *
 *  Reorg handling mirrors the browser fast-sync (chain-scan.ts): if the
 *  block we're about to apply doesn't build on our last-committed block
 *  (`block.prevHash !== reg.last_scanned_hash`), the chain reorganised.
 *  We rewind through the registry's 200-block undo journal to the common
 *  ancestor and resume forward from there — using the SAME audited
 *  `rewindToCommonAncestor` the browser uses, so both compute identical
 *  state. If the reorg is deeper than the journal we can't unwind it
 *  precisely, so we signal `hardReset` and the caller re-derives the
 *  whole registry from genesis. This is what lets the indexer run at
 *  zero safety-lag (index the tip the instant the node sees it) while
 *  staying correct across reorgs. */
export async function walkRange(
  reg: TokenRegistry,
  from: number,
  to: number,
  backend: InferenceBackend,
  onBlock: (height: number, applied: number) => void | Promise<void>,
): Promise<{ hardReset: boolean }> {
  let h = from;
  while (h <= to) {
    const hash = await getBlockHash(h);
    const block = await getFullBlock(hash);

    // Reorg detection — does this block chain onto our last-committed one?
    if (
      reg.last_scanned_height > 0 &&
      reg.last_scanned_hash !== "" &&
      block.prevHash !== undefined &&
      block.prevHash !== reg.last_scanned_hash
    ) {
      const ok = rewindToCommonAncestor(reg, block.prevHash);
      if (!ok) {
        // Reorg exceeds the undo journal — wipe and let the caller
        // re-walk from genesis (cheap for this small post-genesis range).
        Object.assign(reg, emptyRegistry());
        return { hardReset: true };
      }
      // Resume forward from the ancestor we rewound to; the next block
      // on the new chain now chains cleanly onto last_scanned_hash.
      h = reg.last_scanned_height + 1;
      continue;
    }

    const applied = await applyBlock(reg, block, backend);
    await onBlock(h, applied);
    h++;
  }
  return { hardReset: false };
}
