// Local Bitcoin Core JSON-RPC — Node side.
//
// The web client's core-rpc.ts already maps Core → Esplora shapes,
// but it slices blocks into 25-tx pages to mimic Esplora's API. The
// indexer walks whole blocks, so re-fetching a big block 120× would
// be silly. This module fetches each block ONCE (getblock verbosity
// 2) and maps every tx to the EsploraTx shape the registry apply
// functions expect — the SAME shape + the SAME scriptpubkey_type
// mapping the browser's Core path uses, so the two compute identical
// registries.
//
// Auth: Basic, credentials from the bitcoind cookie file (see
// config.rpcAuth). fetch + btoa are Node 18+ globals — no deps.

import type { EsploraTx, EsploraTxVout } from "./types";
import { RPC_URL, rpcAuth } from "./config";

interface JsonRpcResp<T> {
  result?: T;
  error: { code: number; message: string } | null;
}

let authHeader: string | null = null;
function getAuthHeader(): string {
  if (authHeader === null) {
    const { user, pass } = rpcAuth();
    authHeader = "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
  }
  return authHeader;
}

async function rpc<T>(method: string, params: unknown[] = []): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  try {
    const r = await fetch(RPC_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        Authorization: getAuthHeader(),
      },
      body: JSON.stringify({ jsonrpc: "1.0", id: "bitai-indexer", method, params }),
    });
    if (!r.ok) throw new Error(`RPC ${method} → HTTP ${r.status}`);
    const body = (await r.json()) as JsonRpcResp<T>;
    if (body.error) throw new Error(`RPC ${method} → ${body.error.message} (${body.error.code})`);
    if (body.result === undefined) throw new Error(`RPC ${method} → empty result`);
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

// ── Core scriptPubKey.type → Esplora type (mirror of core-rpc.ts) ──
function mapCoreScriptType(t: string | undefined): string | undefined {
  switch (t) {
    case "witness_v0_keyhash":    return "v0_p2wpkh";
    case "witness_v0_scripthash": return "v0_p2wsh";
    case "witness_v1_taproot":    return "v1_p2tr";
    case "pubkeyhash":            return "p2pkh";
    case "scripthash":            return "p2sh";
    case "nulldata":              return "op_return";
    default:                      return t;
  }
}

const COINBASE_TXID = "0000000000000000000000000000000000000000000000000000000000000000";

// ── Core verbose-tx shapes (subset we read) ─────────────────────────
interface CoreVout {
  value: number; // BTC float
  n: number;
  scriptPubKey: { hex: string; type?: string; address?: string };
}
interface CoreVin {
  txid?: string;
  vout?: number;
  coinbase?: string;
  txinwitness?: string[];
  scriptSig?: { hex: string };
  sequence: number;
}
interface CoreTx {
  txid: string;
  vin: CoreVin[];
  vout: CoreVout[];
}
interface CoreBlock {
  hash: string;
  height: number;
  time: number;
  previousblockhash?: string;
  tx: CoreTx[];
}

/** A fully-loaded block: the chain metadata the scanner needs for
 *  reorg detection + every tx mapped to the EsploraTx shape the
 *  registry apply functions consume. */
export interface FullBlock {
  height: number;
  hash: string;
  prevHash: string | undefined;
  time: number;
  txs: EsploraTx[];
}

export async function getBlockCount(): Promise<number> {
  return await rpc<number>("getblockcount");
}

export async function getBlockHash(height: number): Promise<string> {
  return await rpc<string>("getblockhash", [height]);
}

/** Fetch a whole block (verbosity 2 = full tx bodies) and map every
 *  tx to EsploraTx. One RPC call per block. */
export async function getFullBlock(hash: string): Promise<FullBlock> {
  const b = await rpc<CoreBlock>("getblock", [hash, 2]);
  const txs: EsploraTx[] = b.tx.map((tx) => ({
    txid: tx.txid,
    vin: tx.vin.map((i) => ({
      txid: i.txid ?? COINBASE_TXID,
      vout: i.vout ?? 0xffffffff,
      witness: i.txinwitness,
      scriptsig: i.scriptSig?.hex ?? "",
      sequence: i.sequence,
    })),
    vout: tx.vout.map((v): EsploraTxVout => ({
      scriptpubkey: v.scriptPubKey.hex,
      scriptpubkey_type: mapCoreScriptType(v.scriptPubKey.type),
      value: Math.round(v.value * 1e8),
    })),
    status: {
      confirmed: true,
      block_height: b.height,
      block_hash: b.hash,
      block_time: b.time,
    },
  }));
  return { height: b.height, hash: b.hash, prevHash: b.previousblockhash, time: b.time, txs };
}

/** Fetch a block directly by height (hash lookup + full fetch). */
export async function getBlockAtHeight(height: number): Promise<FullBlock> {
  const hash = await getBlockHash(height);
  return await getFullBlock(hash);
}
