// AI inference backend — interface + stub.
//
// Splits the consensus-PoW chain (pure JS, deterministic everywhere)
// from the AI-inference layer (numerically heavy, needs WASM + a
// quantised ONNX model). The miner depends only on this interface;
// the actual MiniLM-L6-v2 INT8 inference lives in `miniml-onnx.ts`
// (Phase 4.b) and is plugged in at runtime.
//
// CONSENSUS REQUIREMENT
// =====================
// Every honest implementation of this interface MUST produce
// byte-identical 384-byte output for the same prompt. The desktop
// reference uses tract-onnx with a forked scalar-only tract-linalg
// (`pow_memory_hard.rs` § Determinism posture) so fp32 reduction
// order is fixed across CPUs.
//
// The web port targets onnxruntime-web's `wasm` backend with
// `simd: false, numThreads: 1` and runs the post-inference mean-
// pool + L2-normalize + int8 quantize in deterministic JS code.
// Where the two implementations agree on a fixed set of golden
// (prompt → embedding) test vectors, the miner is safe to ship.
// Where they diverge, the indexer would reject web-mined hits.

/**
 * Backend contract. Implementations must:
 *   * Accept any UTF-8 prompt string (the miner builds these from
 *     BIP39 words so they are always ASCII, but tokenisers may
 *     still apply normalisation).
 *   * Return a Uint8Array. The reference model returns 384 bytes
 *     (the int8-quantised L2-normalised mean-pooled hidden state).
 *   * Be deterministic — given the same prompt, the returned bytes
 *     never differ between calls or sessions.
 *   * Be self-contained — no network I/O on the hot path. Loading
 *     the model file is fine in `init()`, but `encode()` must run
 *     entirely from memory.
 *
 * Implementations are typically constructed once per page load and
 * reused across many encode calls. Callers should never instantiate
 * a backend per-attempt.
 */
export interface InferenceBackend {
  /** Human-readable identifier shown in the MineTab status line.
   *  e.g. "MiniLM-L6-v2 INT8 (onnxruntime-web)" or "STUB". */
  readonly name: string;

  /** True iff this backend is honest about producing real, indexer-
   *  acceptable embeddings. Stubs return `false`; the production
   *  ONNX backend returns `true`. The miner refuses to broadcast a
   *  hit unless the backend is real. */
  readonly real: boolean;

  /** Lazy initialisation — load weights, compile the ONNX graph,
   *  warm the tokeniser. May download model bytes on first call.
   *  Subsequent calls must be no-ops (idempotent). */
  init(): Promise<void>;

  /** Encode a single prompt to its 384-byte int8 embedding. Must
   *  match the desktop tract-scalar output byte-for-byte for the
   *  same prompt. */
  encode(prompt: string): Promise<Uint8Array>;
}

// ── StubInferenceBackend — development scaffolding ──────────────────
//
// Returns deterministic bytes derived from SHA256(prompt) repeated
// to fill 384 bytes. This is enough for end-to-end testing of the
// nonce-search loop, prompt derivation, PoW pipeline, and tx-mint
// construction — BUT IT DOES NOT PRODUCE MINTS THAT THE DESKTOP
// INDEXER WILL ACCEPT.
//
// Marked `real = false`; the miner refuses to broadcast against this
// backend. Switch to a real backend (Phase 4.b) before any mainnet
// mining.

import { sha256 } from "@noble/hashes/sha2";

export class StubInferenceBackend implements InferenceBackend {
  readonly name = "STUB (dev-only — produces invalid mints)";
  readonly real = false;

  async init(): Promise<void> {
    // No-op; nothing to load.
  }

  async encode(prompt: string): Promise<Uint8Array> {
    // Build 384 bytes by chaining SHA256 forward: each block of 32
    // bytes is SHA256(prompt || u8(blockIdx)) so the output is
    // deterministic, prompt-dependent, and verifiable by an outsider
    // running the same stub. Useful exclusively for unit tests +
    // dev-mode mining-pipeline checks.
    const enc = new TextEncoder();
    const promptBytes = enc.encode(prompt);
    const out = new Uint8Array(384);
    for (let block = 0; block < 12; block++) {
      const h = sha256.create();
      h.update(promptBytes);
      h.update(new Uint8Array([block]));
      const digest = h.digest();
      out.set(digest, block * 32);
    }
    return out;
  }
}

// ── Backend registry ────────────────────────────────────────────────
//
// A single mutable slot holding the active backend. The MineTab and
// the chain-scan applyMint verifier both go through this so they
// stay in sync.

let active: InferenceBackend = new StubInferenceBackend();

/** Replace the active backend. Phase 4.b's `miniml-onnx.ts` will
 *  call this once it has finished initialising. Subsequent calls
 *  to `getInferenceBackend()` return the new instance. */
export function setInferenceBackend(b: InferenceBackend): void {
  active = b;
}

/** Returns the current backend. The miner + verifier both read
 *  this on every encode call so a hot-swap (e.g. once the ONNX
 *  weights finish loading) is picked up at the next attempt. */
export function getInferenceBackend(): InferenceBackend {
  return active;
}
