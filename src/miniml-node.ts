// MiniLM-L6-v2 INT8 inference — Node flavour of the web client's
// `miniml-wasm.ts`, implementing the SAME `InferenceBackend` interface.
//
// CRITICAL: byte-equivalence. The web client and this indexer must
// compute identical 384-byte embeddings for the same prompt, or the
// browser's sample-verify (which re-runs the 16-gate on random mints
// from the snapshot) would reject the snapshot. They DO agree because
// both call the EXACT same Rust scalar kernels compiled to wasm —
// the web uses tract-wasm-spike/pkg-web, this uses pkg-node. Same
// crate, same 12.6 MB .wasm, only the host (browser vs Node) differs.
//
// Differences from the browser backend, all IO-only:
//   * model + tokenizer come from local files (fs.readFileSync), not
//     fetch + IndexedDB.
//   * wasm-bindgen glue is CommonJS (`--target nodejs`), loaded via
//     createRequire — it instantiates the wasm synchronously on first
//     require, so there's no `initWasm(url)` step.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { sha256 } from "@noble/hashes/sha2";
import type { InferenceBackend } from "../lib/inference";

// pkg-node is CommonJS (`exports.MiniLM = MiniLM`). createRequire lets
// an ESM module pull it in; the path resolves relative to THIS file
// (indexer/src/), so ../wasm-node/ reaches the vendored output.
const require = createRequire(import.meta.url);
const { MiniLM: RustMiniLM } = require("../wasm-node/tract_wasm_spike.js") as {
  MiniLM: new (modelBytes: Uint8Array, tokenizerJson: string) => {
    encode(prompt: string): Uint8Array;
    free(): void;
  };
};

// ── SHA-256 pins (identical to web miniml-wasm.ts) ──────────────────
// The indexer refuses to run against a model/tokenizer whose bytes
// don't match what the web client + desktop golden vectors used.
const MODEL_SHA256_HEX =
  "e23a2bca73445bc4ce1bbebce306160ee0a8b9d725eadbbb3fb65329ff413267";
const TOKENIZER_SHA256_HEX =
  "da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0";

// ── Golden vector (identical to web) ────────────────────────────────
// One (prompt → embedding) pair captured from the desktop tract path.
// Verified at init() — a mismatch means this Node wasm build diverged
// from the consensus kernels and the indexer must NOT produce a
// snapshot (it would mint-verify differently than every browser).
const GOLDEN_PROMPT = "the cat is sleeping";
const GOLDEN_EMBEDDING_HEX =
  "0b01fd08fb00f7040206ee000302fc01f50a0803080510fd010300fbfffdf704f70103fa03fefd0b010602fdfc0106fd0207fb05f6fa02ff05fd05fffe0608050001fc08fdfffdf7f9fbfd011802ffffff04040102130b0201011009f6fffeff0502050403feff00fa050c080100fffbfa0405040407070305f8fffdf6fcf10001faf4fd0901fb0af608fd0001fafe00fd00f70109030f02fbf2fcfdfafd01000207f8f4fa05fd01040606fc06fd020b00030cf4f902f900f8f5010503fa06f907fd05f606fa0603fffefefdfe03f4050a020601fb04050bf80bf50400f6040000f3fdfcee0604fafd040407050502f4fcfa0302fe06f00209fff50d0bee0dfd02fe0400f70108fffe00f7f7fd00fd0109ff05f40104030afdfe0101040009fffc0106f800fb0a07fb04fefa0e0201f609fcfa0400f60a04020202fb00fa030000faf40afcfb04f1feff09f603fc0507fd060605f6fef5f806fe02ff09fafcf505fbfafb03f106010a030af9fe0408fcfa0a010bfffdfc0104ff000606040100";

function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}

export class MinilmNodeBackend implements InferenceBackend {
  readonly name = "MiniLM-L6-v2 INT8 (tract-wasm, node)";
  real = false;

  private session: { encode(p: string): Uint8Array; free(): void } | null = null;

  constructor(
    private readonly modelPath: string,
    private readonly tokenizerPath: string,
  ) {}

  async init(): Promise<void> {
    if (this.session) return;

    const modelBytes = new Uint8Array(readFileSync(this.modelPath));
    const modelHash = bytesToHex(sha256(modelBytes));
    if (modelHash !== MODEL_SHA256_HEX) {
      throw new Error(
        `model SHA-256 mismatch — expected ${MODEL_SHA256_HEX}, got ${modelHash} (path: ${this.modelPath})`,
      );
    }

    const tokenizerBytes = new Uint8Array(readFileSync(this.tokenizerPath));
    const tokenizerHash = bytesToHex(sha256(tokenizerBytes));
    if (tokenizerHash !== TOKENIZER_SHA256_HEX) {
      throw new Error(
        `tokenizer SHA-256 mismatch — expected ${TOKENIZER_SHA256_HEX}, got ${tokenizerHash} (path: ${this.tokenizerPath})`,
      );
    }
    const tokenizerJson = new TextDecoder().decode(tokenizerBytes);

    this.session = new RustMiniLM(modelBytes, tokenizerJson);

    // Golden-vector gate — refuse to operate if the wasm output drifted.
    const got = bytesToHex(this.session.encode(GOLDEN_PROMPT));
    if (got !== GOLDEN_EMBEDDING_HEX) {
      this.real = false;
      throw new Error(
        `golden vector mismatch for "${GOLDEN_PROMPT}" — Node wasm is NOT consensus-grade.\n` +
        `  expected: ${GOLDEN_EMBEDDING_HEX}\n` +
        `  got     : ${got}`,
      );
    }
    this.real = true;
  }

  async encode(prompt: string): Promise<Uint8Array> {
    if (!this.session) throw new Error("MinilmNodeBackend not initialised — call init() first");
    return this.session.encode(prompt);
  }
}
