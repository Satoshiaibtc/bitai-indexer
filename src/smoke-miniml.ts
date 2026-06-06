// Standalone smoke test for the Node MiniLM backend.
//   tsx src/smoke-miniml.ts
// Verifies the pkg-node wasm loads, the model+tokenizer SHA-256 match,
// and the golden vector reproduces byte-for-byte (i.e. Node inference
// is consensus-grade / byte-identical with the browser). Exits non-zero
// on any failure so it can gate CI / deploy.
import { MinilmNodeBackend } from "./miniml-node";
import { MODEL_PATH, TOKENIZER_PATH } from "./config";

const t0 = Date.now();
const backend = new MinilmNodeBackend(MODEL_PATH, TOKENIZER_PATH);
await backend.init();
console.log(`init ok in ${Date.now() - t0}ms — real=${backend.real} name="${backend.name}"`);
const emb = await backend.encode("the cat is sleeping");
const hex = [...emb].map((b) => b.toString(16).padStart(2, "0")).join("");
console.log(`embedding length=${emb.length} bytes`);
console.log(`first 32 bytes: ${hex.slice(0, 64)}`);
if (!backend.real) {
  console.error("✗ backend.real === false — golden vector did NOT match. NOT consensus-grade.");
  process.exit(1);
}
console.log("✓ golden vector verified — Node inference is byte-identical with the browser");
