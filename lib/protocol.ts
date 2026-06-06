// BITAI Protocol OP_RETURN codec — byte-exact JS port of Rust
// `bitai-miner/src-tauri/src/protocol.rs`.
//
// SAME WIRE FORMAT, DIFFERENT LANGUAGE. Every byte this codec writes
// MUST round-trip identically through the desktop client's decoder
// (and vice versa), or the two implementations will fork the
// network. Cross-implementation byte-exactness is enforced by
// running the same fixture vectors through both decoders — see
// `protocol.fixtures.ts` (next pass).
//
// Magic bytes / version / opcode constants are intentionally
// duplicated as `const` here instead of being downloaded from the
// Rust crate at build time. Static duplication trades "single
// source of truth" for "no build-time dependency on the desktop
// project" — the consensus rules are slow-changing, and any drift
// surfaces immediately in the round-trip test.
//
// WIRE FORMAT (big-endian)
//   magic[5]  = "BITAI"
//   version   = 0x01
//   op        = u8
//   payload   = op-specific
//
// OP CODES
//   0x00 = DEPLOY
//   0x01 = MINT
//   0x02 = TRANSFER

// ── Consensus constants (mirror protocol.rs) ─────────────────────────
// MUST stay in lock-step with the Rust values — if you tune one, tune
// both. The cross-impl round-trip test catches drift.

/** Magic bytes — ASCII "BITAI" (5 bytes), matching the Rust constant
 *  `MAGIC: &[u8; 5] = b"BITAI"`. These five bytes are consensus-fixed;
 *  do not change the length or contents. */
export const MAGIC: Uint8Array = new Uint8Array([0x42, 0x49, 0x54, 0x41, 0x49]);
export const VERSION: number = 0x01;

// Opcodes (single byte after VERSION), matching the Rust constants:
// OP_DEPLOY = 0x00 / OP_MINT = 0x01 / OP_TRANSFER = 0x02. Consensus-fixed.
export const OP_DEPLOY: number = 0x00;
export const OP_MINT: number = 0x01;
export const OP_TRANSFER: number = 0x02;

/** v1 ships exactly one AI-PoW model (MiniLM-L6-v2 → model_id = 0).
 *  Adding a new model = bump VERSION, NOT extend this list silently. */
export const SUPPORTED_MODEL_IDS: readonly number[] = [0];

/** Max edicts in a TRANSFER. 80-byte OP_RETURN ceiling fits ~16 once
 *  the magic/version/op overhead is subtracted. Reject larger values
 *  at decode time to defeat cheap OOM-DoS via gigantic varint length. */
export const MAX_EDICTS: number = 16;

/** Forward-compat ceiling on `decimals` in DEPLOY. v0.1.0 ADDITIONALLY
 *  rejects any non-zero value via `validateDecimals` — BITAI tokens are
 *  integer-only. The byte stays in the wire format so a future v2 can
 *  relax it without breaking compatibility. */
export const MAX_DECIMALS: number = 18;

/** Lower bound on deploy-time mining difficulty (leading-zero bits).
 *  Below this floor an attacker could drain mint slots in seconds. */
export const MIN_DIFFICULTY_BITS: number = 11;

/** Upper bound on deploy-time mining difficulty AND any effective-
 *  difficulty after halving. Above this ceiling a ticker becomes
 *  effectively unmineable (~40 days/mint at the 40 H/s baseline) and
 *  squats a name in limbo. The two endpoints together define the
 *  productive range [11, 27]. */
export const MAX_DIFFICULTY_BITS: number = 27;

/** Standard-relay OP_RETURN ceiling. The default Bitcoin Core relay
 *  policy refuses to relay any OP_RETURN > 80 bytes. We hard-cap at
 *  encode time so a malformed UI input can never produce an
 *  unrelayable tx. */
export const MAX_OP_RETURN_BYTES: number = 80;

// ── Payload types (mirror protocol.rs structs) ───────────────────────

export interface DeployParams {
  ticker: string;          // 1-8 uppercase ASCII alphanumeric (A-Z, 0-9)
  total_mints: bigint;     // non-zero multiple of 10
  yield_per_mint: bigint;
  decimals: number;        // strict 0 in v0.1.0
  model_id: number;        // 0 (only model 0 supported in v0.1.0)
  difficulty_0: number;    // in [MIN_DIFFICULTY_BITS, MAX_DIFFICULTY_BITS]
  halving_curve: number;   // 0-6
  rate_cap: bigint;        // u64 — max mints per (ticker, hash160) per block; 0 = uncapped
  start_block: number;     // u32 — earliest block height eligible for mining
}

export interface MintPayload {
  ticker: string;
  challenge_h: Uint8Array; // 32 bytes
  nonce: bigint;           // u64
  hash160: Uint8Array;     // 20 bytes
}

export interface Edict {
  amount: bigint;
  output: number; // tx output index this edict credits
}

export interface TransferPayload {
  edicts: Edict[];
}

export type Payload =
  | { kind: "deploy"; params: DeployParams }
  | { kind: "mint"; mint: MintPayload }
  | { kind: "transfer"; transfer: TransferPayload };

// ── Error variants (mirror Rust ProtocolError enum) ──────────────────

/** Discriminated union of every possible decoder / encoder failure.
 *  Mirrors `ProtocolError` in `protocol.rs`. Callers can switch on
 *  `err.kind` to render a precise diagnostic. */
export type ProtocolErrorKind =
  | "Short"
  | "BadMagic"
  | "BadVersion"
  | "UnknownOp"
  | "BadVarint"
  | "BadTicker"
  | "TooLarge"
  | "TrailingBytes"
  | "BadDifficulty"
  | "BadTotalSupply"
  | "BadTotalMints"
  | "BadModelId"
  | "BadDecimals"
  | "BadYield";

export class ProtocolError extends Error {
  readonly kind: ProtocolErrorKind;
  readonly detail?: unknown;
  constructor(kind: ProtocolErrorKind, msg: string, detail?: unknown) {
    super(msg);
    this.name = "ProtocolError";
    this.kind = kind;
    this.detail = detail;
  }
}

// ── LEB128 varint helpers (canonical encoding only) ──────────────────

function writeVarint(out: number[], v: bigint): void {
  // `v` is u64 in Rust; we use bigint here so values above 2^53-1
  // (rate_cap, total_supply, yield_per_mint) survive without loss.
  if (v < 0n) throw new ProtocolError("BadVarint", "negative varint");
  while (v >= 0x80n) {
    out.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  out.push(Number(v));
}

/** Strict canonical LEB128 decode (mirror Rust audit finding P3).
 *
 *  LEB128 admits multiple byte sequences for the same numeric value
 *  (e.g. `01` and `81 00` both decode to 1). A lenient decoder that
 *  accepts both creates an inter-indexer divergence vector: one
 *  implementation accepts the transaction, another rejects it as
 *  malformed, and the network forks on a per-tx basis. We therefore
 *  accept ONLY the shortest valid encoding of each value.
 *
 *  Rejects:
 *   1. Trailing-zero continuation (`80 00`, `81 00` etc.) — only the
 *      shortest form of each value is legal.
 *   2. Terminating byte > 0x01 at shift=63 — the encoding would set
 *      u64 bits ≥ 64, which silently overflow on the `<< 63` shift.
 *   3. More than 10 continuation bytes — u64 overflow.
 *
 *  Returns the decoded value and advances `cur.i`. */
function readVarint(buf: Uint8Array, cur: { i: number }): bigint {
  let v = 0n;
  let shift = 0n;
  while (true) {
    if (cur.i >= buf.length) {
      throw new ProtocolError("BadVarint", "varint truncated");
    }
    const b = buf[cur.i++];
    if ((b & 0x80) === 0) {
      // Terminating byte.
      if (shift > 0n && b === 0) {
        throw new ProtocolError("BadVarint", "non-canonical varint (trailing 0)");
      }
      if (shift === 63n && b > 0x01) {
        throw new ProtocolError("BadVarint", "varint overflows u64 at shift=63");
      }
      v |= BigInt(b & 0x7f) << shift;
      return v;
    }
    v |= BigInt(b & 0x7f) << shift;
    shift += 7n;
    if (shift > 63n) {
      throw new ProtocolError("BadVarint", "varint too long for u64");
    }
  }
}

// ── Validators (mirror Rust validate_* helpers) ──────────────────────

function validateTicker(t: string): void {
  if (t.length === 0 || t.length > 8) {
    throw new ProtocolError("BadTicker", "ticker must be 1-8 chars");
  }
  // Same charset as the Rust matches!(b, b'A'..=b'Z' | b'0'..=b'9').
  if (!/^[A-Z0-9]+$/.test(t)) {
    throw new ProtocolError("BadTicker", "ticker must be ASCII uppercase A-Z / 0-9");
  }
}

function validateTotalMints(totalMints: bigint): void {
  if (totalMints === 0n || totalMints % 10n !== 0n) {
    throw new ProtocolError("BadTotalMints", "total_mints must be a non-zero multiple of 10");
  }
}

function validateModelId(modelId: number): void {
  if (!SUPPORTED_MODEL_IDS.includes(modelId)) {
    throw new ProtocolError("BadModelId", `unsupported model_id ${modelId} (v1 supports only 0)`);
  }
}

function validateDecimals(decimals: number): void {
  if (decimals !== 0) {
    throw new ProtocolError("BadDecimals", `decimals must be 0 (got ${decimals})`);
  }
}

function validateDifficulty0(d0: number): void {
  if (d0 < MIN_DIFFICULTY_BITS || d0 > MAX_DIFFICULTY_BITS) {
    throw new ProtocolError(
      "BadDifficulty",
      `difficulty_0 must be in [${MIN_DIFFICULTY_BITS}, ${MAX_DIFFICULTY_BITS}] (got ${d0})`,
    );
  }
}

const U64_MAX = (1n << 64n) - 1n;

function checkedMulU64(a: bigint, b: bigint): bigint | null {
  if (a === 0n || b === 0n) return 0n;
  const p = a * b;
  return p > U64_MAX ? null : p;
}

function checkedPow10U64(decimals: number): bigint | null {
  let p = 1n;
  for (let i = 0; i < decimals; i++) {
    p *= 10n;
    if (p > U64_MAX) return null;
  }
  return p;
}

function validateYieldScaled(yieldPerMint: bigint, decimals: number): void {
  const pow = checkedPow10U64(decimals);
  if (pow === null || checkedMulU64(yieldPerMint, pow) === null) {
    throw new ProtocolError(
      "BadYield",
      `yield_per_mint × 10^decimals overflows u64 (yield=${yieldPerMint}, decimals=${decimals})`,
    );
  }
}

/** Audit 2026-05-11 finding P4 — lifetime supply must fit in u64,
 *  otherwise transfer-path balance saturation diverges across
 *  indexers. */
function validateTotalSupply(
  totalMints: bigint,
  yieldPerMint: bigint,
  decimals: number,
): void {
  const pow = checkedPow10U64(decimals);
  if (pow === null) {
    throw new ProtocolError("BadTotalSupply", "10^decimals overflows u64");
  }
  const unit = checkedMulU64(yieldPerMint, pow);
  if (unit === null) {
    throw new ProtocolError("BadTotalSupply", "yield × 10^decimals overflows u64");
  }
  if (checkedMulU64(totalMints, unit) === null) {
    throw new ProtocolError(
      "BadTotalSupply",
      `total supply overflow: total_mints=${totalMints}, yield=${yieldPerMint}, decimals=${decimals}`,
    );
  }
}

// ── encode / decode ──────────────────────────────────────────────────

/** Encode a payload into the canonical OP_RETURN byte string. Returns
 *  the payload bytes ONLY — no OP_RETURN / push opcode framing (that
 *  is `opReturnScript`'s job, since whether the length prefix is one
 *  byte or OP_PUSHDATA1 depends on whether `len ≤ 75` or larger).
 *  Throws ProtocolError on validation failure or if the encoded length
 *  exceeds 80 bytes. */
export function encode(payload: Payload): Uint8Array {
  const buf: number[] = [];
  for (const b of MAGIC) buf.push(b);
  buf.push(VERSION);
  switch (payload.kind) {
    case "deploy": {
      const d = payload.params;
      validateTicker(d.ticker);
      validateTotalMints(d.total_mints);
      validateModelId(d.model_id);
      validateDecimals(d.decimals);
      validateDifficulty0(d.difficulty_0);
      validateYieldScaled(d.yield_per_mint, d.decimals);
      validateTotalSupply(d.total_mints, d.yield_per_mint, d.decimals);
      buf.push(OP_DEPLOY);
      const tickerBytes = new TextEncoder().encode(d.ticker);
      buf.push(tickerBytes.length);
      for (const b of tickerBytes) buf.push(b);
      writeVarint(buf, d.total_mints);
      writeVarint(buf, d.yield_per_mint);
      buf.push(d.decimals);
      buf.push(d.model_id);
      buf.push(d.difficulty_0);
      buf.push(d.halving_curve);
      writeVarint(buf, d.rate_cap);
      // start_block: u32 big-endian (matches `start_block.to_be_bytes()`).
      const sb = d.start_block >>> 0; // coerce to unsigned 32-bit
      buf.push((sb >>> 24) & 0xff);
      buf.push((sb >>> 16) & 0xff);
      buf.push((sb >>> 8) & 0xff);
      buf.push(sb & 0xff);
      break;
    }
    case "mint": {
      const m = payload.mint;
      validateTicker(m.ticker);
      if (m.challenge_h.length !== 32) {
        throw new ProtocolError("Short", "challenge_h must be 32 bytes");
      }
      if (m.hash160.length !== 20) {
        throw new ProtocolError("Short", "hash160 must be 20 bytes");
      }
      buf.push(OP_MINT);
      const tickerBytes = new TextEncoder().encode(m.ticker);
      buf.push(tickerBytes.length);
      for (const b of tickerBytes) buf.push(b);
      for (const b of m.challenge_h) buf.push(b);
      // nonce: u64 big-endian
      const n = m.nonce;
      for (let s = 56n; s >= 0n; s -= 8n) {
        buf.push(Number((n >> s) & 0xffn));
      }
      for (const b of m.hash160) buf.push(b);
      break;
    }
    case "transfer": {
      const t = payload.transfer;
      buf.push(OP_TRANSFER);
      writeVarint(buf, BigInt(t.edicts.length));
      for (const e of t.edicts) {
        writeVarint(buf, e.amount);
        writeVarint(buf, BigInt(e.output));
      }
      break;
    }
  }
  if (buf.length > MAX_OP_RETURN_BYTES) {
    throw new ProtocolError(
      "TooLarge",
      `OP_RETURN payload ${buf.length} > ${MAX_OP_RETURN_BYTES} bytes`,
    );
  }
  return new Uint8Array(buf);
}

/** Decode the canonical OP_RETURN payload bytes (post-framing — caller
 *  supplies bytes INSIDE the OP_RETURN push, not including the
 *  OP_RETURN / OP_PUSHBYTES opcodes). Strict: any unrecognised op-code,
 *  invalid magic, non-canonical varint, or trailing bytes after the
 *  last declared field is a hard reject — see the "F4 trailing bytes"
 *  comment in `protocol.rs` for why lenient acceptance would fork
 *  consensus across the network. */
export function decode(buf: Uint8Array): Payload {
  if (buf.length < 7) {
    throw new ProtocolError("Short", "payload too short for magic+version+op");
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (buf[i] !== MAGIC[i]) {
      throw new ProtocolError("BadMagic", 'magic bytes != "BITAI"');
    }
  }
  if (buf[5] !== VERSION) {
    throw new ProtocolError("BadVersion", `unsupported version ${buf[5]}`);
  }
  const op = buf[6];
  const cur = { i: 7 };
  let payload: Payload;
  switch (op) {
    case OP_DEPLOY: {
      if (cur.i >= buf.length) throw new ProtocolError("Short", "deploy: ticker_len missing");
      const tlen = buf[cur.i++];
      if (cur.i + tlen > buf.length) throw new ProtocolError("Short", "deploy: ticker truncated");
      const ticker = new TextDecoder().decode(buf.subarray(cur.i, cur.i + tlen));
      validateTicker(ticker);
      cur.i += tlen;
      const total_mints = readVarint(buf, cur);
      validateTotalMints(total_mints);
      const yield_per_mint = readVarint(buf, cur);
      if (cur.i + 4 > buf.length) {
        throw new ProtocolError("Short", "deploy: decimals/model_id/diff/halving truncated");
      }
      const decimals = buf[cur.i++];
      validateDecimals(decimals);
      validateYieldScaled(yield_per_mint, decimals);
      validateTotalSupply(total_mints, yield_per_mint, decimals);
      const model_id = buf[cur.i++];
      validateModelId(model_id);
      const difficulty_0 = buf[cur.i++];
      validateDifficulty0(difficulty_0);
      const halving_curve = buf[cur.i++];
      const rate_cap = readVarint(buf, cur);
      if (cur.i + 4 > buf.length) {
        throw new ProtocolError("Short", "deploy: start_block truncated");
      }
      // Force the FULL expression unsigned: the chained `|` re-coerces to
      // a signed int32, so without the trailing `>>> 0` any start_block
      // with bit 31 set (>= 0x80000000) would decode negative — Gate 8
      // (blockHeight < start_block) would then always pass, and the value
      // would diverge from the Rust u32 decode. Unsigned keeps it == u32.
      const start_block =
        (((buf[cur.i] << 24) >>> 0) |
          (buf[cur.i + 1] << 16) |
          (buf[cur.i + 2] << 8) |
          buf[cur.i + 3]) >>> 0;
      cur.i += 4;
      payload = {
        kind: "deploy",
        params: {
          ticker, total_mints, yield_per_mint, decimals,
          model_id, difficulty_0, halving_curve, rate_cap, start_block,
        },
      };
      break;
    }
    case OP_MINT: {
      if (cur.i >= buf.length) throw new ProtocolError("Short", "mint: ticker_len missing");
      const tlen = buf[cur.i++];
      if (cur.i + tlen > buf.length) throw new ProtocolError("Short", "mint: ticker truncated");
      const ticker = new TextDecoder().decode(buf.subarray(cur.i, cur.i + tlen));
      validateTicker(ticker);
      cur.i += tlen;
      if (buf.length < cur.i + 32 + 8 + 20) {
        throw new ProtocolError("Short", "mint: challenge/nonce/hash160 truncated");
      }
      const challenge_h = buf.slice(cur.i, cur.i + 32);
      cur.i += 32;
      let nonce = 0n;
      for (let s = 0; s < 8; s++) {
        nonce = (nonce << 8n) | BigInt(buf[cur.i + s]);
      }
      cur.i += 8;
      const hash160 = buf.slice(cur.i, cur.i + 20);
      cur.i += 20;
      payload = { kind: "mint", mint: { ticker, challenge_h, nonce, hash160 } };
      break;
    }
    case OP_TRANSFER: {
      const n = Number(readVarint(buf, cur));
      if (n > MAX_EDICTS) {
        throw new ProtocolError("TooLarge", `transfer edict count ${n} > ${MAX_EDICTS}`);
      }
      const edicts: Edict[] = [];
      for (let i = 0; i < n; i++) {
        const amount = readVarint(buf, cur);
        const output = Number(readVarint(buf, cur));
        edicts.push({ amount, output });
      }
      payload = { kind: "transfer", transfer: { edicts } };
      break;
    }
    default:
      throw new ProtocolError("UnknownOp", `unknown op 0x${op.toString(16)}`);
  }
  // F4 strict trailing-bytes check (mirror Rust audit finding).
  if (cur.i !== buf.length) {
    throw new ProtocolError(
      "TrailingBytes",
      `trailing ${buf.length - cur.i} byte(s) after payload at offset ${cur.i}`,
    );
  }
  return payload;
}

// ── OP_RETURN script wrapping ────────────────────────────────────────

/**
 * Wrap the canonical payload bytes into a full Bitcoin OP_RETURN
 * script: `0x6a <push> <data>`. Length-prefix logic:
 *   * ≤ 75 bytes  → 1-byte direct push (the length itself acts as the
 *                    push opcode for 0x01..0x4b)
 *   * 76..255     → OP_PUSHDATA1 (0x4c) + 1 length byte
 *
 * The current 80-byte ceiling on OP_RETURN means a max-size payload
 * uses the OP_PUSHDATA1 branch (76..80 bytes). Both branches are
 * exercised by the round-trip test.
 *
 * Returned bytes are ready to hand to `@scure/btc-signer`'s
 * `tx.addOutput({ script: <this>, amount: 0n })`.
 */
export function opReturnScript(payload: Uint8Array): Uint8Array {
  const len = payload.length;
  if (len <= 75) {
    const out = new Uint8Array(2 + len);
    out[0] = 0x6a; // OP_RETURN
    out[1] = len;  // direct push opcode
    out.set(payload, 2);
    return out;
  }
  // 76..255 — OP_PUSHDATA1.
  const out = new Uint8Array(3 + len);
  out[0] = 0x6a;
  out[1] = 0x4c; // OP_PUSHDATA1
  out[2] = len;
  out.set(payload, 3);
  return out;
}
