// Strict canonical OP_RETURN data extractor.
//
// Mirrors `extract_op_return_data` in `bitai-miner/src-tauri/src/
// token_registry.rs` (lines 1749-1787 of that file). The web indexer
// MUST agree byte-for-byte with the desktop indexer about which
// OP_RETURN scripts are admissible, or the two implementations
// disagree on which txs carry valid BITAI activity and the meta-
// protocol forks on a per-tx basis.
//
// What "strict canonical" means in this context:
//
//   1. Script must start with 0x6a (OP_RETURN opcode).
//
//   2. The data MUST be carried by ONE of two push opcodes:
//        * 0x01..0x4b — direct push of N bytes
//        * 0x4c       — OP_PUSHDATA1 (1-byte length prefix), but ONLY
//                        when N >= 76 (a 75-byte payload would have
//                        been pushed via the direct opcode 0x4b;
//                        pushing it via PUSHDATA1 is a longer encoding
//                        of the same data and we reject it as non-
//                        canonical to prevent encoder ambiguity).
//
//   3. The script length after the push opcode + length prefix MUST
//      equal exactly the declared payload size (no trailing bytes).
//
// Explicitly REJECTED:
//   * 0x4d (PUSHDATA2) / 0x4e (PUSHDATA4) — never needed at the 80-byte
//     standard relay ceiling.
//   * OP_0 (0x00) and OP_1..OP_16 (0x51..0x60) used as numeric pushes —
//     these can put 0..16 onto the stack but BITAI payloads never start
//     with such a value, and allowing them would create an alternate
//     encoding path that the desktop indexer would reject.
//
// Used by the chain scanner: for every tx, examine `vout[0]`. If
// `extractOpReturnData` returns a Uint8Array and that Uint8Array
// starts with the MAGIC bytes, hand it to `protocol.decode`.

/**
 * Try to extract the canonical-push data from a script that may or may
 * not be a BITAI OP_RETURN. Returns the inner data bytes on success,
 * or `null` if the script does not match the strict canonical shape.
 *
 * Note: returning null for ANY shape deviation is the safe default —
 * it just means "ignore this output, it isn't carrying a BITAI
 * payload". The fact that a non-canonical push *might* technically be
 * a BITAI deploy from a buggy encoder doesn't help us: the desktop
 * indexer rejects it identically, so accepting it here would split
 * consensus.
 *
 * @param script  the raw script bytes (NOT hex)
 */
export function extractOpReturnData(script: Uint8Array): Uint8Array | null {
  if (script.length < 2) return null;
  if (script[0] !== 0x6a /* OP_RETURN */) return null;

  const lenByte = script[1];

  // Branch 1: single-byte direct push (0x01..0x4b).
  // Script must be exactly: [0x6a, lenByte, ...data]  → total length 2 + lenByte.
  if (lenByte >= 0x01 && lenByte <= 0x4b) {
    if (script.length !== 2 + lenByte) return null;
    return script.subarray(2, 2 + lenByte);
  }

  // Branch 2: OP_PUSHDATA1 (0x4c). Canonical only when n >= 76 —
  // anything shorter would have used the direct opcode above.
  if (lenByte === 0x4c) {
    if (script.length < 3) return null;
    const n = script[2];
    if (n < 76) return null;                       // non-canonical (re-encodes a 0..75 push)
    if (script.length !== 3 + n) return null;      // trailing or short bytes
    return script.subarray(3, 3 + n);
  }

  // Everything else (0x4d/0x4e PUSHDATA2/4, OP_0..OP_16, raw data
  // without an opcode prefix, …) is rejected.
  return null;
}

/** Parse a hex-encoded scriptpubkey (as Esplora returns it in
 *  `tx.vout[i].scriptpubkey`) into raw bytes. Returns null on any
 *  parse failure — callers should treat that as "not a BITAI
 *  OP_RETURN" rather than as an error, since malformed-hex outputs
 *  from a tx body should not stop the whole scan. */
export function hexToBytes(hex: string): Uint8Array | null {
  if (typeof hex !== "string") return null;
  // Allow leading "0x" but be strict otherwise — Esplora never
  // prefixes, so this is a defensive escape hatch.
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  }
  return out;
}
