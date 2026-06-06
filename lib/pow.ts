// BITAI PoW chain — SHA256 pre-hash → Argon2id memory-hard post-hash.
//
// Mirrors `bitai-miner/src-tauri/src/pow_memory_hard.rs::compute_pow`
// byte-for-byte. Bug here is a consensus split — the verifier on the
// desktop indexer would reject every web-mined hit.
//
// Pipeline (positional concatenation, no length prefixes anywhere):
//
//   pre_hash = SHA256(
//     embedding[384]                       // int8 MiniLM output reinterpreted as u8
//     || nonce_be[8]                       // u64 big-endian
//     || addr_bech32_utf8[42 or 62 or ...] // ASCII bytes of bc1q... — NOT hash160
//     || challenge_h[32]                    // from miner-prompt.ts::deriveChallengeH
//   )
//
//   pow_hash = Argon2id(
//     password = pre_hash,                  // 32 bytes
//     salt     = b"bitai/v1/mem-hard",      // 17 ASCII bytes, no NUL
//     m = 16384 KiB, t = 1, p = 1,
//     v = 0x13 (Argon2 v1.3), out_len = 32
//   )
//
//   HIT iff leading_zero_bits(pow_hash) >= effective_difficulty
//
// Note that the bech32 STRING — not the hash160 — is concatenated. This
// matters because the verifier reconstructs the address from hash160
// via `Address::from_script(P2WPKH(hash160), Network::Bitcoin).to_string()`
// and must produce the same UTF-8 bytes we hashed against. The wallet
// is mainnet-only P2WPKH so we generate `bc1q...` lowercase.

import { sha256 } from "@noble/hashes/sha2";
import { argon2id } from "@noble/hashes/argon2";

/** Argon2id parameters — frozen at v1 launch. Tuning ANY of these is a
 *  consensus break and requires VERSION bump in protocol.ts. */
export const ARGON2_M_COST = 16_384;   // KiB → 16 MiB
export const ARGON2_T_COST = 1;        // iterations
export const ARGON2_P_COST = 1;        // lane count
export const ARGON2_OUTPUT_LEN = 32;   // bytes

/** Hard-coded salt — 17 ASCII bytes, no null terminator. Mirror of the
 *  Rust `ARGON2_SALT: &[u8] = b"bitai/v1/mem-hard"`. */
export const ARGON2_SALT: Uint8Array = new TextEncoder().encode("bitai/v1/mem-hard");

/**
 * Compute the 32-byte memory-hard PoW hash for one (embedding, nonce,
 * address, challenge) attempt.
 *
 *   * `embedding` is the raw int8-reinterpreted-as-u8 MiniLM output
 *     (384 bytes in v1 — but we don't enforce that here; the inference
 *     backend is the source of truth on the embedding length).
 *   * `nonce` is a u64 (use bigint to survive past 2^53-1).
 *   * `addrUtf8` is the BECH32 STRING bytes of the miner's P2WPKH
 *     address — NOT the 20-byte hash160. `bc1q...` lowercase, plain
 *     ASCII, ~42 bytes for a standard mainnet P2WPKH.
 *   * `challengeH` is the 32-byte challenge produced by
 *     `deriveChallengeH(ticker, tip_hash_hex)`.
 *
 * Returns the 32-byte `pow_hash` ready for `leadingZeroBits`.
 *
 * Pure function. Deterministic. Throws only if the underlying
 * argon2id implementation hits an allocation failure on this device.
 */
export function computePow(
  embedding: Uint8Array,
  nonce: bigint,
  addrUtf8: Uint8Array,
  challengeH: Uint8Array,
): Uint8Array {
  if (challengeH.length !== 32) {
    throw new Error(`challengeH must be 32 bytes, got ${challengeH.length}`);
  }

  // ── pre_hash = SHA256(embedding || nonce_be8 || addrUtf8 || challengeH)
  //
  // `@noble/hashes/sha2.sha256.create()` returns an incremental hasher
  // so we can stream the four pieces without first concatenating into
  // a 400-ish-byte temporary buffer.
  const h = sha256.create();
  h.update(embedding);
  h.update(u64BigEndian(nonce));
  h.update(addrUtf8);
  h.update(challengeH);
  const preHash = h.digest();

  // ── pow_hash = Argon2id(password=preHash, salt=ARGON2_SALT, ...)
  //
  // @noble/hashes' argon2id is the audited reference implementation
  // and produces the same output as the Rust `argon2` crate at the
  // same parameters. The v=0x13 (Argon2 v1.3) is the only version
  // shipped by both crates — we don't need to specify it explicitly.
  return argon2id(preHash, ARGON2_SALT, {
    m: ARGON2_M_COST,
    t: ARGON2_T_COST,
    p: ARGON2_P_COST,
    dkLen: ARGON2_OUTPUT_LEN,
  });
}

/**
 * Big-endian u64 encoder. Used to feed the nonce into both the SHA256
 * pre-hash (here) and the OP_RETURN payload (in protocol.ts).
 *
 * JS BigInt doesn't ship a `toBytesBE` helper and `BigInt64Array` is
 * little-endian on x86, so we hand-roll. Returns a fresh 8-byte
 * Uint8Array — caller can pass directly to `hasher.update`.
 *
 * Tested via `pow.test.ts`: nonces 0, 1, 0xff, 0xffffffffffffffff
 * round-trip through encoder + decoder identically.
 */
export function u64BigEndian(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`nonce out of u64 range: ${n}`);
  }
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/**
 * Leading-zero-bits count for a 32-byte hash. Mirrors
 * `pow_memory_hard.rs::leading_zero_bits` (lines 95-106).
 *
 * Big-endian scan: full 8 zeros per zero byte, otherwise count the
 * leading zeros of the high bit's byte and break. Returns 0..=256.
 *
 * Examples (from Rust tests):
 *   [0x0f, ...]       → 4
 *   [0x00, 0x80, ...] → 8
 *   all-zero          → 256
 */
export function leadingZeroBits(hash: Uint8Array): number {
  let n = 0;
  for (const b of hash) {
    if (b === 0) { n += 8; continue; }
    // Math.clz32 counts leading zeros in a 32-bit int; for an 8-bit
    // value we subtract the 24 bits of high-zero padding.
    n += Math.clz32(b) - 24;
    return n;
  }
  return n;
}
