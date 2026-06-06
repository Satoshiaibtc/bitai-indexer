// BITAI miner — prompt derivation pipeline.
//
// Mirrors `bitai-miner/src-tauri/src/miner.rs` and the matching
// helpers in `ipc.rs:1024-1037`. The pipeline is purely
// deterministic — given the same (ticker, tip_hash_hex, address,
// nonce) it produces the same prompt string, which the AI inference
// then encodes into a fixed embedding.
//
// PIPELINE:
//
//   challenge_h = SHA256(
//     "bitai/v1"           // 8 ASCII bytes, no NUL
//     || ticker_ascii      // 1-8 ASCII bytes (uppercase A-Z/0-9)
//     || tip_hash_hex      // 64 ASCII chars (lowercase hex of the block hash)
//   )
//
//   base_word = bip39[ be_u32(SHA256(challenge_h || addr_bech32_ascii)[0..4]) % 2048 ]
//
//   extra_words[i] = bip39[ be_u16(nonce_be8[2i..2i+2]) % 2048 ]   for i in 0..4
//
//   prompt = "the " + base_word + " is " + w0 + " " + w1 + " " + w2 + " " + w3
//
// The 2048-word BIP39 English list is shared with @scure/bip39's
// mnemonic generator — same identity, same order. We pin to that
// list so a future repo split between mnemonic generation and miner
// can't silently desync.

import { sha256 } from "@noble/hashes/sha2";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { u64BigEndian } from "./pow";

/** Domain-separation prefix for the per-session challenge hash. 8
 *  ASCII bytes, no null terminator. Mirror of `b"bitai/v1"` in
 *  `ipc.rs:1024`. */
const CHALLENGE_PREFIX: Uint8Array = new TextEncoder().encode("bitai/v1");

/**
 * Derive the 32-byte challenge_h for a (ticker, tip_block_hash_hex)
 * pair. This is computed ONCE per mining session — every nonce attempt
 * shares the same challenge_h, the prompt and PoW pre-hash both
 * fold this in.
 *
 * @param ticker          uppercase ASCII (validated before this call)
 * @param tipBlockHashHex 64-char lowercase hex of `getbestblockhash`
 * @returns 32-byte challenge hash
 */
export function deriveChallengeH(
  ticker: string,
  tipBlockHashHex: string,
): Uint8Array {
  if (!/^[A-Z0-9]{1,8}$/.test(ticker)) {
    throw new Error(`ticker must be 1-8 ASCII uppercase A-Z/0-9 (got ${JSON.stringify(ticker)})`);
  }
  if (!/^[0-9a-f]{64}$/.test(tipBlockHashHex)) {
    throw new Error(`tip block hash must be 64 lowercase hex chars (got ${JSON.stringify(tipBlockHashHex)})`);
  }
  const enc = new TextEncoder();
  const h = sha256.create();
  h.update(CHALLENGE_PREFIX);
  h.update(enc.encode(ticker));
  h.update(enc.encode(tipBlockHashHex));
  return h.digest();
}

/**
 * Derive the per-session `base_word` from challenge_h and the miner's
 * bech32 address. Mirror of `miner.rs::derive_base_word`.
 *
 * The address is hashed as its **bech32 STRING bytes** (e.g.
 * `bc1qabcd...`), NOT the 20-byte hash160. This matches the verifier
 * which reconstructs the address from hash160 via the same bech32
 * encoder and hashes it identically.
 */
export function deriveBaseWord(
  challengeH: Uint8Array,
  addrBech32: string,
): string {
  if (challengeH.length !== 32) throw new Error("challengeH must be 32 bytes");
  const enc = new TextEncoder();
  const h = sha256.create();
  h.update(challengeH);
  h.update(enc.encode(addrBech32));
  const seed = h.digest();
  // u32 big-endian from seed[0..4], computed via ARITHMETIC (not
  // bitwise) so the result stays a proper JS Number in the 0..2^32-1
  // range. Bitwise OR (`|`) converts both operands to signed 32-bit,
  // which silently flips the sign bit when seed[0] >= 0x80 — and a
  // negative `idx` then makes `idx % 2048` ALSO negative (JS uses
  // truncated-division modulo, so the result inherits the dividend's
  // sign). `wordlist[-N]` returns undefined → "missing entry" throw.
  // Multiplication keeps us in safe-integer territory (max value
  // 0xFFFFFFFF = 4,294,967,295, well under 2^53), and the modulo is
  // guaranteed non-negative.
  const idx =
    seed[0] * 0x01000000 +
    seed[1] * 0x010000 +
    seed[2] * 0x0100 +
    seed[3];
  const word = wordlist[idx % 2048];
  if (word === undefined) {
    throw new Error("internal: BIP39 wordlist missing entry");
  }
  return word;
}

/**
 * Derive 4 extra words from a u64 nonce. Mirror of
 * `miner.rs::derive_extra_words` (lines 159-169). The nonce is split
 * into four big-endian u16 chunks; each chunk indexes the BIP39 list
 * modulo 2048.
 *
 * @returns array of exactly 4 words
 */
export function deriveExtraWords(nonce: bigint): [string, string, string, string] {
  const n = u64BigEndian(nonce);
  const out: string[] = [];
  for (let i = 0; i < 4; i++) {
    const idx = ((n[i * 2] << 8) | n[i * 2 + 1]) % 2048;
    const w = wordlist[idx];
    if (w === undefined) {
      throw new Error(`internal: BIP39 wordlist missing entry at index ${idx}`);
    }
    out.push(w);
  }
  return out as [string, string, string, string];
}

/**
 * Build the prompt the AI model embeds. Mirror of
 * `miner.rs::build_prompt_with_base` (line 173-176):
 *
 *     format!("the {} is {} {} {} {}", base, w0, w1, w2, w3)
 *
 * Single ASCII spaces, no trailing newline, no Unicode normalisation.
 */
export function buildPrompt(
  base: string,
  extras: [string, string, string, string],
): string {
  return `the ${base} is ${extras[0]} ${extras[1]} ${extras[2]} ${extras[3]}`;
}

/**
 * One-shot convenience: derive base + extras + prompt for a given
 * (challenge_h, address, nonce). Used by the miner loop and by the
 * applyMint verifier in token-registry.ts.
 */
export function promptFor(args: {
  challengeH: Uint8Array;
  addrBech32: string;
  nonce: bigint;
}): { base: string; extras: [string, string, string, string]; prompt: string } {
  const base = deriveBaseWord(args.challengeH, args.addrBech32);
  const extras = deriveExtraWords(args.nonce);
  const prompt = buildPrompt(base, extras);
  return { base, extras, prompt };
}

/**
 * C1 — challenge-freshness gate.
 *
 * For a mint at block `H` carrying `challenge_h`, the protocol accepts
 * the mint iff `challenge_h` equals `deriveChallengeH(ticker, hash)`
 * for SOME `(height, hash)` in `recent_blocks` within the window
 * `[H - CHALLENGE_TIP_DEPTH, H - 1]`. Anything outside that window
 * means the miner pre-computed the challenge against an old / future
 * tip and is trying to dodge the rotating-challenge anti-precompute
 * rule.
 *
 * Mirrors `token_registry.rs::is_challenge_fresh` (lines 961-985).
 * O(144) SHA-256 calls per mint verification — cheap.
 *
 * @param ticker           uppercase ticker the mint claims
 * @param mintChallengeH   32-byte challenge_h from the MINT payload
 * @param mintBlockHeight  the block height of the mint tx
 * @param recentBlocks     registry.recent_blocks (ring of last 200 blocks)
 * @param challengeTipDepth  how far back the window extends (default 144)
 */
export function isChallengeFresh(args: {
  ticker: string;
  mintChallengeH: Uint8Array;
  mintBlockHeight: number;
  recentBlocks: { height: number; hash: string }[];
  challengeTipDepth?: number;
}): boolean {
  const depth = args.challengeTipDepth ?? 144;
  const minH = args.mintBlockHeight - depth;
  const maxH = args.mintBlockHeight - 1;
  for (const rb of args.recentBlocks) {
    if (rb.height < minH || rb.height > maxH) continue;
    const expected = deriveChallengeH(args.ticker, rb.hash);
    if (bytesEqual(expected, args.mintChallengeH)) return true;
  }
  return false;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

