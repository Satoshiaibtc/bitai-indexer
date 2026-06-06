# Constants & Parameters

This page collects the fixed protocol values referenced throughout the
specification. They are consensus constants: an indexer must use exactly these
values to derive the canonical state.

## Framing

| Constant         | Value                                  |
| ---------------- | -------------------------------------- |
| Magic bytes      | ASCII `"BITAI"` = `42 49 54 41 49`     |
| Version          | `0x01`                                 |
| Opcode — deploy  | `0x00`                                 |
| Opcode — mint    | `0x01`                                 |
| Opcode — transfer| `0x02`                                 |
| Max payload size | `80` bytes (`OP_RETURN` relay ceiling) |
| Integer encoding | canonical (shortest-form) LEB128       |

## Network

| Constant            | Value                                                              |
| ------------------- | ----------------------------------------------------------------- |
| Chain               | Bitcoin **mainnet**                                                |
| Genesis height      | `952595` — no operation below this height is indexed              |
| Treasury address    | `bc1pfgtv6nsl7m2e3jefkmv968rrwqqpv22scwha224wq3ptyeaec2mqv9c98l`   |
| Treasury fee        | `546` satoshis per protocol-relevant transaction                  |

## Token parameters

| Constant                | Value / range                                              |
| ----------------------- | ---------------------------------------------------------- |
| Ticker characters       | ASCII uppercase `A–Z` and digits `0–9`                     |
| Ticker length           | 1–8 characters                                             |
| `total_mints`           | non-zero multiple of 10, fits `u64`                        |
| `yield_per_mint`        | `u64`; `yield × 10^decimals` must not overflow `u64`       |
| `decimals`              | `0` (integer-only units)                                   |
| Max supply              | `total_mints × yield_per_mint × 10^decimals`, fits `u64`   |
| `difficulty_0`          | `11`–`27` leading-zero bits                                |
| Effective-difficulty cap| `27` leading-zero bits                                     |
| `halving_curve`         | `0`–`6` (`0` = constant difficulty)                        |
| `rate_cap`              | `u64`; `0` = uncapped                                      |
| Max edicts per transfer | `16`                                                       |

## AI proof-of-work

| Constant            | Value                                                            |
| ------------------- | --------------------------------------------------------------- |
| Model `0`           | `all-MiniLM-L6-v2` sentence embedding                           |
| Challenge prefix    | `"bitai/v1"`                                                    |
| Challenge           | `SHA256( "bitai/v1" \|\| ticker \|\| tip_block_hash_hex )`      |
| Work pre-hash       | `SHA256( embedding \|\| nonce_be \|\| recipient_address \|\| challenge_h )` |
| Work function       | Argon2id                                                        |
| Argon2id memory     | `16 MiB` (`16384` KiB)                                          |
| Argon2id iterations | `1`                                                             |
| Argon2id lanes      | `1`                                                             |
| Argon2id output     | `32` bytes                                                      |
| Argon2id salt       | `"bitai/v1/mem-hard"`                                           |
| Target              | `leading_zero_bits(work) ≥ effective_difficulty`               |

## Snapshot

| Constant         | Value                                             |
| ---------------- | ------------------------------------------------- |
| State signature  | Ed25519 over the serialized registry bytes        |
| State digest     | SHA-256, published in the descriptor              |
| Descriptor fields| schema version, tip height, tip hash, chain tip, state digest, signing key, signing time |
