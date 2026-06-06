# Payload Encoding

The bytes inside the `OP_RETURN` push are a compact binary structure. This page
defines the framing header, the integer encoding, and the byte layout of each
operation's payload. The format is big-endian and is decoded strictly: any
unknown opcode, bad magic, non-canonical integer, or trailing byte after the
last declared field is a hard reject.

## Framing header

Every payload begins with a 7-byte header:

| Offset | Size | Field   | Value                                            |
| ------ | ---- | ------- | ------------------------------------------------ |
| 0      | 5    | magic   | ASCII `"BITAI"` = `42 49 54 41 49`               |
| 5      | 1    | version | `0x01`                                           |
| 6      | 1    | op      | `0x00` deploy · `0x01` mint · `0x02` transfer    |

A payload shorter than 7 bytes, with the wrong magic, or with an unrecognised
version or opcode is rejected.

## Integer encoding (LEB128)

Variable-length integers use unsigned **LEB128** in its **canonical** form: the
shortest byte sequence that represents the value. Because LEB128 admits multiple
encodings of the same number (for example `01` and `81 00` both mean 1), a
lenient decoder would let one indexer accept a transaction another rejects,
forking state per transaction. To prevent that, decoders enforce:

* no trailing-zero continuation byte (only the shortest form is legal);
* no value exceeding the `u64` range;
* at most 10 continuation bytes.

Fixed-width integers (`u32` block heights, the `u64` nonce) are big-endian and
are **not** LEB128.

## Deploy payload (`op = 0x00`)

| Order | Field            | Encoding                         |
| ----- | ---------------- | -------------------------------- |
| 1     | ticker length    | 1 byte                           |
| 2     | ticker           | ASCII, `length` bytes            |
| 3     | `total_mints`    | LEB128                           |
| 4     | `yield_per_mint` | LEB128                           |
| 5     | `decimals`       | 1 byte                           |
| 6     | `model_id`       | 1 byte                           |
| 7     | `difficulty_0`   | 1 byte                           |
| 8     | `halving_curve`  | 1 byte                           |
| 9     | `rate_cap`       | LEB128                           |
| 10    | `start_block`    | `u32` big-endian (4 bytes)       |

Field semantics and validity bounds are given in [Deploy](operations/deploy.md).

## Mint payload (`op = 0x01`)

| Order | Field         | Encoding              |
| ----- | ------------- | --------------------- |
| 1     | ticker length | 1 byte                |
| 2     | ticker        | ASCII, `length` bytes |
| 3     | `challenge_h` | 32 bytes              |
| 4     | `nonce`       | `u64` big-endian (8 bytes) |
| 5     | `hash160`     | 20 bytes              |

`challenge_h` is the per-attempt proof-of-work challenge, `nonce` is the value
that solves it, and `hash160` is the `HASH160` of the miner's public key. See
[Mint & AI Proof-of-Work](operations/mint.md).

## Transfer payload (`op = 0x02`)

| Order | Field          | Encoding                              |
| ----- | -------------- | ------------------------------------- |
| 1     | edict count    | LEB128                                |
| 2…    | edicts         | `count` × `{ amount: LEB128, output: LEB128 }` |

Each **edict** assigns `amount` units to the transaction output at index
`output`. A transfer carries at most **16** edicts — the largest list that fits
the 80-byte `OP_RETURN` ceiling. Transfer semantics are given in
[Transfer](operations/transfer.md).

## Strictness summary

| Rejected                                             | Reason                              |
| ---------------------------------------------------- | ----------------------------------- |
| magic ≠ `"BITAI"`                                    | not a BITAI payload                 |
| version ≠ `0x01`                                     | unsupported version                 |
| opcode ∉ {`0x00`, `0x01`, `0x02`}                    | unknown operation                   |
| non-canonical or overflowing LEB128                  | inter-indexer divergence vector     |
| bytes remaining after the last declared field        | ambiguous payload                   |
| payload length > 80 bytes                            | unrelayable `OP_RETURN`             |
