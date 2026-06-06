# Deploy

A **deploy** registers a new token ticker and fixes its issuance schedule
permanently. It is the genesis event for a token: every later mint and transfer
refers back to the parameters set here.

## Effect

The first valid, confirmed deploy of a given ticker claims that ticker and opens
it for minting. A ticker is unique across the protocol — once claimed, later
deploys naming the same ticker are ignored, and the original parameters are
immutable. There is no admin key, no pause, and no upgrade.

## Parameters

| Field            | Type      | Meaning                                                                 |
| ---------------- | --------- | ----------------------------------------------------------------------- |
| `ticker`         | string    | 1–8 characters, ASCII uppercase `A–Z` and digits `0–9`                  |
| `total_mints`    | u64       | total number of mints the ticker will ever allow                        |
| `yield_per_mint` | u64       | units granted by each successful mint                                   |
| `decimals`       | u8        | fractional precision of the unit                                        |
| `model_id`       | u8        | the AI model that secures minting                                       |
| `difficulty_0`   | u8        | initial mining difficulty, in leading-zero bits                         |
| `halving_curve`  | u8        | number of difficulty steps across the mint schedule (`0` = flat)        |
| `rate_cap`       | u64       | max mints per `(ticker, miner)` per block (`0` = uncapped)              |
| `start_block`    | u32       | earliest block height at which mining may begin                         |

### Supply

A token's maximum supply is fixed at deploy time:

```
max_supply = total_mints × yield_per_mint × 10^decimals
```

`total_mints` must be a **non-zero multiple of 10**, which keeps the supply
schedule cleanly divisible by the halving curve. The computed `max_supply`, and
the intermediate `yield_per_mint × 10^decimals`, must each fit in a `u64`;
deploys whose arithmetic would overflow are rejected.

### Precision

`decimals` declares the unit's fractional precision and is carried in the wire
format for forward compatibility. In the current version BITAI tokens are
integer-only: `decimals` is `0`, so one mint credits exactly `yield_per_mint`
whole units.

### Difficulty and the halving curve

`difficulty_0` sets how hard the very first mint is, measured in required
leading-zero bits of the proof-of-work output. It must fall within the
productive range **`[11, 27]`**: below the floor a ticker could be drained in
seconds; above the ceiling it becomes effectively unmineable.

`halving_curve` controls how difficulty rises over the life of the ticker. With
`halving_curve = 0`, difficulty is constant at `difficulty_0`. With a non-zero
curve, the mint schedule is divided into that many equal intervals and the
effective difficulty steps up at each boundary, so early mints are easier and
later mints progressively harder, always clamped to the `[11, 27]` ceiling. The
exact effective-difficulty function is given in
[Mint & AI Proof-of-Work](mint.md).

### Rate cap

`rate_cap` bounds how many times a single miner identity can mint a given ticker
within one block. A value of `0` leaves the ticker uncapped. A positive cap
spreads issuance across more participants by preventing a single party from
sweeping many slots in the same block.

### Start block

`start_block` is the earliest height at which mints for the ticker are valid.
Mints in earlier blocks — including the deploy's own block — are rejected. This
gives every participant a fair, announced starting line and rules out same-block
pre-mining by the deployer.

## Validity

A deploy is accepted when:

* the transaction pays the treasury fee;
* the `OP_RETURN` decodes as a well-formed deploy payload;
* `ticker` matches the character and length rules;
* `total_mints` is a non-zero multiple of 10;
* `model_id` is a supported model;
* `decimals` is within the protocol's precision rules;
* `difficulty_0` is within `[11, 27]`;
* the supply arithmetic does not overflow `u64`;
* the ticker is not already claimed.

A deploy that fails any check is ignored and does not claim the ticker.
