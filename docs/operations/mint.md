# Mint & AI Proof-of-Work

A **mint** claims one issuance slot of an open ticker and credits its yield to a
recipient output. Minting is the only way new units are created, and every mint
must carry a valid **AI proof-of-work** — a small, verifiable computation over a
fixed sentence-embedding model. This is the heart of the protocol.

## Why proof-of-work for minting

Fee-race issuance rewards whoever pays the most, which in practice means
automated bidders. BITAI replaces the auction with *work*: to claim a unit you
must actually run an AI model and search for an input that clears a difficulty
target. The search is probabilistic and memory-hard, so it cannot be shortcut by
a clever encoding or accelerated cheaply on specialised hardware, yet a single
embedding-plus-hash is enough for any indexer to verify the result. Issuance
therefore tracks computation performed, and the difficulty curve keeps the rate
predictable over the ticker's lifetime.

## The proof-of-work, step by step

The proof binds together four things: the **ticker**, a **recent block** (for
freshness), the **miner's recipient key**, and a search **nonce**.

### 1. Challenge

The per-attempt challenge is derived from the ticker and a recent Bitcoin block
hash:

```
challenge_h = SHA256( "bitai/v1" || ticker || tip_block_hash_hex )
```

Binding the challenge to a recent block hash makes it **fresh**: a proof is only
valid for a short, recent window of the chain, so work cannot be precomputed far
in advance or replayed against old blocks.

### 2. Prompt

The challenge and the recipient address deterministically select a sequence of
words from the standard BIP-39 English wordlist:

* a **base word** from `SHA256(challenge_h || recipient_address)`, and
* **four more words** selected by the 64-bit search `nonce`.

The resulting word sequence is the model's input. Different nonces produce
different prompts, which is what the miner iterates over.

### 3. Embedding

The prompt is run through the fixed AI model for the ticker — model `0`,
`all-MiniLM-L6-v2`, a sentence-embedding network — producing a deterministic
fixed-length embedding vector. Because the work depends on the model's output,
it cannot be produced without actually evaluating the model.

### 4. Work hash

The embedding is combined with the nonce, the recipient address, and the
challenge, then run through a memory-hard function:

```
pre  = SHA256( embedding || nonce_be || recipient_address || challenge_h )
work = Argon2id( pre, salt = "bitai/v1/mem-hard", m = 16 MiB, t = 1, p = 1, 32 bytes )
```

### 5. Target

The mint is valid when the work hash has at least **`D` leading zero bits**,
where `D` is the ticker's *effective difficulty* for the current point in its
mint schedule:

```
leading_zero_bits(work) ≥ D
```

A miner searches over nonces until it finds one that satisfies the target, then
publishes the mint with that `nonce`, the `challenge_h`, and the `HASH160` of its
recipient key.

## Effective difficulty

The required number of leading-zero bits rises over a ticker's life according to
its halving curve:

* If `halving_curve = 0`, the effective difficulty is constant at `difficulty_0`.
* Otherwise the schedule of `total_mints` is divided into `halving_curve` equal
  intervals, and the effective difficulty steps up by one level at each interval
  boundary as mints accumulate.

Effective difficulty is always clamped to the protocol ceiling of **27 bits**.

## Yield

An accepted mint credits `yield_per_mint × 10^decimals` units to **`vout[1]`**,
the recipient output. That output becomes a new token-bearing UTXO carrying the
ticker and amount, spendable thereafter under the [transfer](transfer.md) rules.

## Acceptance rules

An indexer accepts a mint only if **all** of the following hold. They are listed
in evaluation order.

| #  | Check                                                                              |
| -- | ---------------------------------------------------------------------------------- |
| 1  | the transaction has at least two outputs                                           |
| 2  | `vout[1]` is not an `OP_RETURN`                                                     |
| 3  | `vout[1]` is a standard **P2WPKH** output                                           |
| 4  | the `ticker` is deployed                                                            |
| 5  | the ticker still has unminted slots (`mints_done < total_mints`)                   |
| 6  | the ticker's deploy is already confirmed                                            |
| 7  | the mint's block height is **after** the deploy block (no same-block pre-mining)   |
| 8  | the block height is at or after the ticker's `start_block`                          |
| 9  | the `model_id` is a supported model                                                 |
| 10 | the `(challenge_h, nonce, hash160)` triple has not been used before (no replay)    |
| 11 | the `challenge_h` is fresh — derived from a sufficiently recent block              |
| 12 | an input witness authorises the claimed `hash160` (the miner holds the key)        |
| 13 | the model backend is available                                                      |
| 14 | the prompt embeds successfully                                                      |
| 15 | the recomputed work hash meets the effective-difficulty target                      |
| 16 | the `(ticker, miner)` per-block `rate_cap` is not exceeded                          |

A mint failing any check is rejected and credits nothing; the issuance slot it
attempted to claim remains open.

## Anti-Sybil guarantees

Three of the rules above are what make farming a ticker expensive rather than
free:

* **Freshness (rule 11)** ties every proof to a recent block, so work has a
  short shelf life and cannot be stockpiled.
* **Witness binding (rule 12)** forces the proof's recipient key to control a
  real Bitcoin input. A proof-of-work is therefore non-transferable — it can
  only be redeemed by the identity that produced it.
* **Triple uniqueness (rule 10)** prevents a single solved proof from being
  replayed to mint twice.

Together with the per-block `rate_cap` and the memory-hard work function, these
rules keep issuance tied to genuine, recent, per-identity computation.
