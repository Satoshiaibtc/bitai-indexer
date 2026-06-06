# Indexing Rules

An indexer turns the raw Bitcoin blockchain into the global BITAI token state. It
is a deterministic state machine: it walks blocks in order, selects the
protocol-relevant transactions, decodes their payloads, and applies them under
the rules in the previous chapters. This page specifies that pipeline and how it
stays correct across chain reorganisations.

## The pipeline

For each block, from the protocol genesis height upward:

1. **Discover.** Read the block's transactions. The indexer needs only the
   block contents — outputs, scripts, and input witnesses — which a full node
   provides directly. No external address index is required.
2. **Fee-gate.** Keep only transactions that pay the treasury fee (see
   [Transaction Format](transaction-format.md)). Everything else is ignored.
   This single filter reduces a whole block to the handful of transactions that
   can possibly affect token state.
3. **Decode.** Extract and decode the first valid BITAI `OP_RETURN` into a
   deploy, mint, or transfer (see [Payload Encoding](encoding.md)). A payload
   that fails to decode is discarded.
4. **Apply.** Run the operation against the registry under its acceptance rules.
   Accepted operations mutate state; rejected ones leave it unchanged.

## The genesis floor

No deploy, mint, or transfer below the protocol **genesis height** is ever
indexed. The genesis height is a fixed constant (see [Reference](reference.md)).
This gives every indexer the same, unambiguous starting point and bounds the
range it must scan.

## State

The registry holds exactly what is needed to validate future operations and
report balances:

| Component        | Contents                                                              |
| ---------------- | --------------------------------------------------------------------- |
| **tokens**       | one record per deployed ticker: its parameters and mints-done counter |
| **token UTXOs**  | a `(ticker, amount)` tag for every output that currently holds units  |
| **minted set**   | the set of used `(challenge_h, nonce, hash160)` triples (replay guard) |
| **chain cursor** | the height and hash of the last fully-applied block                   |

Balances are read straight off the token-UTXO map. A holder's balance for a
ticker is the sum of the amounts on the token UTXOs their keys control.

## Determinism

Every input to the state machine is on-chain and order-fixed: transaction bytes,
output scripts, input witnesses, block heights, and block hashes. There is no
wall-clock dependence and no indexer-local state beyond what is derived from the
chain. Consequently, any two correct indexers that apply the same blocks in the
same order produce **byte-identical** registries. This reproducibility is the
foundation of the snapshot model in the next chapter.

## Reorg handling

Bitcoin can reorganise: a block at the tip may be replaced by a competing block.
A correct BITAI indexer must undo the effects of any block that is no longer on
the active chain and re-apply the replacements, with no residue.

The indexer maintains two structures for this:

* a **recent-block ring** of the last *N* block hashes at the tip, and
* a **per-block undo journal** recording exactly which state changes each recent
  block produced — registry entries added, token UTXOs created or removed, and
  triples recorded.

When a new block does not build on the indexer's current tip (its previous-block
hash does not match), the indexer:

1. walks back through the recent-block ring to find the **common ancestor** of
   the old and new chains;
2. replays the undo journal in reverse for every block above that ancestor,
   restoring the registry to its exact pre-fork state;
3. resumes forward application along the new chain.

If a reorg ever runs deeper than the journal window, the indexer falls back to a
clean **re-derivation from the genesis height** — always available because the
state is a pure function of the chain. Either way the result is the unique,
correct state for the new active chain.
