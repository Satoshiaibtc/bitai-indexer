# Protocol Overview

BITAI defines three operations — **deploy**, **mint**, and **transfer** — each
carried by a single Bitcoin transaction. This page gives the mental model; the
following chapters give the exact bytes and rules.

## The token lifecycle

```
 DEPLOY ──▶ opens a ticker with a fixed issuance schedule
   │
   ▼
 MINT  ──▶ AI proof-of-work claims one issuance slot; credits new units
   │
   ▼
 TRANSFER ──▶ moves existing units between Bitcoin outputs (UTXOs)
```

A **ticker** is a 1–8 character uppercase name (`A–Z`, `0–9`). Deploying a
ticker fixes, immutably, how many times it can be minted, how many units each
mint yields, the mining difficulty, and the difficulty schedule. Once deployed,
the ticker is open to anyone.

Minting is the only way new units are created, and every mint must carry a valid
AI proof-of-work for that ticker. Each accepted mint consumes one of the
ticker's issuance slots and credits its yield to a specified Bitcoin output.

Once units exist, they live **on UTXOs** — exactly like bitcoin itself. A
transfer spends one or more token-bearing outputs and re-allocates their balance
to new outputs using a compact list of *edicts*. Holding, splitting, and merging
token balances all reduce to spending and creating Bitcoin outputs.

## Where state lives

BITAI carries no balances in its `OP_RETURN` data. The `OP_RETURN` only records
*intent* (deploy this ticker, mint this ticker, move these amounts). The actual
balances are an **overlay on Bitcoin's UTXO set**, maintained by indexers:

* Each accepted mint or transfer-credit attaches a `(ticker, amount)` tag to a
  specific Bitcoin output.
* Spending that output moves or destroys the tagged balance, governed by the
  transfer rules.

Because balances ride on real UTXOs, BITAI inherits Bitcoin's double-spend
protection for free: a token output can be spent exactly once, and only by the
party holding its key.

## The discovery rule: the treasury fee gate

To be recognised by the protocol, every deploy, mint, and transfer must pay a
fixed flat fee to a single, hard-coded **treasury address**. This output is what
makes a transaction *protocol-relevant*.

The fee gate has two purposes. First, it gives indexers a cheap, exact filter:
the treasury address's transaction history is the complete and authoritative
list of all BITAI activity, so an indexer never has to inspect unrelated
transactions. Second, it sets a small, uniform cost for every protocol action,
which discards spam before it ever reaches the validity rules.

A transaction that omits the treasury fee is simply invisible to BITAI — it is
not a malformed action, it is a non-action.

## Determinism and reproducibility

Every BITAI rule in this book is a deterministic function of on-chain data:
transaction bytes, output scripts, input witnesses, block heights, and block
hashes. There is no timestamp dependence, no off-chain data, and no
indexer-local randomness. Two indexers that process the same blocks in order
arrive at byte-identical token state — the same balances, the same registry
hash. This property is what lets a light client trust a snapshot it did not
compute itself: the snapshot can be independently regenerated from the chain and
checked for an exact match.
