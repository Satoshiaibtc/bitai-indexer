---
description: A fungible-token meta-protocol on Bitcoin, with issuance gated by verifiable AI proof-of-work.
---

# Introduction

BITAI is an open, fully on-chain meta-protocol for issuing and transferring
fungible tokens on Bitcoin mainnet. Like other Bitcoin token standards, BITAI
records every token action inside the witness-less `OP_RETURN` output of an
ordinary Bitcoin transaction. No sidechain, bridge, or trusted issuer is
involved: the canonical state of every token is a pure function of the Bitcoin
blockchain.

What makes BITAI distinct is **how new units come into existence**. Most token
standards distribute supply on a first-come, fee-race basis, which collapses
into mempool auctions dominated by automated bots. BITAI instead gates each
mint behind a **verifiable AI proof-of-work**: to claim a unit, a participant
must run a fixed sentence-embedding model over a per-attempt challenge and find
an input whose embedding, hashed through a memory-hard function, clears a
difficulty target. The work is cheap to verify and expensive to fake, so
issuance flows to participants who actually perform computation rather than to
whoever bids the highest fee.

### Design goals

* **Permissionless.** Anyone can deploy a ticker, mint against an open ticker,
  or transfer holdings, using only standard Bitcoin transactions.
* **Deterministic.** Token state is computed by a deterministic state machine.
  Given the same chain, every correct indexer derives byte-identical state.
* **Self-contained.** Validity depends only on data already committed to
  Bitcoin. There is no off-chain ordering, no second consensus layer.
* **Light-client friendly.** Indexers publish cryptographically signed,
  reproducible state snapshots so thin clients can adopt verified token state
  without scanning the chain themselves.

### What this documentation covers

This book specifies the BITAI wire format, the three protocol operations
(deploy, mint, transfer), the AI proof-of-work that secures minting, and the
indexing rules that turn raw Bitcoin transactions into a global token registry.
It is the reference for anyone building a wallet, an explorer, or an independent
indexer.

> The companion source repository documents one reference implementation of the
> read side — the indexer — so the rules described here can be audited against
> working code.
