# bitai-indexer

A reference that documents **how the BITAI Protocol indexer works.**

BITAI is a meta-protocol on Bitcoin mainnet: token deploys, AI
proof-of-work mints, and transfers are encoded in `OP_RETURN` outputs
that each pay a flat service fee to a single treasury address. This
repository explains the *read* side — how a server rebuilds the global
token registry from the chain and publishes a snapshot a thin client can
trust.

> This is published **for study, to explain the mechanism.** It is
> deliberately **not** a runnable or deployable package: the dependency
> manifest, build configuration, and deployment scripts are omitted. The
> source under `src/` and `lib/` is here to be read, not cloned and run.

## The indexing mechanism

The indexer turns the raw chain into a verified token registry in a few
well-defined steps.

**1. Discovery — a block walk.**
The indexer runs against a *local* Bitcoin Core node, which holds every
block, so it simply fetches each block (`getblock` verbosity 2) and looks
at its transactions. No address index is needed. New blocks arrive
instantly over ZMQ (`hashblock`) rather than by polling, so indexing
keeps pace with the tip in real time — see `src/scan.ts`, `src/rpc.ts`,
`src/main.ts`.

**2. Fee gate.**
Only transactions that pay the treasury address are protocol-relevant;
everything else in the block is ignored. This is what makes the registry
cheap to build and is the protocol's discoverability rule — pay the fee,
be indexed. See `paysTreasury` in `src/scan.ts`.

**3. Application — a deterministic state machine.**
Each fee-paying transaction's `OP_RETURN` is decoded (`lib/protocol.ts`)
into a `deploy`, `mint`, or `transfer` and applied to the registry
(`lib/token-registry.ts`). The decisive part is **mint verification**: a
mint is only credited if it passes the full 16-gate check, whose core is
an AI proof-of-work — a MiniLM sentence embedding of the miner's prompt
(`lib/inference.ts`, `src/miniml-node.ts`) hashed with SHA-256 and run
through Argon2id, a memory-hard function (`lib/pow.ts`,
`lib/miner-prompt.ts`), then checked for the required number of leading
zero bits. A fee-paid mint with invalid work is rejected.

**4. Reorg safety.**
Every applied block records an undo journal entry. When a new block does
not build on the last one (prev-hash mismatch), the registry is rewound
through that journal to the common ancestor; a reorg deeper than the
200-block journal triggers a clean re-derivation from genesis. See
`rewindToCommonAncestor` in `lib/token-registry.ts` and the detection in
`src/scan.ts`.

**5. Signed snapshots.**
After each catch-up the registry is serialized and signed with an ed25519
key, then written atomically as three files — the serialized state, the
signature, and a small JSON descriptor (tip height, registry hash,
public key). A client verifies the signature against a known public key
before adopting a snapshot and falls back to scanning the chain itself if
verification fails. See `src/snapshot.ts` and `src/signer.ts`.

## Why the registry logic lives in `lib/`

`lib/` is the protocol codec and registry state machine. Sharing one
implementation between the indexer and the client is the whole point: if
the two computed the registry differently they would disagree on token
balances. Keeping the logic identical is what lets a client trust a
snapshot the indexer produced.

## Reading guide

| File | What it shows |
|---|---|
| `src/scan.ts` | block walk, fee gate, apply loop, reorg detection |
| `lib/token-registry.ts` | registry state machine, 16-gate `applyMint`, reorg rewind |
| `lib/protocol.ts` | the `OP_RETURN` encoding (magic + version + op + fields) |
| `lib/pow.ts`, `lib/miner-prompt.ts` | the Argon2id memory-hard proof-of-work + prompt derivation |
| `lib/inference.ts`, `src/miniml-node.ts` | the MiniLM embedding gate |
| `src/snapshot.ts`, `src/signer.ts` | serialize + ed25519-sign the snapshot |
| `src/main.ts`, `src/rpc.ts` | the runtime: Core RPC + ZMQ catch-up loop |

It builds on a few well-known libraries — `@noble/hashes` (SHA-256,
Argon2id, RIPEMD-160), `@noble/curves` (ed25519), `@scure/*` (BIP39,
address encoding), and a ZMQ binding for the new-block notifications.
