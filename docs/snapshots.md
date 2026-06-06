# Signed Snapshots

Scanning Bitcoin from the genesis height is more than a thin wallet wants to do
on a cold start. To serve light clients, an indexer publishes its registry as a
**signed snapshot**: a serialized copy of the token state, plus a small
descriptor and a cryptographic signature. A client can adopt verified token
state from a single download, and — because the state is reproducible — can
re-derive and check that state against the chain whenever it chooses.

## What a snapshot contains

A published snapshot is three artefacts:

| Artefact     | Contents                                                              |
| ------------ | --------------------------------------------------------------------- |
| **state**    | the serialized registry (tokens, token UTXOs, replay set, cursor)     |
| **signature**| an Ed25519 signature over the serialized state bytes                  |
| **descriptor**| a small JSON header: schema version, tip height and hash, the observed chain tip, a SHA-256 of the state, the signing public key, and the signing time |

The descriptor is written last and atomically, so a client never reads a header
that points at state still being written.

## How a client verifies a snapshot

Before adopting a snapshot, a client checks, in order:

1. **Schema.** The snapshot's schema version matches the one the client
   understands.
2. **Freshness.** The signing time is recent; a stale snapshot is rejected so a
   client never serves hours-old token state.
3. **Integrity.** The SHA-256 of the downloaded state matches the value in the
   descriptor.
4. **Signature.** The Ed25519 signature verifies against the expected signing
   key.

Only a snapshot that passes every check is adopted. The signature proves the
snapshot is the exact byte sequence the indexer produced — it cannot be altered
in transit without detection.

## Independent reproducibility

Because the registry is a deterministic function of the Bitcoin blockchain
(see [Indexing Rules](indexing.md)), a snapshot is not an opaque feed that must
be taken on faith. Any party running the same rules over the same blocks
produces the identical registry and therefore the identical state hash. A
snapshot's `state` SHA-256 can be regenerated from the chain and compared
exactly; a client, an explorer, or a second indexer can confirm a published
snapshot is correct without trusting the publisher's word. The signature
establishes *who* produced the snapshot; reproducibility establishes that the
snapshot is *right*.

## Continuous publication

The indexer re-publishes after every catch-up to the chain tip, refreshing the
descriptor's tip height and observed chain tip. A client polling the snapshot
sees token state track the chain in near-real-time, while always holding a copy
whose integrity and origin it has independently verified.
