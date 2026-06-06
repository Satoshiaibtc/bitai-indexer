# Transaction Format

A BITAI action is an ordinary Bitcoin transaction that satisfies three
structural requirements: it carries the protocol payload in an `OP_RETURN`
output, it pays the treasury fee, and — for mints — it designates a recipient
output. This page specifies that envelope. The bytes *inside* the `OP_RETURN`
are covered in [Payload Encoding](encoding.md).

## The OP_RETURN output

The protocol payload is embedded in a standard `OP_RETURN` data output:

```
OP_RETURN <push> <payload>
```

* The script begins with `OP_RETURN` (`0x6a`).
* A single data push follows. Pushes of 1–75 bytes use a direct length byte
  (`0x01`–`0x4b`); pushes of 76–80 bytes use `OP_PUSHDATA1` (`0x4c`) followed by
  a one-byte length. Both encodings are accepted; non-canonical re-encodings of
  a short push are rejected.
* The pushed data is the BITAI payload and **must not exceed 80 bytes**, the
  standard Bitcoin Core relay ceiling for `OP_RETURN`. Anything larger is
  unrelayable and is rejected at decode time.

Only the first valid BITAI `OP_RETURN` in a transaction is considered.

## The treasury fee output

Every protocol-relevant transaction **must** include an output that pays the
flat service fee to the hard-coded treasury address:

| Field   | Value                                                              |
| ------- | ----------------------------------------------------------------- |
| Amount  | `546` satoshis (the standard P2TR/P2WPKH dust threshold)          |
| Address | the protocol treasury address (see [Reference](reference.md))     |

A transaction that does not pay this fee is not indexed. The treasury address's
on-chain history is therefore the canonical, exhaustive log of BITAI activity.

## Output layout

The required output positions depend on the operation:

### Deploy and Transfer

A deploy or transfer needs only the `OP_RETURN` payload and the treasury fee
output; their positions among the transaction's outputs are not constrained
beyond those two requirements. Transfer edicts address outputs by explicit
index (see [Transfer](operations/transfer.md)).

### Mint

A mint has a fixed recipient convention so that its yield has an unambiguous
home:

| Output     | Requirement                                                      |
| ---------- | ---------------------------------------------------------------- |
| `vout[0]`  | the `OP_RETURN` payload                                          |
| `vout[1]`  | the **yield recipient** — must be a standard **P2WPKH** output, and must not be an `OP_RETURN` |
| elsewhere  | the treasury fee output                                          |

The minted units are credited to `vout[1]`. A mint with fewer than two outputs,
or whose `vout[1]` is an `OP_RETURN` or is not P2WPKH, is rejected. The recipient
key committed by `vout[1]` is also bound into the proof-of-work, which prevents a
third party from re-using someone else's work to mint to their own address (see
[Mint & AI Proof-of-Work](operations/mint.md)).

## Witness commitment

Minting additionally requires that one of the transaction's **input witnesses**
authorises the public-key hash claimed in the mint payload. In practice this
means the miner signs the transaction with the key whose `HASH160` is committed
in the work. This ties each proof-of-work to an identity that controls a Bitcoin
input, anchoring the protocol's anti-Sybil guarantees to Bitcoin's own signature
checks.
