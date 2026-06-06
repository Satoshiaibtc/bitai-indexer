# Transfer

A **transfer** moves existing units between Bitcoin outputs. It spends one or
more token-bearing UTXOs and re-allocates their combined balance to new outputs
using a list of **edicts**. The model mirrors how bitcoin itself moves on the
UTXO set, so splitting, merging, and sending balances are all the same
operation.

## Inputs: the donor balance

The transfer's *donor balance* is the sum of the token amounts on the
transaction's spent inputs. When a transfer is processed:

* every input that is a known token UTXO is **consumed** — its tagged balance is
  removed from the spending UTXO and pooled as input to the transfer;
* the total of those consumed amounts is the maximum the edicts can re-allocate.

Spending a token UTXO without a transfer `OP_RETURN`, or in a transaction that
does not pay the treasury fee, destroys the tagged balance. Token balances ride
on real outputs, so an output can only be moved by the party holding its key.

### Single-ticker rule

All token inputs to a transfer must carry the **same ticker**. A transaction
that spends token UTXOs of more than one ticker is treated as a full-transaction
burn: every consumed balance is destroyed and **no** output is credited. This
keeps each transfer unambiguous about which ticker its edicts move.

## Edicts: the allocation

Each edict is a `{ amount, output }` pair: it credits `amount` units of the
donor ticker to the transaction output at index `output`. Edicts are processed
**in order**:

* Each edict credits its `amount` to the named output, drawing from the
  remaining donor balance.
* A credited output becomes a new token UTXO carrying the donor ticker and the
  credited amount, spendable in future transfers.
* Crediting stops when the donor balance is exhausted. Any edict amount beyond
  the remaining balance, and any donor balance left unallocated after the last
  edict, is **burned** (permanently destroyed).

A transfer carries at most **16** edicts. To send to one recipient and keep
change, a transfer simply uses two edicts — one to the recipient output and one
to a change output the sender controls.

## Worked example

A holder controls a UTXO carrying `1000 FOO`. They want to send `300 FOO` to a
counterparty and keep the rest. They build a transaction that:

1. spends the `1000 FOO` input;
2. pays the treasury fee;
3. carries a transfer `OP_RETURN` with two edicts:
   * `{ amount: 300, output: 1 }`
   * `{ amount: 700, output: 2 }`

After confirmation, `vout[1]` holds `300 FOO`, `vout[2]` holds `700 FOO`, and the
original input is consumed. The donor balance (`1000`) exactly equals the sum of
the edicts, so nothing is burned.

If the holder had written only the first edict, `300 FOO` would land on `vout[1]`
and the remaining `700 FOO` — unallocated — would be burned. Always allocate the
full donor balance, including change.

## Validity

A transfer is processed when the transaction pays the treasury fee and its
`OP_RETURN` decodes as a well-formed transfer payload. Edicts that name a
non-existent output index, or that over-draw the donor balance, do not abort the
transfer — they simply credit nothing for the excess, which is burned. This
keeps transfer outcomes a total, deterministic function of the transaction.
