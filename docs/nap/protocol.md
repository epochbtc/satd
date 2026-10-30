# Node Attestation Protocol (NAP)

```
Title:   Node Attestation Protocol: coin-signed statements over P2P
Status:  Draft
Type:    Specification
Version: 1
```

Status: draft for review. The wire format and the publisher side are
implemented in satd 0.7.0; anything
here may still change in response to review. The aggregator's report format
(see [Reports](#reports)) is not yet specified.

## Abstract

NAP lets node operators publish signed, non-binding statements, weighted by
the coins they control. A node operator signs one key-value pair for one unspent
output with the key or script that locks it, using BIP 322 or, for P2PKH
outputs, Bitcoin Core's `signmessage`. Nothing is locked up or spent. The
statement counts with the coin's value for as long as the coin stays unspent
and the signature stays fresh.

The name follows the economic-node argument: a node's say in Bitcoin rests on the coins and payments behind it, not on the node itself. NAP makes that weight explicit. A node publishes statements signed by coins its operator controls, and an aggregator counts them by value. Running more nodes adds nothing.

This document specifies the signed message, the attestation's serialization,
the rules that make an attestation valid at a chain tip, supersession, the
P2P service bit and messages by which publishers serve attestations to
aggregators, and the serving limits.

## Motivation

Soft fork activation has been gated on miner signaling. Miners are one
constituency. Node operators, exchanges, custodians and merchants have no legible way to signal; their views surface on mailing lists and social media, where they cannot be measured.

NAP measures **auditable coin-backed statements**: statements authorised by
the scripts controlling participating outputs. It does not establish who owns
those coins, and it says nothing about holders who did not participate.
Participation is self-selected, so a result is correct about the coins that
signed and silent about the rest.

NAP allows economic participants to express preferences as a human-interpreted signal. This is intended to be used in addition to traditional miner signaling and allows a greater proportion of the network to participate in signaling. NAP is *not* intended to gate decisions in an automated, mechanical fashion (e.g., a softfork must be activated if some arbitrary NAP threshold is met).

NAP is not binding. No activation logic, policy or consensus rule reads NAP
data. Weight comes from coins, not from node count or hash rate, so running many
publishers adds no weight.

Not every attestor needs to run a node themselves: public nodes may accept valid attestations from the public anonymously if they so choose.

The key-value format is generic. Keys can name soft fork parameters, policy
questions, or nothing of consequence. A mechanism already in everyday use
before a contentious question arrives is harder to dismiss as manufactured
than one stood up during the debate.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

All integers are little-endian. `compact_size` is Bitcoin's variable-length
integer and MUST be minimally encoded. `varstr` and `varbytes` are a
`compact_size` length followed by that many bytes. An `outpoint` is the
32-byte txid in its serialized (internal) byte order followed by the `u32`
output index, as in a transaction input.

### Constants

| Name | Value | Meaning |
|---|---|---|
| `FRESHNESS_WINDOW` | 26,208 blocks (~6 months) | How long a signature stands without re-signing |
| `MIN_COIN_AGE` | 4,032 blocks (~4 weeks) on mainnet; 6 on testnet3, testnet4, signet and regtest | How old a coin must be at the anchor |
| `COINBASE_MATURITY` | 100 blocks | The least age of a coinbase coin at the anchor, on every network |
| `MIN_COIN_VALUE` | 10,000 satoshis | The smallest coin that attests, on every network |
| `MAX_ATTESTATION_SIZE` | 4,000 bytes | The largest serialized attestation |
| `MAX_KEY_LEN` | 128 bytes | The longest key; keys are at least 1 byte |
| `MAX_VALUE_LEN` | 128 bytes | The longest value; a value may be empty |
| `MAX_KEYS_PER_OUTPOINT` | 32 | The keys a publisher stores and serves per outpoint |
| `MAX_NAPATT_SIZE` | 1,000,000 bytes | The largest `napatt` payload |
| `MAX_GETNAPATT_KEYS` | 32 | The most keys a `getnapatt` filters on |
| `NODE_NAP` | `1 << 30` | The service bit |

`MIN_COIN_AGE` is short on the test networks so that a test coin can attest
within an hour.

### Keys and values

An attestation states one key-value pair for one outpoint. Keys and values
consist of printable ASCII bytes (0x20 to 0x7E inclusive). A key is 1 to
`MAX_KEY_LEN` bytes and a value 0 to `MAX_VALUE_LEN` bytes. There is no
namespace: any key is valid. Proposal authors are encouraged to name a
canonical key for their proposal, such as `bip_xyz.support`.

An empty value is a **withdrawal**. It supersedes the operator's earlier value
for that key like any other value, and counts toward no value.

### Signed message

The operator signs the following text, with LF (0x0A) line endings and no
trailing newline:

```
NAP attestation v1
outpoint: <txid>:<vout>
key: <key>
value: <value>
anchor: <height> <block hash>
```

- `<txid>` and `<block hash>` are 64 lowercase hexadecimal digits, in the
  usual display order (byte-reversed from serialization), as RPCs print them.
- `<vout>` and `<height>` are decimal, with no sign and no leading zeros.
- `<key>` and `<value>` are the bytes themselves. Because neither contains a
  control character, neither can start a new line.

There is exactly one message text for each set of fields. A verifier that
parses a message text MUST refuse any text other than the one these rules
produce from the fields it names.

The anchor is a block on the active chain: `<height>` and the hash of the
block at that height. It dates the attestation and ties it to one chain.
Software that creates attestations SHOULD anchor 6 blocks below the tip, so
that a shallow reorganisation does not invalidate them.

### Signature formats

| `sig_format` | Name | Applies to | Signature bytes |
|---|---|---|---|
| 0 | BIP 322 simple | Native segwit outputs: P2WPKH, P2WSH, P2TR | The consensus-serialized witness stack |
| 1 | BIP 322 full | Any output | The consensus-serialized BIP 322 `to_sign` transaction |
| 2 | Legacy | P2PKH outputs only | The 65-byte compact recoverable signature of Bitcoin Core's `signmessage` |

Other `sig_format` values are invalid in version 1.

Formats 0 and 1 follow BIP 322, with the message text above as the message
and the outpoint's scriptPubKey as `message_challenge`:

- The message hash is BIP 322's tagged hash (`BIP0322-signed-message`) of the
  message text.
- Every signature in the proof MUST use `SIGHASH_ALL`, or `SIGHASH_DEFAULT`
  for Taproot.
- A proof BIP 322 finds *inconclusive* is invalid: for example one for an
  unknown witness version, one that fails only BIP 322's upgradeable rules,
  or a `to_sign` whose version is neither 0 nor 2.
- A simple proof is invalid for an output that is not native segwit,
  including P2SH-wrapped segwit, which needs a full proof. A simple proof
  carries version, locktime and sequence 0, so a timelocked script can pass
  in simple form only if its timelock is met at zero.
- Proof-of-funds proofs (extra `to_sign` inputs) are not used: the outpoint
  is named in the message and the proof is checked against its script, so
  extra inputs prove nothing NAP needs. A full proof with more than one input
  is invalid.

Format 2 is verified exactly as Bitcoin Core's `verifymessage` over the
message text: the double-SHA256 of the compact-size-prefixed string
`Bitcoin Signed Message:\n` followed by the compact-size-prefixed message
text, with the public key recovered from the signature. It is valid only when
the outpoint is P2PKH and the recovered key, compressed or uncompressed as
the signature's header byte says, hashes to the output's key hash. The same
magic string is used on every network.

Wallets and RPCs exchange signatures in base64. BIP 322 prefixes (`smp` for
simple, `ful` for full) are recommended in text form; on the wire the
`sig_format` byte carries the variant, and signatures are raw bytes.

### Serialization

```
attestation {
    version        u8           // 1
    outpoint       outpoint
    key            varstr
    value          varstr
    anchor_height  u32
    anchor_hash    [32]u8       // serialized (internal) byte order
    sig_format     u8           // 0, 1 or 2
    signature      varbytes
}
```

An attestation MUST NOT exceed `MAX_ATTESTATION_SIZE` serialized bytes.
Decoding is strict: a decoder MUST refuse a `version` other than 1, a key or
value that breaks the rules above, a non-minimal `compact_size`, and
signature bytes that are not the canonical serialization for their format
(re-serializing the decoded witness stack or transaction MUST reproduce
them). An attestation therefore has exactly one serialization.

The attestation's **id** is the SHA256 of its serialization. It identifies
the attestation however many peers serve it, and breaks supersession ties.

### Validity

An attestation is **valid at a tip** (the tip of the evaluator's active
chain, of height `tip_height`) when all of the following hold. They are
listed cheapest first.

1. **Anchor.** `anchor_hash` is the hash of the active chain's block at
   `anchor_height`.
2. **Fresh.** `tip_height - anchor_height < FRESHNESS_WINDOW`.
3. **Unspent, and large enough.** The outpoint is in the UTXO set at the
   tip, and its coin holds at least `MIN_COIN_VALUE`. Unconfirmed outputs are
   never counted.
4. **Old enough.** The coin's confirmation height is at most
   `anchor_height - age`, where `age` is `MIN_COIN_AGE` for the network, or
   `max(MIN_COIN_AGE, COINBASE_MATURITY)` for a coinbase coin.
5. **Signature.** The signature verifies over the message text against the
   coin's scriptPubKey under the rules for its format.
6. **Timelocks.** A full proof may set `to_sign`'s version, locktime and
   input sequence, making it valid only from a given time or coin age. Those
   conditions are evaluated as if `to_sign` were in the block after the tip:
   the locktime against height `tip_height + 1` and the tip's median time
   past (Bitcoin Core's `IsFinalTx`), and the BIP 68 relative lock against the
   coin's confirmation height, or for a time lock against the median time
   past of the block before the coin's confirming block, as Bitcoin Core's
   `SequenceLocks` takes it. A proof that fails only this rule is *not yet valid*,
   and becomes valid when the chain reaches its conditions.

A valid attestation's **weight** is the value of its coin in satoshis,
uncapped.

Rules 1 to 4 and 6 depend on the tip; rule 5 does not, because an outpoint's
scriptPubKey never changes. An evaluator can verify a signature once and
re-check the rest at each tip. Only the UTXO set and the header chain are
needed, so pruned nodes can evaluate attestations.

Some scripts can be satisfied without a signature, such as anyone-can-spend
outputs or a hash lock whose preimage is public. Attestations for them are
valid. Anyone can make them, but anyone can also sweep the coin, so such
coins do not hold weight for long.

### Supersession

For each `(outpoint, key)`, of the attestations valid at the tip, the one
with the highest `anchor_height` counts; at equal heights, the one whose id,
compared as 32 bytes in the order SHA256 outputs them, is lower. The others
count for nothing. A holder changes a value, or withdraws it with an empty
value, by signing again with a newer anchor.

Supersession works only over the attestations an evaluator has seen. An
aggregator that missed a newer attestation still counts the older one.

If an anchor block is reorganised out of the active chain, its attestations
are invalid until re-signed, and the holder's previous attestation for that
key, if still valid, counts again.

### Publishing

A **publisher** is a node that stores attestations submitted to it and
serves those valid at its own tip. How attestations reach a publisher is not
specified; satd accepts them over RPC.

- A publisher MUST store at most `MAX_KEYS_PER_OUTPOINT` keys per outpoint.
  This bounds storage and page size. It is not a counting rule: a holder can
  split a coin to sign more keys, and aggregators count every valid key they
  keep (see [Keys per outpoint](#keys-per-outpoint)).
- A publisher MUST serve only attestations valid at its tip. It SHOULD stop
  serving an attestation as soon as it stops being valid, and MAY drop
  attestations whose coin has been spent.
- A publisher MUST serve at most one attestation per `(outpoint, key)`, the
  one that counts at its tip. With the keys limit, this bounds what one
  outpoint can put in a page.

An attestation verifies on its own; nothing binds it to the node serving it.
Any implementation can serve valid attestations. It can add reach, but not
weight.

## P2P protocol

### Service bit

A publisher sets `NODE_NAP` (bit 30) in its `version` message services and
in the address records it advertises. Bit 30 is in the range Bitcoin Core
reserves for temporary experiments (`protocol.h`, bits 24 to 31); a survey of
reachable nodes found no software using it. A permanent bit would be
requested if NAP is standardized.

The bit propagates through ordinary address gossip, which is how aggregators
find publishers. A node that does not publish MUST NOT set it.

### Messages

Both messages use the standard message header. Their payloads:

```
getnapatt {
    anchor_height_min  u32
    keys               compact_size count, then count × varstr   // count <= 32
    cursor             optional_outpoint
}

napatt {
    attestations       compact_size count, then count × attestation
    next_cursor        optional_outpoint
}

optional_outpoint {
    present            u8       // 0 or 1
    outpoint           outpoint // only when present is 1
}
```

Each key in a `getnapatt` follows the key rules above. A `present` byte other
than 0 or 1 is malformed. A `napatt` payload over `MAX_NAPATT_SIZE` bytes,
or containing an attestation that does not decode, is malformed.

The fields decode strictly, but bytes after the last field MUST be ignored,
so that a later version can append fields without older nodes treating its
messages as malformed. A change that older nodes cannot safely skip takes a
new command.

### Sending rules

- A node MUST send `getnapatt` only to a peer that advertises `NODE_NAP`,
  and only after the version handshake completes.
- A node MUST NOT send `napatt` except in reply to a `getnapatt`. A node
  MUST ignore a `napatt` it did not request.
- A publisher answers a `getnapatt` from any peer, whether or not the peer
  advertises `NODE_NAP`, so an aggregator need not set the bit.

Since a node that does not implement NAP neither advertises `NODE_NAP` nor
sends `getnapatt`, it never receives a NAP message.

### Requests and pages

`getnapatt` asks for the attestations the publisher serves whose
`anchor_height` is at least `anchor_height_min` and, unless `keys` is empty,
whose key is one of `keys`. The publisher answers with one `napatt` page:

- Attestations are ordered by outpoint (txid compared as 32 bytes in
  serialized order, then output index as an integer), then by key (compared
  as bytes).
- With a `cursor`, the page starts after every attestation of the cursor's
  outpoint.
- A page MUST NOT split an outpoint: all of one outpoint's matching
  attestations go in the same page. At most 32 attestations of at most 4,000
  bytes each, one outpoint always fits.
- A page holds as many whole outpoints as fit within `MAX_NAPATT_SIZE`, and
  always at least one if any match.
- When matching attestations remain after the page, `next_cursor` is the
  last outpoint in it. Otherwise `next_cursor` is absent, and the pull is
  complete. A page with no attestations and no cursor means nothing matched.

A **pull** is a request without a cursor, followed by the requests that
continue it. A request continues a pull only if its `cursor` is the
`next_cursor` of the last page sent on that connection; any other request,
with or without a cursor, starts a new pull.

A publisher MAY leave a request unanswered: over a serving limit, or while
busy. Requesters MUST NOT treat a missing reply as an error and SHOULD give
up on the pull after a timeout.

### Serving limits

A publisher limits what it serves so that peers cannot make it serve without
bound, while a large publisher can still be drained in one session. The
reference values:

| Limit | Per connection | Per network group |
|---|---|---|
| New pulls | 1 per 10 minutes | 8 per 10 minutes |
| Bytes served | 200 MB per hour | 1.6 GB per hour |

Continuations count against the byte limits only. A network group is the
group Bitcoin Core's address manager uses (an IPv4 /16, an IPv6 /32, or the
AS under an asmap). A connection's limits end with the connection; a group's
outlive it, so reconnecting resets only the connection's own limits. The
per-connection limits keep one peer from starving others in its group; the
group limits keep reconnection, or many connections from one group, from
multiplying the load.

A publisher SHOULD NOT start a page that it could not finish within the
remaining byte limits, and SHOULD silently ignore requests over a limit
rather than penalise the peer. A malformed `getnapatt` is misbehaviour.

Inbound Tor connections all arrive from the loopback address and so share
one group. A peer opening many Tor connections can use up that group's
limits; nothing distinguishes Tor peers from one another.

There is no gossip of attestations. Publishers serve only what was submitted
to them; aggregators pull.

## Aggregation

An **aggregator** collects attestations from publishers, keeps those valid
at its tip, and reports on them. This section is partly informative: the
collection strategy is up to the aggregator, but conforming aggregators
produce the same report from the same attestations at the same tip.

### Collection

The reference aggregator collects only over P2P, by opening short
connections to addresses advertising `NODE_NAP` and pulling their
attestations. Other aggregators MAY accept attestations from any source; an
attestation's validity does not depend on how it arrived.

### Verification

An aggregator SHOULD apply the validity rules in the order listed, cheapest
first, and SHOULD cache verified signatures by attestation id, so that an
attestation served by many publishers is verified once. Signature checks run
the script interpreter, so an aggregator SHOULD bound them per peer and per
unit of time, deferring work beyond the bound rather than dropping it.

A peer that sends a malformed `napatt`, or an attestation that fails rule 5
or uses a format that does not apply to its output, is misbehaving and
SHOULD be disconnected. An attestation that fails only because of chain
state (rules 1 to 4, or 6) is not misbehaviour: the publisher's tip may
differ from the aggregator's.

### Keys per outpoint

An aggregator MAY bound the keys it keeps per outpoint, so that one old coin
signing unlimited keys through a modified publisher cannot grow its set
without limit. The bound SHOULD be well above `MAX_KEYS_PER_OUTPOINT`, so that
a holder publishing through several publishers is not cut short. The
reference aggregator keeps at most 256 keys per outpoint, in the order first
seen: a key new to an outpoint that already has 256 is refused, while a key
already held still takes newer attestations. Two aggregators that saw an
outpoint's keys in different orders may then keep different sets for it;
their snapshots show the difference.

### Reorganisations

An aggregator SHOULD keep each attestation that is superseded for an
`(outpoint, key)` until the anchor of the attestation that superseded it is
deep enough that a reorganisation is no longer a practical concern. The
reference aggregator keeps it until that anchor is 144 blocks deep. Every
generation is kept this way, so after several re-signs within the window
each one still has its predecessor. If the newer anchors are reorganised
out, the newest predecessor still valid counts again, as
[Supersession](#supersession) requires. Publishers serve only the newest
attestation, so an aggregator that discarded the predecessor could not
recover it.

### Weight

For each key and value, the weight is the sum of the weights of the
`(outpoint, key)` pairs whose counting attestation has that value. Each
`(outpoint, key)` counts once, so splitting coins adds no weight and serving
the same attestation from many publishers adds nothing.

### Reports

A report states the tip it was evaluated at (height and hash) and a digest
of the attestation set it was computed from, so that another aggregator can
replay it from an exported copy of that set. For each key it gives, per
value, the weight and number of outpoints, and breakdowns of participation
by outpoint value, anchor age, coin age and script type. Given the same
attestation set and the same tip, every conforming aggregator produces the
same report.

The digest's construction, the snapshot export format and the report's
fields will be specified with the reference aggregator's report RPC. Until
then this section is informative.

## Rationale

**Coins, not compute or node count.** Compute is rentable by the hour, and nodes
are free to multiply. Coin weight cannot be multiplied, and borrowed coins
must stay put for `MIN_COIN_AGE` and drop out when returned.

**Economic nodes** NAP allows economic participants to express preferences as a human-interpreted signal. This is intended to be in addition to traditional miner signaling and allows a greater proportion of the network to participate in signaling. NAP is *not* intended to gate decisions in an automated, mechanical fashion (e.g., a softfork must be activated if some arbitrary NAP threshold is met).

**A human-readable message.** Hardware signers display what they sign. Every
field of the attestation appears in the text, so the signer sees the whole
statement.

**An anchor block.** The anchor dates the attestation, which gives
supersession an order that the signer controls, and lets stale signatures
expire. Anchoring a few blocks below the tip makes losing the anchor to a
reorganisation rare.

**A long freshness window.** Re-signing often needs a hardware signer, so
signatures stand for about six months. Spent coins drop out at once
regardless. A report that breaks weight down by anchor age lets readers apply
a shorter window.

**Coin age at the anchor, not at the tip.** Measuring age at the anchor makes
validity stable as the chain grows: an attestation valid when made does not
become invalid later on age grounds.

**A minimum coin value.** Weight follows value, so dust cannot sway a count,
but without a floor anyone could fill an aggregator's bounds with dust coins
for almost no capital. At 10,000 satoshis, filling a bound of a million
attestations at 256 keys per coin ties up about 0.39 BTC. The floor is far
above the dust limits of every standard output type, and low enough that
any holding worth stating a view with clears it. Unlike `MIN_COIN_AGE`, it
is the same on every network.

**Withdrawal by empty value.** A holder may want to retract a statement
without spending the coin. An empty value supersedes the old one and counts
toward nothing.

**The keys-per-outpoint limit is a resource bound.** It bounds what a
publisher stores and what a page holds. A holder can split coins to sign more
keys, so the limit cannot be a scarcity rule, and aggregators do not apply
it. An aggregator's own, larger bound protects it from a modified publisher
that ignores the limit.

**Pull, not gossip.** Gossiping attestations would make every node carry
every attestation. Pulling puts the cost on aggregators, who choose to bear
it, and the serving limits bound what each one can ask of a publisher.

**Answering any asker.** An aggregator that does not publish need not
advertise `NODE_NAP`, so it cannot be told apart from an ordinary node by its
services.

**Ignoring trailing bytes, without a version byte.** Appended fields can be
added without breaking older nodes. A change older nodes cannot skip needs a
new command anyway, so a version byte would add nothing.

**Legacy signatures for P2PKH.** Many wallets can sign a P2PKH message only
with `signmessage`. BIP 322 full proofs are also accepted for P2PKH.

## Custodians

Exchanges, companies and ETFs control a large supply of coins. Conceptually, these custodians are free to signal on behalf of the beneficial owners of those coins (similar in concept to how a corporate proxy might vote on behalf of shareholders). A downside of this approach is that it exposes public information about the exact UTXOs under their control, because NAP attestations are public.

One mitigation to this issue available in v1 is to attest only for a small fraction of custodied coins, but do so in proportion to the voting preferences of the underlying beneficial owners. For example, only NAP attest for 10% of coins but ensure that the distribution of attestations matches the distribution of beneficial owners' preferences. The downside of this is that it reduces the total weight of attestations relative to the rest of the network.

Custodians are also free to decline to attest at all, or to attest purely based on their internal interests. This is an acknowledged potential concern that NAP cannot fully address technically; users who care about this should consider sovereign self-custody instead.

## Security and privacy considerations

**Paid signing.** A holder or custodian can be paid to sign. This needs no
capital and no coin movement, and the attestation is a verifiable receipt for
the payer. It is inherent to any signed-signal scheme.

**Withheld attestations.** A publisher or network path that withholds a newer
attestation leaves the older one counting at that aggregator. Comparing
snapshots across aggregators detects it.

**Privacy.** An attestation reveals its outpoint, and with it the coin's
amount and history, and links the statement to that coin permanently. A
holder who does not want the outpoint linked to their IP address should
publish through a node reachable over Tor.

**Key exposure.** For P2PKH, P2WPKH and script outputs that have never
spent, signing publishes the public key or script, removing the hash that
protected the coin. Taproot key-path outputs already expose their key.
Holders of long-term coins should weigh this before signing.

**Denial of service.** Every size is bounded before allocation
(`MAX_ATTESTATION_SIZE`, `MAX_NAPATT_SIZE`, `MAX_GETNAPATT_KEYS`), the
serving limits bound what a publisher spends on each peer and group, and
verification budgets bound what an aggregator spends on script execution.

## Backwards compatibility

NAP is opt-in. Nodes that do not implement it never advertise `NODE_NAP`,
never send `getnapatt`, and so are never sent a NAP message. No consensus or
relay rule changes.

## Reference implementation

satd: the attestation types, message and validity rules in
[`node/src/nap/`](../../node/src/nap/), the BIP 322 verifier in
[`node/src/bip322/`](../../node/src/bip322/), and the P2P messages and
serving limits in [`node/src/nap/p2p.rs`](../../node/src/nap/p2p.rs). The
Operator Manual's [NAP chapter](../manual/src/nap.md) describes running a
publisher.

## Test vectors

Signatures made by real wallets (Bitcoin Core, Sparrow, and a Ledger signing
through Sparrow),
each with its message text, scriptPubKey, signature and format, are in
[`node/src/nap/testdata/wallet-signatures.json`](../../node/src/nap/testdata/wallet-signatures.json).

The first of them, a legacy signature on signet:

```
message:
NAP attestation v1
outpoint: 91b6ac3b411725a16dbc4ef2e5bd50098b919731e1a1b4e3aad2f865c42a9793:1
key: g1.core.signmessage
value: yes
anchor: 327643 00000000a1d0aac203eaeb384a3486826e0b78288ea41f038c44bb57d52857ec

scriptPubKey: 76a91400bbd829d91f63cf5433af8d2c330f7ece69e51e88ac
signature (base64): H7xw2kNB5RUYHB7BRtL7aimQjn0HivJb3+ji0i2jQBzwOl9KNRFhLZhHAh29WTZOrfugKaWm0IlELou8MsrIYAg=

attestation (164 bytes):
0193972ac465f8d2aae3b4a1e13197918b0950bde5f24ebc6da12517413bacb6910100
00001367312e636f72652e7369676e6d65737361676503796573dbff0400ec5728d557
bb448c031fa48e28780b6e8286344a38ebea03c2aad0a10000000002411fbc70da4341
e515181c1ec146d2fb6a29908e7d078af25bdfe8e2d22da3401cf03a5f4a3511612d98
47021dbd59364eadfba029a5a6d089442e8bbc32cac86008

id: 196a69fcb0efc23124e0d7ef92323eb7d091df1e3d5f345d7316c397537cbac5
```

A `getnapatt` starting a pull for every attestation: `000000000000`.

A `getnapatt` continuing a pull after the outpoint above, for anchors at or
above 327,000 and the key `g1.core.signmessage`:

```
58fd0400011367312e636f72652e7369676e6d6573736167650193972ac465f8d2aae3
b4a1e13197918b0950bde5f24ebc6da12517413bacb69101000000
```

A `napatt` carrying the attestation above as the last page:

```
010193972ac465f8d2aae3b4a1e13197918b0950bde5f24ebc6da12517413bacb69101
0000001367312e636f72652e7369676e6d65737361676503796573dbff0400ec5728d5
57bb448c031fa48e28780b6e8286344a38ebea03c2aad0a10000000002411fbc70da43
41e515181c1ec146d2fb6a29908e7d078af25bdfe8e2d22da3401cf03a5f4a3511612d
9847021dbd59364eadfba029a5a6d089442e8bbc32cac8600800
```

## Open questions

- **Service bit.** Bit 30 is experimental; a permanent bit would be requested
  on standardization.
- **Serving and verification limits.** The reference values need measuring
  against realistic publishers.
- **Delegation.** Whether a holder may authorise a separate key to re-sign
  for a coin, so that refreshing does not need the hardware signer each time.
- **Anonymous attestations.** Proving control of some qualifying output
  without revealing which, with a one-per-coin tag against double counting.
  Curve-tree constructions do this for Taproot outputs; their maturity needs
  evaluating. This would mitigate the privacy concern around custodians
  exposing UTXOs under their control. This is a possible avenue of exploration for NAP v2.
- **Reports.** The snapshot digest and report format (see
  [Reports](#reports)).

## Copyright

This document is licensed under the MIT license, as is the repository it is
part of.
