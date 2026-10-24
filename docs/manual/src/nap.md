# Node Attestation (NAP)

The Node Attestation Protocol lets Bitcoin holders publish signed,
non-binding statements weighted by the coins they control: a view on a soft
fork's activation method, on mempool policy, or on anything else. A holder
proves control of a coin by signing the statement with the key or script
that locks it. Nothing is locked up or spent, and the statement counts for as
long as the coin stays unspent.

An attestation is one key-value pair for one outpoint. What NAP measures is
statements authorised by the scripts controlling the coins that took part.
It does not establish who owns those coins, and it says nothing about holders
who did not take part. No node behaves differently because of an
attestation.

satd is a publisher. satd has no wallet, so the holder signs in their own
wallet and hands the signature to their node, which checks it, stores it and
judges it again at every new block, and serves the valid ones to peers that
ask. satd is also an aggregator: with `napaggregator=1` it collects the
attestations publishers serve and keeps the ones that count (see
[Aggregating](#aggregating)). Reports on the collected set are not in this
build.

## Enabling

```text
satd -nap=1
```

or `nap=1` in the config file. Changing it needs a restart. Without it, the
four NAP RPCs answer `-1` "NAP is disabled".

The attestations are kept in `nap/attestations.dat` in the network's data
directory (`~/.bitcoin/signet/nap/attestations.dat` on signet, for example).
Every change is written through a temporary file and a rename. If the file
cannot be read back at startup, satd refuses to start rather than start with
none of them: it holds signatures that may be hard to make again. Move the
file aside to start without it, or set `napstorerecover=1`, and satd does
that itself: it renames the file to `attestations.dat.bad-<unix time>`, logs
a warning naming it, and starts with an empty store. Either way the damaged
file's signatures are still on disk.

## What gets signed

The holder signs this text exactly, with LF line endings and no newline at
the end:

```text
NAP attestation v1
outpoint: <txid>:<vout>
key: <key>
value: <value>
anchor: <height> <block hash>
```

- **Key and value.** Printable ASCII (0x20–0x7E). Keys are 1–128 bytes,
  values 0–128. There is no namespace; a BIP may name a key for itself, such
  as `bip_xyz.activation_method`. An empty value withdraws the holder's
  earlier value for the key.
- **Anchor.** A recent block on the active chain. `createnapattestation`
  anchors 6 blocks below the tip.

Copy the message as `createnapattestation` returns it. A wallet that adds a
trailing newline or turns line endings into CRLF signs different text, and
the signature does not verify.

## When an attestation counts

An attestation is valid at a tip when:

| Rule | Status when it fails | Meaning |
|---|---|---|
| The anchor is the active chain's block at that height | `anchor-not-on-chain` | A reorg replaced the anchor block. Sign again. |
| `tip - anchor < 26,208` (about six months) | `stale` | Sign again with a new anchor. |
| The coin is unspent | `coin-not-found` | A spent coin's attestation is dropped. |
| The coin holds at least 10,000 sats, on every network | `coin-too-small` | A smaller coin cannot attest. Weight follows value, so a dust coin could not sway a count, but the floor keeps dust from filling an aggregator's set. |
| The coin confirmed at least 4,032 blocks (about four weeks) before the anchor; 6 blocks on testnet, testnet4, signet and regtest | `coin-too-young` | A coin moved recently cannot attest yet. A coinbase coin also waits for coinbase maturity, 100 blocks. |
| The signature verifies against the coin's scriptPubKey | `signature-invalid`, `signature-inconclusive`, `wrong-format` | |
| A timelocked proof's locktime and relative lock are met at the next block | `not-yet-valid` | See below. |

For each outpoint and key, the attestation with the higher anchor counts.
Signing again with a newer anchor replaces or withdraws a statement. A node
stores one attestation per outpoint and key, and at most 32 keys per
outpoint. There is no limit on the number of outpoints unless the operator
sets one: `napmaxattestations=<n>` refuses a submission that would take the
store past `n` attestations, while still taking replacements of stored
ones.

## Publishing

1. Ask the node for the message:

   ```text
   sat-cli createnapattestation "<txid>:<vout>" "bip_xyz.support" "yes"
   {
     "message": "NAP attestation v1\noutpoint: …\nkey: bip_xyz.support\nvalue: yes\nanchor: 912340 00000000…",
     "outpoint": "<txid>:<vout>",
     "key": "bip_xyz.support",
     "value": "yes",
     "anchor_height": 912340,
     "anchor_hash": "00000000…",
     "amount": 0.25000000,
     "address": "bc1q…",
     "formats": ["simple", "full"],
     "psbt": "cHNidP8BAD0AAAAAAf…",
     "warnings": []
   }
   ```

   It checks that the coin exists, holds at least 10,000 sats, and is old
   enough at the anchor. `formats`
   lists the signature formats the coin's script takes, and `address` is the
   address to sign with. `psbt` is the same request as a PSBT, for signers
   that sign BIP 322 through one; an optional fourth argument, the coin's
   descriptor, fills in what they need (see
   [Signing through a PSBT](#signing-through-a-psbt)). `warnings` names anything that will get in the way,
   such as a message too long for a Coldcard (330 characters) or an outpoint
   that already has 32 keys on this node.

2. Sign the message in the wallet that holds the coin (see the next section).

3. Submit the message and the signature, the signed PSBT, or the signed
   transaction in hex:

   ```text
   sat-cli submitnapattestation "$MESSAGE" "smpAkcwRAIg…"
   {
     "id": "5c1e…",
     "outpoint": "<txid>:<vout>",
     "key": "bip_xyz.support",
     "value": "yes",
     "anchor_height": 912340,
     "format": "simple",
     "signature": "smpAkcwRAIg…",
     "status": "valid",
     "amount": 0.25000000,
     "replaced": null
   }
   ```

   The node parses the message, decodes the signature for the coin's script,
   and checks every rule above. An attestation that is not valid is refused
   with `-26` and the rule it failed, as in `rejected (coin-too-young): …`.
   `replaced` is the id of the attestation for the same key that this one
   replaced. Submitting the same attestation twice changes nothing; an older
   one is refused while a newer valid one is stored.

The `id` is the SHA256 of the attestation's serialized form, the same
whichever node holds it.

## Signing

Signatures are base64. satd takes BIP 322's prefixed forms, `smp…` (simple:
the witness stack) and `ful…` (full: the signed `to_sign` transaction), and
an unprefixed string, which it reads as simple for a native segwit coin and
as Core's legacy format for a P2PKH coin, because most wallets made before
BIP 322 was finalized emit unprefixed signatures. Proof-of-funds (`pof…`)
signatures are refused: sign without extra inputs. The RPCs return
signatures in the prefixed form.

`submitnapattestation` also takes the signed `to_sign` transaction as raw
hex, with no prefix, and reads it as a full proof. This is what a wallet
exports when it finalizes the PSBT itself (see
[Signing through a PSBT](#signing-through-a-psbt)). A string of hex digits
that decodes as a transaction is read as one; `verifybip322` takes BIP 322's
own forms only.

| Coin | Format | Signers (as surveyed in 2026) |
|---|---|---|
| P2WPKH, P2TR key path | simple | BIP 322 message signing in Sparrow (`smp`), Unisat, Xverse and Leather (unprefixed) |
| P2PKH | legacy | Bitcoin Core's `signmessage`, Electrum, Trezor, Jade, or `signmessagewithprivkey` |
| P2WSH and P2TR script paths, multisig | simple or full | The PSBT, signed by each cosigner, or a BIP 322 tool that builds the witness for the script, such as the Rust `bip322` crate or btcd |
| P2SH-wrapped segwit, P2SH, bare scripts | full | As above. BIP 322's simple format covers native segwit only |
| Timelocked scripts | full | As above, with `to_sign`'s locktime and sequence set |

Wallet support changes quickly. Check your wallet's documentation for BIP 322
before relying on a row above. Hardware signers and multisig coordinators
mostly sign BIP 322 through a PSBT, described next.

### Signing through a PSBT

`createnapattestation` returns `psbt`: BIP 322's `to_sign` transaction as a
version 0 PSBT. Its input spends the virtual `to_spend` transaction, which
the PSBT carries as the input's UTXO, and the message is in BIP 322's global
field `0x09`. A signer signs it the way it signs a transaction; one that
knows the field shows it as a message to sign rather than a payment. Submit
the signed PSBT in place of a signature:

```text
sat-cli submitnapattestation "$MESSAGE" "cHNidP8BAD0AAAAAAf…"
```

A hardware signer finds the key to sign with through the PSBT's BIP 32 key
origins, and a script coin also needs its script in the PSBT. satd holds no
wallet and knows neither, so pass the coin's public output descriptor as
`createnapattestation`'s fourth argument and the node adds them:

```text
sat-cli createnapattestation "<txid>:<vout>" "bip_xyz.support" "yes" \
  "wsh(sortedmulti(2,[a1b2c3d4/48h/0h/0h/2h]xpub6E…/<0;1>/*,[e5f6a7b8/48h/0h/0h/2h]xpub6F…/<0;1>/*))"
```

The descriptor is the one your wallet exports, with key origins. It must
hold public keys only; one with private keys is refused, as is one with a
hardened step after an xpub, which a public key cannot derive. A ranged
descriptor is searched at indices 0 to 999, each branch of a `<0;1>`
multipath one in turn, for the coin's address. A descriptor that does not
parse is refused with `-5`, and one that does not derive the coin with
`-8`. Without a descriptor the PSBT carries neither, and the wallet or
coordinator that holds the coin's descriptor has to add them before the
signer signs.

The node finalizes the signed PSBT, building the input's witness from the signatures, and
stores the proof: simple for a native segwit coin, full for P2SH-wrapped,
P2PKH and bare scripts, or when the signer changed `to_sign`'s version,
locktime or sequence. The PSBT must carry the message the node was given,
for the outpoint's own script.

- **Single key** (P2WPKH, P2TR key path, P2SH-P2WPKH, P2PKH): the signer's
  signature is enough.
- **Multisig and other scripts**: the PSBT must also carry the script: the
  witness script for P2WSH, the redeem script for P2SH, or the leaf and its
  control block for a Taproot script path, as the descriptor adds them.
  Each cosigner signs; merge their PSBTs with `combinepsbt`, or submit the
  coordinator's combined PSBT. The node finalizes any script that
  [miniscript](https://bitcoin.sipa.be/miniscript/) can satisfy with the
  signatures given, which covers `multi`, `sortedmulti` and `multi_a`. For
  a script outside miniscript, or a timelocked one, build a `ful` signature
  with your own tools.
- **Coldcard** signs these PSBTs (from firmware 5.5.1, and 1.4.1 on the Q),
  shows them as messages, and returns the signed PSBT without finalizing
  it, which is what the node expects.
- **Sparrow** signs the PSBT with a connected hardware wallet (a Ledger on
  the Bitcoin app 2.5.1, for one), finalizes it and exports the signed
  transaction in hex. Submit that hex as the signature, without a prefix:

  ```text
  sat-cli submitnapattestation "$MESSAGE" "00000000000101c144…"
  ```

  On the device the request looks like a transaction with one input, a
  zero-value `OP_RETURN` output and no fee. It spends nothing on chain; do
  not broadcast it.

A PSBT is refused with `-8` when it lacks the message field, has more than
one input (proof of funds), has any output but the zero-value `OP_RETURN`,
signs another message or another coin, or is not fully signed; the message
says which.

**Coldcard** signs messages of up to 330 characters. Everything in a NAP
message but the key and value comes to about 190 characters (more for a
large output index), so a key and value that add up to more than about 140
characters do not fit. `createnapattestation` warns when a message is longer
than 330.

**Timelocks.** A full proof for a timelocked script sets `to_sign`'s
locktime or input sequence. satd judges them as if `to_sign` were in the
block after the tip, as consensus would, against that block's height and the
tip's median time past, and the coin's age. Until they are met the proof is
`not-yet-valid`, and the node refuses it; submit it once the lock has
passed.

Some scripts can be satisfied without a signature: anyone-can-spend, or a
hash lock with a known preimage. Proofs for those coins are valid, but anyone
can make them, and anyone can sweep the coin.

## Following the chain

The node judges every stored attestation again at each new block:

- An attestation whose coin was spent is dropped from the store.
- One that goes stale, or whose anchor block a reorg replaced, stays stored
  but is not served. A lost anchor is logged as a warning naming the outpoint
  and key: sign again to keep publishing it. An anchor 6 blocks deep makes
  this rare.
- A missing coin counts as spent only on a chain that holds the anchor. A
  node that is behind its stored anchors, during a reindex for example, or
  on a fork without them, keeps everything until it is back on the anchor's
  chain.
- At startup, an attestation that lost its anchor while the node was
  stopped is reported the same way, once the node has reached the anchor's
  height.

During initial block download the attestations are judged once, when it ends.

```text
sat-cli listnapattestations
[
  {
    "id": "5c1e…",
    "outpoint": "<txid>:<vout>",
    "key": "bip_xyz.support",
    "value": "yes",
    "anchor_height": 912340,
    "anchor_hash": "00000000…",
    "format": "simple",
    "signature": "smpAkcwRAIg…",
    "message": "NAP attestation v1\n…",
    "status": "valid",
    "amount": 0.25000000
  }
]
```

`status` is `valid` or the name of the rule the attestation fails at the
current tip, with a `reason`. It is `unknown` for an attestation the node has
not been able to judge since it started, because the tip kept changing; ask
again. `amount`, the coin's value, is the
attestation's weight while it is valid.

`removenapattestation "<txid>:<vout>" "<key>"` stops publishing an
attestation and returns its `id`. That is not a withdrawal: copies already
collected stay valid until they go stale or the coin is spent. To withdraw,
sign an empty value.

## Serving to peers

With `nap=1` the node advertises the `NODE_NAP` service bit, bit 30 from the
range Bitcoin Core leaves for experiments (`getnetworkinfo` lists it as
`NAP`), and answers the `getnapatt` P2P message with the attestations valid
at its tip, in `napatt` pages of up to 1,000,000 bytes ordered by outpoint.
It answers any peer that asks, but never sends a NAP message unasked, so a
Bitcoin Core peer, which never asks, never receives one. There is no gossip:
a node serves only what was submitted to it.

Serving is limited so that a peer cannot make the node serve without bound:

| Limit | Per connection | Per network group |
|---|---|---|
| New pulls (a request without a continuation cursor) | 1 per 10 minutes | 8 per 10 minutes |
| Bytes served | 200 MB per hour | 1.6 GB per hour |

A network group is an IPv4 /16, an IPv6 /32, or the AS under `-asmap`. A
connection's limits end with it; a group's do not, so reconnecting does not
reset them. Requests over a limit are ignored, not punished. Peers that
reach the node over Tor all arrive from the loopback address and share one
group, so many Tor connections from one source can use up that group's
limits. A malformed `getnapatt` counts as misbehaviour.

## Aggregating

With `napaggregator=1` the node collects attestations from publishers over
P2P and keeps, for each coin and key, the one that counts at its tip. It does
not need `nap=1`, and does not advertise `NODE_NAP` unless it also publishes.

*   **Where it looks.** Every full-relay, manual or inbound peer the node is
    connected to that advertises `NODE_NAP` is asked as soon as the
    connection opens, and again every hour while it stays up; block-relay,
    address-fetch and feeler connections are never asked. At most eight
    pulls run at once, and at most four of them over inbound connections.
    Publishers the address book knows but the node
    is not connected to are reached over short `nap-pull` connections, at
    most two at a time and each address at most once an hour. A `nap-pull`
    connection (`getpeerinfo` lists it with that `connection_type`) takes no
    outbound slot and carries the pull and nothing else: no blocks,
    transactions or addresses. It closes when the pull ends.
*   **What it checks.** Cheapest first: whether it already holds the
    attestation, then the anchor, freshness, the coin and its age, and only
    then the signature. Signature results are cached, so an attestation
    served by many publishers is verified once. At most 5,000 signatures are
    verified per pull and 50,000 an hour; the rest wait, and pulling pauses
    while 16 MB of them are waiting. Nothing received is dropped for lack of
    budget.
*   **Misbehaviour.** A malformed `napatt`, or an attestation whose
    signature fails or does not fit its coin, is misbehaviour, and the peer
    is disconnected and punished as for any other (a manually added peer is
    not). An attestation that fails only on chain state, such as a spent
    coin or an anchor the node does not have, is not: the publisher's tip
    may differ.
*   **What it keeps.** For each coin and key the attestations that verified,
    newest first. The newest valid one counts. One that is superseded is kept
    until the attestation that superseded it is valid and its anchor 144
    blocks deep, so that if a reorg takes the newer anchor, the older one
    counts again. At most 8 are kept per coin and key, and at most 256 keys
    per coin, the first seen; a key new to a full coin is refused. The whole
    set holds at most `napaggregatormax` attestations (default 1,000,000);
    when full, pairs new to it are refused, while pairs already held still
    take newer attestations. At every
    new block the set is judged again: a spent coin drops out at once, and
    a stale one, or one whose anchor is lost for good, goes too.
*   **On disk.** `<datadir>/nap/aggregate/aggregate.dat`, written every 30
    seconds when it changed and at shutdown. Every signature is verified again
    when it is loaded; an attestation the chain cannot judge yet (during
    initial block download, say) waits for it. A file that does not read back
    is renamed to `aggregate.dat.bad-<unix time>` with a warning, and the node
    starts with an empty set: collection rebuilds it.

`listnapaggregate` lists the attestations that count, each with its coin's
value (`amount`) and the peer it was first collected from (`source`), and the
collection's counters:

```text
sat-cli listnapaggregate
{
  "height": 870000,
  "held": 3,
  "counting": 2,
  "deferred": 0,
  "pulls": { "active": 0, "completed": 4, "timed_out": 0, "pages": 4 },
  "misbehaving": 0,
  "unsolicited": 0,
  "key_limit": 0,
  "full": 0,
  "attestations": [
    { "id": "…", "outpoint": "…:0", "key": "bip_xyz.support", "value": "yes",
      "anchor_height": 869994, "anchor_hash": "…", "amount": 0.5, "source": "203.0.113.5:8333" }
  ]
}
```

`held` counts the superseded attestations kept for reorgs too; `counting`
is one per coin and key.

## Access

`createnapattestation`, `listnapattestations` and `listnapaggregate` change
nothing and need `rpc:read`; they are allowed on the read-only listener. `submitnapattestation`
and `removenapattestation` decide what the node publishes and need
`rpc:write`. See [Authentication & Authorization](authentication.md).

| Error | Meaning |
|---|---|
| `-26` | The attestation is not valid, or is superseded, or the outpoint has 32 keys (`key-limit`), or the store is at `napmaxattestations` (`store-full`). The message names the rule. |
| `-8` | The message, signature, PSBT, key, value or outpoint is malformed, a PSBT is not fully signed, or `removenapattestation` found nothing to remove. |
| `-1` | NAP is disabled (`nap=1` for the publisher RPCs, `napaggregator=1` for `listnapaggregate`), or the chain moved during the call (try again). |

## Privacy and key exposure

An attestation reveals its outpoint, and with it the coin's amount and
history. Expect a published attestation to link your statement to that coin
permanently.

For P2PKH, P2WPKH and script outputs that have never been spent, signing also
publishes the public key or script. That is a security cost as well as a
privacy one: it removes the hash protecting a coin that may otherwise sit
unspent for years, which matters if elliptic-curve keys are ever broken.
Taproot key-path outputs already show their key on chain.

- Sign with a coin you are willing to have identified with the statement.
- For long-term holdings, consider the key exposure before signing with a
  coin whose key is not yet public.
- Publish through a node reachable over Tor if you do not want the outpoint
  linked to your IP address.

## Custody

Exchanges and custodians control the largest coins and can sign with coins
their customers own. NAP cannot tell owned coins from custodied ones, and
publishing an outpoint does not identify the custodian behind it. Weight
caps and concentration statistics are both defeated by splitting coins, so
NAP has neither; interpreting custodial weight is left to whoever reads the
results.
