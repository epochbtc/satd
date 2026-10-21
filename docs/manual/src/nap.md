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
judges it again at every new block. This chapter covers publishing. Serving
attestations to peers and collecting them from peers are not in this build.

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
satd NAP attestation v1
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
| The coin confirmed at least 4,032 blocks (about four weeks) before the anchor | `coin-too-young` | A coin moved recently cannot attest yet. |
| The signature verifies against the coin's scriptPubKey | `signature-invalid`, `signature-inconclusive`, `wrong-format` | |
| A timelocked proof's locktime and relative lock are met at the next block | `not-yet-valid` | See below. |

For each outpoint and key, the attestation with the higher anchor counts.
Signing again with a newer anchor replaces or withdraws a statement. A node
stores one attestation per outpoint and key, and at most 32 keys per
outpoint.

## Publishing

1. Ask the node for the message:

   ```text
   sat-cli createnapattestation "<txid>:<vout>" "bip_xyz.support" "yes"
   {
     "message": "satd NAP attestation v1\noutpoint: …\nkey: bip_xyz.support\nvalue: yes\nanchor: 912340 00000000…",
     "outpoint": "<txid>:<vout>",
     "key": "bip_xyz.support",
     "value": "yes",
     "anchor_height": 912340,
     "anchor_hash": "00000000…",
     "amount": 0.25000000,
     "address": "bc1q…",
     "formats": ["simple", "full"],
     "warnings": []
   }
   ```

   It checks that the coin exists and is old enough at the anchor. `formats`
   lists the signature formats the coin's script takes, and `address` is the
   address to sign with. `warnings` names anything that will get in the way,
   such as a message too long for a Coldcard (330 characters) or an outpoint
   that already has 32 keys on this node.

2. Sign the message in the wallet that holds the coin (see the next section).

3. Submit the message and the signature:

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

| Coin | Format | Signers (as surveyed in 2026) |
|---|---|---|
| P2WPKH, P2TR key path | simple | BIP 322 message signing in Sparrow (`smp`), Unisat, Xverse and Leather (unprefixed) |
| P2PKH | legacy | Bitcoin Core's `signmessage`, Electrum, Trezor, Jade, or `signmessagewithprivkey` |
| P2WSH and P2TR script paths, multisig | simple or full | A BIP 322 tool that builds the witness for the script, such as the Rust `bip322` crate or btcd |
| P2SH-wrapped segwit, P2SH, bare scripts | full | As above. BIP 322's simple format covers native segwit only |
| Timelocked scripts | full | As above, with `to_sign`'s locktime and sequence set |

Wallet support changes quickly. Check your wallet's documentation for BIP 322
before relying on a row above. Hardware signers and multisig coordinators
mostly sign BIP 322 through a PSBT of the `to_sign` transaction; satd does
not build or finalize that PSBT in this build.

**Coldcard** signs messages of up to 330 characters. Everything in a NAP
message but the key and value comes to about 195 characters (more for a
large output index), so a key and value that add up to more than about 135
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
    "message": "satd NAP attestation v1\n…",
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

## Access

`createnapattestation` and `listnapattestations` change nothing and need
`rpc:read`; they are allowed on the read-only listener. `submitnapattestation`
and `removenapattestation` decide what the node publishes and need
`rpc:write`. See [Authentication & Authorization](authentication.md).

| Error | Meaning |
|---|---|
| `-26` | The attestation is not valid, or is superseded, or the outpoint has 32 keys. The message names the rule. |
| `-8` | The message, signature, key, value or outpoint is malformed, or `removenapattestation` found nothing to remove. |
| `-1` | NAP is disabled, or the chain moved during the call (try again). |

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
