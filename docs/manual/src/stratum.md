# Stratum Mining Server

satd ships a **Stratum V1** solo-mining server built into the node. A miner —
a BitAxe, an NerdQAxe, any ASIC or firmware that speaks Stratum — connects to
the node directly, receives work built from satd's own block template, and
has any block it finds accepted, taken out of the mempool and relayed by the
same process. There is no pool in between and no separate proxy to run.

It is a solo server, not a pool. The username a miner presents **is** the
payout address: the coinbase of every block that miner finds pays that
address the full subsidy plus fees. There is no share accounting, no payout
splitting and no share database; shares exist only so the miner (and its
operator) can see that it is hashing. This is the same model as
`ckpool -B` solo mode.

The server is off by default. Enable it with `--stratum=1`.

## Quick start

```sh
satd --stratum=1
```

Point the miner at `stratum+tcp://<node-address>:3333`, with the username
`<your-address>.<worker-name>` and any password. The worker name after the
first `.` is optional and appears only in the node's log.

The default listener is **loopback only** (`127.0.0.1:3333`), so the command
above serves a miner on the same host. A miner on the network needs either the
TLS listener (recommended, [below](#tls-with-real-miners)) or an explicit
plaintext bind:

```sh
satd --stratum=1 --stratumbind=0.0.0.0:3333 --stratumallowplaintextremote=1
```

## Exposure posture

A Stratum V1 session is cleartext JSON. The payout address travels in the
clear on every `mining.authorize`, and a device on the path between the miner
and the node can rewrite it: the miner keeps hashing, and every block it finds
pays someone else. Nothing on the miner shows that anything is wrong.

So satd refuses to start when `--stratumbind` is not a loopback address and no
`--stratumtlsbind` is configured:

```
Error: --stratumbind=0.0.0.0:3333 is not a loopback address and no
--stratumtlsbind is configured. Miners on the network would receive work
and submit shares in cleartext. Set --stratumtlsbind (recommended) or
--stratumallowplaintextremote=1 to accept this.
```

`--stratumallowplaintextremote=1` accepts the risk, and is reasonable on a
network segment you control end to end. The TLS listener runs beside the
plaintext one, not instead of it: loopback clients can keep using port 3333.

This is stricter than the Electrum server's defaults. The difference is what
is at stake — an Electrum session leaks privacy, a Stratum session can be
robbed.

## TLS with real miners

Set `--stratumtlsbind` (the conventional port is 4333) with a certificate and
key, and point the miner at `stratum+tls://<node-address>:4333`. Add
`--stratummtls=1` with `--stratummtlsclientca` to require a client certificate,
and `--stratummtlsclientallow` to accept only listed certificate names.

A home node has no public certificate, so the miner has to trust a CA you
create. Two things decide whether that works.

**The certificate must name the address the miner dials.** Miner firmware
verifies the server certificate against the host in the pool URL. If the
miner is pointed at `stratum+tls://192.168.1.50:4333`, the server certificate
needs `192.168.1.50` as an IP subject alternative name; a hostname SAN alone
fails.

**The CA certificate must be small.** ESP-Miner-based firmware (AxeOS, used by
the BitAxe family) accepts a custom CA certificate in its pool settings, but
copies it into a 512-byte buffer — at most **511 bytes of PEM**. A longer
certificate is truncated without an error message, and the TLS connection then
never verifies. An RSA-2048 CA is about 1,100 bytes. Even an EC P-256 CA
exceeds the limit once it carries the usual key-identifier extensions: the CA
that `contrib/stack/tls/mkca.sh` issues for the other TLS surfaces is about 700
bytes and does not fit.

A P-256 CA with a short name and only the two extensions a CA needs fits, at
497 bytes:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -config /dev/null -key ca.key -sha256 -days 3650 \
  -subj "/CN=satd" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  -addext "subjectKeyIdentifier=none" \
  -out ca.crt

openssl ecparam -name prime256v1 -genkey -noout -out stratum.key
openssl req -new -key stratum.key -subj "/CN=satd-stratum" -out stratum.csr
printf 'subjectAltName=IP:192.168.1.50\nextendedKeyUsage=serverAuth\n' > stratum.ext
openssl x509 -req -in stratum.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extfile stratum.ext -out stratum.crt
cat stratum.crt ca.crt > stratum-fullchain.crt
wc -c ca.crt    # must be 511 or less
```

Then run:

```sh
satd --stratum=1 \
  --stratumtlsbind=0.0.0.0:4333 \
  --stratumtlscert=stratum-fullchain.crt \
  --stratumtlskey=stratum.key
```

and paste the contents of **`ca.crt`** — not the full chain, not the server
certificate — into the miner's custom-CA field.

At startup satd warns when the last certificate in `--stratumtlscert` (the CA,
in a full-chain file) is larger than 511 bytes of PEM. It is a warning, not an
error: firmware that uses a system CA bundle, or keeps a larger buffer, is not
affected.

## Configuration

Every Stratum key is restart-only.

| Flag | Default | Notes |
|---|---|---|
| `--stratum=<0\|1>` | `0` | Enable the server. Refused on signet (see [Networks](#networks)). |
| `--stratumbind=<addr:port>` | `127.0.0.1:3333` | Plaintext listener. A non-loopback address needs `--stratumtlsbind` or `--stratumallowplaintextremote=1`. |
| `--stratumtlsbind=<addr:port>` | none | TLS listener (conventional port 4333). Requires cert + key. |
| `--stratumtlscert=<path>` | none | PEM certificate or full chain. |
| `--stratumtlskey=<path>` | none | PEM private key. |
| `--stratummtls=<0\|1>` | `0` | Require a client certificate on the TLS listener. Requires `--stratummtlsclientca`. |
| `--stratummtlsclientca=<path>` | none | PEM CA bundle for client certificates. |
| `--stratummtlsclientallow=<name>` | any CA-signed | Accepted client-certificate CN / DNS-SAN names. Repeatable or comma-separated. Requires `--stratummtls=1`. |
| `--stratumaddress=<address>` | none | Payout address for a miner whose username is not a valid address for this network. |
| `--stratumdifficulty=<n>` | `10000` mainnet, `1000` testnet3/testnet4, `1` regtest | Initial share difficulty. |
| `--stratummaxconns=<n>` | `64` | Connection cap across both listeners. |
| `--stratumallowplaintextremote=<0\|1>` | `0` | Accept a non-loopback `--stratumbind` with no TLS listener. |

The server runs on satd's [isolated API runtime](api-scaling.md), and block
submission runs on a blocking thread, so a found block does not stall the
other API listeners. `getserverstatus` reports the bound `stratum` and
`stratum_tls` listeners, including the real port when a bind used `:0`.

## Payout address

The address is resolved on `mining.authorize`, in order:

1. The username, up to the first `.`, if it is a valid address for this
   network.
2. Otherwise `--stratumaddress`.
3. Otherwise authorize fails with
   `[24, "Unauthorized worker: username is not a valid address for this network and no --stratumaddress is set", null]`.

"For this network" means mainnet versus the test networks. A mainnet address
is refused on testnet and regtest, and a test address on mainnet; but testnet3,
testnet4 and signet share an address encoding, so one test network's address
is accepted on another. The log line for each authorize shows the address and
script that will be paid.

## Difficulty and vardiff

A connection starts at `--stratumdifficulty` (or the per-network default) and
vardiff steers it toward one share every 30 seconds. Every 90 seconds the
difficulty is scaled by how far the observed share rate is from that target,
by at most a factor of four per step, and never above the network difficulty.
A difficulty change is sent as `mining.set_difficulty` followed by a new job;
shares for the previous job are still judged at the difficulty that job was
issued with.

`mining.suggest_difficulty` sets the connection's difficulty and makes it the
floor vardiff will not go below. It is clamped to `[1, 2^48]`.

A ~1.2 TH/s BitAxe-class device at the mainnet default of 10,000 finds a share
about every 35 seconds, so it starts close to the target rate.

A share is checked against the easier of the share target and the block
target. On regtest, where the block target is far easier than difficulty 1,
that is what lets a block-winning header through.

## Protocol

Methods served: `mining.configure` (BIP 310 version rolling, mask
`1fffe000`), `mining.subscribe`, `mining.authorize`,
`mining.suggest_difficulty`, `mining.submit`, `mining.extranonce.subscribe`
(accepted, no-op) and `mining.ping`. The server sends `mining.notify` and
`mining.set_difficulty`.

- `mining.subscribe` returns a 4-byte extranonce1 unique to the connection and
  an extranonce2 size of 4 bytes.
- A new job is sent on every chain tip change (with `clean_jobs` set: earlier
  jobs are stale) and every 30 seconds otherwise, so new mempool transactions
  reach the miner.
- The last eight jobs per connection are kept. A share for any other job is
  `[21, "Job not found", null]`. Other rejections are
  `[22, "Duplicate share", null]`, `[23, "Low difficulty share", null]`, and
  `[20, "Invalid ntime", null]` for a timestamp below the median time past or
  more than two hours ahead of the node's clock.
- On testnet3 and testnet4, a block timestamped more than 20 minutes after its
  parent may use the minimum difficulty, so a job's difficulty holds only on
  one side of that moment. A share timestamped on the other side from the job
  is stale; the next refresh issues a job with the right difficulty.
- Lines are limited to 8 KiB, and a connection that sends nothing for 120
  seconds is closed.

## When work is withheld

During initial block download the server accepts connections and answers
`subscribe`, `configure` and `authorize`, but sends no work: a block built on
a tip days behind the network is worthless. It logs
`stratum: not issuing work during initial block download` once and sends work
as soon as the node catches up. Regtest is exempt, because a fresh regtest
chain's genesis block is from 2011.

The server does not wait for peers. Outside regtest it logs a warning the
first time it issues work with no peer connected, since a block found then
cannot be relayed until one connects.

## When a block is found

A share whose header meets the block target is assembled into a full block
and submitted exactly as `submitblock` would: proof of work, then block
acceptance. If the block joins the active chain its transactions leave the
mempool and it is announced to peers; every miner receives a clean job for the
new tip. The node logs:

```
Stratum miner found a block height=... hash=... address=... worker=...
```

The miner's submit is answered `true` whatever the outcome — the miner did its
part. A block that is valid but does not join the active chain, or that is
rejected, is logged at `warn`.

## Networks

- **mainnet, testnet3, testnet4, regtest**: supported.
- **signet**: refused at startup with
  `--stratum is not available on signet: signet blocks require the network's signing key`.
  Signet blocks carry a signature from the network's signing key (BIP 325),
  which no block template here provides, so every block a miner found would be
  invalid.

## Not supported

- Pool operation: multiple payout addresses per share stream, PPLNS or any
  other reward splitting, share accounting.
- The Stratum V2 Template Distribution Protocol (the `TemplateProvider`
  role).
- Stratum V2 is not yet available; it is planned for a later 0.6.0 change.
