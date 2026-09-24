# Stratum Mining Server

satd ships a **Stratum V1 and Stratum V2** solo-mining server built into the
node. A miner —
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

The server is off by default. Enable it with `--stratum=1`; add
`--stratumv2bind` for a Stratum V2 listener beside the V1 one.

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

## Stratum V2

Stratum V2 runs the mining protocol over a Noise-encrypted connection
(`Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`), authenticated by the
server's **authority key**. Enable it with `--stratumv2bind`:

```sh
satd --stratum=1 --stratumv2bind=0.0.0.0:3336
```

Because the connection is encrypted and the server authenticated, the V2
listener may bind a network address without TLS; the plaintext refusal above
applies only to the V1 listener. ESP-Miner-based firmware (AxeOS 2.14 and
later) speaks Stratum V2 natively, using an extended channel by default.

**The authority key.** On first start satd creates the key at
`<datadir>/stratum_v2.key` (override with `--stratumv2key`), readable only by
its owner, and logs the public key in both forms the ecosystem uses:

```
Stratum V2 authority key ... created=true authority_pubkey=<64 hex characters> authority_pubkey_base58=<base58check>
```

A miner either trusts the key it sees on first connection or is configured
with it in advance; either way it refuses a server that later presents a
different one. **Back the key file up with the rest of the datadir.** Losing it
means reconfiguring every miner that pinned the old key. A key file that
exists but cannot be read, or does not hold a valid key, stops the node rather
than being replaced. The base58check form — a little-endian key version of 1
followed by the 32-byte x-only key — is what AxeOS and most Stratum V2 tooling
accept as the pool's authority public key.

**Channels.** Both channel types are served. An extended channel receives the
coinbase split around an extranonce hole, the merkle path and an extranonce
range, and rolls its own extranonce; this is what AxeOS uses. A standard
channel receives a finished merkle root and rolls only the nonce, timestamp
and version bits. `--stratumv2maxchannels` caps channels per connection. The
`user_identity` a channel is opened with is the payout address, resolved
exactly as a V1 username is; without a usable address the channel is refused
with `unknown-user`.

**Jobs.** Each channel's first job on a tip is sent as a future job followed by
the `SetNewPrevHash` that activates it; a new tip repeats that for every
channel, and the 30-second refresh sends a job that is active at once. Vardiff
changes are sent as `SetTarget`. Shares are judged exactly as V1 shares are;
rejections carry the Stratum V2 codes `stale-share`, `difficulty-too-low`,
`duplicate-share`, `invalid-share`, `invalid-timestamp` and
`invalid-channel-id`.

A connection must complete the handshake within 10 seconds. After that it is
held to the same limits on silence as a Stratum V1 connection, counting a
frame on any of its channels; see [Idle connections](#idle-connections).

## Job Declaration

With `--stratumv2jd=1` the Stratum V2 listener also serves the Job
Declaration Protocol, for a miner that wants to choose the transactions in its
blocks. The miner runs a Job Declarator Client, which:

1. opens a Job Declaration connection to the same port and sends
   `AllocateMiningJobToken` with its payout address as the user identifier
   (the answer names the payout output its coinbase must include);
2. declares a coinbase and a list of transactions by wtxid
   (`DeclareMiningJob`);
3. on a mining connection opened with `REQUIRES_WORK_SELECTION`, sends
   `SetCustomMiningJob` on an extended channel with the token the declaration
   returned, and mines the job id it gets back. A block found on it is
   submitted with ordinary shares, or pushed with `PushSolution`.

This is solo-mining Job Declaration, so the checks are strict and nothing is
fetched:

- Every declared transaction must already be in this node's mempool and
  eligible for a block template. A declaration naming anything else is refused
  with `invalid-job-param-value-wtxid_list`; the server never asks for missing
  transactions.
- A transaction that spends an unconfirmed parent must be listed after it, and
  the set must fit in a block: its weight, and its signature-operation cost
  together with the coinbase's, at most 80,000. When the extranonce sits
  outside any push in the coinbase scriptSig, its bytes are opcodes the miner
  chooses later, so the scriptSig is counted at 20 per byte, the most any
  opcode costs; putting the extranonce inside a push, as the reference client
  does, makes the count exact.
- The coinbase must commit to the next height on the current tip, pay the
  address the token was issued for, claim no more than the subsidy plus the
  declared fees, and carry a witness commitment that matches the declared
  transactions.
- The custom job must name the current tip and difficulty, a merkle path that
  matches the declaration, a coinbase prefix of at most eight bytes starting
  with the height, and outputs that satisfy the same payout and value rules
  and keep the block within the sigop limit.

Refusals use the Stratum V2 codes `invalid-mining-job-token` and
`invalid-job-param-value-<field>`, with a human-readable reason in
`DeclareMiningJobError`'s details. A token is good for one declaration and
expires after ten minutes. Without `--stratumv2jd`, a Job Declaration
connection is refused with `unsupported-protocol`, and a mining connection
asking for work selection with `unsupported-feature-flags`.

## Monitoring

`getstratuminfo` reports the listeners, the authority key, open connections
and channels, share counters, blocks found, the current job, and every
connected miner with its device, difficulty, share counts, best share and
estimated hashrate. See [JSON-RPC Extensions](json-rpc-extensions.md#stratum).
The same counters are Prometheus metrics; see
[Observability](observability.md#stratum-server).

## Verifying a miner

For a quick check, `sat-cli getstratuminfo` lists each connected miner with
its share counts, the time of its last accepted share and its estimated
hashrate. The log has the history. Every miner gets these lines with no extra
flags:

| Line | Level | Says |
|---|---|---|
| `Stratum miner authorized` (V1), `Stratum V2 channel opened` | info | The payout address and worker, the user agent (V1) or device (V2), and the starting difficulty. |
| `Stratum share rejected` | warn | Why: `low difficulty`, `stale or unknown job`, `duplicate`, `ntime out of range`, or a malformed submit (V2 uses its protocol's error codes). A submit from a connection that has not authorized is logged at debug instead, so a peer that is not a miner cannot fill the log. Where known it also names the job, the difficulty it was issued at, and `share_difficulty`, the difficulty the header actually achieved. |
| `Stratum miner disconnected` (V1), `Stratum V2 channel closed` | info | Why it ended (for example `end of stream` when the miner hung up, `idle`, `write failed` when it stopped reading, `protocol violation`, `node shutting down`), how long it was connected, accepted, rejected and stale share counts, the best share, and the estimated hashrate. |

`-debug=stratum` adds the detail for a device that is not behaving. Like any
`-debug` category it can go in the config file (`debug=stratum`), be switched
on at runtime with `sat-cli logging '["stratum"]'` and off with
`sat-cli logging '[]' '["stratum"]'`, and a SIGHUP puts it back to what the
config file says. `-debugexclude=stratum` keeps it out of `-debug=all`. With it
on:

- `Stratum miner subscribed` names the user agent the firmware sent, and
  `Stratum V2 SetupConnection` the vendor, hardware version, firmware and
  device id.
- `Stratum version rolling negotiated` shows the mask the miner asked for and
  the mask it was granted, and `Stratum miner suggested a difficulty` shows a
  `mining.suggest_difficulty` and the difficulty adopted.
- `Stratum share accepted` for every share, with the worker, job, difficulty and
  `share_difficulty`. A share that is also a block is logged as a found block
  instead.
- A `vardiff retarget` line for every difficulty change.
- `Stratum miner status` every five minutes for each miner: shares accepted,
  rejected and stale since the last status line, the current difficulty, the
  estimated hashrate, and the seconds since the last accepted share.

`-loglevel=stratum:trace` also logs every job sent to a miner.

The hashrate is estimated from the shares the node accepted: a share at
difficulty `d` takes `d × 2^32` hashes on average, so the estimate is the sum of
the accepted shares' difficulties over the last ten minutes (or since the miner
connected, if that is shorter), times `2^32`, divided by that span. At
vardiff's one share every 30 seconds, ten minutes is about twenty shares, so
expect the estimate to wander about a quarter either side of the device's rated
hashrate. A status line early in a connection covers only a few shares.

What the lines point to:

- **No `authorized` line.** The miner is not reaching the listener, or its
  username is refused; the refusal is logged at warn.
- **Authorized, then no shares for a long time.** A device far slower than
  the starting difficulty needs several minutes for vardiff to lower it, and a
  sub-MH/s device over an hour for its first share at difficulty 1 (see
  [Slow miners](#difficulty-and-vardiff)). If a fast device shows no shares
  after several minutes, check that the node is issuing work: during initial
  block download it withholds work and says so once.
- **Disconnected with `reason="binary data on the Stratum V1 port (a Stratum V2
  client?)"`.** The miner is set to Stratum V2 but pointed at the V1 port. Point
  it at the `--stratumv2bind` port, or switch it to Stratum V1.
- **Every share `low difficulty`, with `share_difficulty` far below
  `difficulty`.** The miner is hashing a different header from the one the
  node rebuilds, so its shares are effectively random. Compare the granted
  version-rolling mask with what the firmware rolls. Real bad luck puts
  `share_difficulty` near `difficulty`, not orders of magnitude below it.
- **Mostly `stale or unknown job`.** The miner is slow to switch to new work,
  or its connection is lagging.
- **A hashrate well below the device's rating over several status lines.** The
  device is hashing slower than it should (thermal throttling, a failing
  hashboard), or losing work to rejects.
- **Repeated disconnect lines.** The device or its network is dropping the
  connection. `connected_secs` says how long each one lasted.

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
| `--stratumv2bind=<addr:port>` | none | Stratum V2 listener. Noise-encrypted; may bind a network address without TLS. Requires `--stratum=1`. |
| `--stratumv2key=<path>` | `<datadir>/stratum_v2.key` | Authority key file, created if absent. Back it up: miners pin the key. |
| `--stratumv2maxchannels=<n>` | `16` | Channels one Stratum V2 connection may open. |
| `--stratumv2jd=<0\|1>` | `0` | Serve Stratum V2 Job Declaration on the V2 listener. Requires `--stratumv2bind`. |

The server runs on satd's [isolated API runtime](api-scaling.md), and block
submission runs on a blocking thread, so a found block does not stall the
other API listeners. `getserverstatus` reports the bound `stratum`, `stratum_tls`
and `stratum_v2` listeners, including the real port when a bind used `:0`.

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
vardiff steers it toward one share every 30 seconds.

Shares arrive at random, so a few minutes of them say little about a miner's
speed: at the target rate, seven shares in 90 seconds where three were
expected happens about 3% of the time. Vardiff therefore changes the
difficulty only when the shares since the last change are clearly off target:

- when a miner exactly on target would produce a count that far off with
  probability below 1 in 100,000 (checked every 10 seconds, so that luck
  alone rarely gets through); or
- once at least 40 shares were expected since the last change, when that
  probability is below 1 in 1,000, so that a moderate error is still
  corrected, on enough shares to land close to the target; or
- for a miner that has not had a share accepted since it connected, when that
  probability is below 1 in 100. Its difficulty is only a starting guess, and
  a slow device can be lowered from the default to difficulty 1 in about
  twelve minutes instead of half an hour. A fast miner lowered too far by
  this floods shares and is raised again within a minute.

Even then, a rate within 15% of the target is left alone. A change moves the
difficulty to where the observed rate says it should be, by at most a factor
of eight, never below the `mining.suggest_difficulty` floor and never above
the network difficulty. Shares are counted for the difficulty they were
judged at, so a share on an older job still counts for its work.

In practice, measured over 300 simulated six-hour runs of miners from 100 GH/s
to 100 TH/s:

- A miner whose difficulty is ten times too low (shares far too fast) is
  within a factor of two of its best difficulty within a minute and a half.
- A miner whose difficulty is ten times too high is within a factor of two of
  its best difficulty in about two and a half minutes, at worst about forty.
- Once settled, the difficulty of 95% of miners stays within a factor of two,
  changing at most four times in five hours, with the mean share interval
  within 20% of 30 seconds. The check runs every ten seconds, so now and then
  luck passes even a 1-in-100,000 test; such a miner makes one excursion of
  no more than one step and is corrected within minutes.
- A miner that has submitted before and goes quiet has its difficulty lowered
  after about eleven expected share intervals without a share.

**Slow miners.** Difficulty is a whole number, so no miner gets shares easier
than difficulty 1, which takes `2^32` hashes (about 4.3 billion) on average. A
device's share interval at difficulty 1 is `2^32 / hashrate` seconds: about 72
minutes at 1 MH/s and about a day at 50 kH/s. Simulated from the mainnet
default difficulty of 10,000, without `mining.suggest_difficulty`:

| Device | First share (median) | Shares a day | Idle disconnects a day |
|---|---|---|---|
| 1.2 TH/s | 22 s | ~2,900 | 0 |
| 100 GH/s | 2.6 min | ~2,900 | 0 |
| 1 GH/s | 7.5 min | ~2,800 | 0 |
| 7 MH/s | 19 min | ~140 | 0 |
| 1 MH/s | 76 min | ~19 | 0 |
| 50 kH/s | 16 h | ~1 | about one |

A device below about 1 MH/s cannot find twenty difficulty-1 shares a day, so
it now and then outlasts the one-day idle limit ([below](#idle-connections))
and reconnects. That costs it nothing but the reconnect: its chance of finding
a block does not depend on its shares, and every connection gets current work.

A difficulty change is sent as `mining.set_difficulty` followed by a new job
(Stratum V1) or `SetTarget` (Stratum V2); shares for the previous job are
still judged at the difficulty that job was issued with.

`mining.suggest_difficulty` sets the connection's difficulty and makes it the
floor vardiff will not go below. It is clamped to `[1, 2^48]`.

A ~1.2 TH/s BitAxe-class device at the mainnet default of 10,000 finds a share
about every 35 seconds, so it starts close to the target rate.

Stratum V2 channels start at the same difficulty and are steered the same
way; a channel's target also never exceeds the `max_target` the miner opened
it with.

A share is checked against the easier of the share target and the block
target. On regtest, where the block target is far easier than difficulty 1,
that is what lets a block-winning header through.

## Stratum V1 protocol

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
- Lines are limited to 8 KiB. A connection that sends nothing for too long is
  closed; see [Idle connections](#idle-connections).

## Idle connections

A miner sends nothing but shares, so how long it can go quiet depends on how
often it should find one. A connection that has not authorized (Stratum V1) or
opened a channel (Stratum V2) is closed after **120 seconds** of silence. After
that:

- Once the miner has four accepted shares, it may go quiet for **twenty
  expected share intervals** at its current difficulty, but never less than 120
  seconds and never more than a day. The expected interval comes from the
  slower of two hashrate estimates: the ten minutes before its last accepted
  share, and the whole connection up to that share. Both stop at the last
  share, so the silence being timed does not stretch its own limit. At
  vardiff's one share every 30 seconds the limit is ten minutes.
- Before that, it may go quiet for **a day**. A new miner's silence says
  nothing yet: a slow device at the default difficulty can take over an hour
  to find its first share, most of it after vardiff has lowered it as far as
  it goes.

The limit is recomputed as the difficulty changes. Shares arrive at random, so
a gap of twenty expected intervals has a probability of about 2 in a billion.
A Stratum V2 connection counts the share rates of all its channels.

The idle limit is a backstop, not how a miner that has gone away is noticed.
The node sends every miner a job at least every 30 seconds, so a peer that is
switched off or unplugged stops acknowledging them, the operating system's TCP
retransmission gives up on the connection (after about fifteen minutes with
Linux defaults), and the session ends with a read or write error.

The one-day ceiling matters for a miner that expects fewer than one share
every 72 minutes: a device slower than about 1 MH/s even at difficulty 1 (see
[Slow miners](#difficulty-and-vardiff)), or one whose
`mining.suggest_difficulty` floor is above what it can reach. Such a miner is
now and then dropped while it is hashing and reconnects; lower the floor if
you set one.

When vardiff lowers the difficulty of a miner that has gone quiet, the idle
limit is still judged at the difficulty of the miner's last share, so the
lowering itself cannot make a silence already endured exceed the limit.

## Template checks

Every block template is checked before a miner gets it, as Bitcoin Core checks
the templates it builds (`TestBlockValidity`). A template that would make a
block the node rejects is a node bug — the mempool admitted a transaction
consensus refuses — and the check exists so that a miner who finds a block
has not found it on a template that was never valid.

The check has two tiers:

- **Structural**, on every template, before it is issued: every rule block
  connection applies except running scripts — size and weight, sigops, the
  BIP 34 height, lock times and sequence locks, the coinbase value, the witness
  commitment, and inputs that are missing or already spent.
- **Full**, which adds the scripts, run through the same verifier the node
  connects blocks with (under `-consensus=cpp-shadow`, the shadow comparison
  included). It runs in the background, never delaying work: for each new tip,
  and at most every two minutes while the tip stands still. It costs about as
  much as connecting a block, since satd has no script-execution cache: a few
  CPU-seconds for a full mainnet template.

A template that fails either check is replaced by a **coinbase-only** job on
the same tip, which is always valid, and every miner switches to it at once.
`getstratuminfo` shows `"coinbase_only": true` on the current job. While that
lasts, each new template must pass the full check before it is issued; the
first one that does brings transactions back. The failure is logged at error
with Core's reject reason and the offending transaction, counted in
`satd_template_checks_total`, and raised as the `template_invalid` alert (see
[Observability](observability.md#node-health-alerts)). The transaction is not
evicted from the mempool: Core does not do that either, and the bug that let it
in should stay visible.

`getblocktemplate` runs the structural check too and answers an invalid
template with `TestBlockValidity failed: <reason>`, as Core does; the full
check for its template follows in the background once per tip. The `generate`
RPCs refuse such a block the same way before solving it.

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

### The saved copy

Before a found block is submitted, it is written to

```
<datadir>/stratum/found/<height>-<hash>.hex
```

(under the network subdirectory on a test network, like the rest of the
datadir). The file is the serialized block as a single line of hex, exactly
what `submitblock` takes. It is written to a temporary file, synced and renamed
into place, so it either holds the whole block or is absent. The node logs

```
Stratum found block saved; submitting it height=... hash=... path=...
```

and the `warn` for a refused block names the file again in `saved=`.

The copy is there for the case the node itself gets wrong. If this node
refuses a block — a bug, a disk error part way through connecting it — the
block is still worth broadcasting, and any other node will take it. A full
block is megabytes of hex, more than a single command-line argument can carry,
so pass it on standard input:

```sh
sat-cli -stdin submitblock < <datadir>/stratum/found/968181-<hash>.hex
bitcoin-cli -stdin submitblock < <datadir>/stratum/found/968181-<hash>.hex
```

A block that was refused as invalid (`bad-cb-amount`, `bad-txns-...`) will be
refused everywhere; one refused for a reason that is this node's own is not.
Submit it promptly: a block is only worth anything until the network builds
another one at its height.

Files are kept after a successful submission too, as a record of the blocks
found. There is one per block, so the directory does not grow in practice.
Only a header that meets its block target is ever saved. If the directory
cannot be written, the node logs an error and submits the block anyway.

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
  role), group channels, and fetching declared transactions this node does not
  already have (`ProvideMissingTransactions`).
