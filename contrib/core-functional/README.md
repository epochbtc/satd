# Bitcoin Core functional tests against satd

Runs Bitcoin Core's functional test suite, unmodified, against satd. Every test
file in the pinned Core release has a row in `inventory.toml`: `run`, or `skip`
with a reason.

## Layout

| Path | What it is |
|---|---|
| `PIN` | Core release targeted: tag + commit. |
| `fetch-core.sh` | Fetches that tree into `core/` (gitignored, never vendored). |
| `<tag>-tests.txt` | Test files in that tag. Checked in so the inventory validates offline. |
| `inventory.toml` | One row per test file. |
| `check_inventory.py` | Enforces the inventory schema; prints the run-set and the scoreboard. |
| `run.sh` | Runs the run-set via Core's `test_runner.py`. |
| `check_results.py` | Fails the run if a `run` row was skipped at runtime or is absent from the results. |
| `gen-named-params.py` | Derives satd's named-parameter table from Core's `RPCHelpMan` declarations; `--check` fails on drift. |
| `shims/bitcoind`, `shims/bitcoin-cli` | Executed by Core's framework in place of Core's binaries. |
| `debuglog_map.toml` | Maps satd log lines onto the phrasing `assert_debug_log` greps for. |
| `tests/` | Tests for the harness. |

## Running

```sh
./fetch-core.sh                                  # honours SATD_CORE_MIRROR
cargo build --release --bin satd --bin sat-cli   # from the repo root

./run.sh --dry-run               # verify pin, inventory, binaries
./run.sh --list                  # print the run-set
./run.sh
./check_inventory.py --summary   # scoreboard

./run.sh --candidate rpc_getblockfilter.py   # measure a row that is still skip
```

`--candidate` ignores inventory status and does not touch the scoreboard.

`run.sh` is not a `cargo test`: it needs built binaries and real ports.

It runs in CI twice, for different reasons.

**The PR gate** is the `core-functional` job in `canary.yml`, on a hosted
runner. It downloads the same `satd-canary-binaries` artifact the nine canaries
share, so the release build is paid for once per run, and the suite itself is
under a minute at `SATD_CF_JOBS=4`. This is what stops a merge: without it, a
`skip` -> `run` flip is never validated by pull-request CI, and any later change
can silently un-pass a row the scoreboard still advertises.

**The nightly run** is the `Run` job in `core-functional.yml`. It pays for its
own build rather than sharing an artifact, and it is where the run set gets
widened and where a `--candidate` measurement runs unattended. To exercise a
branch there, push it to this repo and use `workflow_dispatch` on that ref.

Both run on **GitHub-hosted runners**, as does every other job in this
repository. satd is public, and these jobs build and execute the checked-out
tree -- `cargo build` alone runs every dependency's `build.rs`, and the harness
then runs `run.sh`, the shims and Core's python. On a maintainer-owned machine
that is arbitrary code execution with that host's filesystem and credentials.
A hosted runner is a disposable VM.

## Rules

The scoreboard is only worth publishing if it cannot be inflated.

1. **A row flips to `run` only in the PR that makes it pass.** The flip and the
   fix ride together.
2. **The shim does not translate for the node.** It supplies a `debug.log`,
   rewords log lines, and disables satd-only surfaces. It does not drop, rename
   or invent options. A test needing something satd lacks is a `skip` row, not a
   shim special case.
3. **A `debuglog_map.toml` rule rewords an event, never manufactures one.**
   Rules append Core's phrasing to a line satd emitted, leaving the original in
   place. Emitting a string satd never logged turns `assert_debug_log` into a
   no-op.
4. **Every skip names a taxonomy reason; open-ended ones name a follow-up.**
   `rpc-missing`, `feature-missing`, `harness`, `needs-triage` and
   `flaky-quarantine` require a `note` — for `needs-triage`, the observed error.
   `check_inventory.py` fails the build otherwise.

Not mechanically enforced: **declare satd's real gaps in `config.ini`.** `run.sh`
sets `ENABLE_WALLET=false`, `ENABLE_ZMQ=false` and so on, which fires Core's own
`skip_if_no_*` guards. Declaring a component satd lacks as `true` turns honest
skips into noise; declaring one it has as `false` hides tests that should pass.

## Skip taxonomy

`check_inventory.py` carries the categories and their meanings; run
`./check_inventory.py --summary` for counts. Each describes a property of satd
or of the harness, except `needs-triage`, which records a measured failure not
yet attributed and carries the observed error. That bucket should only shrink.

## Bumping the pin

Core's `/releases/latest` reports the most recently published tag, which can be
a maintenance release for an older series. Take the newest final (non-`rc`) tag
by version order.

1. Update `PIN` with the tag and its commit.
2. Regenerate `<tag>-tests.txt`; delete the old one.
3. Run `./check_inventory.py` and triage: new files need rows, removed files
   need their rows deleted, renames are both.
4. Run `./gen-named-params.py --check --cross-check core`. If Core changed an
   RPC's arguments, regenerate with `--emit-rust` and splice the arms into
   `arg_names()` in `node/src/rpc/named_params.rs`. CI runs this check; a
   reordered argument would otherwise bind values to the wrong positions
   silently.
5. One PR, separate from any flip.

## Blockers

Every reason came from running the test, not from reading it.

**Re-measured 2026-09-15.** Every eligible skip row -- 134 rows, 146
executions, leaving out the buckets that can never run (`no-wallet`, `no-tool`,
`prev-release`, `no-usdt`, `core-internal`, `no-ipc`, `no-core-zmq`) -- was run
as `--candidate` in one batch. Two executions passed: `feature_fastprune`,
which went into the run-set, and `rpc_bind --nonloopback`, one of that row's
three variants. Many rows still named a blocker that had since shipped (the
keepalive ping, `getpeerinfo.inflight` during IBD, `getmininginfo.bits`,
`getdeploymentinfo`, `getprioritisedtransactions`); every row now carries the
line it actually stopped on, and the blocker known to sit behind it where one
is.

The first blocker per failing execution, grouped. This is a map of what the
framework hits first, not a priority order: a row almost always stops again
behind its first blocker.

| Execs | First blocker |
|---:|---|
| 21 | **A log line satd never writes.** `assert_debug_log` greps for an event satd handles silently: a tx or block reject reason, a redundant `verack`, an inbound accept with its peer id, a disconnect's node-state cleanup, the RPC method being served. Where satd logs the event in other words, `debuglog_map.toml` can carry it; where it logs nothing, satd needs the line first. The rest of this group (addrman, assumevalid, anti-DoS headers, reindex ordering) has no event to log. |
| 19 | **Core's P2P policy.** `feefilter` send rules, `-blocksonly` and `-peerbloomfilters=0` violation disconnects, ping timing on the mock clock, the stale-block serving cutoff, single-peer initial headers sync, the stale-tip outbound eviction probe, header announcement state, `NODE_NETWORK_LIMITED`, address relay, inbound eviction, Erlay. |
| 15 | **A missing RPC.** `createmultisig` (three rows), `signmessagewithprivkey`, `getorphantxs` (two), `sendmsgtopeer` (two variants), `addpeeraddress` (two), `mockscheduler`, `getdescriptoractivity`, and per-method `help` text (three executions). |
| 13 | **A missing or differently shaped RPC field.** `getmininginfo.bits`, `getblockchaininfo.signet_challenge`, `getprioritisedtransactions.modified_fee`, `getmempoolentry.wtxid`, `getrawmempool(mempool_sequence=true)`, `NODE_P2P_V2` in `localservices`, per-message byte counts under v2, `decodescript` asm, `muhash`, `uploadtarget`, coinstatsindex fields, `hash_serialized_3`. |
| 11 | **Core v31 options or out-of-scope surfaces.** Cluster mempool limits, `-txospenderindex`, `-privatebroadcast`, I2P, RPC whitelists. |
| 10 | **Core's on-disk layout.** `rev*.dat`, `blocks/index`, `anchors.dat`, `-debuglogfile`, datadir permissions, `getrpcinfo.logpath`, REST. |
| 9 | **Chain behaviour.** `preciousblock` is a no-op, the filter index is keyed by height, the unknown-versionbits and large-work-invalid-chain warnings, `stop` during a long call, txindex over a cached datadir, block reject wording, the prune target across a reorg. |
| 9 | **Mempool policy.** The rolling minimum fee, `-bytespersigop` rounding, the `-26` reject message prefix, `-maxtipage`, TRUC, package RBF, fee estimation, key-based descriptors in `scantxoutset`. |
| 8 | **`-prune=1` refused at startup.** satd prunes automatically under `-prune=<MiB>` but has no manual mode, and seven rows start a node with `-prune=1`. |
| 8 | **Message ordering behind `ping`.** satd answers `ping` on the peer's socket task, while blocks and transactions go through the block processor, so `send_and_ping` does not guarantee the block or tx was processed when the pong arrives. |
| 8 | **Startup text.** `-rpcauth` validation, `-rpcbind` port errors, `-nolisten=0`, a missing `-blocksdir`, `-pid` path resolution, `uacomment` from an included config. |
| 4 | **Sync wedges.** The IBD scheduler stuck at `0 in-flight, N pending`, and `invalidateblock` leaving the headers tip on the invalidated branch. |
| 4 | **wtxid relay** (#714). |
| 3 | **In-flight blocks outside IBD.** `getpeerinfo.inflight` is filled only by the IBD scheduler. |
| 2 | **High-bandwidth compact blocks.** |

Nine rows are outside the compatibility target: six use Core v31 options
(cluster mempool, `-txospenderindex`, `-privatebroadcast`) against a stated v30
target; the rest need Core-only binaries or internals.

**Re-measured 2026-09-05.** Fifty-seven skip rows still named a since-shipped
blocker (`setmocktime`, named parameters, `syncwithvalidationinterfacequeue`,
`scantxoutset`); all 66 rows that had a stale or unattributed note were re-run
as `--candidate` in one batch. **73 executions, 73 failures** -- a stale note
is never a near-pass, removing the stated blocker only exposes the next one.

**`addconnection` landed, and the nine rows behind it were re-measured.** Two
passed outright (`p2p_add_connections`, `p2p_addrfetch`); the other seven each
carry the blocker that was actually observed once the RPC existed.

## Fixed

- **`-connect=0` was dialled as an address.** Core spells "open no outbound
  connections" that way and every functional-test node is started with it, so
  satd dialled `0.0.0.0:8333` at startup and kept re-dialling it from the
  reconnect loop. Where something answers on that port -- a Bitcoin Core node
  on the same host, as on the measuring machine -- the dial succeeds far
  enough to consume peer id 0, and the first real peer then comes back as id 1
  where Core reports 0. That is what `p2p_addrfetch` and `p2p_mutated_blocks`
  were failing on. `-connect` now also stops the node dialling gossiped
  addresses, as Core's `m_use_addrman_outgoing` does.
- **`addconnection`.** Core's hidden regtest-only dial RPC, with the four
  connection types and the behaviour each implies: `block-relay-only` clears
  `fRelay` and gets no address relay, `feeler` is closed on the peer's
  `version`, `addr-fetch` gets a `getaddr` and no `getheaders` and is dropped
  once answered. `getpeerinfo.connection_type` reports the real type.
- `getdeploymentinfo` reported the buried deployments as `dersig`/`cltv`.
  Core's `DeploymentName` spells them `bip66`/`bip65` on the way out, even
  though `-testactivationheight` takes `dersig`/`cltv` on the way in, and the
  test framework keys on the reported name.
- `validateaddress` never checked the network (a mainnet address validated on
  regtest) and reported no `error`/`error_locations`. Both fixed, including
  Core's Bech32 error locator, against Core's own vectors.
- `dumptxoutset` read its arguments with a helper accepting exactly one, so
  every `dumptxoutset(path, "latest")` was a parse error; and a relative path
  was resolved against the process's working directory rather than the network
  datadir.

- `-minrelaytxfee` / `-dustrelayfee` units: Core denominates in BTC/kvB, satd in
  sat/kvB. Both accepted now. An unparseable value in `bitcoin.conf` was also
  silently discarded and the default used.
- Bare `-blockfilterindex`, which Core accepts with no value.
- Panic on an unparseable `-bind`. Underneath it, satd bracketed no IPv6 literal
  before joining it to `-port`, so `-bind=::1` could never have worked.
- `generatetoaddress` parameter shape, which measurement showed was the named
  JSON-RPC parameter gap above.
- `scantxoutset`, over the key-free descriptors (`raw()`, `addr()`) with BIP380
  checksums and Core's `desc` inference. `desc` parity was settled against a live
  Bitcoin Core rather than by reading `InferScript`. Unblocked
  `mempool_resurrect` and moved the other 22 onto measured causes.
- Repeated command-line options aborted startup. Core takes the last value on
  the command line and the first in `bitcoin.conf`.
- `-bind` took a single bare address. Now repeatable, understands
  `addr[:port][=onion]`, and refuses a duplicate binding across
  `-bind`/`-whitebind`. This put `feature_bind_extra.py` in the run-set.
- `getpeerinfo` was missing `addrbind`, `bytessent_per_msg` and
  `bytesrecv_per_msg`. Adding them unblocked none of the 27 tests that wanted
  them: with the fields present those tests reach the real blocker underneath,
  which for 22 of them is the keepalive ping above.

- Named JSON-RPC parameters. satd was positional-only, so an object `params`
  failed on every method — and Core's `authproxy` sends one for any keyword
  argument, which is the first thing the framework does.
- `setmocktime`, on a node clock reaching block-template timestamps, the
  future-block check and mempool expiry. Regtest-only as in Core, and behind a
  `test:clock` capability that `rpc:write` does not imply.
- `syncwithvalidationinterfacequeue`, draining the event bridges. These three
  together built the 199-block cache for the first time and took the scoreboard
  from three to six.

- `MAX_LOCATOR_SZ` enforcement: satd now disconnects peers that send a
  `getheaders` or `getblocks` locator with more than 101 hashes, matching Core's
  `net_processing.cpp`. Also added a basic `getblocks` response (respond with
  `inv` for up to 500 blocks). This put `p2p_invalid_locator.py` in the run-set.
- JSON-RPC 1.0 response normalization: the compat layer now strips `"jsonrpc"`,
  adds `"error":null` to success responses and `"result":null` to error
  responses, and adds a default `Content-Type: application/json` and `"id":null`
  when missing from the request. Core's `authproxy` takes different code paths
  for 1.0 vs 2.0 responses, and many Core tests assert `"error":null` in the
  raw byte stream.

- `generatetodescriptor` RPC: parses `raw()` and `addr()` descriptors and mines
  blocks paying to the derived output script. This is how Core's MiniWallet
  mines; without it, every MiniWallet-based test failed before reaching its
  real logic. Put `feature_framework_miniwallet.py` in the run-set.
- `getmininginfo` now includes `currentblocktx`, `currentblockweight`, and a
  live `pooledtx` count (was hardcoded 0).
- Mempool rejection error codes: policy rejections (non-final, non-BIP68-final,
  insufficient fee, dust, chain limits, conflicts) now return `-26`
  (`RPC_VERIFY_REJECTED`) instead of `-25`. Core distinguishes consensus errors
  (`-25`) from policy rejections (`-26`); satd mapped everything to `-25`.

Two rows that looked like satd defects were the harness's own: `shims/bitcoind`
spawned satd as a child, so `node.process.pid` was the shim's. `get_bind_addrs`
reads `/proc/<pid>/fd` to find a node's listening sockets and a shim owns none,
so two bind tests reported binding nothing at all. The shim now execs satd in
its own process and tees the log from a forked child.

That arrangement carries an invariant worth knowing before adding to it: the
tee is a separate process, and the framework waits on *satd's* pid before
reading the node's stdout, so the tee is only safe for a node that outlives
that first read. An invocation that prints one thing and exits (`-h`, `-help`,
`-?`, `-version`) can lose the race outright and hand the test an empty
stdout, so those exec straight through with no tee at all --
`EXITS_IMMEDIATELY` in the shim. Anything added later that prints and exits
belongs in that set.

## Extending

`debuglog_map.toml` rules for `core-log` rows, and the `core-net-policy` and
`no-core-zmq` buckets — Core-topic ZMQ is a plausible small satd feature with
real ecosystem value, and would convert a whole category.
