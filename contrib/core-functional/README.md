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

**Re-measured 2026-09-05.** Fifty-seven skip rows still named a since-shipped
blocker (`setmocktime`, named parameters, `syncwithvalidationinterfacequeue`,
`scantxoutset`); all 66 rows that had a stale or unattributed note were re-run
as `--candidate` in one batch. **73 executions, 73 failures** -- a stale note
is never a near-pass, removing the stated blocker only exposes the next one.
Every one of those rows now carries the blocker that was actually observed, so
the table below and the inventory agree with the machine.

Ranked by executions blocked. This is a map of the framework's demands, not a
priority order.

| Execs | Blocker |
|---:|---|
| 15 | **debug.log phrasing.** `assert_debug_log` greps for a line satd either words differently or does not log: `bad-txns-vout-empty`, `bad-txns-duplicate`, `Added connection peer=0`, `Misbehaving`, `DNS seeding disabled`, `LoadExternalBlockFile: Out of order block`, the assumevalid and addrman lines. Where satd logs the event, a `debuglog_map.toml` rule can carry it; where it does not, the row is `core-log`. |
| 6 | **`addconnection` hidden RPC.** `add_outbound_p2p_connection` answers Method not found: `p2p_addrfetch`, `p2p_compactblocks`, `p2p_ibd_stalling` (x2), `p2p_mutated_blocks`, plus `feature_anchors`, `p2p_add_connections`, `p2p_addr_relay`, `p2p_outbound_eviction`, `p2p_v2_encrypted` which were credited to it before and have not been re-run. |
| 4 | **Startup-abort text.** Four tests assert Core's exact fatal message on stderr for a condition satd does not detect at all: a missing `-blocksdir`, a pre-segwit chainstate, a block-database timestamp from the future. |
| 3 | **Missing RPC methods.** `createmultisig` (`feature_nulldummy`), `signmessagewithprivkey`, `getdescriptoractivity`. All three are pure secp256k1/script over code satd already has -- no wallet. |
| 3 | **UTXO-set hashing.** `hash_serialized_3` is not Core's serialization and there is no `muhash`, which blocks `feature_utxo_set_hash`, `rpc_dumptxoutset` and (with Core's own tool on top) `tool_utxo_to_sqlite`. |
| 2 | **Unrequested-block connection.** A block pushed over P2P with `send_and_ping` does not connect, so `feature_cltv` and `feature_dersig` stall one block short. Same root as `p2p_unrequested_blocks`. |
| 2 | **Missing RPC fields.** `getnettotals.uploadtarget` (only the doorway -- the test then drives real `-maxuploadtarget` behaviour), `getmininginfo.bits`. |
| 32 | **Real policy and behaviour gaps**, each named in its inventory row: TRUC, package relay, high-bandwidth compact blocks, fee estimation, min-relay-fee divergence, reindex logging, assumeutxo rollback, addrman and address relay, the P2P keepalive ping, `-debuglogfile`, `-capturemessages`, datadir permissions, `decodescript` asm rendering, preciousblock and invalidateblock branch selection, key-based descriptors in `scantxoutset`. |

Nine rows are outside the compatibility target: six use Core v31 options
(cluster mempool, `-txospenderindex`, `-privatebroadcast`) against a stated v30
target; the rest need Core-only binaries or internals.

## Fixed

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

## Extending

`debuglog_map.toml` rules for `core-log` rows, and the `core-net-policy` and
`no-core-zmq` buckets — Core-topic ZMQ is a plausible small satd feature with
real ecosystem value, and would convert a whole category.
