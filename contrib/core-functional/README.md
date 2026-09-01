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

`run.sh` is not a `cargo test`: it needs built binaries and real ports, and runs
nightly.

It is not reachable from a pull request. The job builds and executes the
checked-out tree, so PR code would run on the runner host; a label gate does not
help, because the label outlives the push it was applied to. Push a branch to
this repo and use `workflow_dispatch` on that ref.

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

Every reason came from running the test, not from reading it. Ranked by tests
unblocked, which is a map of the framework's demands rather than a priority
order.

**No `cache` rows remain.** Every test that was blocked by the framework cache
has been measured to its real blocker. Ranked by tests unblocked:

| Tests | Blocker |
|---:|---|
| 5 | Missing `addconnection` hidden RPC. The framework uses it for outbound test connections; five P2P tests cannot proceed without it. |
| 4 | `generatetodescriptor`. The framework mines to MiniWallet's own descriptor. satd already parses the `raw()` form it passes, so this is a mining-RPC gap, not a descriptor one. `generateblock` has the same shape (1 more test). |
| 4 | Debug-log message mismatches (`assert_debug_log`). Tests grep for Core-specific phrasing that satd either does not log or words differently. |
| 2 | `-blockfilterindex=1` accepted but not activated. `getindexinfo` never reports `synced:true`, so tests that poll for index sync time out. |
| 2 | `setban` / ban persistence. satd now accepts bare IPs and disconnects matching peers, but bans are in-memory only; the test restarts the node and checks the ban survives (`banlist.json`). |
| 2 | `getchaintips` only reports the active tip. Fork tips (headers-valid, valid-fork) are not tracked or returned. |
| 2 | Handshake protocol: satd does not send `wtxidrelay` or `sendtxrcncl` (BIP 330 erlay) during the version handshake. |
| 2 | `getpeerinfo` permissions field type mismatch (list vs string). |
| 1 | `NODE_NETWORK_LIMITED` under `-prune`. satd advertises `NODE_NETWORK\|NODE_WITNESS` where Core signals `NODE_NETWORK_LIMITED\|NODE_WITNESS`. |
| 1 | Every `-rpcbind` entry. Given two, satd binds only the IPv4 one. |
| 1 | Core's automatic onion bind. Not adopted — an extra listening socket on every default node is a design decision. |
| 1 | `MAX_LOCATOR_SZ` enforcement. satd does not disconnect peers that send oversized locators. |
| 1 | tx download scheduling for `WTX` inv. satd does not send GETDATA after receiving a wtxid-based announcement. |
| 1 | `OP_RETURN` output size. satd rejects a ~20000-byte `OP_RETURN` as nonstandard; Core v31's `-datacarriersize` defaults to `MAX_STANDARD_TX_WEIGHT/4`. |
| 1 | `sendrawtransaction` returns the right rejection reason under the wrong code: `-25` where Core returns `-26`. |
| 1 | Dust policy: satd allows an output Core's dust rule rejects. |
| 1 | Sigop-equivalent vsize differs by one (satd 344, Core 345). |
| 1 | `prioritisetransaction` with no arguments leaks a Rust `ErrorObject { .. }` Debug rendering where Core returns its help text. |
| 1 | Key-based descriptors — `pkh()`, `combo()`, `sh(multi())`, `tr()`, and ranged xpub derivation — which `rpc_scantxoutset.py` needs. |

Missing RPCs not in the table above (1 test each): `echo` (×2 tests),
`deriveaddresses`, `getdescriptorinfo`, `gettxoutproof`/`verifytxoutproof`,
`scanblocks`, `dump_all_command_conversions`, `getprioritisedtransactions`,
`getorphantxs`, `createmultisig`.

Nine rows are outside the compatibility target: six use Core v31 options
(cluster mempool, `-txospenderindex`, `-privatebroadcast`) against a stated v30
target; the rest need Core-only binaries or internals.

## Fixed

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
