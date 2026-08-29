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
order — the top two are test-only facilities no operator calls.

| Tests | Blocker |
|---:|---|
| 73 | `setmocktime`. Also used by `create_cache.py` to seed the 199-block chain most tests start from. Largest item: a mockable clock has to reach validation, mempool expiry and P2P timeouts. |
| 48 | `syncwithvalidationinterfacequeue`. Hidden test-only RPC that blocks until queued validation callbacks are delivered; the framework calls it from `sync_all()`. Cheap if satd already applies these side effects synchronously, but that needs establishing, not assuming. |
| 22 | No periodic P2P ping. `connect_nodes()` waits for a `pong` in both directions. satd has no keepalive: `ping_all()` runs only from the `ping` RPC, there is no inactivity disconnect, and `-peertimeout` is unimplemented. An availability gap before it is a test blocker. |
| 5 | Named JSON-RPC parameters. satd is positional-only; an object `params` fails on every method, not just the one that surfaced it. |
| 2 | `scantxoutset`, used by the framework's wallet to rescan. |
| 1 | `NODE_NETWORK_LIMITED` under `-prune`. satd advertises `NODE_NETWORK\|NODE_WITNESS` (9) where Core signals `NODE_NETWORK_LIMITED\|NODE_WITNESS` (1032), inviting requests for blocks it does not have. |
| 1 | Every `-rpcbind` entry. Given two, satd binds only the IPv4 one; its invalid-port error also differs from Core's wording. |
| 1 | Core's automatic onion bind: `127.0.0.1:<port + 1>` with `-listen` and no `-bind`. Not adopted — an extra listening socket on every default node is a decision about what a stock satd exposes, not a parsing fix. |

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
- Repeated command-line options aborted startup. Core takes the last value on
  the command line and the first in `bitcoin.conf`.
- `-bind` took a single bare address. Now repeatable, understands
  `addr[:port][=onion]`, and refuses a duplicate binding across
  `-bind`/`-whitebind`. This put `feature_bind_extra.py` in the run-set.
- `getpeerinfo` was missing `addrbind`, `bytessent_per_msg` and
  `bytesrecv_per_msg`. Adding them unblocked none of the 27 tests that wanted
  them: with the fields present those tests reach the real blocker underneath,
  which for 22 of them is the keepalive ping above.

Two rows that looked like satd defects were the harness's own: `shims/bitcoind`
spawned satd as a child, so `node.process.pid` was the shim's. `get_bind_addrs`
reads `/proc/<pid>/fd` to find a node's listening sockets and a shim owns none,
so two bind tests reported binding nothing at all. The shim now execs satd in
its own process and tees the log from a forked child.

## Extending

`debuglog_map.toml` rules for `core-log` rows, and the `core-net-policy` and
`no-core-zmq` buckets — Core-topic ZMQ is a plausible small satd feature with
real ecosystem value, and would convert a whole category.
