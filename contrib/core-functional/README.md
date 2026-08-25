# Bitcoin Core functional tests against satd

This harness runs Bitcoin Core's own functional test suite, **unmodified**,
against satd. Every test file in the pinned Core release gets a row in
`inventory.toml` saying either "we run this" or "we skip it, and here is why",
so "Core-compatible" becomes a number anyone can check rather than a claim.

It is the third leg of satd's conformance stack, alongside the ported fixture
corpora and the live block-acceptance differential against `bitcoind`.

## Layout

| Path | What it is |
|---|---|
| `PIN` | The Core release this harness targets: tag + commit. |
| `fetch-core.sh` | Fetches that tree into `core/` (gitignored, never vendored). |
| `<tag>-tests.txt` | The test files that tag contains. Checked in so the inventory can be validated offline. |
| `inventory.toml` | One row per test file: `run`, or `skip` with a reason. |
| `check_inventory.py` | Enforces the inventory's schema. Also prints the run-set and the scoreboard. |
| `run.sh` | Runs the run-set via Core's `test_runner.py`. |
| `check_results.py` | Holds the run's results to the inventory's claim: a `run` row that was skipped at runtime, or absent from the results, fails the run. |
| `shims/bitcoind`, `shims/bitcoin-cli` | What Core's framework executes instead of Core's binaries. |
| `debuglog_map.toml` | Maps satd log lines onto the phrasing `assert_debug_log` greps for. |
| `tests/` | Tests for the harness itself. |

## Running it

```sh
# once, to get the pinned Core tree (honours SATD_CORE_MIRROR for a local clone)
./fetch-core.sh

cargo build --release --bin satd --bin sat-cli   # from the repo root

./run.sh --dry-run    # verify pin, inventory and binaries
./run.sh --list       # print the run-set
./run.sh              # run it
./check_inventory.py --summary   # the scoreboard

# measure a test that is still `skip`, to find out whether a fix unblocks it
./run.sh --candidate rpc_getblockfilter.py
```

`--candidate` is the measuring step of fix -> measure -> flip. It ignores
inventory status and says so on stderr; it is not the scoreboard, and a row
still only flips to `run` in the PR that makes it pass.

`run.sh` never runs from `cargo test`: it needs a built binary pair and real
network ports, and it is a nightly job, not a unit test.

It is also never reachable from a pull request. The job builds and executes
the checked-out tree, so running it on PR code would execute a contributor's
code on the runner host; a label gate does not change that, because the label
outlives the push it was applied to. Push a branch to this repo and use
`workflow_dispatch` on that ref instead.

## The rules that keep the number honest

The scoreboard is only worth publishing if it cannot be inflated. Four rules
do that work, and they are the part of this directory to defend in review.

**1. A row flips to `run` only in the PR that makes it pass.** Never
speculatively, never in a batch "these look fine". The flip and the fix ride
together, so every increment of the score has a diff behind it.

**2. The shim does not translate on the node's behalf.** It provides a
`debug.log`, rewords log lines, and turns off satd-only surfaces. It does not
drop, rename, or invent node options. satd accepts Core's spelling directly and
skips recognized-but-unsupported Core options with a warning of its own; an
option neither side knows still aborts startup, which is the honest outcome. A
test that needs something satd lacks is a `skip` row, not a shim special case.

**3. A `debuglog_map.toml` rule may reword an event, never manufacture one.**
Rules append Core's phrasing to a line satd actually emitted, leaving the
original text in place. If a test greps for a line describing behaviour satd
does not have, that is a `core-log` or feature-specific skip — writing a rule
that emits the string anyway would turn `assert_debug_log` into a no-op.

**4. Every skip names a reason from the taxonomy, and the open-ended ones name
a follow-up.** `rpc-missing`, `feature-missing`, `harness`, `needs-triage` and
`flaky-quarantine` rows must carry a `note` pointing at the work that will
retire them — for `needs-triage`, the error actually observed — so a skip cannot
quietly become permanent. `check_inventory.py` fails the build otherwise.

There is also a fifth rule that is not mechanically enforced, because it
cannot be: **declare satd's real gaps in `config.ini`.** `run.sh` tells the
framework `ENABLE_WALLET=false`, `ENABLE_ZMQ=false` and so on, which makes
Core's own `skip_if_no_*` guards fire. That is how a wallet test reports
"skipped" instead of failing on a missing RPC — the framework is doing the
skipping, on the strength of a true statement about satd. Declaring a
component we do not have as `true` would convert honest skips into noise, and
declaring one we do have as `false` would hide tests we ought to be passing.

## Skip taxonomy

`check_inventory.py` carries the list and its one-line meanings; run
`./check_inventory.py --summary` for the current counts. Every category
describes a property of satd or of the harness rather than "this one fails" —
with one deliberate exception, `needs-triage`, which records a measured failure
whose cause has not been attributed yet. It carries the observed error so the
row is still evidence, and it is the one bucket expected to empty.

## Bumping the pin

Core's `/releases/latest` is not a reliable source: it reports whatever tag was
published most recently, which can be a maintenance release for an older
series. Take the newest **final** (non-`rc`) tag by version order.

1. Update `PIN` with the new tag and its commit hash.
2. Regenerate `<tag>-tests.txt` and delete the old one.
3. Run `./check_inventory.py` and triage what it reports: new files need rows,
   removed files need their rows deleted, renamed files are both.
4. Do it in one PR, separate from any flip.

## What the run found

Every row's reason came from running the test, not from reading it. The
resulting work queue, ranked by how many tests each item unblocks:

| Tests | Blocker |
|---:|---|
| 73 | **`setmocktime`.** Needed for deterministic time, and by `create_cache.py`, which seeds the 199-block chain most tests start from. Unblocks the largest single bucket, and is the largest piece of work: a mockable clock has to reach validation, mempool expiry and P2P timeouts. |
| 48 | **`syncwithvalidationinterfacequeue`.** A hidden, test-only Core RPC that blocks until queued validation callbacks have been delivered. The framework calls it from `sync_all()`, so it is on the path of nearly every multi-node test. Worth thinking through rather than stubbing: if satd applies these side effects synchronously the honest implementation is cheap, but that has to be established, not assumed. |
| 22 | **No periodic P2P ping.** `connect_nodes()` waits for a `pong` in both directions, which can only arrive if each side pings. satd has no keepalive at all: `ping_all()` is called only by the `ping` RPC, there is no inactivity disconnect, and `-peertimeout` is unimplemented. This is an availability gap before it is a test blocker — a half-open connection holds its slot forever. |
| 6 | **Repeated command-line options.** Core accepts an option given twice — `-v2transport=0 -v2transport=1` — and takes the last (its config file deliberately takes the first). satd's parser rejects the duplicate, so any wrapper that appends an override to a base command line breaks. |
| 5 | **Named JSON-RPC parameters.** satd accepts positional parameters only; a request whose `params` is an object fails on every method, not just the one that surfaced it. Core supports both, and its framework calls `generatetoaddress(nblocks=…, address=…)` by name. |
| 2 | **`scantxoutset`**, which the framework's wallet uses to rescan. |
| 1 | **Core's `-bind=addr[:port][=onion]` syntax**, and more than one `-bind`. satd takes a single bare address and gets the port from `-port`. |
| 1 | **`NODE_NETWORK_LIMITED` under `-prune`.** A pruned satd advertises `NODE_NETWORK|NODE_WITNESS` (9) where Core signals `NODE_NETWORK_LIMITED|NODE_WITNESS` (1032), so it invites requests for blocks it does not have. |

Ranked this way the table answers "what unblocks the most tests", which is not
the same question as "what is most worth fixing" — the top two entries are
test-only facilities no operator will ever call. Read it as a map of the
framework's demands, not as a priority order.

### Already fixed

Items the harness surfaced that have since landed, with what they turned out to
be once measured rather than read:

- **`-minrelaytxfee` / `-dustrelayfee` units.** Core denominates them in BTC/kvB,
  satd in sat/kvB. Both spellings are accepted now. The unit mismatch was the
  visible half; the dangerous half was that an unparseable value in
  `bitcoin.conf` was silently discarded and the default used instead.
- **Bare `-blockfilterindex`.** Core accepts the flag with no value.
- **A panic on an unparseable `-bind`.** Underneath it: satd bracketed no IPv6
  literal before joining it to `-port`, so `-bind=::1` could never have worked.
- **`generatetoaddress` parameter shape**, which measurement showed was not
  about `generatetoaddress` at all — see "Named JSON-RPC parameters" above.
- **`getpeerinfo` was missing `addrbind`, `bytessent_per_msg` and
  `bytesrecv_per_msg`.** Adding them unblocked none of the 27 tests that wanted
  them, which is the useful part of the result: with the fields in place those
  tests get far enough to reveal the real blocker underneath, and for 22 of
  them it is the missing keepalive ping above.

Nine rows outside satd's compatibility target are skipped as such: six use Core
v31 options (cluster mempool, `-txospenderindex`, `-privatebroadcast`) against a
stated Core v30 target, and the rest need Core-only binaries or internals.

Four rows remain `needs-triage` — measured as failing with the error recorded in
the row, cause not yet attributed. That bucket should only ever shrink.

## Extending it

Beyond the table above: `debuglog_map.toml` rules for `core-log` rows, and
re-examining the `core-net-policy` and `no-core-zmq` buckets — Core-topic ZMQ is
a plausible small satd feature with real ecosystem value, and would convert a
whole category.
