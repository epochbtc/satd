# Core Functional-Test Conformance

satd runs Bitcoin Core's own functional test suite, **unmodified**, against
itself. Every test file in the pinned Core release is accounted for: it either
runs, or it carries a reason it does not. This page is the scoreboard.

It is deliberately a different kind of evidence from satd's other conformance
work. The ported fixture corpora check that satd agrees with Core on specific
inputs, and the live block-acceptance differential checks that satd and
`bitcoind` accept the same blocks from the real network. This suite checks
something neither of those can: that Core's *own* idea of how a Bitcoin node
behaves — written by Core's developers, in Core's terms, exercising Core's RPC
surface, P2P behaviour and startup semantics — holds when pointed at satd.

## Scoreboard

The current numbers come from the harness itself:

```sh
contrib/core-functional/check_inventory.py --summary
```

The harness is in `contrib/core-functional/`; its `README.md` documents the
rules that keep the number honest, the most important being that **a test flips
to `run` only in the pull request that makes it pass**. The count moves when
behaviour changes, never because a batch of rows was re-labelled.

At the time this harness landed the run-set was deliberately tiny: two tests.
That number is not a measure of how Core-compatible satd is — it is a measure of
how much of Core's *test framework* satd can currently drive. The framework
leans on test-only facilities that satd had no reason to implement until the
harness needed them — `setmocktime`, `syncwithvalidationinterfacequeue` and a
periodic P2P ping, all of which have since landed. Clearing one rarely turns a
row green on its own: the blockers are layered, and a test that gets past the
framework's setup then stops on whatever its body needs next. Every skip records
what actually blocked it *when it was last measured*, so the queue of work is
explicit rather than a guess; `contrib/core-functional/README.md` ranks it.

## How to read a skip

A skip is not an admission that satd fails a test. Most are statements about
what satd deliberately is:

| Reason | What it means |
|---|---|
| `no-wallet` | The test drives the legacy Core wallet. satd is walletless by design — see [CORE_DIFFERENCES.md](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md). |
| `no-tool` | The test drives a Core-only binary (`bitcoin-tx`, `bitcoin-util`, `bitcoin-wallet`, `bitcoin-chainstate`, `bench_bitcoin`). |
| `no-core-zmq` | The test uses Core's ZMQ topics. satd's ZMQ carries the [satd-events](streaming.md) wire instead. |
| `no-ipc`, `no-usdt`, `no-qt` | Core interfaces satd does not ship. |
| `core-internal` | The test asserts on Core implementation details satd does not share — LevelDB files, `blk*.dat` layout, `settings.json`. |
| `core-net-policy` | The test asserts on Core-specific net artifacts: `anchors.dat`, asmap, banlist format. |
| `core-log` | The test greps `debug.log` for a line satd has no honest equivalent of. |
| `rpc-missing`, `feature-missing` | A genuine gap. These rows must name the follow-up work, so they cannot quietly become permanent. |
| `cache`, `harness`, `prev-release`, `flaky-quarantine` | Blocked by the harness rather than by satd. |
| `needs-triage` | Measured as failing, cause not yet attributed. The row carries the observed error. This is the one bucket expected to empty. |

The two buckets worth watching are `rpc-missing` and `feature-missing`: those
are the ones that represent work, and the harness refuses to accept such a row
unless it names what will retire it.

## Where satd already matched Core, and where it did not

Standing the harness up was itself a conformance test, because Core's framework
is an exacting client: it drives the node the way Core's own developers assume a
node behaves. Several places where satd had drifted only became visible once
that client was pointed at it — most of them affecting real Core-compatible
software, not just tests:

- **`Content-Type: application/json`.** satd answered RPC with
  `application/json; charset=utf-8`. The parameter is redundant (RFC 8259 fixes
  JSON's encoding), but Core-derived clients compare the header for equality
  rather than parsing it, so the suffix reads as a non-JSON response. Core's own
  test client rejected every satd reply without reading the body.
- **`-28 RPC in warmup` during startup.** While coming up, Core answers every
  RPC with `-28` and a status line; that is how a client learns "alive, retry
  shortly". satd's startup listener answered `-32601 Method not found` for
  anything but its own progress method, which a Core-compatible client reads as
  a permanent failure.
- **Core options on the command line.** satd skipped
  recognized-but-unsupported Core options in `bitcoin.conf` with a warning, but
  the same option passed as a flag aborted startup. Core treats the two as one
  namespace; satd now does too, while still rejecting genuine typos.
- **Single-dash spelling for satd's own flags.** Core spells every option with
  a single dash. satd's compatibility table had drifted from its parser, so 56
  flags — including Core's own `-blockfilterindex` and `-peerblockfilters` —
  were reachable only as `--double-dash`. The set is now derived from the
  parser, so a new flag cannot fall out of reach.
- **`-version` and unknown-argument errors.** satd's `-version` output did not
  contain the word "version", and a bad flag was not reported in Core's
  wording.
- **Core's fee-rate units.** Core denominates `-minrelaytxfee` and
  `-dustrelayfee` in BTC/kvB (`0.00001`); satd documents them in sat/kvB
  (`1000`) — the same rate, written differently. satd now takes both. An
  unparseable value used to be *silently discarded* in `bitcoin.conf`, leaving
  the node relaying at a default the operator never chose; it is now an error.
- **`-blockfilterindex` with no value**, which Core accepts as `basic`.
- **A panic on an unparseable `-bind`.** satd joined `-bind` to `-port` and
  unwrapped, so a value it could not parse aborted on a stack trace rather than
  an error. Underneath that, IPv6 literals were never bracketed, so `-bind=::1`
  could not have worked at all.

None of these were consensus defects, and none would have shown up in satd's
own test suite — they are exactly the class of difference that only an
outside-in client finds.

## Running it yourself

```sh
cd contrib/core-functional
./fetch-core.sh          # fetch the pinned Core tree
cargo build --release --bin satd --bin sat-cli   # from the repo root
./run.sh                 # run the inventory's run-set
./run.sh --candidate <test.py>   # measure a still-skipped test after a fix
```

Nothing in the harness assumes a particular machine: the satd binaries, the
Core checkout location, the scratch directory and the job count are all
environment overrides, documented in `contrib/core-functional/README.md`.

## In CI

The run set gates every pull request. The build is the only slow part of it,
and it is shared: the `core-functional` job downloads the same release binaries
the third-party canary fleet uses, so the suite adds about a minute and sits off
the critical path. A red run set blocks the merge.

A second, nightly run on a dedicated runner is where the run set gets widened
and where a `--candidate` measurement runs unattended. That one is not reachable
from a pull request, because it builds and executes the branch under test.

The split matters: for a while the suite ran only nightly, so a test could be
marked `run` in one pull request and quietly stop passing in the next, with the
published scoreboard still claiming it. That is not hypothetical -- it is how
the count came to read 30 while four of those thirty were failing.
