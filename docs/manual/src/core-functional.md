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
leans on two test-only facilities satd does not implement, `setmocktime` and
`syncwithvalidationinterfacequeue`, and between them they account for 119 of the
262 skipped rows. Every skip records what actually blocked it, so the queue of
work is explicit rather than a guess; `contrib/core-functional/README.md` ranks
it.

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

None of these were consensus defects, and none would have shown up in satd's
own test suite — they are exactly the class of difference that only an
outside-in client finds.

## Running it yourself

```sh
cd contrib/core-functional
./fetch-core.sh          # fetch the pinned Core tree
cargo build --release --bin satd --bin sat-cli   # from the repo root
./run.sh                 # run the inventory's run-set
```

Nothing in the harness assumes a particular machine: the satd binaries, the
Core checkout location, the scratch directory and the job count are all
environment overrides, documented in `contrib/core-functional/README.md`.
