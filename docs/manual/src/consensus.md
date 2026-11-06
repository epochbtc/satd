# Consensus Engines & Shadow Verification

satd ships two independent script-verification engines: Bitcoin Core's C++
script interpreter, built from Core's source through `libbitcoinkernel`, and a
from-scratch Rust verifier. By default it runs both and verifies every script
twice: one engine decides, the other checks it in the background. Bitcoin Core
has no equivalent.

## Choosing an engine: `-consensus`

Read a mode name as "which engine is the shadow". In `<engine>-shadow`, the
named engine is the shadow, the one that only checks. The other engine is
primary; its verdict is what the node acts on. The shadow re-verifies the same
scripts in the background and logs any disagreement. So:

- `cpp-shadow`: the C++ engine is the shadow; Rust is primary.
- `rust-shadow`: the Rust engine is the shadow; C++ is primary.

| `-consensus=` | Primary (decides) | Shadow (checks, logs mismatches) |
|---|---|---|
| `cpp-shadow` (default) | Rust | C++ (`libbitcoinkernel`) |
| `rust-shadow` | C++ (`libbitcoinkernel`) | Rust |
| `rust` | Rust | none (single engine) |
| `cpp` | C++ (`libbitcoinkernel`) | none (single engine) |

The option takes effect at startup and can be set on the command line or in
`bitcoin.conf`. An unknown value prints a warning and falls back to the
default.

## Why the Rust engine is primary

The Rust engine passes Bitcoin Core's script test suite. Shadow verification
against Core's C++ interpreter across the whole mainnet chain, genesis to about
height 945,000, found zero divergence. It has then run as the primary engine,
with the C++ engine shadowing it, under sustained production use on mainnet,
signet and testnet4 for months, again with no divergence.

The two engines verify at about the same speed. Signature checks dominate the
cost, and both use libsecp256k1 for them. On the benchmarks in
`consensus/benches`, which verify the same inputs with both engines on one
thread, they are within a few percent of each other on every input of
mainnet block 300,000 and on the SegWit v0 and Taproot cases.

Both engines hash a transaction's signature data once and reuse it for every
input, as Core's own `CheckInputScripts` does. (Up to 0.7.x the C++ engine was
`libbitcoinconsensus`, whose API made it redo that work for every input, so a
transaction with many inputs cost time quadratic in their number.)

Up to 0.7.x the default was `rust-shadow`, with the C++ engine primary. 0.8.0
makes `cpp-shadow` the default. Either way both engines run, and the property
that matters most is unchanged: two independently written engines check each
other on every script. To keep Core's interpreter as the deciding engine, set
`-consensus=rust-shadow`.

Treat the single-engine modes with care. Both engines are proven, but either
one alone gives up the cross-check. satd logs a caution at startup when `rust`
or `cpp` is selected.

## Tuning the shadow engine

The shadow engine runs on a bounded background worker pool, so it consumes
spare CPU without slowing block connection. Three flags tune it:

- `-shadowworkers=<n>` (default 4): background shadow-verification threads.
  When it is unset, a positive `-par` is used instead.
- `-shadowqueuesize=<n>` (default 4194304): the most transactions the shadow
  work queue holds.
- `-shadowqueuemb=<n>` (default 128): the most memory, in MiB, the queued
  work may hold. Each queued transaction holds its serialized bytes and a copy
  of every output it spends. On a host with few cores the shadow engine can
  fall behind the primary for hours during IBD, and this budget, not the
  entry count, is what keeps the queue from growing into the process's memory
  limit. `0` removes the byte bound and leaves only `-shadowqueuesize`.

When either bound is reached, shadow work is dropped, and an aggregated WARN
is logged at most once per 5 s with the queue's depth and bytes. The primary
engine still verifies every script, so correctness is unaffected. Frequent
drops mean the shadow engine cannot keep up on this host; `-consensus=rust` or
`-consensus=cpp` runs a single engine.

## Where the engine is used

The engines selected by `-consensus` verify scripts at block connection, at
mempool acceptance, and in the full check of a [Stratum](stratum.md) block
template. The signet block solution is the exception: it is always checked by
the C++ engine.

> **Difference from Bitcoin Core.** Core has a single C++ engine and no shadow
> mode. satd's default runs both engines at once, with the Rust engine
> deciding. `-consensus`, `-shadowworkers`, `-shadowqueuesize` and
> `-shadowqueuemb` are satd-specific.
