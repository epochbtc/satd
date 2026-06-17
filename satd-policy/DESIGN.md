# satd-policy — Design & Rationale

This is the design document for satd's transaction-filtering policy DSL: the
`satd-policy` crate (the language engine) and its node integration (the
quarantine mempool, reload, and observability surfaces in `node/`).

It is the **contributor-facing companion** to the operator chapter in the
Operator Manual (`docs/manual/src/policy.md`). The manual tells an operator how
to *use* policy; this document explains how it is *built* and *why*. The code is
densely annotated with references like `// §6.1` and `// I9` — the
[Design-reference index](#design-reference-index) and the
[Invariants](#invariants) section below are what those tags resolve to. Keep the
section numbers stable: they are a contract with the comments.

---

## 1. The problem and the stance

Operators sometimes want to decline to *help* certain transaction shapes — bulk
data, dust storms, content inscriptions — propagate or get mined by their node.
Bitcoin Core expresses a fixed set of such preferences in C++ relay policy;
changing them means a patch and a rebuild. The demand is for something
configurable.

The danger is that a configurable filter invites two mistakes: (1) treating
filtering as *control* over what confirms, and (2) doing collateral damage —
to one's own node, and to the network — in pursuit of an illusion. The design is
shaped end-to-end by refusing both.

Three stances follow, and they explain almost every decision downstream:

- **Quarantine, never reject.** Policy can *withhold assistance* (don't relay,
  don't mine) but can never make the node reject a transaction baseline policy
  would accept. There is no `Reject` verdict. Consensus and validity are
  untouched by construction ([I1](#invariants)). This makes every policy
  judgment **reversible** and **lossless** — a too-broad rule is survivable and
  fixable with one `SIGHUP`, not an irreversible drop.

- **The ceiling is acknowledged, not hidden.** Filtering cannot prevent
  confirmation; a shape with real economic demand confirms via other relay paths
  or direct miner submission. The observability surfaces exist specifically so
  an operator can *watch filtered transactions confirm anyway* (the
  "confirmed-anyway" stream). Policy is an operator preference, not a censorship
  primitive — and the tool is built to keep proving that to its user.

- **A total, bounded language — not a scripting runtime.** The filter predicate
  is a small, statically-typed, non-Turing-complete expression language that is
  **total** (every operator defined on every input,
  [I4](#invariants)) and carries a **static worst-case cost** so the loader can
  reject anything that could slow the admission path *before* a single
  transaction is evaluated ([I5](#invariants)). It cannot loop, cannot allocate
  unboundedly, cannot panic, and cannot do I/O.

---

## 2. Architecture at a glance

Two layers, deliberately separated:

```
┌─────────────────────────────────────────────────────────────┐
│ satd-policy crate  (pure, no node deps, no I/O)              │
│   lexer → parser → typecheck → cost → eval                  │
│   ruleset layer: version gate, first-match-wins, scopes      │
│   advisory lint (L2-shape warnings), explain (plain English) │
│   operates over a BORROWED TxView / Ctx the node fills in     │
└─────────────────────────────────────────────────────────────┘
                              ▲  Verdict { Pass | Allow | Quarantine{scope} }
                              │
┌─────────────────────────────────────────────────────────────┐
│ node integration  (node/src/mempool, node/src/rpc, metrics)  │
│   the single eval point in accept_transaction                │
│   QuarantineScope mempool: acting class vs quarantine class   │
│   three-consumer split (relay / template / union)            │
│   SIGHUP reload + lossless re-placement                      │
│   observability RPCs, MCP tools, Prometheus, events          │
└─────────────────────────────────────────────────────────────┘
```

The crate knows nothing about mempools, RocksDB, or RPC. It parses, typechecks,
statically costs, and evaluates an expression against a `view::TxView` /
`view::Ctx` that the node populates. Everything that requires consensus
knowledge (dust thresholds, fee-rate semantics, script classification, prevout
resolution) is computed **once by the node** at the evaluation point and handed
to the engine as plain data. This keeps the language total and testable in
isolation, and keeps a single authoritative definition of each derived fact.

The same engine backs three surfaces — admission policy, block-template policy,
and (planned) streaming subscription filters — which is why it is a standalone
crate rather than a module inside `node`.

---

## 3. The expression engine

### 3.1 Pipeline (`§4`)

`parse` → `typecheck` → `cost` → `eval`. `compile()` runs the first three and
returns a `CompiledExpr` carrying its AST, type, and worst-case `Cost`.
`parse_ruleset()` does the same for a whole policy file, yielding a
`CompiledRuleset`.

- **Lexer / parser (`§4.5`)** — hand-rolled, dependency-free, total over any
  input. The parser is **depth-capped** at every recursive production (not just
  the top-level one) to make deeply-nested input a load-time error rather than a
  native stack overflow. `script(…)` patterns enforce a token limit.
- **Typechecker (`§4.2`)** — every type error is a load-time error with a
  file/line/column span. No implicit conversions; enums compare only within
  their own kind. Types: `Bool`, `Int` (i128, saturating), `Bytes` (plain and
  script-interpretable), and closed enums (`ScriptType`, `Source`, `Network`).
  Quantifier binders (`in` / `out`) are valid only inside their matching
  `any/all/count … inputs/outputs` quantifier; no nesting in v1.
- **Views (`§4.3`)** — `TxView` (inputs, outputs, fees, source) and `Ctx`
  (network, height, mempool bytes, relay fees) are *borrowed* over the node's
  data. The node fills them in at the single eval point.

### 3.2 Totality and the cost/fuel split (`§7`, [I4](#invariants)/[I5](#invariants))

The headline property is **totality**: `eval` returns a `Value`, never a
`Result`. Division/modulo by zero return `0`; there is no indexing, no parsing,
no allocation that scales with input. The only non-local outcome is **fuel
exhaustion**, reported as a flag, not an error.

There are **two decoupled bounds**, and conflating them is the classic mistake:

| Bound | When | Constant | Purpose |
|---|---|---|---|
| **Static cost** | load time | `POLICY_BUDGET = 256_000_000` | Reject an absurdly expensive *ruleset* before it ever runs. This is what protects the admission path's latency. |
| **Runtime fuel** | per transaction | `DEFAULT_FUEL = 8_000_000` | A per-evaluation wall, decremented per AST node and per scanned byte, calibrated to ~100µs on Pi-class hardware. |

Static cost is split across three axes so the bound is sound: `flat` (per
quantifier element), `scan` (one pass, bounded by transaction size — *not* by
element count × scan), and `scan_elem` (per element drawn from the UTXO set).
Because `POLICY_BUDGET` already bounds ruleset complexity, fuel exhaustion is
*unreachable* for a budget-respecting ruleset on a normally-sized transaction —
if `__fuel` ever fires in production it signals a bug or a pathological input,
and the fail-safe (below) keeps it safe meanwhile. The constants are
fleet-calibration defaults pending the dogfood bench (`§14`).

---

## 4. The policy-file layer

### 4.1 Grammar and first-match-wins (`§5`)

A policy file is a `version 1` declaration followed by rules:

```
quarantine <name> [on <scope>] when <condition>
allow      <name>            when <condition>
```

Rules evaluate top-to-bottom, **first match wins** — the first rule whose
condition is true decides the verdict; later rules are never reached. Unnamed
rules are auto-named (`r-<sha8>`). Loading is **strict**: an unknown key, a type
error, or an over-budget cost is a hard load error, never warn-and-continue.

### 4.2 `allow` vs `quarantine`, and the asymmetry (`§2.6`)

The verdict type has no `Reject` (`§2.6`):

- **`Pass`** — no rule matched; baseline policy decides; transaction is *acting*.
- **`Allow { rule }`** — an `allow` rule matched; the transaction is exempt from
  the *standardness set* and shielded from all later `quarantine` rules. Acting.
- **`Quarantine { rule, scope }`** — a `quarantine` rule matched; held in the
  quarantine class along `scope`.

`allow` is deliberately **capped to the standardness set** — it can forgive
relay standardness checks, never consensus. This makes the tool **asymmetric**:
`quarantine` is unbounded, `allow` is bounded. At scale that means policy can
only ratchet *more* restrictive, never invent new permissiveness. We document
this rather than disputing it; it is a real property of the design.

`allow` is the tool for "this whole transaction is mine/trusted." For "spare
this one output class," the right tool is a condition *inside* the matching
expression (e.g. `… and out.script_type != p2a`), not a blanket `allow` —
because `allow` shields the *entire* transaction from every later rule.

### 4.3 Advisory lint (`§2.5`)

`policylint` (in the crate's `advisory` module) emits an **advisory — never
blocking** warning when a `quarantine` rule plausibly matches time-sensitive
Lightning/L2 shapes (anchor outputs, justice-transaction patterns, witness-size
caps low enough to catch unilateral closes). It never inspects `allow` rules and
carries zero admission weight. Its purpose is to make the most dangerous class
of mistake — silently degrading L2 enforcement — visible before deployment.
`explain` renders each rule in plain English for the same auditing reason.

---

## 5. The quarantine data model

### 5.1 `QuarantineScope` (`§3`)

Every mempool entry carries a `QuarantineScope { relay: bool, template: bool }`.
**A set bit means the transaction is *withheld* along that axis** (this polarity
matters — read it carefully):

| Helper | Meaning |
|---|---|
| `is_acting()` | both bits clear — fully assisted, relayed *and* mineable |
| `is_quarantined()` | either bit set |
| `assists_relay()` | `relay` bit **clear** — this tx still participates in relay |
| `assists_template()` | `template` bit **clear** — this tx is still mineable here |

An *acting* entry (`is_acting()`) behaves exactly like a transaction in a node
without this feature. The **quarantine class** lives in the *same physical
mempool* — held, not dropped — with its own byte budget (`quarantinemempool`,
default 50 MB ≈ ⅙ of the acting mempool, `§13`), accounted and fee-rate-evicted
separately so neither class can crowd the other out.

### 5.2 Infectious propagation (`§3` / `§7`)

A transaction inherits the **union** of its quarantined in-mempool ancestors'
scopes. The node will not announce or mine a child whose parent it is
withholding. A consequence worth stating: an *acting* transaction can never have
a quarantined ancestor (it would have inherited the scope), though it can have a
quarantined *descendant*. Re-placement (below) recomputes this in topological
order so a parent's new scope is visible before its children are evaluated.

---

## 6. The three-consumer split (`§2.4`)

This is the heart of the integration's correctness, and the easiest place to
introduce a silent bug. Mempool consumers fall into exactly three categories,
each of which must read a **different view**:

| Consumer | View | Filter |
|---|---|---|
| **Relay paths** — inv/announce, BIP35 `mempool`, `getdata`, rebroadcast, announce-to-new-peer | per-entry | `assists_relay()` |
| **Template + fee** — block-template selection, smart-fee simulator | `get_template_entries()` | `assists_template()` |
| **Union** — compact-block (BIP152) reconstruction, `mempool.dat` persistence, quarantine-aware observability | `get_all_entries()` | none |

The rationale per row:

- **Relay** filters on `assists_relay` so a `relay`-withheld tx is never put on
  the wire, yet is still *tracked* for later lossless promotion.
- **Template/fee** filters on `assists_template` so a tx quarantined `on
  template` is neither mined by this node *nor* counted by fee estimation —
  otherwise a "don't mine this" rule would silently inflate the fees the node
  quotes to wallets.
- **Union** must see everything: compact-block reconstruction needs every
  physically-present tx (so quarantine costs *no* extra `getblocktxn` round-trip
  — only budget *eviction* does), and persistence must round-trip the full pool.

Mixing these views is a correctness bug, not a style nit. The standard
read surfaces are a fourth case, covered next.

---

## 7. Invisibility and observability (`§6.1`, `§10`)

### 7.1 Standard surfaces show the acting class only (`§6.1`)

Every Core-compatible read surface — `getrawmempool`, `getmempoolinfo`,
`getmempoolentry`, `getrawtransaction`'s mempool branch, Electrum, Esplora, the
address/history indexes, and the standard MCP mempool tools — presents the
**acting class only**. To a Core-compatible client, a quarantining node is
byte-for-byte indistinguishable from one whose relay policy simply refused the
transaction. Quarantine never leaks into a Core-compatible response. This is
verified by **differential tests** that assert each surface is byte-identical
whether the quarantine class is occupied or empty — the same property
[I8](#invariants) guarantees for a node with *no* policy at all.

A locally-submitted transaction that draws a *relay*-scope verdict is **refused
at submission with the rule named** (rather than silently held), so an operator
never has an invisible own-transaction. `allowquarantined=true` overrides to hold
it anyway; `P2p` and `Reload` sources are never refused.

### 7.2 Dedicated observability surfaces (`§10`)

The quarantine class is exposed *only* through purpose-built surfaces, because
the whole point is that policy consequences are visible and measurable:

| RPC / surface | Purpose |
|---|---|
| `getpolicyinfo` | ruleset path/sha256/version, per-rule match counters, fuel-backstop count, quarantine totals |
| `getquarantineinfo` | per-rule rollup (count/bytes/fee-rate span), **confirmed-anyway** count (the ceiling, in data), **foregone-fees** estimate |
| `listquarantine [rule] [count] [skip]` | paged list of the quarantine class |
| `getquarantineentry <txid>` | the `getmempoolentry` analogue for a held tx |
| `policytest <rawtx-hex>` | dry-run against the live ruleset: per-rule trace (matched/decisive), verdict, and resulting placement — the `testmempoolaccept` of policy |
| MCP tools | `get_policy_info` / `get_quarantine_info` / `list_quarantine` / `get_quarantine_entry` mirror the RPCs |
| Prometheus | `satd_policy_*` counters and gauges; **silent until a ruleset loads** ([I8](#invariants)) |

Quarantine lifecycle is also surfaced as events on a **separate channel** from
the default mempool stream (which reflects the acting class only): the
`QuarantineEvent` enum has `Quarantined` (admission-time placement), `Demoted` (a
reload moved a tx into, or to a different held scope within, the quarantine
class), and `Promoted` (a reload **fully** cleared the scope — acting again). The
strict `Promoted`-means-fully-cleared contract is load-bearing for subscribers
and is enforced at the emit site.

---

## 8. Reload and lossless re-placement (`§8`, [I7](#invariants)/[I9](#invariants))

`policyfile=<absolute-path>` points the node at a policy file. Startup load is
**fatal on error** (fail-loud). The file is **live-reloadable on `SIGHUP`** using
the `TokenStore` precedent: the external file's *contents* are re-read on every
signal (even if the path is unchanged), recompiled, and swapped atomically behind
an `ArcSwap`. A reload that fails to compile keeps the **last-good** ruleset and
returns the error to log — never a partial apply ([I7](#invariants)). A no-op
reload (same `sha256`) skips the re-placement walk entirely.

A successful change drives `Mempool::reapply_policy()`, which walks the pool
**parents-before-children** (Kahn topological order), re-resolves each
transaction's prevouts exactly as admission does, re-evaluates the ruleset,
unions in the direct parents' freshly-recomputed scopes (infectious), and moves
each entry between classes with correct per-class byte accounting.

Re-placement is **lossless** ([I9](#invariants)): it changes *placement only*,
never validity, and **standardness is never re-litigated**. The only removal is
the destination class's ordinary budget eviction *after* the moves — and an
evicted transaction is reported solely as `LeaveEvicted`, filtered out of the
promoted/demoted transition lists so a tx that left the pool is never
re-announced or surfaced as `Promoted`. Removing a rule (or removing `policyfile`
and reloading) promotes everything it held straight back to acting without
re-hearing anything from the network. Re-announcement of promoted transactions is
handled by a **bounded promotion queue** (token-bucket drained per tick,
IBD-suppressed) so a large promotion can't burst the wire.

---

## 9. Deferred standardness (`§6.2`)

When (and only when) a ruleset contains at least one `allow` rule, a standardness
failure (non-standard output, oversize, dust, OP_RETURN limits) is **deferred**
and resolved at the eval point: `Allow` forgives it (the tx enters the acting
class); `Pass`/`Quarantine` let the baseline rejection stand. With no `allow`
rules present, standardness failures reject early exactly as today. This ordering
lets an `allow` rule key on prevout-derived attributes that aren't known until
after input resolution, without weakening the default path. Consensus checks are
never deferrable — they are not in the exemptable set.

---

## Invariants

The tags the code cites. These are the load-bearing guarantees; a change that
violates one is a bug even if tests pass.

- **I1 — Consensus/validity is never affected.** Policy only changes relay and
  template *assistance*. A block containing a quarantined transaction validates
  and connects normally. Every other invariant serves this one. (In code, cited
  as the corollary that consensus-critical paths like compact-block
  reconstruction must read the *union*, never a filtered view — see `§2.4`.)
- **I4 — Totality / determinism.** `eval` returns a `Value`, never fails; every
  operator is defined on every input of its type (saturating arithmetic, no
  indexing, no parsing). Fuel exhaustion is a flag, not an error. (`satd-policy/src/eval.rs`)
- **I5 — Static cost bound.** Every `CompiledExpr`/`CompiledRuleset` carries a
  worst-case cost; the loader rejects anything over `POLICY_BUDGET`. Admission
  latency is bounded before any transaction is seen. (`satd-policy/src/cost.rs`)
- **I7 — Last-good-wins reload.** A failed recompile keeps the previous ruleset
  untouched and logs the error — never a partial apply. (`node/src/mempool/pool.rs`,
  `reload_policy_file`)
- **I8 — No-policy byte equivalence.** With no ruleset loaded (or an empty
  `version 1` ruleset), the admission hot path, every standard surface, and
  `/metrics` are byte-identical to a build with the engine compiled out.
  `has_policy()` gates this. (`node/src/mempool/pool.rs`, `node/src/metrics.rs`)
- **I9 — Lossless re-placement.** A reload re-evaluates and re-places every
  resident transaction; nothing is dropped except by the destination class's
  ordinary budget eviction. Placement changes never affect validity.
  (`node/src/mempool/pool.rs`, `reapply_policy`)

---

## Design-reference index

What each `§N` tag in the code means. Section numbers are stable so the inline
comments resolve here.

| § | Topic |
|---|---|
| §2.4 | The three-consumer split — relay (`assists_relay`) vs template+fee (`assists_template`) vs union; mixing views is a bug |
| §2.5 | L2-shape advisory lint — never blocking; warns when a rule may match Lightning/L2 shapes |
| §2.6 | Verdict model — `Pass` / `Allow` / `Quarantine`, deliberately **no** `Reject` |
| §3 | Quarantine scopes (`relay`/`template`, set = withheld) and infectious descendant propagation |
| §4 | The expression pipeline overview (parse → typecheck → cost → eval) |
| §4.2 | Static typechecker — load-time errors with spans, closed enums, binder rules |
| §4.3 | Borrowed `TxView` / `Ctx`; the node fills in everything consensus-derived |
| §4.4 | Total, fuel-metered evaluator; `__fuel` fail-safe full-scope quarantine |
| §4.5 | Hand-rolled lexer + depth-capped recursive-descent parser |
| §5 | Policy-file layer — grammar, scopes, auto-naming, strict loading, first-match-wins |
| §6 / §6.1 | Quarantine visibility — standard surfaces present the **acting class only** |
| §6.2 | Deferred standardness — `allow` can forgive standardness, resolved at the eval point |
| §6.3 | RBF / whitelisted-peer / forcerelay interaction (policy never overrides forcerelay) |
| §7 | Static cost model vs runtime fuel (the two decoupled bounds) |
| §8 | Live SIGHUP reload + lossless topological re-placement |
| §10 | Observability RPCs, MCP tools, Prometheus metrics, quarantine event channel |
| §13 | Quarantine-class budget; the Tier-2 / `version 2` fast-follow boundary |
| §14 | Cost-constant calibration precondition (dogfood-fleet bench) |
| §17 | Worked cookbook examples (also exercised as integration tests) |

---

## Version 1 / Tier-2 boundary (`§13`)

The shipped language is **version 1** and is the stability contract. The Tier-2
byte transforms — `rc4`, `sha256`, `reverse`, plus `tx.first_input_txid` and
`out.op_return_data` — are a deliberate **`version 2` fast-follow** and are *not*
implemented here. A policy file must declare `version 2` to use them once they
land; `version 1` files are unaffected.

---

## Key types and entry points

For a contributor finding their way in:

**Engine (`satd-policy/`)**
- `lib.rs` — `compile()`, `CompiledExpr`; crate-level invariant docs
- `ruleset.rs` — `parse_ruleset()`, `CompiledRuleset` (`evaluate`,
  `evaluate_trace`), `Rule`, `Action`, `RuleTrace`
- `verdict.rs` — `Verdict { Pass, Allow, Quarantine }`, `ScopeSet`
- `view.rs` — `TxView`, `InputView`, `OutputView`, `Ctx` (what the node fills in)
- `eval.rs` / `cost.rs` / `typeck.rs` / `parser.rs` / `lexer.rs` — the pipeline
- `advisory.rs` / `explain.rs` — `policylint` support
- `scope.rs` — the in-language scope set

**Node integration (`node/`)**
- `mempool/policy_engine.rs` — `load_policy_file()`, `evaluate()`,
  `evaluate_trace()`, `with_view()`; the bridge that builds `TxView`/`Ctx`
- `mempool/pool.rs` — `QuarantineScope`, the acting/quarantine classes,
  `get_acting_entries()` / `get_template_entries()` / `get_all_entries()`,
  `accept_transaction()` (the single eval point), `reload_policy_file()`,
  `reapply_policy()`, `clear_policy()`, `has_policy()`
- `mempool/events.rs` — `QuarantineEvent { Quarantined, Demoted, Promoted }`
- `rpc/policy.rs` — `getpolicyinfo`, `getquarantineinfo`, `listquarantine`,
  `getquarantineentry`, `policytest`
- `metrics.rs` — `render_policy_metrics()` (gated on `has_policy()`)

---

## See also

- **Operator Manual — Transaction-Filtering Policy** (`docs/manual/src/policy.md`,
  published at <https://epochbtc.github.io/satd/>): the operator-facing guide —
  the quarantine model in practice, configuration, the cookbook, and the
  node-local / network-scale consequences (E1–E3) stated in full.
- `contrib/policy/example.policy` — a posture-balanced, `policylint`-verified
  example ruleset.
