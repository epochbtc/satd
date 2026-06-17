# Transaction-Filtering Policy

satd ships an optional, total, statically-cost-bounded **transaction-filtering
policy language**. It lets an operator describe transaction shapes to *withhold*
— from relay, from block templates, or both — without ever changing what the
node will *accept* as valid.

> **The one sentence to internalize first:**
> *Filtering cannot prevent confirmation; it can only decline to assist it.*

> This chapter is intended for operators. For the internal **design and rationale** —
> the architecture, the quarantine data model, the invariants, the cost/fuel
> system, and the reasoning behind the quarantine-only stance — see
> [`satd-policy/DESIGN.md`](https://github.com/epochbtc/satd/blob/master/satd-policy/DESIGN.md).

A transaction shape with real economic demand will confirm via other relay paths
or direct miner submission regardless of your policy. What policy gives you is a
local, reversible, fully-observable way to decline to *help* — and the
observability surfaces (below) let you watch filtered transactions confirm
anyway, block after block, in your own data. Understanding this ceiling is the
point: it is what keeps filtering an operator preference rather than an illusion
of control.

## The quarantine model

There is no `reject`. Every verdict is **quarantine** (hold the transaction back
along a scope) or **allow** (an explicit exemption); a transaction that matches
no rule is simply *acting* — relayed and mineable, exactly as today.

- **Acting class** — fully assisted: relayed to peers, served on request,
  selected into block templates, visible on every standard surface.
- **Quarantine class** — held in the same physical mempool, but withheld along
  a **scope**:
  - `relay` — not announced, not served, not in BIP35 `mempool` replies, not
    rebroadcast. (Still held, so it can be promoted later losslessly.)
  - `template` — not selected into block templates and not counted by fee
    estimation, but **still relayed** ("relay neutrally, decline to mine").
  - both — withheld from everything (the default for a bare `quarantine`).

Consensus is untouched by construction: quarantine changes only relay and
template *assistance*, never validity. A block containing a quarantined
transaction still validates and connects normally.

### Rules, first-match-wins, and infectious propagation

A policy file is a `version 1` declaration followed by rules. Each rule is
`quarantine <name> [on <scope>] when <condition>` or `allow <name> when
<condition>`. Rules are evaluated top-to-bottom, **first match wins**, so put
exceptions first.

- `allow` is first-match-wins and shields a matching transaction from *all*
  later quarantine rules. It is the right tool for "this whole transaction is
  mine/trusted" and the *wrong* tool for "spare this one output class" — for
  narrow carve-outs, use a condition *inside* the matching expression instead
  (see the cookbook's `dust-storm` rule). `allow` is also capped to the
  standardness set: it can forgive standardness relay checks, never consensus.
- A transaction inherits the union of its quarantined in-mempool ancestors'
  scopes (**infectious propagation**): the node will not announce or mine a
  child whose parent it is withholding. This is automatic.

## Configuration and reload

Point the node at a policy file with `policyfile=/path/to/policy.txt` (config
file or `-policyfile` flag); the path must be **absolute**. On startup a bad file
is **fatal** (fail-loud).

The file is **live-reloadable on `SIGHUP`**: the contents are re-read and
recompiled on every signal (even if the path is unchanged), the whole mempool is
re-placed synchronously (promote/demote/evict), and promoted transactions are
re-announced on a bounded drain. A reload that fails to compile keeps the
**last-good** ruleset and logs the error — never a partial apply. Removing
`policyfile=` and reloading drops the engine entirely and promotes everything
back to acting. Re-placement only ever changes *placement*, never validity, so a
reload is lossless apart from ordinary budget eviction.

The quarantine class has its own byte budget, `quarantinemempool=<MB>`
(in **megabytes**, default 50), accounted and fee-rate-evicted separately from
the acting mempool so neither class can crowd the other out.

Validate a file offline before deploying it:

```sh
sat-cli policylint /path/to/policy.txt          # parse, typecheck, cost report
sat-cli policylint --explain /path/to/policy.txt # plain-English per rule
```

`policylint` also emits an **advisory** (never blocking) when a rule plausibly
matches time-sensitive Lightning/L2 shapes — anchor outputs, justice-transaction
patterns, witness-size caps low enough to catch unilateral closes. Heed it: an
overly broad shape filter can silently degrade L2 enforcement (see *Network-scale
effects*).

## Cookbook

These examples deliberately span **postures** — they are a demonstration of the
language, not a starter policy to deploy wholesale. The unifying discipline:
**filter on a self-identifying protocol marker or a distinctive economic shape,
never on a structural feature legitimate traffic also has.** Taproot
script-path spends, OP_RETURN, large witnesses, and dust are all used
legitimately; no rule below triggers on any of those alone.

```text
version 1

# ── Permissive: my own submissions are never filtered (allow, posture 1) ──
allow own-submissions when tx.source == rpc or tx.source == mcp

# ── Resource protection: cheap, oversized generic OP_RETURN (posture 2) ──
# NOT "OP_RETURN is bad" — bulk data that doesn't pay its way. Small markers
# (OpenTimestamps ~40B) and well-paying data both pass freely.
quarantine cheap-bulk-opreturn when
    any output (out.script_type == op_return and out.op_return_size > 83)
    and tx.fee_rate < node.min_relay_fee * 3

# ── Resource protection: dust storms, with L2 anchors carved out IN-PLACE ─
# The `!= p2a` carve-out lives inside the expression, not in an `allow`, so a
# real inscription that merely *has* a P2A output is not exempted wholesale.
quarantine dust-storm when
    count outputs (out.is_dust and out.script_type != p2a) >= 5

# ── Mine-neutral (template-only) big witness (posture 3) ─────────────────
# Relays like everyone else; just not in blocks I build. Zero relay impact,
# so a false positive can't degrade anyone's propagation.
quarantine no-mine-big-witness on template when
    tx.total_witness_size > 100kb

# ── Restrictive content quarantine: a self-identifying marker (posture 4) ─
# Keys on the protocol's own tapleaf marker, NOT on script-path spends in
# general, so Lightning/vault/MuSig tapscript spends are untouched.
quarantine ordinals when
    any input (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))
```

`sat-cli policylint --explain` will render each of these as a sentence; use it to
audit any ruleset handed to you.

### The ceiling — what precise filtering cannot reach

- **Secret-keyed obfuscation.** A marker keyed by something not on-chain is not
  matchable without the key; only structural/economic shape remains.
- **Migration to standard output types.** When a protocol moves to plain P2WSH
  it is byte-identical to legitimate P2WSH — filtering it means filtering all of
  it. Structural filters are a cat-and-mouse game with a hard collateral floor.
- **Untagged anchors** (e.g. some zk-proof anchors) expose no marker; the only
  handle is a structural template, whose precision equals its uniqueness.

Because every verdict is quarantine (not reject), a too-broad rule is
*survivable*: watch it accumulate legitimate traffic in quarantine and fix it
losslessly with one `SIGHUP`. Hard rejection would have made every such
judgment call irreversible and invisible.

## Observability

The quarantine class is the point: policy consequences must be *visible*. The
quarantine view appears **only** on the dedicated surfaces below — every standard
mempool surface (`getrawmempool`, `getmempoolinfo`, `getmempoolentry`, Electrum,
Esplora, the standard MCP mempool tools) presents the **acting class only**, so
to a Core-compatible client the node behaves exactly like one whose relay policy
refused the transaction. Quarantine never leaks into a Core-compatible response.

| Surface | What it tells you |
|---|---|
| `getpolicyinfo` | Ruleset path / sha256 / version, per-rule match counters since load, fuel-backstop count, quarantine-class totals. |
| `getquarantineinfo` | The comparison surface: per-rule rollup (count, bytes, fee-rate span), the **confirmed-anyway** count (quarantined txs later mined — D4's evidence stream), and a **foregone-fees** estimate (sat) — what declining to mine is costing you. |
| `listquarantine [rule] [count] [skip]` | The quarantine class as a paged list (txid, rule, scope, time, fee). |
| `getquarantineentry <txid>` | The `getmempoolentry` analogue for a held transaction. |
| `policytest <rawtx-hex>` | Dry-run a transaction against the live ruleset: per-rule trace (matched / decisive), the verdict, and the placement it would receive. The `testmempoolaccept` analogue for policy. |
| MCP tools | `get_policy_info`, `get_quarantine_info`, `list_quarantine`, `get_quarantine_entry` mirror the RPCs. |
| Prometheus | `satd_policy_evaluations_total`, `satd_policy_quarantined_total{rule,scope}`, `satd_policy_allows_total{rule}`, `satd_policy_fuel_exhausted_total`, `satd_policy_reload_failures_total`, `satd_policy_promoted_total` / `_demoted_total`, `satd_policy_quarantine_confirmed_total`, gauges for quarantine bytes/count/budget, and `satd_policy_foregone_fees_sat`. All silent until a ruleset loads. |

The standard surfaces and the metrics page are **byte-identical** whether or not
the quarantine class is occupied (verified by differential tests): a node with no
policy is indistinguishable from the same node before this feature existed.

## Node-local consequences

Quarantine-only filtering repairs most of the collateral damage filtering does to
your own node, but not all of it:

- **Compact-block relay is unaffected.** Quarantined transactions stay in the
  one physical pool, so BIP 152 reconstruction finds them with no extra
  round-trip. Only transactions *evicted* from the quarantine budget cost a
  `getblocktxn` — bounded by the budget, not by how aggressive your rules are.
- **Fee estimation is scope-correct.** The smart-fee simulator counts the
  template class only, so a tx you quarantine `on template` does not inflate the
  fees you quote to wallets.
- **Bandwidth.** Peers still INV you transactions you quarantine (no wire
  protocol expresses arbitrary predicates), but you download each once and
  *hold* it — no re-download churn. Only post-eviction re-announcements cost
  extra fetches.
- **Your own transactions.** A locally-submitted transaction that draws a
  *relay*-scope verdict is **refused at submission with the rule named**, rather
  than silently held — so you never have an invisible own-transaction. Use
  `allowquarantined=true` on the submit call to override and hold it anyway;
  `getquarantineentry` is then authoritative for it.

## Network-scale effects

At the consensus layer, this changes nothing: a filtering supermajority of nodes
and miners still cannot orphan a block containing a filtered transaction — any
valid transaction confirms eventually so long as some hashrate accepts it. But
Bitcoin's *practical* guarantees emerge from relay-layer behavior, and wide
adoption of a filtering DSL changes three real things. We publish the strongest
case against wide filtering alongside the tool:

- **E1 — Propagation predictability is load-bearing for L2 security.**
  Lightning enforcement (justice transactions, force-close + anchor CPFP)
  assumes a sufficiently-fee'd transaction percolates to hashrate before a
  timelock expires. That rests on relay-policy *homogeneity*. A popular
  copy-paste ruleset whose witness-size cap or anchor rule happens to match
  force-close or penalty transactions can silently degrade L2 enforcement
  network-wide — and the user whose justice transaction never confirms does not
  learn why. This is the critique to take most seriously.
- **E2 — Policy-change friction was an unintentional stabilizer.** Today, mass
  policy shift needs a Core release or an implementation switch. A DSL plus a
  viral gist converts policy into a fast, memetic equilibrium with less review
  than a Core PR. (Zero-conf acceptance died via the full-RBF *policy* rollout,
  no consensus change required.)
- **E3 — Effective filtering feeds the miner-direct-submission loop.** Every
  shape that stops propagating over p2p creates demand for out-of-band channels
  (accelerators, direct miner APIs), shifting power to identified, pressure-able
  miner endpoints — weaker censorship resistance where it actually binds, worse
  submission privacy, a moat for large miners.

**Caveat on the quarantine model:** from *peers'* perspective, a
quarantining node and a hard-rejecting node are indistinguishable — neither
propagates the transaction — so E1–E3 are **not** softened by the quarantine-only
design. What quarantine changes is the *local* picture: collateral damage to your
node is repaired, and policy consequences become visible and reversible. The
filtering capability itself is exactly as strong as a hard reject.

Two structural observations, acknowledged rather than disputed: the tool is
**asymmetric** (`quarantine` is unbounded; `allow` is capped at standardness), so
at scale it is a ratchet toward *more* restrictive relay, never more permissive;
and **shipped examples become defaults**, so the cookbook above is deliberately
posture-balanced rather than an anti-data starter kit.
