# Transaction-Filtering Policy

satd ships an optional **transaction-filtering policy language**, total and
statically cost-bounded. It lets an operator describe transaction shapes to
withhold: from relay, from block templates, or both. It never changes what the
node accepts as valid.

The principle to understand first: filtering cannot prevent confirmation; it
can only decline to assist it.

> **Note.** This chapter is for operators. For the architecture, the quarantine
> data model, the invariants, the cost and fuel system, and the reasoning
> behind the quarantine-only stance, see
> [`satd-policy/DESIGN.md`](https://github.com/epochbtc/satd/blob/master/satd-policy/DESIGN.md).

A transaction shape with real economic demand will confirm through other relay
paths or direct miner submission, whatever your policy says. Policy gives you a
local, reversible, observable way to decline to help. The observability
surfaces below let you watch filtered transactions confirm anyway, block after
block, in your own data. That ceiling is what keeps filtering an operator
preference rather than an illusion of control.

## The quarantine model

There is no `reject`. Every verdict is **quarantine** (hold the transaction
back along a scope) or **allow** (an explicit exemption). A transaction that
matches no rule is **acting**: relayed and mineable, exactly as without a
policy.

- **Acting class**: fully assisted. Relayed to peers, served on request,
  selected into block templates, and visible on every standard surface.
- **Quarantine class**: held in the same physical mempool but withheld along a
  **scope**:
  - `relay`: not announced, not served, not in BIP35 `mempool` replies, not
    rebroadcast. The transaction is still held, so it can be promoted later
    without loss.
  - `template`: not selected into block templates and not counted by fee
    estimation, but still relayed. This scope means "relay neutrally, decline
    to mine."
  - both: withheld from everything. A bare `quarantine` defaults to this.

Consensus is untouched by construction: quarantine changes relay and template
assistance, never validity. A block containing a quarantined transaction still
validates and connects normally.

### Rules, first-match-wins, and infectious propagation

A policy file is a `version 1` declaration followed by rules. Each rule is
`quarantine <name> [on <scope>] when <condition>` or `allow <name> when
<condition>`. Rules are evaluated top to bottom and the first match wins. Put
exceptions first.

- `allow` shields a matching transaction from all later quarantine rules. Use
  it when the whole transaction is yours or trusted. For a narrow carve-out
  ("spare this one output class"), put a condition inside the matching
  expression instead; see the cookbook's `dust-storm` rule. `allow` is also
  capped to the standardness set: it can forgive standardness relay checks,
  never consensus.
- A transaction inherits the union of its quarantined in-mempool ancestors'
  scopes (**infectious propagation**): the node will not announce or mine a
  child whose parent it withholds. This is automatic.

## Configuration and reload

Point the node at a policy file with the `policyfile=/path/to/policy.txt`
config key or the `-policyfile` flag. The path must be absolute. On startup, a
bad file is fatal. A file that trips the Lightning-enforcement danger gate
(below) is also fatal, unless `allowdangerousfilters=1`.

The file is live-reloadable on `SIGHUP`. Every signal re-reads and recompiles
the contents, even if the path is unchanged. The whole mempool is then
re-placed synchronously (promote, demote, evict), and promoted transactions are
re-announced on a bounded drain. A reload that fails to compile keeps the
last-good ruleset and logs the error; there is never a partial apply. To drop
the engine entirely and promote everything back to acting, remove `policyfile=`
and reload. Re-placement changes only placement, never validity, so a reload is
lossless apart from ordinary budget eviction.

The quarantine class has its own byte budget, the `quarantinemempool=<MB>`
config key (megabytes, default 50). It is accounted and fee-rate-evicted
separately from the acting mempool, so neither class can crowd the other out.

Lint a policy file offline before you deploy it:

```sh
sat-cli policylint /path/to/policy.txt          # parse, typecheck, cost report
sat-cli policylint --explain /path/to/policy.txt # plain-English rendering per rule
```

`policylint` reports L2 safety in two tiers. The advisory tier never blocks;
silence it with `--no-advisories`. It flags rules that mention time-sensitive
Lightning and L2 shapes: anchor outputs, witness-size caps, `OP_CSV` and
`OP_CLTV`. The danger gate is stricter. It evaluates each rule against
synthetic Lightning enforcement transactions and reports the rules that quarantine
one. A rule that would withhold relay for an enforcement shape makes
`policylint` exit non-zero (code 3) and makes the node refuse to load the
policy. That refusal is the default. An `on template` match warns but does not
block, because the transaction still relays.

### The danger gate and `allowdangerousfilters`

The gate exists because a too-broad relay filter can degrade Lightning
enforcement network-wide (E1, below), and that failure is silent for the user
whose justice transaction never confirms. Detection mirrors the protocols.
BOLT-3 legacy and anchor enforcement scripts are spec-mandated, so they are
matched exactly. A taproot-channel key-path force-close is indistinguishable
from any P2TR key-path spend, so a rule broad enough to catch generic P2TR
keyspends is flagged as sweeping them. Taproot script-path enforcement reveals
a recognizable tapleaf.

To run such a rule deliberately, set `allowdangerousfilters=1` (config key or
flag). The rule then loads with a loud warning instead of being refused. The
gate does not make E1 go away: it cannot catch a rule that snags enforcement
through an angle the probes do not model, so the network-scale critique below
still stands. The gate removes the most common operator mistake. For a loaded
policy, `getpolicyinfo` reports a `danger` section with the findings and
whether they are allowed.

## Cookbook

These examples span postures on purpose. They demonstrate the language; they
are not a starter policy to deploy wholesale. They share one discipline: filter
on a self-identifying protocol marker or a distinctive economic shape, never on
a structural feature that legitimate traffic also has. Taproot script-path
spends, OP_RETURN, large witnesses, and dust all have legitimate uses, and no
rule below triggers on any of them alone.

```text
version 1

# ── Permissive: my own submissions are never filtered (allow, posture 1) ──
allow own-submissions when tx.source == rpc or tx.source == mcp

# ── Resource protection: cheap, oversized generic OP_RETURN (posture 2) ──
# Not "OP_RETURN is bad": bulk data that does not pay its way. Small markers
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
# Relays like everyone else; excluded only from blocks this node builds.
# Zero relay impact, so a false positive cannot degrade propagation.
quarantine no-mine-big-witness on template when
    tx.total_witness_size > 100kb

# ── Restrictive content quarantine: a self-identifying marker (posture 4) ─
# Keys on the protocol's own tapleaf marker, NOT on script-path spends in
# general, so Lightning/vault/MuSig tapscript spends are untouched.
quarantine ordinals when
    any input (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))
```

`sat-cli policylint --explain` renders each of these as a sentence. Use it to
audit any ruleset handed to you.

### The ceiling: what precise filtering cannot reach

- **Secret-keyed obfuscation.** A marker keyed by something not on-chain
  cannot be matched without the key; only structural and economic shape
  remains.
- **Migration to standard output types.** When a protocol moves to plain
  P2WSH, its transactions are byte-identical to legitimate P2WSH; filtering
  them means filtering all of it. A structural filter has to chase each move,
  and every move raises the collateral floor.
- **Untagged anchors.** Some anchors (zk-proof anchors, for example) expose no
  marker. The only handle is a structural template, whose precision equals its
  uniqueness.

Because every verdict is quarantine rather than reject, a too-broad rule is
survivable. Watch it accumulate legitimate traffic in quarantine, then fix it
losslessly with one `SIGHUP`. Hard rejection would have made every such
judgment call irreversible and invisible.

## Observability

The quarantine class exists to make policy consequences visible. The quarantine
view appears only on the dedicated surfaces below. Every standard mempool
surface (`getrawmempool`, `getmempoolinfo`, `getmempoolentry`, Electrum,
Esplora, the standard MCP mempool tools) presents the acting class only. To a
Core-compatible client, the node behaves exactly like one whose relay policy
refused the transaction. Quarantine never leaks into a Core-compatible
response.

| Surface | What it tells you |
|---|---|
| `getpolicyinfo` | Ruleset path, sha256, and version; per-rule match counters since load; fuel-backstop count; quarantine-class totals. |
| `getquarantineinfo` | The comparison surface: a per-rule rollup (count, bytes, fee-rate span), the confirmed-anyway count (quarantined transactions later mined), and a foregone-fees estimate in sat (what declining to mine is costing you). |
| `listquarantine [rule] [count] [skip]` | The quarantine class as a paged list (txid, rule, scope, time, fee). |
| `getquarantineentry <txid>` | The `getmempoolentry` analogue for a held transaction. |
| `policytest <rawtx-hex>` | Dry-runs a transaction against the live ruleset: a per-rule trace (matched, decisive), the verdict, and the placement it would receive. The `testmempoolaccept` analogue for policy. |
| MCP tools | `get_policy_info`, `get_quarantine_info`, `list_quarantine`, and `get_quarantine_entry` mirror the JSON-RPC methods. |
| Prometheus | `satd_policy_evaluations_total`, `satd_policy_quarantined_total{rule,scope}`, `satd_policy_allows_total{rule}`, `satd_policy_fuel_exhausted_total`, `satd_policy_reload_failures_total`, `satd_policy_promoted_total` / `_demoted_total`, `satd_policy_quarantine_confirmed_total`, gauges for quarantine bytes/count/budget, and `satd_policy_foregone_fees_sat`. All silent until a ruleset loads. |

Differential tests verify that the standard surfaces and the metrics page are
byte-identical whether or not the quarantine class is occupied. A node with no
policy is indistinguishable from the same node before this feature existed.

## Node-local consequences

Quarantine-only filtering repairs most of the collateral damage filtering does
to your own node. Not all of it:

- **Compact-block relay is unaffected.** Quarantined transactions stay in the
  one physical pool, so BIP 152 reconstruction finds them with no extra round
  trip. Only transactions evicted from the quarantine budget cost a
  `getblocktxn`, and that cost is bounded by the budget, not by how aggressive
  your rules are.
- **Fee estimation is scope-correct.** The smart-fee simulator counts the
  template class only, so a transaction you quarantine `on template` does not
  inflate the fees you quote to wallets.
- **Bandwidth.** Peers still INV you transactions you quarantine, because no
  wire protocol expresses arbitrary predicates. You download each once and hold
  it; there is no re-download churn. Only post-eviction re-announcements cost
  extra fetches.
- **Your own transactions.** A locally submitted transaction that draws a
  relay-scope verdict is refused at submission with the rule named, rather than
  held silently. You never have an invisible transaction of your own. To
  override and hold it anyway, pass `allowquarantined=true` on the submit call;
  `getquarantineentry` is then authoritative for it.

## Network-scale effects

At the consensus layer this changes nothing. A filtering supermajority of nodes
and miners still cannot orphan a block containing a filtered transaction; any
valid transaction confirms eventually, so long as some hashrate accepts it. But
Bitcoin's practical guarantees emerge from relay-layer behavior, and wide
adoption of a filtering DSL changes three real things. We publish the strongest
case against wide filtering alongside the tool:

- **E1: propagation predictability is load-bearing for L2 security.**
  Lightning enforcement (justice transactions, force-close plus anchor CPFP)
  assumes that a sufficiently-fee'd transaction percolates to hashrate before a
  timelock expires. That rests on relay-policy homogeneity. A popular
  copy-paste ruleset whose witness-size cap or anchor rule happens to match
  force-close or penalty transactions can silently degrade L2 enforcement
  network-wide. The user whose justice transaction never confirms does not
  learn why. This is the critique to take most seriously. The
  strict-by-default danger gate (above) is a partial mitigation: it refuses,
  by default, the rules whose match against Lightning enforcement traffic it
  can prove. It does not close E1. It cannot detect a rule that catches
  enforcement through an angle its probes do not model, and taproot key-path
  force-closes are indistinguishable from ordinary P2TR spends. The gate
  raises the floor; it is not a guarantee.
- **E2: policy-change friction was an unintentional stabilizer.** Today, a
  mass policy shift needs a Core release or an implementation switch. A DSL
  plus a viral gist converts policy into a fast, memetic equilibrium with less
  review than a Core PR. Zero-conf acceptance died through the full-RBF policy
  rollout, with no consensus change required.
- **E3: effective filtering feeds the miner-direct-submission loop.** Every
  shape that stops propagating over p2p creates demand for out-of-band
  channels (accelerators, direct miner APIs). That shifts power to identified,
  pressure-able miner endpoints: weaker censorship resistance where it binds,
  worse submission privacy, and a moat for large miners.

A caveat on the quarantine model: from peers' perspective, a quarantining node
and a hard-rejecting node are indistinguishable, because neither propagates the
transaction. E1 through E3 are therefore not softened by the quarantine-only
design. What quarantine changes is the local picture: collateral damage to your
node is repaired, and policy consequences become visible and reversible. The
filtering capability itself is exactly as strong as a hard reject.

Two structural observations are acknowledged rather than disputed. The tool is
asymmetric: `quarantine` is unbounded while `allow` is capped at standardness,
so at scale it is a ratchet toward more restrictive relay, never more
permissive. And shipped examples become defaults, which is why the cookbook
above is posture-balanced rather than an anti-data starter kit.
