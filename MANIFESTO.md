# Node Sovereignty: The satd Manifesto

Node sovereignty is the bedrock of Bitcoin. 

The network does not derive its security from miners, mining pools, or developers. It derives its security from the economic nodes—individuals, exchanges, and businesses who run their own software to independently verify the rules of the system. 

An economic node is only sovereign if the operator has meaningful choices. `satd` exists to empower node operators with maximum flexibility, deep technical visibility, and ultimate sovereignty over the rules they enforce.

To achieve this, we must address the structural risks of monoculture, elevate the protocol above any single codebase, and provide a conservative check and balance against contentious changes.

## 1. The Monoculture Risk

For years, the Bitcoin network has relied almost entirely on a single software implementation: Bitcoin Core. 

The Core maintainers have done an extraordinary, historically unprecedented job of stewarding this software. This is not a critique of their skill, dedication, or integrity. It is an observation of a systemic vulnerability: **a single implementation is a single point of failure.**

When a network with a trillion-dollar capitalization is enforced by a single codebase, a memory leak, a subtle parsing bug, or a compiler quirk can become a global network outage. Software diversity is the immune system of a decentralized network. Multiple robust, independent implementations ensure that a zero-day vulnerability in one codebase does not bring down the entire Bitcoin network.

`satd` provides this diversity. Written from the ground up in memory-safe Rust, with a modern asynchronous architecture and integrated indexes, it gives operators a robust alternative. 

## 2. Protocol Over Implementation

When there is only one dominant implementation, the line between the protocol and the software blurs. A Bitcoin Improvement Proposal (BIP) risks becoming defined simply as "whatever the C++ codebase does."

The existence of multiple serious implementations strengthens the BIP process. It forces the ecosystem to define Bitcoin as a formal, implementation-agnostic protocol. It requires standards to be written clearly enough that disparate engineering teams can implement them identically without relying on undocumented quirks. A multi-client ecosystem elevates Bitcoin from a software project to a true global standard.

## 3. The Consensus Shield

The historical argument against alternative Bitcoin clients is the fear of consensus divergence: the risk that a subtle difference in validation could quietly split a node off the network. We take that risk seriously, and we do not ask operators to take our correctness on faith. `satd` ships a complete, independently written Rust consensus engine — it is *not* a wrapper around Core's — and we hold it to Core's behavior with two distinct, complementary defenses.

**Shadow validation of script evaluation.** Script evaluation is the subtlest and most divergence-prone surface in consensus — historically the source of the most dangerous client bugs. For this layer `satd` runs both engines at once: alongside its native Rust verifier it validates every script against `libbitcoinconsensus`, the exact C++ engine compiled from Bitcoin Core, and compares the two results at runtime. A disagreement is detected at the moment it would occur and raised as a loud, explicit alert, pinned to the offending block and input — a divergence cannot slip through silently. This is runtime-verified equivalence on every script your node actually evaluates, not a guarantee transcribed from a spec. It has been run across the mainnet chain from genesis through ~945k blocks with zero divergence.

**Differential testing of block acceptance.** `libbitcoinconsensus` only checks scripts. The rest of the consensus pipeline — proof-of-work, merkle and witness commitments, sigop limits, BIP 34 height, value conservation, coinbase maturity, timestamps, locktime and sequence locks — is held to Core's exact behavior by an independent differential test battery. Static fixtures port Bitcoin Core's own block-acceptance test cases; a generative fuzzer then submits adversarial, mutated blocks to `satd` and a live `bitcoind` in lockstep and asserts that both nodes accept, or both reject, every one. Where no human thought to write a test, the fuzzer finds the divergence.

Together these give the systemic resilience and operational ergonomics of a fully independent Rust implementation, with divergence from the reference node caught before it can fork your node off the chain — at runtime for scripts, and continuously in CI for the block-acceptance rules around them.

## 4. The BIP Policy: The Status Quo is the Default

Because `satd` exists to protect node sovereignty, our governance policy regarding network upgrades is strictly conservative.

1.  **No Unilateral Additions:** `satd` will never unilaterally implement or activate a consensus-altering BIP that has not been accepted by Bitcoin Core. We are not a vehicle for forcing new rules or alt-features onto the network.
2.  **The Right to Reject:** We reserve the right to reject or delay a Core-accepted BIP if it lacks broad acceptance across the network or appears contentious. 

In Bitcoin, inaction is always the safest path. In the event that a contentious upgrade is merged into the reference implementation, `satd` will default to the existing consensus rules. This empowers economic node operators to easily enforce the status quo, shifting power away from developers and back to the users.

## 5. Built for the Operator

Ultimately, sovereignty requires usability. A node that is too resource-intensive, too difficult to index, or too opaque to monitor cannot effectively serve as an economic anchor.

We built `satd` to treat the operator as a first-class citizen. By integrating the wallet-server protocols (Electrum, Esplora) directly into the shared chainstate, exposing deep operational metrics, and providing rich CLI/TUI interfaces, `satd` strips away the friction of self-custody.

Bitcoin belongs to the node operators. `satd` is built for them.
