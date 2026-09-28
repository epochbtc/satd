#!/usr/bin/env python3
"""Differential consensus check across every tank in the network.

Mines on one tank and asserts that every other tank, whatever its
implementation, converges on the same tip after each step: plain blocks, a
relayed transaction, a reorg, and a valid block carrying a non-standard
transaction that never went through a mempool. MiniWallet holds the keys
in the scenario, so no tank needs a wallet and no implementation is special.

    warnet run consensus_diff.py
    warnet run consensus_diff.py --miner tank-0000 --timeout 180 --reorgs 10

A failing step logs `tip mismatch` and every tank's height and tip.
Run it from a Warnet project's scenarios/ directory (`warnet new` or
`warnet init` creates one), next to commander.py and test_framework/:
`warnet run` uploads only the scenario's own directory. Arguments must not
contain commas.
"""

import time

from commander import Commander
from test_framework.descriptors import descsum_create
from test_framework.script import OP_TRUE, CScript
from test_framework.wallet import MiniWallet

# Blocks to mine, one at a time, for compact block relay to show up on every
# tank before step 4 gives up.
COMPACT_BLOCK_TRIES = 5

# A bare OP_TRUE coinbase output, which no MiniWallet block pays to.
BARE_OP_TRUE = descsum_create("raw(51)")


class ConsensusDiff(Commander):
    def set_test_params(self):
        self.num_nodes = 0

    def add_options(self, parser):
        parser.description = "Check that every tank follows the same chain"
        parser.usage = "warnet run consensus_diff.py [--miner NAME] [--timeout S] [--reorgs N]"
        parser.add_argument("--miner", type=str, help="tank that mines (default: the first tank)")
        parser.add_argument(
            "--timeout", type=int, default=120, help="seconds to wait for convergence per step (default 120)"
        )
        parser.add_argument(
            "--reorgs",
            type=int,
            default=3,
            help="times to repeat the reorg step; block arrival order varies between rounds (default 3)",
        )

    # --- helpers -----------------------------------------------------------

    def table(self):
        rows = []
        for n in self.nodes:
            try:
                rows.append(f"  {n.tank}: height {n.getblockcount()} tip {n.getbestblockhash()}")
            except Exception as e:  # a tank that stopped answering is itself a finding
                rows.append(f"  {n.tank}: unreachable ({e})")
        return "\n".join(rows)

    def wait_same_tip(self, step):
        want = self.miner.getbestblockhash()
        deadline = time.time() + self.options.timeout
        while time.time() < deadline:
            if all(n.getbestblockhash() == want for n in self.nodes):
                self.log.info(f"ok - {step} (tip {want})")
                return want
            time.sleep(1)
        raise AssertionError(f"tip mismatch after '{step}':\n{self.table()}")

    def used_cmpctblock(self, n):
        """Whether a cmpctblock crossed any of the tank's connections, either
        way. None when the tank does not report per-message byte counts."""
        peers = n.getpeerinfo()
        if not all("bytesrecv_per_msg" in p for p in peers):
            return None
        return any(
            p["bytesrecv_per_msg"].get("cmpctblock", 0) > 0 or p["bytessent_per_msg"].get("cmpctblock", 0) > 0
            for p in peers
        )

    def wait_in_mempool(self, txid, step, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            missing = [n.tank for n in self.nodes if txid not in n.getrawmempool()]
            if not missing:
                self.log.info(f"ok - {step}")
                return
            time.sleep(1)
        raise AssertionError(f"{step}: {txid} never reached {missing}")

    # --- the run -----------------------------------------------------------

    def run_test(self):
        self.miner = self.tanks[self.options.miner] if self.options.miner else self.nodes[0]
        self.log.info(f"{len(self.nodes)} tanks; mining on {self.miner.tank}")
        w = MiniWallet(self.miner)

        # 1. A mature chain every tank agrees on.
        self.generate(w, 110, sync_fun=self.no_op)
        self.wait_same_tip("mature chain")

        # 2. A transaction relays to every tank.
        txid = w.send_self_transfer(from_node=self.miner)["txid"]
        self.wait_in_mempool(txid, "transaction relayed to every tank")

        # 3. The block that confirms it is accepted everywhere.
        self.generate(w, 1, sync_fun=self.no_op)
        tip = self.wait_same_tip("block with the relayed transaction")
        for n in self.nodes:
            assert txid in n.getblock(tip)["tx"], f"{n.tank}: {txid} not in block {tip}"
        self.log.info("ok - every tank has the transaction in the tip block")

        # 4. Blocks travel as compact blocks somewhere on every tank. A node
        #    asks a peer to push new blocks as cmpctblock (BIP 152 high
        #    bandwidth) only once that peer has delivered it a new tip, so on
        #    a network this scenario has just brought up the first blocks can
        #    all arrive whole. Mine one more block at a time until every tank
        #    has used compact blocks.
        for extra in range(COMPACT_BLOCK_TRIES + 1):
            used = {n.tank: self.used_cmpctblock(n) for n in self.nodes}
            unused = [tank for tank, u in used.items() if u is False]
            if not unused:
                break
            assert extra < COMPACT_BLOCK_TRIES, (
                f"no cmpctblock sent or received on any peer of {', '.join(unused)} after {extra} more blocks"
            )
            self.generate(w, 1, sync_fun=self.no_op)
            self.wait_same_tip(f"block {extra + 1} more for compact block relay")
        for tank in [tank for tank, u in used.items() if u is None]:
            self.log.info(f"skip - {tank} does not report per-message byte counts")
        self.log.info("ok - compact blocks carried blocks on every tank")

        # 5. Reorgs: drop the top two blocks on the miner and mine a longer
        #    chain. Blocks of the new chain reach each tank in whatever order
        #    relay delivers them, so repeat the step to exercise more orders.
        for i in range(1, self.options.reorgs + 1):
            height = self.miner.getblockcount()
            old_tip = self.miner.getbestblockhash()
            dropped = self.miner.getblockhash(height - 1)
            self.miner.invalidateblock(dropped)
            # The miner falls back to the dropped block's parent, or to a
            # taller branch an earlier round's reconsiderblock made valid
            # again, and the new chain grows from there. Its first block can
            # sit where the dropped block did: a burst of blocks runs block
            # times ahead of the clock, so its time is the parent's median
            # time past plus one, and mined to the same output with the same
            # transactions it would be the dropped block again, which the
            # miner refuses as known invalid.
            self.generatetodescriptor(self.miner, 1, BARE_OP_TRUE, sync_fun=self.no_op)
            self.generate(w, 2, sync_fun=self.no_op)
            assert self.miner.getblockcount() > height, f"reorg {i}: the new chain is not longer"
            assert self.miner.getblockhash(height) != old_tip, f"reorg {i}: the old tip is still active"
            self.wait_same_tip(f"reorg {i} onto a longer chain")
            self.miner.reconsiderblock(dropped)
            self.wait_same_tip(f"reconsiderblock {i} leaves the longer chain in place")

        # 6. A valid block carrying a non-standard transaction. A bare OP_TRUE
        #    output is non-standard, so no mempool would relay it; generateblock
        #    puts it straight into a block. The taproot OP_TRUE input signs
        #    nothing, so the output can be rewritten after the fact.
        tx = w.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = CScript([OP_TRUE])
        block = self.generateblock(
            self.miner, output=w.get_address(), transactions=[tx.serialize().hex()], sync_fun=self.no_op
        )
        self.wait_same_tip("block with a non-standard transaction")
        for n in self.nodes:
            assert tx.txid_hex in n.getblock(block["hash"])["tx"], f"{n.tank}: non-standard tx missing"
        w.rescan_utxos()

        self.log.info("final state:\n" + self.table())
        self.log.info("consensus_diff: all steps passed")


def main():
    ConsensusDiff("").main()


if __name__ == "__main__":
    main()
