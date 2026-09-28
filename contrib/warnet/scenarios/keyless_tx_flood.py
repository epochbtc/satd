#!/usr/bin/env python3
"""Send a stream of transactions from a tank that has no wallet.

MiniWallet holds the coins in the scenario and submits signature-free
anyone-can-spend taproot spends with `sendrawtransaction`, so no wallet RPC
is needed. Each transaction spends one confirmed coin and fans out into
--outputs new ones; a block is mined every 25 transactions so the flood
confirms and the coin supply grows. Runs against Bitcoin Core and satd.

    warnet run keyless_tx_flood.py --tank tank-0003 --txs 40

Run it from a Warnet project's scenarios/ directory (`warnet new` or
`warnet init` creates one), next to commander.py and test_framework/:
`warnet run` uploads only the scenario's own directory. Arguments must not
contain commas.
"""

from time import sleep

from commander import Commander
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

BLOCK_EVERY = 25


class KeylessTxFlood(Commander):
    def set_test_params(self):
        self.num_nodes = 0

    def add_options(self, parser):
        parser.description = "Flood a tank with transactions without a node wallet"
        parser.usage = "warnet run keyless_tx_flood.py [--tank NAME] [--txs N] [--outputs N] [--interval S]"
        parser.add_argument("--tank", type=str, help="tank to send through (default: the first tank)")
        parser.add_argument("--txs", type=int, default=100, help="transactions to send (default 100)")
        parser.add_argument("--outputs", type=int, default=4, help="outputs per transaction (default 4)")
        parser.add_argument(
            "--interval", type=float, default=0, help="seconds between transactions (default 0)"
        )

    def run_test(self):
        node = self.tanks[self.options.tank] if self.options.tank else self.nodes[0]
        wallet = MiniWallet(node)
        wallet.rescan_utxos()
        if not wallet.get_utxos(mark_as_spent=False, confirmed_only=True):
            self.log.info(f"no mature coins on {node.tank}; mining 101 blocks first")
            self.generate(wallet, 101, sync_fun=self.no_op)

        for i in range(1, self.options.txs + 1):
            if not wallet.get_utxos(mark_as_spent=False, confirmed_only=True):
                self.generate(wallet, 1, sync_fun=self.no_op)
            tx = wallet.send_self_transfer_multi(from_node=node, num_outputs=self.options.outputs)
            if i % 10 == 0:
                self.log.info(f"sent {i} txs; last {tx['txid']}; mempool {node.getmempoolinfo()['size']}")
            if i % BLOCK_EVERY == 0:
                self.generate(wallet, 1, sync_fun=self.no_op)
            if self.options.interval:
                sleep(self.options.interval)

        self.generate(wallet, 1, sync_fun=self.no_op)
        assert_equal(node.getrawmempool(), [])
        self.log.info(f"sent {self.options.txs} txs; all confirmed at height {node.getblockcount()}")


def main():
    KeylessTxFlood("").main()


if __name__ == "__main__":
    main()
