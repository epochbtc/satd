#!/usr/bin/env python3
"""Mine blocks on a tank that has no wallet.

The keys live in the scenario: MiniWallet mines to an anyone-can-spend
taproot output with `generatetodescriptor` and finds its coins with
`scantxoutset`, so the node never needs a wallet RPC. Runs against any tank
that has those two RPCs: Bitcoin Core (built with or without a wallet) and
satd.

    warnet run keyless_miner.py --tank tank-0001 --blocks 110
    warnet run keyless_miner.py --forever --interval 30

Run it from a Warnet project's scenarios/ directory (`warnet new` or
`warnet init` creates one), next to commander.py and test_framework/:
`warnet run` uploads only the scenario's own directory. Arguments must not
contain commas.
"""

from time import sleep

from commander import Commander
from test_framework.wallet import MiniWallet


class KeylessMiner(Commander):
    def set_test_params(self):
        self.num_nodes = 0

    def add_options(self, parser):
        parser.description = "Generate blocks without a node wallet"
        parser.usage = (
            "warnet run keyless_miner.py [--tank NAME] [--blocks N] [--interval S] [--forever]"
        )
        parser.add_argument("--tank", type=str, help="tank to mine on (default: the first tank)")
        parser.add_argument(
            "--blocks", type=int, default=101, help="blocks to mine in the first batch (default 101)"
        )
        parser.add_argument(
            "--interval",
            type=int,
            default=60,
            help="seconds between single blocks with --forever (default 60)",
        )
        parser.add_argument(
            "--forever", action="store_true", help="after the first batch, keep mining one block per interval"
        )

    def run_test(self):
        node = self.tanks[self.options.tank] if self.options.tank else self.nodes[0]
        wallet = MiniWallet(node)
        self.log.info(f"mining {self.options.blocks} blocks on {node.tank}")
        # sync_fun=no_op: the default syncs every tank, which is not this scenario's job.
        self.generate(wallet, self.options.blocks, sync_fun=self.no_op)
        self.log.info(f"{node.tank} height {node.getblockcount()}")
        while self.options.forever:
            sleep(self.options.interval)
            self.generate(wallet, 1, sync_fun=self.no_op)
            self.log.info(f"{node.tank} height {node.getblockcount()}")


def main():
    KeylessMiner("").main()


if __name__ == "__main__":
    main()
