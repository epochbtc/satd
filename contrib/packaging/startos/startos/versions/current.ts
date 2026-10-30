import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  // Tagged `v0.7.0_0` in the package repository: Start9's convention swaps
  // the `:` for `_` and adds no package prefix.
  version: '0.7.0:0',
  releaseNotes: {
    en_US:
      'Updates satd to 0.7.0. satd now publishes Bitcoin Core\'s ZMQ notifications, accepts package CPFP and TRUC (version 3) transactions as Core does, and can strip large OP_RETURN payloads from deep blocks with -pruneopreturn (off by default). Headers and P2P messages are read as Core reads them. Several defaults change to match Core: getrawtransaction, getblock and decoderawtransaction drop the fields Core does not have, the mempool limits each transaction\'s cluster to 64, transactions reach peers a few seconds later, and Electrum and Esplora refuse balance and UTXO requests for a scripthash with more than 200,000 transactions unless -addrindexmaxhistory is raised. Updating from 0.6.x needs no rebuild; a node that has used -pruneopreturn cannot go back to 0.6.x. Updating straight from 0.5.2 rebuilds the chainstate once from the block files already on disk, and the Blockchain Sync check shows its progress. Updating from 0.6.0 also brings the 0.6.1 to 0.6.3 fixes, including the 30-second Electrum and Esplora request timeout. Full notes: https://github.com/epochbtc/satd/blob/v0.7.0/docs/release-notes/0.7.0.md',
  },
  // 0.6.0, 0.6.2 and 0.6.3 -> 0.7.0 are binary swaps: same storage schema, same config.
  migrations: {},
})
