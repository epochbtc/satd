import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  // Tagged `v0.6.3_0` in the package repository: Start9's convention swaps
  // the `:` for `_` and adds no package prefix.
  version: '0.6.3:0',
  releaseNotes: {
    en_US:
      'Updates satd to 0.6.3, a security release for the bundled sat-cli and sat-tui: when given -rpccacert, they now trust only that certificate authority for the node\'s TLS certificate, instead of adding it to the public ones. The node itself is unchanged from 0.6.2. Updating from 0.6.0 also brings 0.6.2, which refuses TLS certificates that chain through the eMudhra (emSign) intermediate certificate authorities, whose private keys were disclosed on 2026-10-20, and the 0.6.1 fixes: block validation, header sync and peer handling match Bitcoin Core in more places, initial sync no longer stalls on a slow peer, and a restart keeps the whole mempool. Electrum and Esplora requests now time out after 30 seconds, so a wallet reading a very long address history can see a request fail. Updating from 0.6.0 needs no rebuild. Updating straight from 0.5.2 rebuilds the chainstate once from the block files already on disk, and the Blockchain Sync check shows its progress. Full notes: https://github.com/epochbtc/satd/blob/v0.6.3/docs/release-notes/0.6.3.md, https://github.com/epochbtc/satd/blob/v0.6.3/docs/release-notes/0.6.2.md and https://github.com/epochbtc/satd/blob/v0.6.3/docs/release-notes/0.6.1.md',
  },
  // 0.6.0 and 0.6.2 -> 0.6.3 are binary swaps: same storage schema, same config.
  migrations: {},
})
