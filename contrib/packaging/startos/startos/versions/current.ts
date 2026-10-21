import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  // Tagged `v0.6.2_0` in the package repository: Start9's convention swaps
  // the `:` for `_` and adds no package prefix.
  version: '0.6.2:0',
  releaseNotes: {
    en_US:
      'Updates satd to 0.6.2, a security release: satd refuses TLS certificates that chain through the eMudhra (emSign) intermediate certificate authorities, whose private keys were disclosed on 2026-10-20. Updating from 0.6.0 needs no rebuild. Updating straight from 0.5.2 rebuilds the chainstate once from the block files already on disk, and the Blockchain Sync check shows its progress. Full notes: https://github.com/epochbtc/satd/blob/v0.6.2/docs/release-notes/0.6.2.md',
  },
  // 0.6.0 -> 0.6.2 is a binary swap: same storage schema, same config.
  migrations: {},
})
