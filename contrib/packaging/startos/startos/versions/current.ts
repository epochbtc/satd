import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  // Tagged `v0.6.0_0` in the package repository: Start9's convention swaps
  // the `:` for `_` and adds no package prefix.
  version: '0.6.0:0',
  releaseNotes: {
    en_US:
      'Updates satd to 0.6.0. The first start after the update rebuilds the chainstate once from the block files already on disk: nothing is downloaded again, but on mainnet it takes about as long as a fresh sync, and the Blockchain Sync check shows its progress. There is no going back to 0.5.2 afterwards without another rebuild. The service UI now opens onto satd\'s status page. Full notes: https://github.com/epochbtc/satd/blob/v0.6.0/docs/release-notes/0.6.0.md',
  },
  migrations: {},
})
