import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  // Tagged `v0.5.2_0` in the package repository: Start9's convention swaps
  // the `:` for `_` and adds no package prefix.
  version: '0.5.2:0',
  releaseNotes: {
    en_US:
      'First StartOS release of satd, packaging satd 0.5.2. Backups leave out the chain and chainstate, including the AssumeUTXO background chainstate, which the node downloads again on its own.',
  },
  migrations: {},
})
