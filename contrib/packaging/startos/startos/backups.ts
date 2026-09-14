import { sdk } from './sdk'

/**
 * A wallet-less node holds nothing irreplaceable: the chain, the chainstate
 * and every index rebuild from the network, and backing them up would move
 * hundreds of gigabytes to reproduce something the node fetches on its own.
 *
 * What is worth keeping is small and cannot be re-derived: the per-install CA
 * and certificate, the MCP bearer token, and the network selection. Restoring
 * without the CA means every client that imported it has to import a new one
 * — which on StartOS matters less than it does elsewhere, since the OS
 * terminates TLS with its own certificate, but the CA is still what a
 * container-to-container client and the MCP surface present.
 */
export const { createBackup, restoreInit } = sdk.setupBackups(async () =>
  sdk.Backups.ofVolumes('main').setOptions({
    // Checked against a datadir satd 0.5.2 wrote, not against Bitcoin
    // Core's layout. satd keeps every index inside `chainstate/`, so there is
    // no `indexes/`, and it logs to stdout, so there is no `debug.log`; both
    // were here and matched nothing. `chainstate_background/` exists only
    // while an AssumeUTXO snapshot's background validation runs, which is
    // exactly when it is large.
    exclude: [
      'blocks/',
      'chainstate/',
      'chainstate_background/',
      'mempool.dat',
      '.cookie',
      // Every network but mainnet is a subdirectory with the same layout.
      '*/blocks/',
      '*/chainstate/',
      '*/chainstate_background/',
      '*/mempool.dat',
      '*/.cookie',
      'rpc-cookie',
    ],
  }),
)
