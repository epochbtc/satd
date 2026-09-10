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
    exclude: [
      'blocks/',
      'chainstate/',
      'indexes/',
      // Per-network subdirectories hold the same three, plus the cookie.
      '*/blocks/',
      '*/chainstate/',
      '*/indexes/',
      '.cookie',
      '*/.cookie',
      'rpc-cookie',
      'debug.log',
      '*/debug.log',
    ],
  }),
)
