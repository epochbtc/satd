import { FileHelper, z } from '@start9labs/start-sdk'
import { sdk } from '../sdk'

/**
 * StartOS-level state, which is why it lives here rather than in
 * bitcoin.conf: the network is passed to satd as a command-line argument on
 * every start, and satd accepts a `signet=1` line in a config file and then
 * ignores it — silently running mainnet. Writing it to the config file would
 * therefore look like it worked.
 */
export const shape = z
  .object({
    network: z
      .enum(['mainnet', 'signet', 'testnet4', 'testnet', 'regtest'])
      .catch('mainnet'),
    /**
     * Comma-separated names for MCP's Host allowlist, from the MCP Hostnames
     * action. Empty means loopback only, which is satd's own default and
     * which refuses every request that arrives by name.
     */
    mcpHostnames: z.string().catch(''),
  })
  .strip()

export const storeJson = FileHelper.json(
  {
    base: sdk.volumes.main,
    subpath: '/startos-store.json',
  },
  shape,
)
