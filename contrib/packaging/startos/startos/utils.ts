import { sdk } from './sdk'

export { networks, p2pPorts } from './networks'
export type { Network } from './networks'

/**
 * Where the volume lands, matching `--datadir` in the reference stack.
 */
export const rootDir = '/var/lib/satd'

/**
 * Ports, mirroring contrib/stack/satd/satd.conf.tmpl. satd-init renders that
 * template inside the image, so these are read from it rather than chosen
 * here — changing one on this side alone would bind nothing.
 *
 * The plain listeners are what this package exports. satd also serves TLS on
 * 8336 / 50002 / 3001 from its own per-install CA, and on StartOS those go
 * unexported: StartOS terminates TLS at its reverse proxy with a certificate
 * chaining to the server's root CA, which every client on the box already
 * trusts. Exporting satd's CA instead would ask each user to import a second
 * one for a single service. MCP is the exception — see interfaces.ts.
 */
export const rpcPort = 8332
export const electrumPort = 50001
export const esploraPort = 3000
export const metricsPort = 9332
export const mcpPort = 8339

/** Conventional external ports, requested via `preferredExternalPort`. */
export const electrumTlsPort = 50002
export const esploraTlsPort = 3001

export const rpcHostId = 'rpc'
export const electrumHostId = 'electrum'
export const esploraHostId = 'esplora'
export const mcpHostId = 'mcp'
export const peerHostId = 'peer'

export const rpcInterfaceId = 'rpc'
export const electrumInterfaceId = 'electrum'
export const esploraInterfaceId = 'esplora'
export const mcpInterfaceId = 'mcp'
export const peerInterfaceId = 'peer'

/**
 * StartOS puts every service container on one bridge, `lxcbr0`, with the OS
 * itself at a fixed 10.0.3.1. satd's `rpcallowip` has to admit that range or
 * the OS reverse proxy — and every other package on the box — is refused at
 * the RPC surface.
 */
export const bridgeSubnet = '10.0.3.0/24'

export const satdMounts = sdk.Mounts.of().mountVolume({
  volumeId: 'main',
  mountpoint: rootDir,
  subpath: null,
  readonly: false,
  type: 'directory',
})

/**
 * `sat-cli` invocation for a node in this container.
 *
 * Both flags matter. `-rpcport` because the stack fixes RPC at 8332 on every
 * network while sat-cli derives its default from the chain, and
 * `-rpccookiefile` because sat-cli works out the cookie's per-network
 * subdirectory by reading `regtest=1`/`testnet=1` from bitcoin.conf — lines
 * this stack deliberately never writes, since satd accepts a network in a
 * config file and then ignores it. satd-init maintains `rpc-cookie` as a
 * symlink to whichever path is live, so naming it outright sidesteps the
 * detection entirely and is correct on every network.
 */
export const satCliArgs = [
  'sat-cli',
  `-datadir=${rootDir}`,
  `-rpcport=${rpcPort}`,
  `-rpccookiefile=${rootDir}/rpc-cookie`,
  '-rpcconnect=127.0.0.1',
]

export type GetBlockchainInfo = {
  chain: string
  blocks: number
  headers: number
  verificationprogress: number
  initialblockdownload: boolean
}
