/**
 * The network tables, kept free of any SDK import.
 *
 * That is deliberate rather than tidiness: test/networks.test.ts checks these
 * against satd-init, and node's type stripping resolves a transitive
 * extensionless import of the SDK at runtime, so a test that reached these
 * through a module importing `./sdk` could not run at all.
 */

/**
 * The networks satd-init accepts. It exits 2 on anything else, so this list
 * and its list have to agree.
 */
export const networks = {
  mainnet: 'Mainnet',
  signet: 'Signet',
  testnet4: 'Testnet4',
  testnet: 'Testnet3',
  regtest: 'Regtest',
} as const

export type Network = keyof typeof networks

/**
 * P2P ports, from satd-init's own case statement. satd-init refuses to start
 * when SATD_P2P_PORT disagrees with the network's standard port, which is
 * what makes a mismatch here a startup failure rather than a silent one.
 */
export const p2pPorts: Record<Network, number> = {
  mainnet: 8333,
  signet: 38333,
  testnet4: 48333,
  testnet: 18333,
  regtest: 18444,
}
