export const DEFAULT_LANG = 'en_US'

const dict = {
  // startos/actions/caCertificate.ts
  'CA Certificate': 1,
  'This install\'s certificate authority, for clients that reach satd\'s own TLS listeners directly': 2,
  'Not generated yet': 3,
  'satd-init writes the CA on the first start. Start the service once, then run this action again.': 4,
  'Import this certificate to trust this node directly.': 5,
  'PEM-encoded certificate authority': 6,
  // startos/actions/mcpToken.ts
  'MCP Token': 7,
  'The bearer token an AI assistant needs to query this node': 8,
  'Anyone holding this token can query this node through the MCP surface. Treat it as a password.': 9,
  'satd-init mints the token on the first start. Start the service once, then run this action again.': 10,
  'Send this as `Authorization: Bearer <token>` to the MCP interface.': 11,
  'Bearer token': 12,
  // startos/actions/network.ts
  'Network': 13,
  'Which Bitcoin network this node runs on': 14,
  'Changing the network restarts the node on a different chain. The existing chain data is kept — each network has its own directory — but the node re-syncs the new network from scratch, and the P2P port changes with it.': 15,
  'Mainnet is the Bitcoin network. The others are test networks whose coins have no value.': 16,
  // startos/interfaces.ts
  'RPC': 17,
  'Bitcoin Core-compatible JSON-RPC': 18,
  'Electrum': 19,
  'Electrum server, for Sparrow, Electrum, BlueWallet and Zeus': 20,
  'Esplora': 21,
  'Esplora REST API, compatible with Blockstream\'s': 22,
  'MCP': 23,
  'Model Context Protocol server, so an AI assistant can query this node': 24,
  'Peer': 25,
  'Listens for connections from other Bitcoin nodes': 26,
  // startos/main.ts
  'satd is starting…': 27,
  'Could not read ${cmd} from satd: ${error}': 28,
  'Node': 29,
  'satd is ready': 30,
  'Blockchain Sync': 31,
  'satd is fully synced': 32,
  'Syncing block headers: ${count}': 33,
  'Syncing block headers…': 34,
  'Syncing blocks: ${percentage}%': 35,
} as const

export type LangDict = typeof dict

export default dict
