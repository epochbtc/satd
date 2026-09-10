import { storeJson } from './fileModels/store.json'
import { i18n } from './i18n'
import { sdk } from './sdk'
import {
  electrumHostId,
  electrumInterfaceId,
  electrumPort,
  electrumTlsPort,
  esploraHostId,
  esploraInterfaceId,
  esploraPort,
  esploraTlsPort,
  mcpHostId,
  mcpInterfaceId,
  mcpPort,
  p2pPorts,
  peerHostId,
  peerInterfaceId,
  rpcHostId,
  rpcInterfaceId,
  rpcPort,
} from './utils'

/**
 * Who terminates TLS.
 *
 * satd serves TLS itself on 8336 / 50002 / 3001 from a CA it generates per
 * install. That is the right answer for the reference stack and the
 * appliance, where nothing else can issue a certificate. It is the wrong
 * answer here: StartOS already terminates TLS at its reverse proxy with a
 * certificate chaining to this server's root CA, which every client the user
 * has set up already trusts. Exporting satd's own listeners instead would ask
 * each user to import a second CA for one service.
 *
 * So the plain listeners are what get bound, and the OS wraps them. satd's
 * TLS listeners still run — satd-init is used unmodified, which is what keeps
 * this package from drifting away from the stack — they simply are not
 * exported, which leaves them on `lo` and `lxcbr0` and off the LAN.
 *
 * MCP is the one exception, below.
 */
export const setInterfaces = sdk.setupInterfaces(async ({ effects }) => {
  const network = (await storeJson.read((s) => s.network).const(effects)) ?? 'mainnet'

  // --- JSON-RPC -----------------------------------------------------------
  // `http` rather than a raw binding: it publishes both a plaintext bridge
  // address for other packages on lxcbr0 and a TLS-terminated one for the
  // LAN, which is the split Core-compatible clients expect. Cookie auth is
  // unchanged and is still satd's.
  const rpcOrigin = await sdk.MultiHost.of(effects, rpcHostId).bindPort(
    rpcPort,
    { protocol: 'http', preferredExternalPort: rpcPort },
  )
  const rpc = sdk.createInterface(effects, {
    name: i18n('RPC'),
    id: rpcInterfaceId,
    description: i18n('Bitcoin Core-compatible JSON-RPC'),
    type: 'api',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })

  // --- Electrum -----------------------------------------------------------
  // Not HTTP: the Electrum protocol is line-delimited JSON over a raw TCP
  // socket, so the OS adds TLS in front of the plaintext listener rather than
  // proxying requests. No X-Forwarded headers — there is no request to put
  // them on — and no ALPN, which is an HTTP/2 negotiation Electrum clients do
  // not speak.
  const electrumOrigin = await sdk.MultiHost.of(
    effects,
    electrumHostId,
  ).bindPort(electrumPort, {
    protocol: null,
    preferredExternalPort: electrumPort,
    secure: { ssl: false },
    addSsl: {
      preferredExternalPort: electrumTlsPort,
      addXForwardedHeaders: false,
      alpn: null,
      auth: null,
    },
  })
  const electrum = sdk.createInterface(effects, {
    name: i18n('Electrum'),
    id: electrumInterfaceId,
    description: i18n(
      'Electrum server, for Sparrow, Electrum, BlueWallet and Zeus',
    ),
    type: 'api',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })

  // --- Esplora ------------------------------------------------------------
  // Unauthenticated, as every public Esplora deployment is: it serves public
  // chain data. The prefix is satd's `esploraprefix`.
  const esploraOrigin = await sdk.MultiHost.of(effects, esploraHostId).bindPort(
    esploraPort,
    {
      protocol: 'http',
      preferredExternalPort: esploraPort,
      addSsl: { preferredExternalPort: esploraTlsPort },
    },
  )
  const esplora = sdk.createInterface(effects, {
    name: i18n('Esplora'),
    id: esploraInterfaceId,
    description: i18n("Esplora REST API, compatible with Blockstream's"),
    type: 'api',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '/api',
    query: {},
  })

  // --- MCP ----------------------------------------------------------------
  // The exception. satd refuses to start with MCP bound off-loopback unless
  // TLS and auth are both configured, so this listener speaks TLS from satd's
  // own certificate and cannot be handed over as plaintext.
  //
  // `secure.ssl` says the container's port is already TLS; `addSsl` makes the
  // OS terminate the client's connection with the server's own certificate
  // and open a fresh one inward. That inward leg is what
  // `upstreamCertValidation: 'disable'` covers: it is a hop across lxcbr0 to
  // a certificate from satd's per-install CA, which the OS has no reason to
  // trust and no way to be taught. Without it the OS validates against the
  // StartOS root CA and every MCP request fails.
  const mcpOrigin = await sdk.MultiHost.of(effects, mcpHostId).bindPort(
    mcpPort,
    {
      protocol: null,
      preferredExternalPort: mcpPort,
      secure: { ssl: true },
      addSsl: {
        preferredExternalPort: mcpPort,
        addXForwardedHeaders: true,
        alpn: null,
        auth: null,
        upstreamCertValidation: 'disable',
      },
    },
  )
  const mcp = sdk.createInterface(effects, {
    name: i18n('MCP'),
    id: mcpInterfaceId,
    description: i18n(
      'Model Context Protocol server, so an AI assistant can query this node',
    ),
    type: 'api',
    masked: true,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })

  // --- P2P ----------------------------------------------------------------
  // The port follows the chain, because other nodes rely on the convention.
  // No TLS in either direction: the Bitcoin P2P protocol has its own
  // encrypted transport (BIP 324) and wrapping it in TLS would make this node
  // unreachable to every peer.
  const peerOrigin = await sdk.MultiHost.of(effects, peerHostId).bindPort(
    p2pPorts[network],
    {
      protocol: null,
      preferredExternalPort: p2pPorts[network],
      secure: { ssl: false },
      addSsl: null,
    },
  )
  const peer = sdk.createInterface(effects, {
    name: i18n('Peer'),
    id: peerInterfaceId,
    description: i18n('Listens for connections from other Bitcoin nodes'),
    type: 'p2p',
    masked: false,
    schemeOverride: { ssl: null, noSsl: null },
    username: null,
    path: '',
    query: {},
  })

  return [
    await rpcOrigin.export([rpc]),
    await electrumOrigin.export([electrum]),
    await esploraOrigin.export([esplora]),
    await mcpOrigin.export([mcp]),
    await peerOrigin.export([peer]),
  ]
})
