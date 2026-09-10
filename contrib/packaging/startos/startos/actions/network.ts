import { ISB } from '@start9labs/start-sdk'
import { storeJson } from '../fileModels/store.json'
import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { networks } from '../utils'

/**
 * The only setting this package offers.
 *
 * `txindex` and `addressindex` are deliberately not options: Electrum and
 * Esplora both require them, so turning either off would break the two
 * surfaces that are the reason to run satd rather than Bitcoin Core. Pruning
 * is incompatible with txindex for the same reason, so there is no prune
 * option to offer either.
 */
export const network = sdk.Action.withInput(
  'network',

  async () => ({
    name: i18n('Network'),
    description: i18n('Which Bitcoin network this node runs on'),
    warning: i18n(
      'Changing the network restarts the node on a different chain. The existing chain data is kept — each network has its own directory — but the node re-syncs the new network from scratch, and the P2P port changes with it.',
    ),
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  }),

  ISB.InputSpec.of({
    network: ISB.Value.select({
      name: i18n('Network'),
      description: i18n(
        'Mainnet is the Bitcoin network. The others are test networks whose coins have no value.',
      ),
      default: 'mainnet',
      values: networks,
    }),
  }),

  async ({ effects }) => storeJson.read().once(),

  async ({ effects, input }) => {
    await storeJson.merge(effects, { network: input.network })
  },
)
