import { sdk } from './sdk'

/**
 * None. satd serves its own Electrum and Esplora surfaces from one process,
 * so there is no indexer to depend on, and it needs nothing else on the box
 * to start or to stay healthy.
 */
export const setDependencies = sdk.setupDependencies(async () => ({}))
