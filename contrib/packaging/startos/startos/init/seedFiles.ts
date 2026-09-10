import { storeJson } from '../fileModels/store.json'
import { sdk } from '../sdk'

/**
 * Only the network selection. Everything else satd needs on disk —
 * bitcoin.conf, the CA, the authfile — is written by satd-init at every
 * start, from the template baked into the image, so seeding a copy here
 * would be a second source of truth that goes stale.
 */
export const seedFiles = sdk.setupOnInit(async (effects, kind) => {
  if (!kind) return
  await storeJson.merge(effects, {})
})
