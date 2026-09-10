import { sdk } from '../sdk'
import { caCertificate } from './caCertificate'
import { mcpToken } from './mcpToken'
import { network } from './network'

export const actions = sdk.Actions.of()
  .addAction(network)
  .addAction(caCertificate)
  .addAction(mcpToken)
