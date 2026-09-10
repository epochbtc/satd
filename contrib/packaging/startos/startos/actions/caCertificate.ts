import { readFile } from 'fs/promises'
import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { rootDir, satdMounts } from '../utils'

/**
 * StartOS terminates TLS for everything this package exports, so a user does
 * not need this to reach the node from the LAN — that certificate is the
 * server's own and is already trusted.
 *
 * It is here for the two places satd's own certificate is what gets
 * presented: a client on the container bridge dialling satd's TLS listeners
 * directly, and the MCP surface, whose inward leg the OS re-wraps without
 * validating.
 */
export const caCertificate = sdk.Action.withoutInput(
  'ca-certificate',

  async () => ({
    name: i18n('CA Certificate'),
    description: i18n(
      "This install's certificate authority, for clients that reach satd's own TLS listeners directly",
    ),
    warning: null,
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  }),

  async ({ effects }) => {
    const cert = await sdk.SubContainer.withTemp(
      effects,
      { imageId: 'satd' },
      satdMounts,
      'ca-certificate',
      async (subc) =>
        readFile(`${subc.rootfs}${rootDir}/tls/ca.crt`, 'utf8').catch(
          () => null,
        ),
    )

    if (!cert)
      return {
        version: '1' as const,
        title: i18n('Not generated yet'),
        message: i18n(
          'satd-init writes the CA on the first start. Start the service once, then run this action again.',
        ),
        result: null,
      }

    return {
      version: '1' as const,
      title: i18n('CA Certificate'),
      message: i18n('Import this certificate to trust this node directly.'),
      result: {
        type: 'single' as const,
        name: i18n('CA Certificate'),
        description: i18n('PEM-encoded certificate authority'),
        value: cert,
        copyable: true,
        qr: false,
        masked: false,
      },
    }
  },
)
