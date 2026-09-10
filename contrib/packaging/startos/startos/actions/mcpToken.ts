import { readFile } from 'fs/promises'
import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { rootDir, satdMounts } from '../utils'

/**
 * The bearer token satd-init mints on first start. Only its hash is written
 * to the authfile, so this file is the only copy — regenerating it would
 * break every client already configured with it, which is why satd-init
 * never does.
 */
export const mcpToken = sdk.Action.withoutInput(
  'mcp-token',

  async () => ({
    name: i18n('MCP Token'),
    description: i18n(
      'The bearer token an AI assistant needs to query this node',
    ),
    warning: i18n(
      'Anyone holding this token can query this node through the MCP surface. Treat it as a password.',
    ),
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  }),

  async ({ effects }) => {
    const token = await sdk.SubContainer.withTemp(
      effects,
      { imageId: 'satd' },
      satdMounts,
      'mcp-token',
      async (subc) =>
        readFile(`${subc.rootfs}${rootDir}/secrets/mcp-token`, 'utf8')
          .then((t) => t.trim())
          .catch(() => null),
    )

    if (!token)
      return {
        version: '1' as const,
        title: i18n('Not generated yet'),
        message: i18n(
          'satd-init mints the token on the first start. Start the service once, then run this action again.',
        ),
        result: null,
      }

    return {
      version: '1' as const,
      title: i18n('MCP Token'),
      message: i18n(
        'Send this as `Authorization: Bearer <token>` to the MCP interface.',
      ),
      result: {
        type: 'single' as const,
        name: i18n('MCP Token'),
        description: i18n('Bearer token'),
        value: token,
        copyable: true,
        qr: false,
        masked: true,
      },
    }
  },
)
