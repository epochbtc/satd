import { ISB } from '@start9labs/start-sdk'
import { storeJson } from '../fileModels/store.json'
import { i18n } from '../i18n'
import { sdk } from '../sdk'

/**
 * The names clients put in the URL when they reach MCP.
 *
 * MCP's transport validates the `Host` header against an allowlist, which
 * defaults to loopback, as a defence against DNS rebinding. StartOS's reverse
 * proxy passes the client's `Host` through unchanged — it does no validation
 * of its own — so satd's check is the only thing standing between a rebound
 * browser and the tool surface, and it has to be told which names are real.
 * Until it is, every request that arrives by name is answered 403.
 *
 * This is asked of the operator rather than derived because the package
 * cannot discover it. `getHostInfo` returns only operator-added custom
 * domains, which are empty on a stock install; the `.local` name comes from
 * the server's own hostname, which no effect exposes; and inside the
 * container `hostname` is a generated container id, with no DNS path back to
 * the server's name.
 *
 * Loopback is always accepted by satd itself and is deliberately not asked
 * for here.
 */
export const mcpHostnames = sdk.Action.withInput(
  'mcp-hostnames',

  async () => ({
    name: i18n('MCP Hostnames'),
    description: i18n('The names this server is reached by, for MCP clients'),
    warning: null,
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  }),

  ISB.InputSpec.of({
    mcpHostnames: ISB.Value.text({
      name: i18n('Hostnames'),
      description: i18n(
        'The hostname you type in the address bar to reach this server, such as my-server.local. Separate several with commas. Add one for every name clients use — an address reached by a name not listed here is refused.',
      ),
      footnote: i18n(
        'MCP only. The other interfaces are unaffected by this setting.',
      ),
      placeholder: 'my-server.local',
      default: null,
      required: false,
      patterns: [
        {
          regex:
            '^[A-Za-z0-9.-]+(:[0-9]{1,5})?( *, *[A-Za-z0-9.-]+(:[0-9]{1,5})?)*$',
          description: i18n(
            'A hostname, or hostname:port, separated by commas. Not a full URL — no https:// and no path.',
          ),
        },
      ],
    }),
  }),

  async ({ effects }) => storeJson.read().once(),

  async ({ effects, input }) => {
    await storeJson.merge(effects, { mcpHostnames: input.mcpHostnames ?? '' })
  },
)
