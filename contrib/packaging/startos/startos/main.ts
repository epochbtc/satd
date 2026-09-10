import { healthFns } from '@start9labs/start-sdk'
import { storeJson } from './fileModels/store.json'
import { i18n } from './i18n'
import { sdk } from './sdk'
import {
  bridgeSubnet,
  GetBlockchainInfo,
  metricsPort,
  p2pPorts,
  rootDir,
  satCliArgs,
  satdMounts,
} from './utils'

export const main = sdk.setupMain(async ({ effects }) => {
  const store = await storeJson.read().once()
  if (!store) throw new Error('No store')
  const { network } = store

  const satdSub = await sdk.SubContainer.eager(
    effects,
    { imageId: 'satd' },
    satdMounts,
    'satd-sub',
  )

  /**
   * One read-only sat-cli call, parsed. Every outcome is a value: a node not
   * answering yet reads as `starting`, and a call that cannot be run or whose
   * reply cannot be parsed reads as `failure` — neither is a state satd
   * reaches while running normally. `exec` rather than `execFail` because a
   * non-zero exit is the expected signal here, not an error.
   */
  const probe = async <T>(
    ...cmd: string[]
  ): Promise<{ value: T } | { health: healthFns.HealthCheckResult }> => {
    try {
      const res = await satdSub.exec([...satCliArgs, ...cmd])
      if (
        res.exitCode !== 0 ||
        typeof res.stdout !== 'string' ||
        res.stdout === ''
      ) {
        return {
          health: { result: 'starting' as const, message: i18n('satd is starting…') },
        }
      }
      return { value: JSON.parse(res.stdout) as T }
    } catch (e) {
      return {
        health: {
          result: 'failure' as const,
          message: i18n('Could not read ${cmd} from satd: ${error}', {
            cmd: cmd[0],
            error: String(e),
          }),
        },
      }
    }
  }

  return sdk.Daemons.of(effects)
    /**
     * StartOS creates the volume owned by root; the image runs as `satd`
     * (uid 2121) and satd-init writes the CA, the config and the token into
     * it. Cheap and idempotent, and without it the first start fails on the
     * first write rather than on anything that names the cause.
     */
    .addOneshot('own-volume', {
      subcontainer: satdSub,
      exec: {
        command: ['chown', '-R', 'satd:satd', rootDir],
        user: 'root',
      },
      requires: [],
    })
    /**
     * The same satd-init the reference stack and the appliance run, from the
     * image, unmodified — it issues this install's CA and certificate,
     * renders bitcoin.conf for the selected network, mints the MCP token and
     * points `rpc-cookie` at the network's cookie. A package that
     * re-implemented any of that would drift from the stack within a release.
     *
     * SATD_STACK_SUBNET becomes satd's `rpcallowip`. On StartOS every service
     * shares one bridge with the OS at 10.0.3.1, so this range is what admits
     * the OS reverse proxy and other packages; narrower and the RPC interface
     * answers nothing.
     */
    .addOneshot('satd-init', {
      subcontainer: satdSub,
      exec: {
        command: ['/usr/local/bin/satd-init'],
        user: 'satd',
        env: {
          NETWORK: network,
          SATD_MCP: '1',
          SATD_STACK_SUBNET: bridgeSubnet,
          // The name clients reach this server by. StartOS terminates TLS
          // itself, so this only labels satd's own certificate — the one used
          // on the bridge and for MCP.
          SATD_TLS_HOSTNAME: 'satd.startos',
          SATD_P2P_PORT: String(p2pPorts[network]),
          SATD_CA_EXPORT_HINT:
            'the CA certificate is shown by this service’s "CA Certificate" action',
        },
      },
      requires: ['own-volume'],
    })
    .addDaemon('satd', {
      subcontainer: satdSub,
      exec: {
        // The network is an argument, never a config-file line: satd accepts
        // `signet=1` in a file and then ignores it, silently running mainnet.
        // `--chain=` because there are bare flags for the test networks but
        // none for mainnet.
        command: ['satd', `--datadir=${rootDir}`, `--chain=${network}`],
        user: 'satd',
        // A node writing out its chainstate should not be killed mid-flush.
        sigtermTimeout: 600_000,
      },
      ready: {
        display: i18n('Node'),
        /**
         * satd's own readiness gate rather than a port check: /readyz reports
         * not-ready until the chainstate is loaded and every configured
         * listener is bound, which is what a dependent package needs "ready"
         * to mean. The probe is in the image and speaks HTTP over bash's
         * /dev/tcp, so it needs no curl in this thin image.
         */
        fn: async () => {
          const res = await satdSub.exec(['/usr/local/bin/satd-healthcheck'], {
            env: {
              SATD_HEALTH_URL: `http://127.0.0.1:${metricsPort}/readyz`,
            },
          })
          return res.exitCode === 0
            ? { result: 'success' as const, message: i18n('satd is ready') }
            : {
                result: 'starting' as const,
                message: i18n('satd is starting…'),
              }
        },
      },
      requires: ['satd-init'],
    })
    .addHealthCheck('sync-progress', {
      ready: {
        display: i18n('Blockchain Sync'),
        trigger: sdk.trigger.statusTrigger(30_000, {
          starting: 5_000,
          failure: 5_000,
        }),
        fn: async () => {
          const res = await probe<GetBlockchainInfo>('getblockchaininfo')
          if ('health' in res) return res.health
          const info = res.value

          if (!info.initialblockdownload)
            return {
              result: 'success' as const,
              message: i18n('satd is fully synced'),
            }

          // At genesis nothing sits above the tip yet and
          // verificationprogress is still 0 — the header chain is the only
          // thing moving, so reporting a percentage there reads as stuck.
          if (info.blocks === 0)
            return {
              result: 'loading' as const,
              message: info.headers
                ? i18n('Syncing block headers: ${count}', {
                    count: info.headers,
                  })
                : i18n('Syncing block headers…'),
            }

          return {
            result: 'loading' as const,
            message: i18n('Syncing blocks: ${percentage}%', {
              percentage: (info.verificationprogress * 100).toFixed(2),
            }),
          }
        },
      },
      requires: ['satd'],
    })
})
