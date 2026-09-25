import { deepStrictEqual, ok } from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { describeStartup, rebuildPhases } from '../startos/startup.ts'
import { upstream } from './upstream.ts'

const info = (phase: string, over: Record<string, unknown> = {}) => ({
  started: false,
  status: 'Replaying UTXO set',
  phase,
  current: 412_930,
  total: 967_870,
  stop_height: null,
  percent: 42.7,
  ...over,
})

/**
 * The first start after an update that changes the chainstate format
 * rebuilds it for hours. "satd is starting…" for all of that reads as a hang;
 * the check says how far the rebuild has got instead.
 */
test('a chainstate rebuild reads as progress', () => {
  deepStrictEqual(describeStartup(info('reindex_chainstate')), {
    kind: 'rebuilding',
    current: 412_930,
    total: 967_870,
    percent: '42.7',
  })
  deepStrictEqual(describeStartup(info('reindex_chainstate', { percent: null })).kind, 'rebuilding')
  deepStrictEqual(
    describeStartup(info('reindex_chainstate', { percent: null })),
    { kind: 'rebuilding', current: 412_930, total: 967_870, percent: '42.7' },
    'without satd’s percent, the same figure is derived',
  )
})

test('any other startup phase says what satd is doing', () => {
  deepStrictEqual(describeStartup(info('chain_init', { status: 'Loading block index' })), {
    kind: 'starting',
    status: 'Loading block index',
  })
  // A rebuild phase before the total is known has no progress to show.
  deepStrictEqual(describeStartup(info('clearing_db', { total: 0, status: 'Clearing' })), {
    kind: 'starting',
    status: 'Clearing',
  })
})

/** The phase names are satd's; a renamed phase would silently read as "starting". */
const sources = ['satd/src/main.rs', 'node/src/chain/state.rs'].map(upstream)
test(
  'the rebuild phases are ones satd sets',
  { skip: sources.includes(null) && 'satd source not present' },
  () => {
    const src = sources.join('\n')
    for (const phase of rebuildPhases)
      ok(src.includes(`set_phase("${phase}"`), `satd never sets the phase ${phase}`)
  },
)

/** The check asks for startup progress only when the node is not answering yet. */
test('the sync check falls back to getstartupinfo', () => {
  const main = readFileSync(new URL('../startos/main.ts', import.meta.url), 'utf8')
  ok(/probe<GetStartupInfo>\('getstartupinfo'\)/.test(main))
})
