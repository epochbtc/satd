import { match, ok } from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { upstream } from './upstream.ts'

const read = (p: string) =>
  readFileSync(new URL(p, import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')

/**
 * StartOS starts every daemon with RUST_LOG=warn,start_core=debug in its
 * environment, and satd reads RUST_LOG in preference to its own default of
 * info. A package that passes no RUST_LOG gets a service log of warnings
 * only: on a StartOS server the log said nothing of sync progress, a
 * reindex's phases or the steps of a shutdown.
 */
test('satd runs with RUST_LOG=info, not the RUST_LOG StartOS hands it', () => {
  const main = read('../startos/main.ts')
  const start = main.indexOf(".addDaemon('satd',")
  ok(start >= 0, "main.ts has no addDaemon('satd', …)")
  // Up to the next step of the chain (.addHealthCheck, .addOneshot, …).
  const rest = main.slice(start + 1)
  const next = rest.search(/\.add[A-Z]\w*\(/)
  const daemon = next < 0 ? rest : rest.slice(0, next)
  match(daemon, /env:\s*\{[^}]*RUST_LOG:\s*'info'/)
})

const config = upstream('satd/src/config.rs')
test(
  'satd takes its log filter from RUST_LOG',
  { skip: config === null && 'satd source not present' },
  () => {
    ok(
      config!.includes('std::env::var("RUST_LOG")'),
      'satd no longer reads RUST_LOG; the env line in main.ts may be moot',
    )
  },
)
