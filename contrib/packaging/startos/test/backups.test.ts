import { ok, deepEqual } from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { upstream } from './upstream.ts'

/**
 * The backup exclusions name directories satd writes, and nothing else. They
 * were first written from Bitcoin Core's layout: `indexes/` and `debug.log`,
 * neither of which satd creates, and no `chainstate_background/`, which it
 * does, and which is large for as long as an AssumeUTXO snapshot validates.
 * A wrong name here is not an error anywhere; the backup just grows by the
 * size of the directory it missed.
 */
const src = readFileSync(new URL('../startos/backups.ts', import.meta.url), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:])\/\/.*$/gm, '$1')

const excluded = [...src.matchAll(/'([^']+)'/g)]
  .map((m) => m[1])
  .filter((s) => s !== 'main' && s !== './sdk')

test('every large directory satd writes is excluded, at the root and per network', () => {
  for (const dir of ['blocks/', 'chainstate/', 'chainstate_background/']) {
    ok(excluded.includes(dir), `${dir} is not excluded`)
    ok(excluded.includes(`*/${dir}`), `*/${dir} is not excluded`)
  }
})

/**
 * Skipped in the published package repository, which does not carry satd's
 * storage code. satd's CI runs it on every change to this package.
 */
const store = upstream('node/src/storage/rocksdb_store.rs')
test('the directory names match the ones satd opens', { skip: store === null && 'satd source not present' }, () => {
  if (store === null) return
  ok(store.includes('path.join("chainstate")'), 'satd no longer opens chainstate/')
  ok(
    store.includes('datadir.join("chainstate_background")'),
    'satd no longer opens chainstate_background/',
  )
})

test('nothing from Core’s layout that satd never creates', () => {
  deepEqual(
    excluded.filter((e) => /indexes|debug\.log/.test(e)),
    [],
  )
})
