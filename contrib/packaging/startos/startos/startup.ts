/**
 * `getstartupinfo`, which satd's startup RPC answers while every other method
 * is still in warm-up (`-28`): through chain initialisation, and through a
 * chainstate rebuild that runs for hours on the first start after an update
 * that changes the storage format. Pure, so the tests can import it.
 */
export type GetStartupInfo = {
  started: boolean
  status: string
  phase: string
  current: number
  total: number
  stop_height: number | null
  percent: number | null
}

/**
 * The startup phases in which satd is rebuilding from its block files: a
 * `-reindex` (clearing, scanning, replaying) or a chainstate rebuild, which
 * is what `upgradechainstate=1` runs after a format change.
 */
export const rebuildPhases: readonly string[] = [
  'clearing_db',
  'reindex_scan',
  'reindex_connect',
  'reindex_chainstate',
]

/** What the Blockchain Sync check says while satd is starting. */
export type StartupMessage =
  | { kind: 'rebuilding'; current: number; total: number; percent: string }
  | { kind: 'starting'; status: string }

export const describeStartup = (info: GetStartupInfo): StartupMessage => {
  if (rebuildPhases.includes(info.phase) && info.total > 0) {
    const percent =
      info.percent ?? Math.round((info.current / info.total) * 1000) / 10
    return {
      kind: 'rebuilding',
      current: info.current,
      total: info.total,
      percent: percent.toFixed(1),
    }
  }
  return { kind: 'starting', status: info.status }
}
