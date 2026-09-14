import { existsSync, readFileSync } from 'node:fs'

/**
 * A file from satd's own tree, which some tests check this package against.
 *
 * In the satd repository the package lives at `contrib/packaging/startos/` and
 * reads the file where it is. The published package repository is a copy of
 * this directory alone, so `contrib/packaging/sync-store.sh` vendors each file
 * a test needs into `test/upstream/`, from the same satd commit. The in-tree
 * path wins when both exist, so a vendored copy can never mask drift in satd.
 *
 * Returns `null` for a file that is in neither place; the test decides whether
 * that is a skip or a failure.
 */
export const upstream = (satdPath: string): string | null => {
  const inTree = new URL(`../../../../${satdPath}`, import.meta.url)
  if (existsSync(inTree)) return readFileSync(inTree, 'utf8')
  const vendored = new URL(`./upstream/${satdPath.split('/').pop()}`, import.meta.url)
  if (existsSync(vendored)) return readFileSync(vendored, 'utf8')
  return null
}
