import { match, ok } from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const read = (p: string) =>
  readFileSync(new URL(p, import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')

/**
 * The service's UI is satd's status page. satd-init writes the page's keys
 * only for a satd that has them, so an older image still starts, but "Launch
 * UI" would open onto a 404. The page first ships in satd 0.6.0.
 *
 * Between releases the manifest pins a master commit's `sha-` image instead.
 * Whether that commit has the page is a question about git history, which
 * compose-test.sh answers for both packages; here it only has to be a `sha-`
 * pin rather than an older release.
 */
test('the status page is on, and the pinned satd has it', () => {
  match(read('../startos/main.ts'), /SATD_STATUSPAGE:\s*'1'/)
  const manifest = read('../startos/manifest/index.ts')
  if (/ghcr\.io\/epochbtc\/satd:sha-[0-9a-f]{7,40}@sha256:[0-9a-f]{64}'/.test(manifest)) return
  const tag = manifest.match(/ghcr\.io\/epochbtc\/satd:(\d+)\.(\d+)\.(\d+)@/)
  ok(tag, 'the manifest pins neither a release nor a sha- image')
  const [major, minor] = [Number(tag[1]), Number(tag[2])]
  ok(
    major > 0 || minor >= 6,
    `the manifest pins satd ${tag[1]}.${tag[2]}.${tag[3]}, which has no status page (0.6.0)`,
  )
})

test('the status page is exported as the UI, at /status', () => {
  const src = read('../startos/interfaces.ts')
  match(src, /id: statusInterfaceId,[\s\S]*?type: 'ui',[\s\S]*?path: '\/status'/)
  match(src, /bindPort\(\s*metricsPort/)
})
