import { match, doesNotMatch } from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

/**
 * The Network action's only effect is a write to the store. Nothing restarts
 * the node on its own: main re-runs — and so re-runs satd-init and satd with
 * the new `--chain=` — only because it reads the store with `.const`, which
 * the SDK defines as "reruns the context from which it has been called if the
 * underlying value changes". `.once` is the same call with that behaviour
 * removed.
 *
 * Swapping one for the other is not a type error, and every other test still
 * passes: the store updates, the UI shows the new network, the P2P port even
 * rebinds because interfaces.ts reads it reactively. Only the daemon stays on
 * the old chain, silently, until something else restarts it. That is what
 * shipped, and it took installing on a server to see.
 */
/**
 * Read a source file with its comments stripped. These assertions are about
 * what the code does, and the comments here discuss the very constructs being
 * asserted against — `/readyz` is named in main.ts precisely to say it is not
 * used, and a naive grep reads that as the defect.
 */
const read = (p: string) =>
  readFileSync(new URL(p, import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')

test('main reads the store reactively, so the Network action takes effect', () => {
  const src = read('../startos/main.ts')
  match(src, /storeJson\.read\(\)\.const\(effects\)/)
  doesNotMatch(src, /storeJson\.read\([^)]*\)\.once\(\)/)
})

test('interfaces reads the store reactively, so the P2P port follows', () => {
  const src = read('../startos/interfaces.ts')
  match(src, /storeJson\.read\([\s\S]*?\)\.const\(effects\)/)
})

/**
 * `/readyz` is 503 until the tip is within six blocks of the headers tip.
 * As the daemon's ready gate that means the service never finishes starting
 * during an initial sync, and `sync-progress`, which requires it, never runs
 * — so the one screen the instructions tell the user to watch shows nothing
 * for the days it matters.
 */
test('the ready gate probes liveness, not readiness', () => {
  const src = read('../startos/main.ts')
  match(src, /satdSub\.exec\(\['\/usr\/local\/bin\/satd-healthcheck'\]\)/)
  doesNotMatch(src, /readyz/)
  doesNotMatch(src, /SATD_HEALTH_URL/)
})

/**
 * MCP's transport refuses any `Host` outside its allowlist, and the StartOS
 * proxy forwards the client's `Host` unchanged rather than validating or
 * rewriting it — so on this platform satd's check is the only one on that
 * path, and it sees whatever name the user typed. The MCP Hostnames action is
 * how those names reach it: the action writes the store, main reads the store
 * reactively, and satd-init turns the value into `mcpallowedhost=` lines.
 *
 * Dropping the environment variable is not a type error and breaks nothing
 * visible — every other interface keeps working, the action keeps accepting
 * input, and only MCP-by-hostname goes back to answering 403.
 */
test('the MCP hostnames reach satd-init', () => {
  const src = read('../startos/main.ts')
  match(src, /SATD_MCP_ALLOWED_HOSTS:\s*mcpHostnames/)
  match(src, /const \{[^}]*mcpHostnames[^}]*\} = store/)
})

/**
 * satd is deliberately never told to accept any `Host`: the allowlist is
 * additive, and a package that emptied it would hand a rebound browser the
 * whole MCP tool surface.
 */
test('the package never disables the MCP Host check', () => {
  const src = read('../startos/main.ts')
  doesNotMatch(src, /mcpallowanyhost|disable_allowed_hosts|mcptrustedproxy/i)
})
