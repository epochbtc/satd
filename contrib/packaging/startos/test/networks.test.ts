import { deepStrictEqual } from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { networks, p2pPorts } from '../startos/networks.ts'

/**
 * satd-init owns both of these facts: which network names it accepts (it
 * exits 2 on anything else) and which P2P port each one uses (it refuses to
 * start when SATD_P2P_PORT disagrees). This package restates both, so it can
 * offer the networks in a dropdown and bind the right peer port.
 *
 * A restatement that drifts is not a compile error and not a lint error — it
 * is a service that fails at first start, on the one network nobody tried.
 * So read satd-init and compare, rather than trusting two lists to stay
 * equal by inspection.
 */
const initScript = readFileSync(
  new URL('../../../stack/satd/satd-init', import.meta.url),
  'utf8',
)

/** The `case "$NETWORK" in` arm that assigns P2P_PORT, as satd-init writes it. */
const parsePorts = (src: string): Record<string, number> => {
  const block = src.match(
    /case "\$NETWORK" in\n([\s\S]*?)\n\s*\*\)\n[\s\S]*?esac/,
  )
  if (!block) throw new Error('could not find satd-init\'s NETWORK case block')
  const found: Record<string, number> = {}
  for (const m of block[1].matchAll(/^\s*(\w+)\)\s*P2P_PORT=(\d+)\s*;;/gm)) {
    found[m[1]] = Number(m[2])
  }
  if (!Object.keys(found).length)
    throw new Error('parsed satd-init\'s case block but found no arms')
  return found
}

test('the offered networks are the ones satd-init accepts', () => {
  deepStrictEqual(
    Object.keys(networks).sort(),
    Object.keys(parsePorts(initScript)).sort(),
  )
})

test('every P2P port matches satd-init', () => {
  deepStrictEqual({ ...p2pPorts }, parsePorts(initScript))
})
