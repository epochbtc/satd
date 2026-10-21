import { VersionGraph } from '@start9labs/start-sdk'
import { current } from './current'
import { v0_6_0 } from './v0.6.0'

export const versionGraph = VersionGraph.of({
  current,
  other: [v0_6_0],
})
