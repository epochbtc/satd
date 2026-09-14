package satdevents

// Version is this SDK's version. It equals the satd node version it was
// released with: the module is tagged clients/go/vX.Y.Z at the node's vX.Y.Z
// commit, even when no Go code changed. TestVersionMatchesWorkspace pins it to
// the workspace Cargo.toml, so a version bump that misses this file fails CI.
const Version = "0.6.0-pre"

// schemaVersion is the NodeEvent.schema_version this SDK decodes. It mirrors
// SCHEMA_VERSION in the satd node; the two are bumped together.
const schemaVersion = 1
