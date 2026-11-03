package satdevents

// SDK <-> node version compatibility (STABILITY_POLICY.md, "Streaming API & SDK
// compatibility").
//
// A node advertises its version and event schema in two gRPC response headers
// on every stream. This file parses them and applies the rule: a node at or
// above this SDK's version is fine; one minor version behind warns; two or more
// minor versions (or a major version) behind is refused. The SDK does not track
// which node version added which feature.
//
// Everything here is pure, so the table can be tested with injected versions,
// and it mirrors satd-events-client's compat module name for name.

import (
	"strconv"
	"strings"

	"google.golang.org/grpc/metadata"
)

const (
	// versionHeader carries the node version ("satd-version").
	versionHeader = "satd-version"
	// schemaHeader carries the node's event schema version ("satd-events-schema").
	schemaHeader = "satd-events-schema"
)

// version is a major/minor pair. Patch numbers and -pre / +build suffixes never
// affect compatibility, so they are not kept.
type version struct {
	major, minor uint64
}

// headerlessNode is what a node that sends no (or an unparseable) satd-version
// header is taken to be: the headers first shipped in 0.6.0, so such a node is
// 0.5.x or older.
var headerlessNode = version{0, 5}

func (v version) less(o version) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	return v.minor < o.minor
}

// parseVersion parses MAJOR.MINOR[.PATCH][-suffix][+build].
func parseVersion(s string) (version, bool) {
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return version{}, false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return version{}, false
		}
		nums[i] = n
	}
	return version{major: nums[0], minor: nums[1]}, true
}

// compat is the outcome of comparing a node's version to the SDK's.
type compat int

const (
	// compatOK: the node is at or above the SDK's version.
	compatOK compat = iota
	// compatOneBehind: exactly one minor version behind - warn.
	compatOneBehind
	// compatTooOld: two or more minor versions, or a major version, behind -
	// refuse unless WithAllowOldNode was given.
	compatTooOld
)

// classify applies the compatibility rule.
func classify(sdk, node version) compat {
	switch {
	case !node.less(sdk):
		return compatOK
	case node.major != sdk.major:
		return compatTooOld
	case sdk.minor-node.minor == 1:
		return compatOneBehind
	default:
		return compatTooOld
	}
}

// nodeVersionFromMD returns the raw satd-version header ("" when absent) and
// the version to compare: the parsed header, or headerlessNode when it is
// missing or unparseable.
func nodeVersionFromMD(md metadata.MD) (string, version) {
	vals := md.Get(versionHeader)
	if len(vals) == 0 {
		return "", headerlessNode
	}
	raw := vals[0]
	if v, ok := parseVersion(raw); ok {
		return raw, v
	}
	return raw, headerlessNode
}

// headCursorHeader is the response metadata key carrying the stream's head
// cursor, "<height>:<tx_index>:<mempool_seq>:<instance_id>" in decimal (see
// docs/api/streaming.md).
const headCursorHeader = "satd-head-cursor"

// headCursorFromMD parses the head cursor. nil when the node sent none (no
// block source, or a node that predates the header) or one that does not
// parse: a malformed anchor must never be presented back to the node.
func headCursorFromMD(md metadata.MD) *Cursor {
	vals := md.Get(headCursorHeader)
	if len(vals) == 0 {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(vals[0]), ":")
	if len(parts) != 4 {
		return nil
	}
	var n [4]uint64
	for i, bits := range []int{32, 32, 64, 64} {
		v, err := strconv.ParseUint(parts[i], 10, bits)
		if err != nil {
			return nil
		}
		n[i] = v
	}
	return &Cursor{Height: uint32(n[0]), TxIndex: uint32(n[1]), MempoolSeq: n[2], InstanceID: n[3]}
}

// schemaFromMD returns the node's schema version from the satd-events-schema
// header. A node without the header predates it and speaks schema 1. A header
// that is present but not a number is reported as 0, which never matches.
func schemaFromMD(md metadata.MD) uint32 {
	vals := md.Get(schemaHeader)
	if len(vals) == 0 {
		return 1
	}
	n, err := strconv.ParseUint(strings.TrimSpace(vals[0]), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// displayNodeVersion is how a node version is shown in the warning and the
// ErrNodeTooOld message.
func displayNodeVersion(raw string) string {
	if raw == "" {
		return "(no version header; older than 0.6.0)"
	}
	return raw
}
