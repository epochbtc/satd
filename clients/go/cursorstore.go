package satdevents

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CursorStore persists the durable resume [Cursor] across reconnects and
// process restarts.
//
// The resilience loop loads it on (re)connect and persists COMMIT-ON-POLL: a
// delivered event's cursor is written only once the caller has come back for
// the following event, which is an implicit ack. The store therefore never
// advances past an event the caller has not yet received, so a crash
// mid-processing replays that event on resume - at-least-once, not
// at-most-once. A consumer that needs exactly-once still dedups on its own
// side, keyed by the (height, hash) it processes.
//
// Implementations must be cheap to call and may be invoked roughly once per
// delivered confirmed cursor (redundant writes for an unchanged cursor are
// elided by the loop), and must be safe for concurrent use. A failing Store is
// surfaced to the caller rather than swallowed: a store that cannot persist
// would otherwise resume from a stale anchor after a crash, silently skipping
// everything in between.
type CursorStore interface {
	// Load returns the last persisted cursor, or nil if none has been saved.
	Load(ctx context.Context) (*Cursor, error)
	// Store persists cursor as the new resume anchor.
	Store(ctx context.Context, cursor Cursor) error
}

// NoopCursorStore persists nothing: Load is always nil, Store is a no-op.
//
// The default. Reconnects still resume from the in-memory last cursor, but a
// process restart starts forward-only.
type NoopCursorStore struct{}

// Load implements [CursorStore].
func (NoopCursorStore) Load(context.Context) (*Cursor, error) { return nil, nil }

// Store implements [CursorStore].
func (NoopCursorStore) Store(context.Context, Cursor) error { return nil }

// FileCursorStore is a [CursorStore] backed by a single file, written
// atomically (temp file + rename) so a crash mid-write never leaves a torn
// cursor.
//
// The on-disk format is one line of four whitespace-separated integers -
// `height tx_index mempool_seq instance_id` - which is stable, trivially
// inspectable, and BYTE-IDENTICAL to the Rust SDK's FileCursorStore, so the two
// can share a cursor file (during a migration, or when a Go and a Rust consumer
// hand off). A missing file loads as nil.
type FileCursorStore struct {
	path string
}

// NewFileCursorStore backs a store with path. The file is created on the first
// Store; a missing file is a clean "no cursor yet".
func NewFileCursorStore(path string) *FileCursorStore {
	return &FileCursorStore{path: path}
}

// Load implements [CursorStore].
func (f *FileCursorStore) Load(context.Context) (*Cursor, error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, wrapError(KindDecode, err, "cursor store read: %s", err)
	}
	c, err := parseCursorLine(string(raw))
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Store implements [CursorStore].
func (f *FileCursorStore) Store(_ context.Context, cursor Cursor) error {
	line := fmt.Sprintf("%d %d %d %d\n",
		cursor.Height, cursor.TxIndex, cursor.MempoolSeq, cursor.InstanceID)

	// Write to a sibling temp file, then rename: rename is atomic on the same
	// filesystem, so a reader never observes a partial line. The temp name comes
	// from os.CreateTemp rather than a derived one, because two writers sharing a
	// cursor path (two subscriptions, or two processes) must not collide on an
	// in-flight temp and rename each other's partial file.
	dir, base := filepath.Split(f.path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return wrapError(KindDecode, err, "cursor store temp: %s", err)
	}
	name := tmp.Name()
	// From here on the temp must not outlive a failure.
	defer func() { _ = os.Remove(name) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return wrapError(KindDecode, err, "cursor store chmod: %s", err)
	}
	if _, err := tmp.WriteString(line); err != nil {
		_ = tmp.Close()
		return wrapError(KindDecode, err, "cursor store write: %s", err)
	}
	// Flush to the device before the rename. Without this the rename can land
	// while the contents are still only in the page cache, and a power loss
	// leaves a zero-length cursor file - exactly the torn state the temp+rename
	// dance exists to prevent.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return wrapError(KindDecode, err, "cursor store sync: %s", err)
	}
	if err := tmp.Close(); err != nil {
		return wrapError(KindDecode, err, "cursor store close: %s", err)
	}
	if err := os.Rename(name, f.path); err != nil {
		return wrapError(KindDecode, err, "cursor store rename: %s", err)
	}
	return nil
}

// Path is the file this store persists to.
func (f *FileCursorStore) Path() string { return filepath.Clean(f.path) }

// parseCursorLine parses the four-integer line [FileCursorStore] writes.
//
// Each field is parsed at its real width - height and tx_index as 32-bit, not
// 64-bit-then-truncate - so a corrupt out-of-range value is a clean error
// rather than a silently truncated cursor that resumes from the wrong height.
func parseCursorLine(text string) (Cursor, error) {
	fields := strings.Fields(text)
	if len(fields) < 4 {
		return Cursor{}, newError(KindDecode,
			"cursor store: want 4 fields, got %d", len(fields))
	}
	height, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return Cursor{}, newError(KindDecode, "cursor store: bad height: %s", err)
	}
	txIndex, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return Cursor{}, newError(KindDecode, "cursor store: bad tx_index: %s", err)
	}
	mempoolSeq, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return Cursor{}, newError(KindDecode, "cursor store: bad mempool_seq: %s", err)
	}
	instanceID, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return Cursor{}, newError(KindDecode, "cursor store: bad instance_id: %s", err)
	}
	return Cursor{
		Height:     uint32(height),
		TxIndex:    uint32(txIndex),
		MempoolSeq: mempoolSeq,
		InstanceID: instanceID,
	}, nil
}
