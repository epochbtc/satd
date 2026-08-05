package main

import (
	"encoding/hex"
	"encoding/json"

	satdevents "github.com/epochbtc/satd/clients/go"
	"github.com/epochbtc/satd/clients/go/eventspb"
)

// Canonical rendering of an [satdevents.Event] as one JSON object.
//
// This is the contract the whole harness rests on: the Rust twin renders the
// same event to the same bytes, and the parity test is a plain line diff. Three
// rules make that possible.
//
//  1. Sorted keys. Every object is a map, and encoding/json sorts map keys;
//     serde_json's BTreeMap does the same. Neither side may use a struct, whose
//     field order is declaration order.
//
//  2. No absent keys. An optional field is emitted as an explicit null rather
//     than omitted, so a None on one side and a Some(0) on the other is a
//     visible diff instead of a silent one.
//
//  3. Enums render as their PROTO name, read from the generated descriptor
//     (Go's `<Enum>_name` table, prost's `as_str_name`). Both come from the same
//     .proto, so no hand-written mapping exists on either side to drift - and an
//     SDK that maps a wire value to the wrong constant still produces a
//     different name, which is exactly the divergence worth catching.
//
// Bytes are lowercase hex in INTERNAL order, as the SDK carries them. No field
// is reversed into display order anywhere in this file.
func render(ev satdevents.Event) map[string]any {
	switch e := ev.(type) {
	case *satdevents.MempoolEnter:
		// `time` is the node's wall clock at admission and is deliberately
		// dropped: it is identical in both dumps only by luck.
		return obj("mempool_enter", map[string]any{
			"txid":                 hexb(e.Txid),
			"fee":                  e.Fee,
			"vsize":                e.Vsize,
			"fee_rate_sat_per_kvb": e.FeeRateSatPerKvB,
		})
	case *satdevents.MempoolLeaveConfirmed:
		return obj("mempool_leave_confirmed", map[string]any{
			"txid":       hexb(e.Txid),
			"block_hash": hexb(e.BlockHash),
			"height":     e.Height,
		})
	case *satdevents.MempoolLeaveEvicted:
		return obj("mempool_leave_evicted", map[string]any{
			"txid":   hexb(e.Txid),
			"reason": enumName(eventspb.EvictReason_name, int32(e.Reason)),
		})
	case *satdevents.MempoolLeaveReplaced:
		return obj("mempool_leave_replaced", map[string]any{
			"txid":           hexb(e.Txid),
			"replacing_txid": hexb(e.ReplacingTxid),
		})

	case *satdevents.BlockConnected:
		return obj("block_connected", map[string]any{
			"hash": hexb(e.Hash), "height": e.Height,
		})
	case *satdevents.BlockDisconnected:
		return obj("block_disconnected", map[string]any{
			"hash": hexb(e.Hash), "height": e.Height,
		})
	case *satdevents.Reorg:
		return obj("reorg", map[string]any{
			"from_height": e.FromHeight,
			"old_tip":     hexb(e.OldTip),
			"to_height":   e.ToHeight,
			"new_tip":     hexb(e.NewTip),
		})
	case *satdevents.Heartbeat:
		// Rendered but normally filtered out before the diff: heartbeats are
		// timer-driven, so two independently-connected clients see different
		// counts of them. uptime_ns is dropped for the same reason as `time`.
		return obj("heartbeat", map[string]any{})
	case *satdevents.Status:
		return obj("status", map[string]any{
			"kind":     enumName(eventspb.StatusKind_name, int32(e.Kind)),
			"state":    enumName(eventspb.StatusState_name, int32(e.State)),
			"severity": enumName(eventspb.StatusSeverity_name, int32(e.Severity)),
			"message":  e.Message,
			"details":  strMap(e.Details),
		})

	case *satdevents.OutpointSpent:
		return obj("outpoint_spent", map[string]any{
			"outpoint":      outpoint(e.Outpoint),
			"spending_txid": hexb(e.SpendingTxid),
			"spending_vin":  e.SpendingVin,
			"confirmed":     e.Confirmed,
		})
	case *satdevents.ScriptMatched:
		return obj("script_matched", map[string]any{
			"scripthash":  hexb(e.Scripthash),
			"txid":        hexb(e.Txid),
			"is_output":   e.IsOutput,
			"index":       e.Index,
			"confirmed":   e.Confirmed,
			"amount":      optU64(e.Amount),
			"raw_tx":      hexb(e.RawTx),
			"descriptors": descriptors(e.Descriptors),
		})
	case *satdevents.TxidMatched:
		return obj("txid_matched", map[string]any{
			"txid": hexb(e.Txid), "confirmed": e.Confirmed, "height": e.Height,
		})
	case *satdevents.TxidReplaced:
		return obj("txid_replaced", map[string]any{
			"txid": hexb(e.Txid), "replacing_txid": hexb(e.ReplacingTxid),
		})
	case *satdevents.TxidEvicted:
		return obj("txid_evicted", map[string]any{
			"txid": hexb(e.Txid), "reason": e.Reason,
		})
	case *satdevents.TxidUnconfirmed:
		return obj("txid_unconfirmed", map[string]any{
			"txid": hexb(e.Txid), "prev_height": e.PrevHeight,
		})
	case *satdevents.TxidDepthReached:
		return obj("txid_depth_reached", map[string]any{
			"txid": hexb(e.Txid), "depth": e.Depth, "height": e.Height,
		})
	case *satdevents.TxidFinalized:
		return obj("txid_finalized", map[string]any{
			"txid": hexb(e.Txid), "depth": e.Depth, "height": e.Height,
		})

	case *satdevents.PrefixMatched:
		return obj("prefix_matched", map[string]any{
			"prefix":           prefix(e.Prefix),
			"raw_tx":           hexb(e.RawTx),
			"confirmed":        e.Confirmed,
			"height":           e.Height,
			"matched_prevouts": prevouts(e.MatchedPrevouts),
		})
	case *satdevents.SilentPaymentMatched:
		return obj("silent_payment_matched", map[string]any{
			"scan_pubkey":   hexb(e.ScanPubkey),
			"txid":          hexb(e.Txid),
			"vout":          e.Vout,
			"output_pubkey": hexb(e.OutputPubkey),
			"amount":        e.Amount,
			"tweak":         hexb(e.Tweak),
			"k":             e.K,
			"label":         optU32(e.Label),
			"confirmed":     e.Confirmed,
			"height":        optU32(e.Height),
			"raw_tx":        hexb(e.RawTx),
		})
	case *satdevents.BlockTweaks:
		return obj("block_tweaks", map[string]any{
			"block_hash": hexb(e.BlockHash),
			"height":     e.Height,
			"entries":    tweakEntries(e.Entries),
			"filtered":   e.Filtered,
		})
	case *satdevents.MempoolTweak:
		return obj("mempool_tweak", map[string]any{"entry": tweakEntry(e.Entry)})

	case *satdevents.Lagged:
		return obj("lagged", map[string]any{
			"dropped_count": e.DroppedCount,
			"resume_cursor": optCursor(e.ResumeCursor),
		})
	case *satdevents.ReplayGap:
		return obj("replay_gap", map[string]any{
			"resume_height": e.ResumeHeight, "first_height": e.FirstHeight,
		})
	case *satdevents.CursorAccepted:
		return obj("cursor_accepted", map[string]any{
			"from":              optCursor(e.From),
			"clamped":           e.Clamped,
			"earliest_replayed": e.EarliestReplayed,
		})
	case *satdevents.CursorRejected:
		return obj("cursor_rejected", map[string]any{
			"reason":       enumName(eventspb.CursorRejected_Reason_name, int32(e.Reason)),
			"current_head": optCursor(e.CurrentHead),
		})
	case *satdevents.WatchSetReplaced:
		return obj("watch_set_replaced", map[string]any{
			"added": e.Added, "removed": e.Removed, "unchanged": e.Unchanged,
		})
	case *satdevents.WatchSetRejected:
		return obj("watch_set_rejected", map[string]any{
			"reason":   enumName(eventspb.WatchSetRejected_Reason_name, int32(e.Reason)),
			"required": e.Required,
			"quota":    e.Quota,
		})
	case *satdevents.RescanAccepted:
		return obj("rescan_accepted", map[string]any{
			"from_height": e.FromHeight, "to_height": e.ToHeight, "clamped": e.Clamped,
		})
	case *satdevents.RescanRejected:
		return obj("rescan_rejected", map[string]any{
			"reason":     enumName(eventspb.RescanRejected_Reason_name, int32(e.Reason)),
			"tip_height": e.TipHeight,
		})
	case *satdevents.RescanComplete:
		return obj("rescan_complete", map[string]any{
			"from_height": e.FromHeight, "to_height": e.ToHeight, "matches": e.Matches,
		})

	case *satdevents.UnknownEvent:
		// A variant the SDK does not know is itself a parity-relevant fact: if
		// one side decodes a payload and the other files it here, that is the
		// missing-variant case the harness exists to catch.
		return obj("unknown", map[string]any{})
	}
	// Unreachable while Event stays sealed, but a nil return would render as a
	// bare `null` line and read like a protocol event.
	return obj("unrenderable", map[string]any{})
}

func obj(kind string, fields map[string]any) map[string]any {
	fields["type"] = kind
	return fields
}

func hexb(b []byte) string { return hex.EncodeToString(b) }

// enumName renders a proto enum value by its generated name. An unmapped value
// is rendered with its number rather than as an empty string, so a wire enum
// newer than this build is legible in the diff instead of blank.
func enumName(table map[int32]string, v int32) string {
	if name, ok := table[v]; ok {
		return name
	}
	return "UNKNOWN(" + itoa(v) + ")"
}

func itoa(v int32) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func optU64(v *uint64) any {
	if v == nil {
		return nil
	}
	return *v
}

func optU32(v *uint32) any {
	if v == nil {
		return nil
	}
	return *v
}

func optCursor(c *satdevents.Cursor) any {
	if c == nil {
		return nil
	}
	return map[string]any{
		"height":      c.Height,
		"tx_index":    c.TxIndex,
		"mempool_seq": c.MempoolSeq,
		// instance_id is the publisher's incarnation id. It changes on every
		// node restart and is unequal between two clients only if one of them
		// reconnected across one, so it carries no parity signal and is dropped.
	}
}

func outpoint(o satdevents.Outpoint) map[string]any {
	return map[string]any{"txid": hexb(o.Txid), "vout": o.Vout}
}

func prefix(p satdevents.ScriptPrefix) map[string]any {
	return map[string]any{"prefix": hexb(p.Prefix), "bits": p.Bits}
}

func descriptors(ds []satdevents.DescriptorMatch) []any {
	out := make([]any, 0, len(ds))
	for _, d := range ds {
		out = append(out, map[string]any{
			"descriptor":       d.Descriptor,
			"branch":           d.Branch,
			"derivation_index": d.DerivationIndex,
		})
	}
	return out
}

func prevouts(ps []satdevents.SpentPrevout) []any {
	out := make([]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, map[string]any{
			"outpoint":      outpoint(p.Outpoint),
			"script_pubkey": hexb(p.ScriptPubkey),
			"amount":        optU64(p.Amount),
		})
	}
	return out
}

func tweakEntry(e satdevents.TweakEntry) map[string]any {
	outs := make([]any, 0, len(e.TaprootOutputs))
	for _, t := range e.TaprootOutputs {
		outs = append(outs, map[string]any{
			"vout":          t.Vout,
			"output_pubkey": hexb(t.OutputPubkey),
			"value":         t.Value,
		})
	}
	return map[string]any{
		"tweak":           hexb(e.Tweak),
		"txid":            hexb(e.Txid),
		"max_value":       e.MaxValue,
		"taproot_outputs": outs,
	}
}

func tweakEntries(es []satdevents.TweakEntry) []any {
	out := make([]any, 0, len(es))
	for _, e := range es {
		out = append(out, tweakEntry(e))
	}
	return out
}

func strMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
