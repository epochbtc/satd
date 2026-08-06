package satdevents

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// fixture pairs a populated wire event with the Go type it must decode to.
//
// The event is held whole rather than as a bare oneof wrapper because
// protoc-gen-go keeps the wrapper interface (isNodeEvent_Body) unexported, so
// it cannot be named from this package.
type fixture struct {
	ev   *eventspb.NodeEvent
	want Event
}

// bodyFixtures is one populated NodeEvent per arm of the wire NodeEvent.body
// oneof, keyed by the proto field name.
//
// This table is the decoder's coverage contract. The test below walks the
// NodeEvent descriptor and fails if the proto has an arm this table does not -
// so a schema addition that lands without Go support fails on the PR that adds
// it, not at some later release. (The Rust SDK gets the same guarantee from an
// exhaustive match; Go has no compiler equivalent, so it is a test.)
//
// The fixtures are populated rather than empty on purpose: several arms wrap a
// nested oneof (mempool, chain, the three *_result frames) and an unpopulated
// one legitimately decodes to UnknownEvent, which would make an
// empty-message version of this test vacuous.
var bodyFixtures = map[string]fixture{
	"mempool": {
		ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
			Mempool: &eventspb.MempoolEvent{
				Body: &eventspb.MempoolEvent_Enter{Enter: &eventspb.MempoolEnter{}},
			},
		}},
		want: &MempoolEnter{},
	},
	"chain": {
		ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Chain{
			Chain: &eventspb.ChainEvent{
				Body: &eventspb.ChainEvent_BlockConnected{BlockConnected: &eventspb.BlockConnected{}},
			},
		}},
		want: &BlockConnected{},
	},
	"heartbeat": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Heartbeat{Heartbeat: &eventspb.Heartbeat{}}},
		want: &Heartbeat{},
	},
	"status": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Status{Status: &eventspb.StatusEvent{}}},
		want: &Status{},
	},
	"outpoint_spent": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_OutpointSpent{OutpointSpent: &eventspb.OutpointSpent{}}},
		want: &OutpointSpent{},
	},
	"script_matched": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_ScriptMatched{ScriptMatched: &eventspb.ScriptMatched{}}},
		want: &ScriptMatched{},
	},
	"txid_matched": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidMatched{TxidMatched: &eventspb.TxidMatched{}}},
		want: &TxidMatched{},
	},
	"txid_replaced": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidReplaced{TxidReplaced: &eventspb.TxidReplaced{}}},
		want: &TxidReplaced{},
	},
	"txid_evicted": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidEvicted{TxidEvicted: &eventspb.TxidEvicted{}}},
		want: &TxidEvicted{},
	},
	"txid_unconfirmed": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidUnconfirmed{TxidUnconfirmed: &eventspb.TxidUnconfirmed{}}},
		want: &TxidUnconfirmed{},
	},
	"txid_depth_reached": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidDepthReached{TxidDepthReached: &eventspb.TxidDepthReached{}}},
		want: &TxidDepthReached{},
	},
	"txid_finalized": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidFinalized{TxidFinalized: &eventspb.TxidFinalized{}}},
		want: &TxidFinalized{},
	},
	"prefix_matched": {
		ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_PrefixMatched{
			PrefixMatched: &eventspb.PrefixMatched{
				Prefix: &eventspb.ScriptPrefix{Prefix: []byte{0xab, 0xcd}, Bits: 16},
			},
		}},
		want: &PrefixMatched{},
	},
	"silent_payment_matched": {
		ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SilentPaymentMatched{
			SilentPaymentMatched: &eventspb.SilentPaymentMatched{},
		}},
		want: &SilentPaymentMatched{},
	},
	"block_tweaks": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_BlockTweaks{BlockTweaks: &eventspb.BlockTweaks{}}},
		want: &BlockTweaks{},
	},
	"mempool_tweak": {
		ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_MempoolTweak{
			MempoolTweak: &eventspb.MempoolTweak{Entry: &eventspb.TweakEntry{}},
		}},
		want: &MempoolTweak{},
	},
	"lagged": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Lagged{Lagged: &eventspb.Lagged{}}},
		want: &Lagged{},
	},
	"set_cursor_result": {
		ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
			SetCursorResult: &eventspb.SetCursorResult{
				Outcome: &eventspb.SetCursorResult_Accepted{Accepted: &eventspb.CursorAccepted{}},
			},
		}},
		want: &CursorAccepted{},
	},
	"set_watch_set_result": {
		ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetWatchSetResult{
			SetWatchSetResult: &eventspb.WatchSetResult{
				Outcome: &eventspb.WatchSetResult_Accepted{Accepted: &eventspb.WatchSetAccepted{}},
			},
		}},
		want: &WatchSetReplaced{},
	},
	"rescan_result": {
		ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_RescanResult{
			RescanResult: &eventspb.RescanResult{
				Outcome: &eventspb.RescanResult_Accepted{Accepted: &eventspb.RescanAccepted{}},
			},
		}},
		want: &RescanAccepted{},
	},
	"rescan_complete": {
		ev:   &eventspb.NodeEvent{Body: &eventspb.NodeEvent_RescanComplete{RescanComplete: &eventspb.RescanComplete{}}},
		want: &RescanComplete{},
	},
}

// nestedOneofFixtures covers the arms one level down - inside the mempool and
// chain envelopes, and inside each control-result frame's accepted/rejected
// outcome. The NodeEvent walk cannot see them, so they get their own walks.
var nestedOneofFixtures = map[string]map[string]fixture{
	"satd.events.v1.MempoolEvent": {
		"enter": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
				Mempool: &eventspb.MempoolEvent{
					Body: &eventspb.MempoolEvent_Enter{Enter: &eventspb.MempoolEnter{}},
				},
			}},
			want: &MempoolEnter{},
		},
		"leave_confirmed": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
				Mempool: &eventspb.MempoolEvent{
					Body: &eventspb.MempoolEvent_LeaveConfirmed{LeaveConfirmed: &eventspb.MempoolLeaveConfirmed{}},
				},
			}},
			want: &MempoolLeaveConfirmed{},
		},
		"leave_evicted": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
				Mempool: &eventspb.MempoolEvent{
					Body: &eventspb.MempoolEvent_LeaveEvicted{LeaveEvicted: &eventspb.MempoolLeaveEvicted{}},
				},
			}},
			want: &MempoolLeaveEvicted{},
		},
		"leave_replaced": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
				Mempool: &eventspb.MempoolEvent{
					Body: &eventspb.MempoolEvent_LeaveReplaced{LeaveReplaced: &eventspb.MempoolLeaveReplaced{}},
				},
			}},
			want: &MempoolLeaveReplaced{},
		},
	},
	"satd.events.v1.ChainEvent": {
		"block_connected": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Chain{
				Chain: &eventspb.ChainEvent{
					Body: &eventspb.ChainEvent_BlockConnected{BlockConnected: &eventspb.BlockConnected{}},
				},
			}},
			want: &BlockConnected{},
		},
		"block_disconnected": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Chain{
				Chain: &eventspb.ChainEvent{
					Body: &eventspb.ChainEvent_BlockDisconnected{BlockDisconnected: &eventspb.BlockDisconnected{}},
				},
			}},
			want: &BlockDisconnected{},
		},
		"reorg": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Chain{
				Chain: &eventspb.ChainEvent{Body: &eventspb.ChainEvent_Reorg{Reorg: &eventspb.Reorg{}}},
			}},
			want: &Reorg{},
		},
	},
	"satd.events.v1.SetCursorResult": {
		"accepted": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
				SetCursorResult: &eventspb.SetCursorResult{
					Outcome: &eventspb.SetCursorResult_Accepted{Accepted: &eventspb.CursorAccepted{}},
				},
			}},
			want: &CursorAccepted{},
		},
		"rejected": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
				SetCursorResult: &eventspb.SetCursorResult{
					Outcome: &eventspb.SetCursorResult_Rejected{Rejected: &eventspb.CursorRejected{}},
				},
			}},
			want: &CursorRejected{},
		},
	},
	"satd.events.v1.WatchSetResult": {
		"accepted": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetWatchSetResult{
				SetWatchSetResult: &eventspb.WatchSetResult{
					Outcome: &eventspb.WatchSetResult_Accepted{Accepted: &eventspb.WatchSetAccepted{}},
				},
			}},
			want: &WatchSetReplaced{},
		},
		"rejected": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetWatchSetResult{
				SetWatchSetResult: &eventspb.WatchSetResult{
					Outcome: &eventspb.WatchSetResult_Rejected{Rejected: &eventspb.WatchSetRejected{}},
				},
			}},
			want: &WatchSetRejected{},
		},
	},
	"satd.events.v1.RescanResult": {
		"accepted": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_RescanResult{
				RescanResult: &eventspb.RescanResult{
					Outcome: &eventspb.RescanResult_Accepted{Accepted: &eventspb.RescanAccepted{}},
				},
			}},
			want: &RescanAccepted{},
		},
		"rejected": {
			ev: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_RescanResult{
				RescanResult: &eventspb.RescanResult{
					Outcome: &eventspb.RescanResult_Rejected{Rejected: &eventspb.RescanRejected{}},
				},
			}},
			want: &RescanRejected{},
		},
	},
}

// TestDecoderCoversEveryNodeEventBody walks the NodeEvent.body oneof descriptor
// and asserts the decoder maps every arm to a typed event.
//
// It is the Go stand-in for Rust's exhaustive match. The wire schema is
// additive, so an arm added upstream would otherwise decode silently to
// UnknownEvent and the omission would surface only when a consumer noticed
// missing events in production.
func TestDecoderCoversEveryNodeEventBody(t *testing.T) {
	oneof := oneofByName(t, (&eventspb.NodeEvent{}).ProtoReflect().Descriptor(), "body")
	seen := map[string]bool{}
	for i := 0; i < oneof.Fields().Len(); i++ {
		name := string(oneof.Fields().Get(i).Name())
		seen[name] = true
		fx, ok := bodyFixtures[name]
		if !ok {
			t.Errorf("NodeEvent.body arm %q has no decoder fixture: the proto grew an event "+
				"this SDK does not decode. Add the case to decodeEvent and a fixture here.", name)
			continue
		}
		assertEventType(t, name, decodeEvent(fx.ev), fx.want)
	}
	for name := range bodyFixtures {
		if !seen[name] {
			t.Errorf("fixture %q names no NodeEvent.body arm (renamed or removed upstream?)", name)
		}
	}
}

// TestDecoderCoversNestedOneofs does the same walk for the oneofs one level
// down, which the NodeEvent walk cannot see.
func TestDecoderCoversNestedOneofs(t *testing.T) {
	// DISCOVER the nested oneofs by walking out from NodeEvent, rather than
	// listing them. A hand-maintained list cannot catch the case this test
	// exists for: the schema's established growth pattern is a new NodeEvent arm
	// wrapping its own accepted/rejected oneof (SetCursorResult, WatchSetResult
	// and RescanResult are all that shape). The outer arm would be caught by the
	// NodeEvent walk, but a missing INNER variant would decode to UnknownEvent
	// with nothing failing - because the new message was never in the list.
	messages := map[string]protoreflect.MessageDescriptor{}
	nodeBody := oneofByName(t, (&eventspb.NodeEvent{}).ProtoReflect().Descriptor(), "body")
	for i := 0; i < nodeBody.Fields().Len(); i++ {
		f := nodeBody.Fields().Get(i)
		if f.Kind() != protoreflect.MessageKind {
			continue
		}
		md := f.Message()
		if md.Oneofs().Len() == 0 {
			continue
		}
		messages[string(md.FullName())] = md
	}
	if len(messages) == 0 {
		t.Fatal("discovered no nested oneofs; the walk is broken")
	}
	// And the reverse: a fixture table for a message the walk no longer reaches
	// would otherwise sit unconsulted, quietly covering nothing.
	for full := range nestedOneofFixtures {
		if _, ok := messages[full]; !ok {
			t.Errorf("fixture table %q is never reached from NodeEvent.body", full)
		}
	}
	for full, desc := range messages {
		fixtures := nestedOneofFixtures[full]
		if fixtures == nil {
			t.Fatalf("no fixture table for %s", full)
		}
		if desc.Oneofs().Len() != 1 {
			t.Fatalf("%s: expected exactly one oneof, got %d", full, desc.Oneofs().Len())
		}
		fields := desc.Oneofs().Get(0).Fields()
		for i := 0; i < fields.Len(); i++ {
			name := string(fields.Get(i).Name())
			fx, ok := fixtures[name]
			if !ok {
				t.Errorf("%s arm %q has no decoder fixture: the proto grew a variant this SDK "+
					"does not decode.", full, name)
				continue
			}
			assertEventType(t, full+"."+name, decodeEvent(fx.ev), fx.want)
		}
		for name := range fixtures {
			if !hasField(fields, name) {
				t.Errorf("%s: fixture %q names no arm (renamed or removed upstream?)", full, name)
			}
		}
	}
}

// TestEveryEventTypeIsReachable asserts each declared Event implementation is
// produced by something - the decoder fixtures above, or (for the
// SDK-synthesized ReplayGap and the UnknownEvent catch-all) named explicitly. A
// typed event nothing can ever return is dead weight in a published API.
func TestEveryEventTypeIsReachable(t *testing.T) {
	produced := map[reflect.Type]bool{
		// Synthesized by ResilientSubscription on a clamped replay, never decoded.
		reflect.TypeOf(&ReplayGap{}): true,
		// The decoder's catch-all for an unrecognized or absent body.
		reflect.TypeOf(&UnknownEvent{}): true,
	}
	for _, fx := range bodyFixtures {
		produced[reflect.TypeOf(decodeEvent(fx.ev))] = true
	}
	for _, table := range nestedOneofFixtures {
		for _, fx := range table {
			produced[reflect.TypeOf(decodeEvent(fx.ev))] = true
		}
	}
	for _, ev := range allEventTypes() {
		if !produced[reflect.TypeOf(ev)] {
			t.Errorf("%T is declared as an Event but nothing produces it", ev)
		}
	}
}

// allEventTypes lists every implementation of [Event].
func allEventTypes() []Event {
	return []Event{
		&MempoolEnter{}, &MempoolLeaveConfirmed{}, &MempoolLeaveEvicted{}, &MempoolLeaveReplaced{},
		&BlockConnected{}, &BlockDisconnected{}, &Reorg{}, &Heartbeat{}, &Status{},
		&OutpointSpent{}, &ScriptMatched{}, &TxidMatched{}, &TxidReplaced{}, &TxidEvicted{},
		&TxidUnconfirmed{}, &TxidDepthReached{}, &TxidFinalized{}, &PrefixMatched{},
		&SilentPaymentMatched{}, &BlockTweaks{}, &MempoolTweak{}, &Lagged{}, &ReplayGap{},
		&CursorAccepted{}, &CursorRejected{}, &WatchSetReplaced{}, &WatchSetRejected{},
		&RescanAccepted{}, &RescanRejected{}, &RescanComplete{}, &UnknownEvent{},
	}
}

func assertEventType(t *testing.T, label string, got, want Event) {
	t.Helper()
	if _, isUnknown := got.(*UnknownEvent); isUnknown {
		if _, wantUnknown := want.(*UnknownEvent); !wantUnknown {
			t.Errorf("%s decoded to UnknownEvent, want %T", label, want)
			return
		}
	}
	if reflect.TypeOf(got) != reflect.TypeOf(want) {
		t.Errorf("%s decoded to %T, want %T", label, got, want)
	}
}

func oneofByName(t *testing.T, d protoreflect.MessageDescriptor, name string) protoreflect.OneofDescriptor {
	t.Helper()
	o := d.Oneofs().ByName(protoreflect.Name(name))
	if o == nil {
		t.Fatalf("%s has no oneof %q", d.FullName(), name)
	}
	return o
}

func hasField(fields protoreflect.FieldDescriptors, name string) bool {
	for i := 0; i < fields.Len(); i++ {
		if string(fields.Get(i).Name()) == name {
			return true
		}
	}
	return false
}

// TestEnumConstantsMatchTheProto pins every Go enum constant to the wire value
// its proto counterpart carries. A renumbering upstream - or a Go constant typo
// - would otherwise silently misclassify events.
func TestEnumConstantsMatchTheProto(t *testing.T) {
	checks := []struct {
		name string
		got  int32
		want int32
	}{
		{"EvictUnspecified", int32(EvictUnspecified), int32(eventspb.EvictReason_EVICT_REASON_UNSPECIFIED)},
		{"EvictFullPool", int32(EvictFullPool), int32(eventspb.EvictReason_EVICT_REASON_FULL_POOL)},
		{"EvictExpiry", int32(EvictExpiry), int32(eventspb.EvictReason_EVICT_REASON_EXPIRY)},
		{"EvictBlockConflict", int32(EvictBlockConflict), int32(eventspb.EvictReason_EVICT_REASON_BLOCK_CONFLICT)},
		{"EvictPolicy", int32(EvictPolicy), int32(eventspb.EvictReason_EVICT_REASON_POLICY)},

		{"StatusKindUnspecified", int32(StatusKindUnspecified), int32(eventspb.StatusKind_STATUS_KIND_UNSPECIFIED)},
		{"StatusKindIBDComplete", int32(StatusKindIBDComplete), int32(eventspb.StatusKind_STATUS_KIND_IBD_COMPLETE)},
		{"StatusKindTipStall", int32(StatusKindTipStall), int32(eventspb.StatusKind_STATUS_KIND_TIP_STALL)},
		{"StatusKindDiskLow", int32(StatusKindDiskLow), int32(eventspb.StatusKind_STATUS_KIND_DISK_LOW)},
		{"StatusKindMempoolCongested", int32(StatusKindMempoolCongested), int32(eventspb.StatusKind_STATUS_KIND_MEMPOOL_CONGESTED)},
		{"StatusKindPeerFloor", int32(StatusKindPeerFloor), int32(eventspb.StatusKind_STATUS_KIND_PEER_FLOOR)},
		{"StatusKindDeepReorg", int32(StatusKindDeepReorg), int32(eventspb.StatusKind_STATUS_KIND_DEEP_REORG)},

		{"StatusStateUnspecified", int32(StatusStateUnspecified), int32(eventspb.StatusState_STATUS_STATE_UNSPECIFIED)},
		{"StatusStateRaised", int32(StatusStateRaised), int32(eventspb.StatusState_STATUS_STATE_RAISED)},
		{"StatusStateCleared", int32(StatusStateCleared), int32(eventspb.StatusState_STATUS_STATE_CLEARED)},
		{"StatusStateEdge", int32(StatusStateEdge), int32(eventspb.StatusState_STATUS_STATE_EDGE)},

		{"SeverityUnspecified", int32(SeverityUnspecified), int32(eventspb.StatusSeverity_STATUS_SEVERITY_UNSPECIFIED)},
		{"SeverityInfo", int32(SeverityInfo), int32(eventspb.StatusSeverity_STATUS_SEVERITY_INFO)},
		{"SeverityWarning", int32(SeverityWarning), int32(eventspb.StatusSeverity_STATUS_SEVERITY_WARNING)},
		{"SeverityCritical", int32(SeverityCritical), int32(eventspb.StatusSeverity_STATUS_SEVERITY_CRITICAL)},

		{"CursorRejectRateLimited", int32(CursorRejectRateLimited), int32(eventspb.CursorRejected_RATE_LIMITED)},
		{"CursorRejectConcurrentReanchor", int32(CursorRejectConcurrentReanchor), int32(eventspb.CursorRejected_CONCURRENT_REANCHOR)},
		{"CursorRejectEmptyCursor", int32(CursorRejectEmptyCursor), int32(eventspb.CursorRejected_EMPTY_CURSOR)},
		{"CursorRejectNoSource", int32(CursorRejectNoSource), int32(eventspb.CursorRejected_NO_SOURCE)},

		{"WatchSetRejectQuotaExceeded", int32(WatchSetRejectQuotaExceeded), int32(eventspb.WatchSetRejected_QUOTA_EXCEEDED)},
		{"WatchSetRejectMalformed", int32(WatchSetRejectMalformed), int32(eventspb.WatchSetRejected_MALFORMED)},
		{"WatchSetRejectCapExceeded", int32(WatchSetRejectCapExceeded), int32(eventspb.WatchSetRejected_CAP_EXCEEDED)},

		{"RescanRejectRateLimited", int32(RescanRejectRateLimited), int32(eventspb.RescanRejected_RATE_LIMITED)},
		{"RescanRejectConcurrentRescan", int32(RescanRejectConcurrentRescan), int32(eventspb.RescanRejected_CONCURRENT_RESCAN)},
		{"RescanRejectInvalidRange", int32(RescanRejectInvalidRange), int32(eventspb.RescanRejected_INVALID_RANGE)},
		{"RescanRejectRangeTooLarge", int32(RescanRejectRangeTooLarge), int32(eventspb.RescanRejected_RANGE_TOO_LARGE)},
		{"RescanRejectNoSource", int32(RescanRejectNoSource), int32(eventspb.RescanRejected_NO_SOURCE)},
		{"RescanRejectEmptyWatchSet", int32(RescanRejectEmptyWatchSet), int32(eventspb.RescanRejected_EMPTY_WATCH_SET)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, proto says %d", c.name, c.got, c.want)
		}
	}
}

// TestEnumsCoverTheProtoValueRange asserts each Go enum's Known predicate spans
// exactly the values the proto declares. A value added upstream would otherwise
// keep reporting Known() == false forever with nobody noticing.
func TestEnumsCoverTheProtoValueRange(t *testing.T) {
	cases := []struct {
		name   string
		values protoreflect.EnumValueDescriptors
		known  func(int32) bool
	}{
		{"EvictReason", eventspb.EvictReason(0).Descriptor().Values(),
			func(v int32) bool { return EvictReason(v).Known() }},
		{"StatusKind", eventspb.StatusKind(0).Descriptor().Values(),
			func(v int32) bool { return StatusKind(v).Known() }},
		{"StatusState", eventspb.StatusState(0).Descriptor().Values(),
			func(v int32) bool { return StatusState(v).Known() }},
		{"StatusSeverity", eventspb.StatusSeverity(0).Descriptor().Values(),
			func(v int32) bool { return StatusSeverity(v).Known() }},
		{"CursorRejectReason", eventspb.CursorRejected_Reason(0).Descriptor().Values(),
			func(v int32) bool { return CursorRejectReason(v).Known() }},
		{"WatchSetRejectReason", eventspb.WatchSetRejected_Reason(0).Descriptor().Values(),
			func(v int32) bool { return WatchSetRejectReason(v).Known() }},
		{"RescanRejectReason", eventspb.RescanRejected_Reason(0).Descriptor().Values(),
			func(v int32) bool { return RescanRejectReason(v).Known() }},
	}
	for _, c := range cases {
		highest := int32(-1)
		for i := 0; i < c.values.Len(); i++ {
			v := int32(c.values.Get(i).Number())
			if !c.known(v) {
				t.Errorf("%s: proto value %d (%s) is not Known() to the SDK",
					c.name, v, c.values.Get(i).Name())
			}
			if v > highest {
				highest = v
			}
		}
		if c.known(highest + 1) {
			t.Errorf("%s: %d is above every proto value but reports Known()", c.name, highest+1)
		}
	}
}
