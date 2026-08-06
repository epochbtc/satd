package satdevents

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

func u64(v uint64) *uint64 { return &v }

// TestDecodeMapsFieldsFaithfully is the field-level companion to the
// exhaustiveness walk: that one proves every arm is decoded, this one proves
// each arm's fields land where they should. A transposed pair (height/depth,
// from/to, txid/replacing_txid) type-checks fine and would otherwise ship.
func TestDecodeMapsFieldsFaithfully(t *testing.T) {
	txid := []byte{0x01, 0x02}
	other := []byte{0x03, 0x04}

	cases := []struct {
		name string
		in   *eventspb.NodeEvent
		want Event
	}{
		{
			name: "mempool enter",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
				Mempool: &eventspb.MempoolEvent{Body: &eventspb.MempoolEvent_Enter{
					Enter: &eventspb.MempoolEnter{
						Txid: txid, Fee: 1200, Vsize: 141, FeeRateSatPerKvb: 8510, Time: 1700000000,
					},
				}},
			}},
			want: &MempoolEnter{
				Txid: txid, Fee: 1200, Vsize: 141, FeeRateSatPerKvB: 8510, Time: 1700000000,
			},
		},
		{
			name: "mempool leave confirmed",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
				Mempool: &eventspb.MempoolEvent{Body: &eventspb.MempoolEvent_LeaveConfirmed{
					LeaveConfirmed: &eventspb.MempoolLeaveConfirmed{
						Txid: txid, BlockHash: other, Height: 812345,
					},
				}},
			}},
			want: &MempoolLeaveConfirmed{Txid: txid, BlockHash: other, Height: 812345},
		},
		{
			name: "mempool leave evicted",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
				Mempool: &eventspb.MempoolEvent{Body: &eventspb.MempoolEvent_LeaveEvicted{
					LeaveEvicted: &eventspb.MempoolLeaveEvicted{
						Txid: txid, Reason: eventspb.EvictReason_EVICT_REASON_EXPIRY,
					},
				}},
			}},
			want: &MempoolLeaveEvicted{Txid: txid, Reason: EvictExpiry},
		},
		{
			name: "mempool leave replaced",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
				Mempool: &eventspb.MempoolEvent{Body: &eventspb.MempoolEvent_LeaveReplaced{
					LeaveReplaced: &eventspb.MempoolLeaveReplaced{Txid: txid, ReplacingTxid: other},
				}},
			}},
			want: &MempoolLeaveReplaced{Txid: txid, ReplacingTxid: other},
		},
		{
			name: "reorg",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Chain{
				Chain: &eventspb.ChainEvent{Body: &eventspb.ChainEvent_Reorg{
					Reorg: &eventspb.Reorg{FromHeight: 10, OldTip: txid, ToHeight: 12, NewTip: other},
				}},
			}},
			want: &Reorg{FromHeight: 10, OldTip: txid, ToHeight: 12, NewTip: other},
		},
		{
			name: "status carries details and enums",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Status{
				Status: &eventspb.StatusEvent{
					Kind:     eventspb.StatusKind_STATUS_KIND_TIP_STALL,
					State:    eventspb.StatusState_STATUS_STATE_RAISED,
					Severity: eventspb.StatusSeverity_STATUS_SEVERITY_CRITICAL,
					Message:  "no block for 3600s",
					Details:  map[string]string{"seconds": "3600"},
				},
			}},
			want: &Status{
				Kind:     StatusKindTipStall,
				State:    StatusStateRaised,
				Severity: SeverityCritical,
				Message:  "no block for 3600s",
				Details:  map[string]string{"seconds": "3600"},
			},
		},
		{
			name: "outpoint spent",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_OutpointSpent{
				OutpointSpent: &eventspb.OutpointSpent{
					OutpointTxid: txid, OutpointVout: 3,
					SpendingTxid: other, SpendingVin: 1, Confirmed: true,
				},
			}},
			want: &OutpointSpent{
				Outpoint:     Outpoint{Txid: txid, Vout: 3},
				SpendingTxid: other, SpendingVin: 1, Confirmed: true,
			},
		},
		{
			name: "script matched with descriptor attribution",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_ScriptMatched{
				ScriptMatched: &eventspb.ScriptMatched{
					Scripthash: txid, Txid: other, IsOutput: true, Index: 2, Confirmed: true,
					Amount: 5000, HasAmount: true,
					DescriptorMatches: []*eventspb.DescriptorMatch{
						{Descriptor_: "wpkh(xpub.../<0;1>/*)", Branch: 1, DerivationIndex: 7},
					},
				},
			}},
			want: &ScriptMatched{
				Scripthash: txid, Txid: other, IsOutput: true, Index: 2, Confirmed: true,
				Amount: u64(5000),
				Descriptors: []DescriptorMatch{
					{Descriptor: "wpkh(xpub.../<0;1>/*)", Branch: 1, DerivationIndex: 7},
				},
			},
		},
		{
			name: "txid depth reached",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidDepthReached{
				TxidDepthReached: &eventspb.TxidDepthReached{Txid: txid, Depth: 6, Height: 900001},
			}},
			want: &TxidDepthReached{Txid: txid, Depth: 6, Height: 900001},
		},
		{
			name: "txid finalized",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidFinalized{
				TxidFinalized: &eventspb.TxidFinalized{Txid: txid, Depth: 12, Height: 900010},
			}},
			want: &TxidFinalized{Txid: txid, Depth: 12, Height: 900010},
		},
		{
			name: "txid unconfirmed",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidUnconfirmed{
				TxidUnconfirmed: &eventspb.TxidUnconfirmed{Txid: txid, PrevHeight: 42},
			}},
			want: &TxidUnconfirmed{Txid: txid, PrevHeight: 42},
		},
		{
			name: "lagged carries its resume cursor",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Lagged{
				Lagged: &eventspb.Lagged{
					DroppedCount: 17,
					ResumeCursor: &eventspb.Cursor{Height: 9, TxIndex: 3, MempoolSeq: 4, InstanceId: 5},
				},
			}},
			want: &Lagged{
				DroppedCount: 17,
				ResumeCursor: &Cursor{Height: 9, TxIndex: 3, MempoolSeq: 4, InstanceID: 5},
			},
		},
		{
			name: "cursor accepted, clamped",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
				SetCursorResult: &eventspb.SetCursorResult{
					Outcome: &eventspb.SetCursorResult_Accepted{Accepted: &eventspb.CursorAccepted{
						From:             &eventspb.Cursor{Height: 100},
						Clamped:          true,
						EarliestReplayed: 90100,
					}},
				},
			}},
			want: &CursorAccepted{
				From: &Cursor{Height: 100}, Clamped: true, EarliestReplayed: 90100,
			},
		},
		{
			name: "cursor rejected",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
				SetCursorResult: &eventspb.SetCursorResult{
					Outcome: &eventspb.SetCursorResult_Rejected{Rejected: &eventspb.CursorRejected{
						Reason:      eventspb.CursorRejected_CONCURRENT_REANCHOR,
						CurrentHead: &eventspb.Cursor{Height: 7},
					}},
				},
			}},
			want: &CursorRejected{
				Reason: CursorRejectConcurrentReanchor, CurrentHead: &Cursor{Height: 7},
			},
		},
		{
			name: "watch-set rejected reports the ceiling that refused it",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetWatchSetResult{
				SetWatchSetResult: &eventspb.WatchSetResult{
					Outcome: &eventspb.WatchSetResult_Rejected{Rejected: &eventspb.WatchSetRejected{
						Reason: eventspb.WatchSetRejected_CAP_EXCEEDED, Required: 900, Quota: 512,
					}},
				},
			}},
			want: &WatchSetRejected{Reason: WatchSetRejectCapExceeded, Required: 900, Quota: 512},
		},
		{
			name: "rescan accepted echoes the post-clamp range",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_RescanResult{
				RescanResult: &eventspb.RescanResult{
					Outcome: &eventspb.RescanResult_Accepted{Accepted: &eventspb.RescanAccepted{
						FromHeight: 100, ToHeight: 200, Clamped: true,
					}},
				},
			}},
			want: &RescanAccepted{FromHeight: 100, ToHeight: 200, Clamped: true},
		},
		{
			name: "rescan complete",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_RescanComplete{
				RescanComplete: &eventspb.RescanComplete{FromHeight: 100, ToHeight: 200, Matches: 3},
			}},
			want: &RescanComplete{FromHeight: 100, ToHeight: 200, Matches: 3},
		},
		{
			name: "block tweaks with taproot outputs",
			in: &eventspb.NodeEvent{Body: &eventspb.NodeEvent_BlockTweaks{
				BlockTweaks: &eventspb.BlockTweaks{
					BlockHash: txid, Height: 5, Filtered: true,
					Entries: []*eventspb.TweakEntry{{
						Tweak: other, Txid: txid, MaxValue: 100,
						TaprootOutputs: []*eventspb.TaprootOutput{
							{Vout: 1, OutputPubkey: other, Value: 100},
						},
					}},
				},
			}},
			want: &BlockTweaks{
				BlockHash: txid, Height: 5, Filtered: true,
				Entries: []TweakEntry{{
					Tweak: other, Txid: txid, MaxValue: 100,
					TaprootOutputs: []TaprootOutput{{Vout: 1, OutputPubkey: other, Value: 100}},
				}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeEvent(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("decoded\n got %#v\nwant %#v", got, tc.want)
			}
		})
	}
}

// TestOptionalFieldsDistinguishAbsentFromZero covers the wire's (has_x, x)
// pairs and the empty-bytes conventions. Collapsing "not retained" into a zero
// is exactly the bug these guard: a consumer would read a 0-sat amount, or an
// unconfirmed match at height 0, as fact.
func TestOptionalFieldsDistinguishAbsentFromZero(t *testing.T) {
	t.Run("script matched amount", func(t *testing.T) {
		absent := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_ScriptMatched{
			ScriptMatched: &eventspb.ScriptMatched{HasAmount: false, Amount: 0},
		}}).(*ScriptMatched)
		if absent.Amount != nil {
			t.Errorf("amount = %v, want nil when the node did not retain it", *absent.Amount)
		}

		zero := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_ScriptMatched{
			ScriptMatched: &eventspb.ScriptMatched{HasAmount: true, Amount: 0},
		}}).(*ScriptMatched)
		if zero.Amount == nil || *zero.Amount != 0 {
			t.Errorf("amount = %v, want a genuine 0", zero.Amount)
		}
	})

	t.Run("script matched raw_tx", func(t *testing.T) {
		off := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_ScriptMatched{
			ScriptMatched: &eventspb.ScriptMatched{RawTx: nil},
		}}).(*ScriptMatched)
		if off.RawTx != nil {
			t.Errorf("raw_tx = %x, want nil without the opt-in", off.RawTx)
		}
		on := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_ScriptMatched{
			ScriptMatched: &eventspb.ScriptMatched{RawTx: []byte{0x01}},
		}}).(*ScriptMatched)
		if len(on.RawTx) != 1 {
			t.Errorf("raw_tx = %x, want the inlined tx", on.RawTx)
		}
	})

	t.Run("silent payment height and label", func(t *testing.T) {
		mempool := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_SilentPaymentMatched{
			SilentPaymentMatched: &eventspb.SilentPaymentMatched{Confirmed: false, Height: 0},
		}}).(*SilentPaymentMatched)
		if mempool.Height != nil {
			t.Errorf("height = %v, want nil while unconfirmed", *mempool.Height)
		}
		if mempool.Label != nil {
			t.Errorf("label = %v, want nil for an unlabeled match", *mempool.Label)
		}

		confirmed := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_SilentPaymentMatched{
			SilentPaymentMatched: &eventspb.SilentPaymentMatched{
				Confirmed: true, Height: 900000, HasLabel: true, Label: 0,
			},
		}}).(*SilentPaymentMatched)
		if confirmed.Height == nil || *confirmed.Height != 900000 {
			t.Errorf("height = %v, want 900000", confirmed.Height)
		}
		// Label 0 is the conventional change label - a genuine value, not absence.
		if confirmed.Label == nil || *confirmed.Label != 0 {
			t.Errorf("label = %v, want a genuine 0", confirmed.Label)
		}
	})

	t.Run("prefix spent prevout amount", func(t *testing.T) {
		ev := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_PrefixMatched{
			PrefixMatched: &eventspb.PrefixMatched{
				Prefix: &eventspb.ScriptPrefix{Prefix: []byte{0x00}, Bits: 8},
				MatchedPrevouts: []*eventspb.SpentPrevout{
					{OutpointTxid: []byte{1}, OutpointVout: 0, HasAmount: false},
					{OutpointTxid: []byte{2}, OutpointVout: 1, HasAmount: true, Amount: 0},
				},
			},
		}}).(*PrefixMatched)
		if ev.MatchedPrevouts[0].Amount != nil {
			t.Error("unretained prevout amount should decode to nil")
		}
		if a := ev.MatchedPrevouts[1].Amount; a == nil || *a != 0 {
			t.Errorf("retained 0-sat prevout amount = %v, want a genuine 0", a)
		}
	})
}

// TestDegenerateFramesDecodeToUnknown covers the malformed-wire paths: a frame
// whose required inner message is absent is surfaced as unknown rather than as
// a structurally-valid-looking zero, which a consumer would act on.
func TestDegenerateFramesDecodeToUnknown(t *testing.T) {
	cases := map[string]*eventspb.NodeEvent{
		"no body at all": {},
		"prefix match without its bucket": {Body: &eventspb.NodeEvent_PrefixMatched{
			PrefixMatched: &eventspb.PrefixMatched{Prefix: nil},
		}},
		"set-cursor result with no outcome": {Body: &eventspb.NodeEvent_SetCursorResult{
			SetCursorResult: &eventspb.SetCursorResult{},
		}},
		"watch-set result with no outcome": {Body: &eventspb.NodeEvent_SetWatchSetResult{
			SetWatchSetResult: &eventspb.WatchSetResult{},
		}},
		"rescan result with no outcome": {Body: &eventspb.NodeEvent_RescanResult{
			RescanResult: &eventspb.RescanResult{},
		}},
		"mempool envelope with no body": {Body: &eventspb.NodeEvent_Mempool{
			Mempool: &eventspb.MempoolEvent{},
		}},
		"chain envelope with no body": {Body: &eventspb.NodeEvent_Chain{
			Chain: &eventspb.ChainEvent{},
		}},
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			if got := decodeEvent(ev); !reflect.DeepEqual(got, &UnknownEvent{}) {
				t.Errorf("decoded to %#v, want UnknownEvent", got)
			}
		})
	}

	// A MempoolTweak with no entry is the one degenerate frame that does NOT
	// degrade to unknown: the event itself is meaningful (a tx was admitted), so
	// it degrades to an empty entry rather than being dropped.
	t.Run("mempool tweak with no entry keeps the event", func(t *testing.T) {
		got := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_MempoolTweak{
			MempoolTweak: &eventspb.MempoolTweak{},
		}})
		if _, ok := got.(*MempoolTweak); !ok {
			t.Fatalf("decoded to %T, want *MempoolTweak", got)
		}
	})
}

// TestUnrecognizedEnumValuesKeepTheirNumber is the forward-compat contract: a
// code a newer node introduces must not be reported as the zero value, which is
// indistinguishable from a producer that omitted the field.
func TestUnrecognizedEnumValuesKeepTheirNumber(t *testing.T) {
	ev := decodeEvent(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_Mempool{
		Mempool: &eventspb.MempoolEvent{Body: &eventspb.MempoolEvent_LeaveEvicted{
			LeaveEvicted: &eventspb.MempoolLeaveEvicted{Reason: eventspb.EvictReason(99)},
		}},
	}}).(*MempoolLeaveEvicted)
	if ev.Reason != EvictReason(99) {
		t.Errorf("reason = %d, want the raw 99 preserved", ev.Reason)
	}
	if ev.Reason.Known() {
		t.Error("99 should not report Known()")
	}
	if ev.Reason.String() != "unknown(99)" {
		t.Errorf("String() = %q", ev.Reason.String())
	}
	// The zero value stays distinguishable from that.
	if !EvictUnspecified.Known() || EvictUnspecified.String() != "unspecified" {
		t.Error("the unset reason must remain its own, recognized value")
	}
}

// TestSeverityOrdering pins the documented filter idiom.
func TestSeverityOrdering(t *testing.T) {
	if !SeverityWarning.AtLeast(SeverityWarning) || !SeverityCritical.AtLeast(SeverityWarning) {
		t.Error("warning and critical must pass a warning floor")
	}
	if SeverityInfo.AtLeast(SeverityWarning) {
		t.Error("info must not pass a warning floor")
	}
	// The regression this exists for: an unset severity must not page on the
	// documented filter.
	if SeverityUnspecified.AtLeast(SeverityWarning) {
		t.Error("an unset severity must not pass a warning floor")
	}
	if !SeverityUnspecified.AtLeast(SeverityUnspecified) {
		t.Error("a floor of unspecified passes everything, including unspecified")
	}
	// A level this build cannot name is not one to filter out quietly, in either
	// direction from the known range.
	for _, unknown := range []StatusSeverity{4, 99, -1} {
		if !unknown.AtLeast(SeverityCritical) {
			t.Errorf("unrecognized severity %d must outrank critical", unknown)
		}
	}
	// Compare stays a total order across distinct unrecognized codes, so this
	// type is usable as a sort key.
	if StatusSeverity(5).Compare(StatusSeverity(9)) >= 0 {
		t.Error("distinct unknown severities must not compare equal")
	}
	if StatusSeverity(5).Compare(StatusSeverity(5)) != 0 {
		t.Error("a severity must compare equal to itself")
	}
}

// TestCursorRejectTransientClassification pins which rejects the resilience
// layer retries in place versus surfaces for a resnapshot.
func TestCursorRejectTransientClassification(t *testing.T) {
	transient := []CursorRejectReason{CursorRejectRateLimited, CursorRejectConcurrentReanchor}
	terminal := []CursorRejectReason{
		CursorRejectUnspecified, CursorRejectEmptyCursor, CursorRejectNoSource, CursorRejectReason(99),
	}
	for _, r := range transient {
		if !r.Transient() {
			t.Errorf("%s should be retried in place", r)
		}
	}
	for _, r := range terminal {
		if r.Transient() {
			t.Errorf("%s should be surfaced, not retried", r)
		}
	}
}

// TestDecodeMapsSameTypedFieldsFaithfully pins the arms where a transposed
// assignment type-checks and so survives review.
//
// TestDecoderCoversEveryNodeEventBody proves every arm decodes to the right Go
// TYPE, which a swap does not disturb; TestDecodeMapsFieldsFaithfully covers 16
// arms by field but not these. The two below are the dangerous shapes: three
// adjacent uint32 counters, and four adjacent 32-byte-ish slices.
func TestDecodeMapsSameTypedFieldsFaithfully(t *testing.T) {
	t.Run("watch set replaced counters are not transposed", func(t *testing.T) {
		// Distinct values, so any permutation of the three fails.
		in := &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetWatchSetResult{
			SetWatchSetResult: &eventspb.WatchSetResult{
				Outcome: &eventspb.WatchSetResult_Accepted{Accepted: &eventspb.WatchSetAccepted{
					Added: 11, Removed: 22, Unchanged: 33,
				}},
			},
		}}
		got, ok := decodeEvent(in).(*WatchSetReplaced)
		if !ok {
			t.Fatalf("decoded to %T", decodeEvent(in))
		}
		if got.Added != 11 || got.Removed != 22 || got.Unchanged != 33 {
			t.Errorf("added/removed/unchanged = %d/%d/%d, want 11/22/33",
				got.Added, got.Removed, got.Unchanged)
		}
	})

	t.Run("silent payment byte fields are not transposed", func(t *testing.T) {
		// Each slice is a different length AND a different value, so a swap
		// cannot pass by coincidence.
		scan := []byte{0xaa, 0xaa, 0xaa}
		txid := []byte{0xbb, 0xbb}
		outKey := []byte{0xcc}
		tweak := []byte{0xdd, 0xdd, 0xdd, 0xdd}
		raw := []byte{0xee, 0xee, 0xee, 0xee, 0xee}
		label := uint32(7)

		in := &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SilentPaymentMatched{
			SilentPaymentMatched: &eventspb.SilentPaymentMatched{
				ScanPubkey: scan, Txid: txid, Vout: 3, OutputPubkey: outKey,
				Amount: 5000, Tweak: tweak, K: 2, Confirmed: true, Height: 812345,
				HasLabel: true, Label: label, RawTx: raw,
			},
		}}
		got, ok := decodeEvent(in).(*SilentPaymentMatched)
		if !ok {
			t.Fatalf("decoded to %T", decodeEvent(in))
		}
		if !bytes.Equal(got.ScanPubkey, scan) {
			t.Errorf("ScanPubkey = %x", got.ScanPubkey)
		}
		if !bytes.Equal(got.Txid, txid) {
			t.Errorf("Txid = %x", got.Txid)
		}
		// The pair a wallet cannot afford to have swapped: deriving from the
		// output key instead of the tweak yields a key that controls nothing.
		if !bytes.Equal(got.OutputPubkey, outKey) {
			t.Errorf("OutputPubkey = %x, want %x", got.OutputPubkey, outKey)
		}
		if !bytes.Equal(got.Tweak, tweak) {
			t.Errorf("Tweak = %x, want %x", got.Tweak, tweak)
		}
		if !bytes.Equal(got.RawTx, raw) {
			t.Errorf("RawTx = %x", got.RawTx)
		}
		if got.Vout != 3 || got.Amount != 5000 || got.K != 2 {
			t.Errorf("vout/amount/k = %d/%d/%d, want 3/5000/2", got.Vout, got.Amount, got.K)
		}
		if got.Label == nil || *got.Label != label {
			t.Errorf("Label = %v, want %d", got.Label, label)
		}
		if got.Height == nil || *got.Height != 812345 {
			t.Errorf("Height = %v, want 812345", got.Height)
		}
	})

	t.Run("unconfirmed silent payment has no height and absent label stays nil", func(t *testing.T) {
		in := &eventspb.NodeEvent{Body: &eventspb.NodeEvent_SilentPaymentMatched{
			SilentPaymentMatched: &eventspb.SilentPaymentMatched{
				Txid: []byte{0x01}, Confirmed: false, Height: 0, HasLabel: false, Label: 9,
			},
		}}
		got := decodeEvent(in).(*SilentPaymentMatched)
		if got.Height != nil {
			t.Errorf("Height = %v on an unconfirmed match, want nil", got.Height)
		}
		if got.Label != nil {
			t.Errorf("Label = %v with has_label false, want nil", got.Label)
		}
	})
}
