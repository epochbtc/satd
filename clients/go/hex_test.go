package satdevents

import (
	"errors"
	"testing"
)

// TestDisplayHexReverses pins the single most common integration bug against
// this API: the wire carries internal (consensus) byte order, JSON-RPC and
// explorers show it reversed.
func TestDisplayHexReverses(t *testing.T) {
	internal := make([]byte, 32)
	for i := range internal {
		internal[i] = byte(i)
	}
	got := DisplayHex(internal)
	if got[:6] != "1f1e1d" {
		t.Errorf("DisplayHex = %q, want it to start reversed (1f1e1d...)", got)
	}
	if len(got) != 64 {
		t.Errorf("DisplayHex length = %d, want 64", len(got))
	}
	if DisplayHex(nil) != "" {
		t.Error("DisplayHex(nil) should be empty")
	}
}

func TestTxidRoundTripsThroughDisplayOrder(t *testing.T) {
	internal := make([]byte, 32)
	for i := range internal {
		internal[i] = byte(i * 7)
	}
	arr, err := ParseTxid(internal)
	if err != nil {
		t.Fatal(err)
	}
	if string(arr[:]) != string(internal) {
		t.Error("ParseTxid must carry the bytes through unchanged")
	}

	back, err := TxidFromDisplayHex(DisplayHex(internal))
	if err != nil {
		t.Fatal(err)
	}
	if back != arr {
		t.Errorf("display round-trip changed the txid:\n got %x\nwant %x", back, arr)
	}
}

func TestTxidHelpersRejectBadInput(t *testing.T) {
	if _, err := ParseTxid(make([]byte, 31)); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("short txid: got %v, want ErrInvalidArgument", err)
	}
	if _, err := TxidFromDisplayHex("zz"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("non-hex: got %v, want ErrInvalidArgument", err)
	}
	if _, err := TxidFromDisplayHex("abcd"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("short hex: got %v, want ErrInvalidArgument", err)
	}
}
