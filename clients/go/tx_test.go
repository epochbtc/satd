package satdevents

import (
	"bytes"
	"encoding/hex"
	"errors"
	"runtime"
	"testing"
	"time"
)

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// The Bitcoin genesis coinbase - an external, universally known vector, so the
// decoder is pinned against something not derived from this codebase.
const genesisCoinbaseHex = "01000000010000000000000000000000000000000000000000000000000000000000000000" +
	"ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f7220" +
	"6f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01" +
	"000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4" +
	"f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

const genesisTxidDisplay = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

// A two-input, two-output segwit transaction with witnesses on the first input,
// plus the byte-identical legacy (witness-stripped) serialization of the same
// transaction. Both were produced by an independent Python serializer.
const (
	segwitTxHex = "0200000000010211111111111111111111111111111111111111111111111111111111111111110000000000" +
		"fdffffff2222222222222222222222222222222222222222222222222222222222222222070000000151ffff" +
		"ffff023930000000000000160014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000056a" +
		"0361626302473030303030303030303030303030303030303030303030303030303030303030303030303030" +
		"3030303030303030303030303030303030303030303030303030303030303030302102020202020202020202" +
		"02020202020202020202020202020202020202020202020000000000"
	legacyTxHex = "020000000211111111111111111111111111111111111111111111111111111111111111110000000000" +
		"fdffffff22222222222222222222222222222222222222222222222222222222222222220700000001" +
		"51ffffffff023930000000000000160014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000" +
		"056a0361626300000000"
	segwitTxidDisplay = "82272f6da66c35a411143b049e065e14085b32dbe23252613b84ed8bf8870358"
)

func TestDecodeLegacyTransaction(t *testing.T) {
	tx, err := decodeTx(mustHexBytes(t, genesisCoinbaseHex))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := DisplayHex(tx.txid[:]); got != genesisTxidDisplay {
		t.Errorf("txid = %s, want the genesis coinbase %s", got, genesisTxidDisplay)
	}
	if len(tx.inputs) != 1 || len(tx.outputs) != 1 {
		t.Fatalf("decoded %d input(s) and %d output(s), want 1 and 1",
			len(tx.inputs), len(tx.outputs))
	}
	if tx.outputs[0].value != 5000000000 {
		t.Errorf("output value = %d, want the 50 BTC subsidy", tx.outputs[0].value)
	}
	if n := len(tx.outputs[0].scriptPubKey); n != 67 {
		t.Errorf("scriptPubKey is %d bytes, want the 67-byte P2PK script", n)
	}
	// A coinbase spends the null outpoint.
	if tx.inputs[0].prevVout != 0xffffffff {
		t.Errorf("coinbase prevout index = %#x, want 0xffffffff", tx.inputs[0].prevVout)
	}
	if tx.inputs[0].prevTxid != ([32]byte{}) {
		t.Errorf("coinbase prevout txid = %x, want all zeroes", tx.inputs[0].prevTxid)
	}
}

// TestDecodeSegwitTransaction is the load-bearing one: the txid must be computed
// over the WITNESS-STRIPPED serialization. Hashing the bytes as received would
// produce the wtxid, which no watch, alarm, or lifecycle is keyed on - every
// txid comparison in the SDK would silently stop matching.
func TestDecodeSegwitTransaction(t *testing.T) {
	tx, err := decodeTx(mustHexBytes(t, segwitTxHex))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := DisplayHex(tx.txid[:]); got != segwitTxidDisplay {
		t.Errorf("txid = %s, want %s", got, segwitTxidDisplay)
	}
	if len(tx.inputs) != 2 || len(tx.outputs) != 2 {
		t.Fatalf("decoded %d input(s) and %d output(s), want 2 and 2",
			len(tx.inputs), len(tx.outputs))
	}
	if tx.inputs[0].prevTxid != [32]byte(bytes.Repeat([]byte{0x11}, 32)) ||
		tx.inputs[0].prevVout != 0 {
		t.Errorf("input 0 = %x:%d", tx.inputs[0].prevTxid, tx.inputs[0].prevVout)
	}
	if tx.inputs[1].prevVout != 7 {
		t.Errorf("input 1 vout = %d, want 7", tx.inputs[1].prevVout)
	}
	if tx.outputs[0].value != 12345 {
		t.Errorf("output 0 value = %d, want 12345", tx.outputs[0].value)
	}
	// A genuine zero-value output (OP_RETURN) must survive as zero, not be
	// confused with a missing value.
	if tx.outputs[1].value != 0 {
		t.Errorf("output 1 value = %d, want 0", tx.outputs[1].value)
	}
	if !bytes.Equal(tx.outputs[0].scriptPubKey, mustHexBytes(t, "0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) {
		t.Errorf("output 0 script = %x", tx.outputs[0].scriptPubKey)
	}
}

// TestSegwitAndLegacySerializationsAgree: the same transaction sent either way
// must decode to the same txid and the same outputs. That is what makes the
// prefix filter indifferent to which form the node serialized.
func TestSegwitAndLegacySerializationsAgree(t *testing.T) {
	sw, err := decodeTx(mustHexBytes(t, segwitTxHex))
	if err != nil {
		t.Fatal(err)
	}
	lg, err := decodeTx(mustHexBytes(t, legacyTxHex))
	if err != nil {
		t.Fatal(err)
	}
	if sw.txid != lg.txid {
		t.Errorf("txid differs by serialization: %x vs %x", sw.txid, lg.txid)
	}
	if len(sw.outputs) != len(lg.outputs) {
		t.Fatalf("output counts differ: %d vs %d", len(sw.outputs), len(lg.outputs))
	}
	for i := range sw.outputs {
		if sw.outputs[i].value != lg.outputs[i].value ||
			!bytes.Equal(sw.outputs[i].scriptPubKey, lg.outputs[i].scriptPubKey) {
			t.Errorf("output %d differs by serialization", i)
		}
	}
}

// TestDecodeRejectsMalformedInput: these bytes come off a socket. A truncated or
// corrupt payload has to be a clean error, never a panic or a huge allocation.
func TestDecodeRejectsMalformedInput(t *testing.T) {
	full := mustHexBytes(t, segwitTxHex)
	cases := map[string][]byte{
		"empty":                  {},
		"version only":           full[:4],
		"truncated mid-input":    full[:20],
		"truncated mid-output":   full[:len(full)-30],
		"missing locktime":       full[:len(full)-4],
		"zero inputs, no marker": mustHexBytes(t, "0200000000"+"00000000"),
		// The zero-input guard is only reachable past the segwit marker: before
		// it, a zero count IS the marker.
		"zero inputs after the marker": mustHexBytes(t, "02000000"+"0001"+"00"+"00"+"00000000"),
		"unknown segwit flag":          mustHexBytes(t, "02000000"+"00"+"02"+"00000000"),
		// A varint claiming billions of inputs: the allocation guard must reject
		// this on the remaining-bytes check rather than trying to make() it.
		"absurd input count":       mustHexBytes(t, "02000000"+"ff"+"ffffffffffffffff"+"00000000"),
		"absurd output count":      mustHexBytes(t, "02000000"+"01"+"1111111111111111111111111111111111111111111111111111111111111111"+"00000000"+"00"+"ffffffff"+"ff"+"ffffffffffffffff"),
		"script longer than input": mustHexBytes(t, "02000000"+"01"+"1111111111111111111111111111111111111111111111111111111111111111"+"00000000"+"fd0010"+"00"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			tx, err := decodeTx(raw)
			if err == nil {
				t.Fatalf("accepted malformed input, decoded %d input(s)/%d output(s)",
					len(tx.inputs), len(tx.outputs))
			}
			if !errors.Is(err, ErrDecode) {
				t.Errorf("got %v, want a decode error", err)
			}
		})
	}
}

// TestDecodeAcceptsNonCanonicalCompactSize: the decoder reads what the node
// sent. Rejecting an over-long but unambiguous length encoding would turn a
// deliverable match into a dropped one for no safety gain.
func TestDecodeAcceptsNonCanonicalCompactSize(t *testing.T) {
	// One input, one output, with the output count written as 0xfd 0x01 0x00
	// instead of the canonical single byte 0x01.
	raw := mustHexBytes(t,
		"02000000"+
			"01"+
			"1111111111111111111111111111111111111111111111111111111111111111"+"00000000"+"00"+"ffffffff"+
			"fd0100"+
			"3930000000000000"+"02"+"6a00"+
			"00000000")
	tx, err := decodeTx(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(tx.outputs) != 1 || tx.outputs[0].value != 12345 {
		t.Errorf("decoded %+v", tx.outputs)
	}
}

func TestCompactSizeRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff, 0x100000000} {
		r := &byteReader{buf: appendCompactSize(nil, v)}
		got, err := r.compactSize()
		if err != nil {
			t.Fatalf("%d: %v", v, err)
		}
		if got != v {
			t.Errorf("round trip of %d gave %d", v, got)
		}
		if r.remaining() != 0 {
			t.Errorf("%d: %d byte(s) left over", v, r.remaining())
		}
	}
}

// TestDecodeBoundsAllocationsOnAbsurdLengths: a length prefix is attacker- or
// corruption-controlled, and Go will happily try to make() a multi-gigabyte
// slice before the read that would have failed. Every length is checked against
// the bytes actually remaining first, so a corrupt payload costs a few
// microseconds instead of the process.
//
// The item counts below are deliberately ~1e6 and not ~4e9, even though the
// decoder must reject both identically. This test only means anything when the
// bound is broken, and a broken bound turns a 4-billion count into ~137 GB of
// resident memory - which does not fail this assertion, it OOMs the machine (and
// on a CI runner, takes the job's whole cgroup with it). A million items is just
// as impossible for a 50-byte payload, blows the budget below by 4x, and costs
// 37 MB to prove it. The one genuinely enormous count is the wrap case, which is
// safe precisely because Go refuses that cap outright instead of trying.
func TestDecodeBoundsAllocationsOnAbsurdLengths(t *testing.T) {
	cases := map[string][]byte{
		// A scriptSig claiming ~4 GiB.
		"absurd script length": mustHexBytes(t, "02000000"+"01"+
			"1111111111111111111111111111111111111111111111111111111111111111"+"00000000"+
			"ff00000000ffffffff"+"00000000"),
		// An input count claiming ~1 million items.
		"absurd input count": mustHexBytes(t, "02000000"+"feffff0f00"+"00000000"),
		// An input count chosen so that count * 41 (the per-input minimum)
		// wraps uint64 down to 4 - exactly the bytes left. A bound computed by
		// multiplying would wave this through and then size a 4.5-quintillion
		// element slice; the bound has to divide instead.
		"input count that wraps the size bound": mustHexBytes(t, "02000000"+
			"ff"+"64703e06e763703e"+"00000000"),
		// An output count claiming ~1 million items.
		"absurd output count": mustHexBytes(t, "02000000"+"01"+
			"1111111111111111111111111111111111111111111111111111111111111111"+"00000000"+"00"+
			"ffffffff"+"feffff0f00"+"00000000"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			start := time.Now()
			if _, err := decodeTx(raw); err == nil {
				t.Fatal("accepted a payload with an impossible length")
			}
			elapsed := time.Since(start)

			runtime.ReadMemStats(&after)
			grew := after.TotalAlloc - before.TotalAlloc
			const budget = 8 << 20
			if grew > budget {
				t.Errorf("decoding allocated %d bytes for a %d-byte payload; the "+
					"length was trusted before being bounds-checked", grew, len(raw))
			}
			if elapsed > 2*time.Second {
				t.Errorf("decoding took %s for a %d-byte payload", elapsed, len(raw))
			}
		})
	}
}
