package satdevents

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func secretOf(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// TestScalarBaseMultAgreesWithTheCurveEquation checks the derived point
// actually satisfies y^2 = x^3 + 7 and that its compressed encoding round-trips
// through the on-curve check. This is self-consistent rather than a golden
// vector, so it also guards the compression parity byte.
func TestScalarBaseMultAgreesWithTheCurveEquation(t *testing.T) {
	// 0xff repeated is above the group order, so it belongs to the
	// rejection test below, not here.
	for _, b := range []byte{0x01, 0x11, 0x22, 0x99, 0xfe} {
		sk := secretOf(b)
		target := SilentPaymentTarget{ScanSecret: sk}
		pub, err := target.ScanPubkey()
		if err != nil {
			t.Fatalf("secret 0x%02x: %v", b, err)
		}
		if pub[0] != 0x02 && pub[0] != 0x03 {
			t.Errorf("secret 0x%02x: bad prefix 0x%02x", b, pub[0])
		}
		if !isOnCurveCompressed(pub[:]) {
			t.Errorf("secret 0x%02x: derived key is not on the curve", b)
		}
		// Recompute the point directly and compare, so a bug in the ladder's
		// bit order does not cancel out with one in compression.
		k := new(big.Int).SetBytes(sk[:])
		p := scalarBaseMult(k)
		y2 := fieldMul(p.Y, p.Y)
		rhs := fieldAdd(fieldMul(fieldMul(p.X, p.X), p.X), secpB)
		if y2.Cmp(rhs) != 0 {
			t.Errorf("secret 0x%02x: derived point is not on the curve", b)
		}
	}
}

// TestScalarBaseMultKnownVectors pins the generator and small multiples against
// the published secp256k1 values - the check that would catch a wrong constant.
func TestScalarBaseMultKnownVectors(t *testing.T) {
	cases := []struct {
		k    string
		want string
	}{
		{"1", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
		{"2", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"},
		{"3", "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"},
		{"4", "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"},
		{"5", "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"},
	}
	for _, c := range cases {
		k, ok := new(big.Int).SetString(c.k, 10)
		if !ok {
			t.Fatalf("bad test scalar %s", c.k)
		}
		got := hex.EncodeToString(compressBytes(scalarBaseMult(k)))
		if got != c.want {
			t.Errorf("%s*G = %s, want %s", c.k, got, c.want)
		}
	}
}

func compressBytes(p point) []byte {
	c := compress(p)
	return c[:]
}

// TestOnCurveCheckRejectsNonPoints is the validation the SDK does instead of
// pulling btcec. A compressed key with an x that has no square root is not a
// point, and the server would simply reject the target - client-side is where
// that turns into an error the caller can act on.
func TestOnCurveCheckRejectsNonPoints(t *testing.T) {
	valid, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if !isOnCurveCompressed(valid) {
		t.Fatal("the generator must pass the on-curve check")
	}
	// Same x with the other parity is also a real point.
	other := append([]byte{0x03}, valid[1:]...)
	if !isOnCurveCompressed(other) {
		t.Error("the odd-parity generator must also pass")
	}

	bad := map[string]string{
		"wrong length": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817",
		"bad prefix":   "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"x = 0":        "020000000000000000000000000000000000000000000000000000000000000000",
		"x >= p":       "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
		// x = 5: 5^3 + 7 = 132 is a quadratic non-residue mod p, so no point
		// has this x. (x = 1 is NOT such a case - 8 is a residue - which is
		// exactly the sort of near-miss this test exists to keep honest.)
		"x with no y":  "020000000000000000000000000000000000000000000000000000000000000005",
		"uncompressed": "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
	}
	for name, h := range bad {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if isOnCurveCompressed(raw) {
			t.Errorf("%s was accepted as a curve point", name)
		}
	}
}

func TestSilentPaymentTargetValidation(t *testing.T) {
	generator, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	var spend [33]byte
	copy(spend[:], generator)

	t.Run("valid target derives its identity", func(t *testing.T) {
		target := SilentPaymentTarget{ScanSecret: secretOf(0x11), SpendPubkey: spend, Labels: []uint32{0, 7}}
		id, err := target.Validate()
		if err != nil {
			t.Fatal(err)
		}
		direct, err := target.ScanPubkey()
		if err != nil {
			t.Fatal(err)
		}
		if id != direct {
			t.Error("Validate and ScanPubkey disagree on the identity")
		}
	})

	t.Run("a zero scan secret has no public key", func(t *testing.T) {
		target := SilentPaymentTarget{SpendPubkey: spend}
		if _, err := target.Validate(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("got %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("a scan secret at or above the group order is rejected", func(t *testing.T) {
		var sk [32]byte
		secpN.FillBytes(sk[:])
		target := SilentPaymentTarget{ScanSecret: sk, SpendPubkey: spend}
		if _, err := target.Validate(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("n itself: got %v, want ErrInvalidArgument", err)
		}
		for i := range sk {
			sk[i] = 0xff
		}
		target = SilentPaymentTarget{ScanSecret: sk, SpendPubkey: spend}
		if _, err := target.Validate(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("all-ones: got %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("a spend pubkey that is not a point is rejected", func(t *testing.T) {
		var bad [33]byte
		bad[0] = 0x02
		bad[32] = 0x05 // x = 5: x^3 + 7 is a non-residue, so no point has it
		target := SilentPaymentTarget{ScanSecret: secretOf(0x11), SpendPubkey: bad}
		_, err := target.Validate()
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("got %v, want ErrInvalidArgument", err)
		}
		if !strings.Contains(err.Error(), "spend pubkey") {
			t.Errorf("error should name the field: %v", err)
		}
	})

	t.Run("the label cap counts distinct values", func(t *testing.T) {
		target := SilentPaymentTarget{ScanSecret: secretOf(0x11), SpendPubkey: spend}
		// Duplicates collapse, so a long list of repeats is fine.
		for i := 0; i < 100; i++ {
			target.Labels = append(target.Labels, 3)
		}
		if _, err := target.Validate(); err != nil {
			t.Errorf("repeated labels should collapse: %v", err)
		}
		target.Labels = nil
		for i := 0; i < MaxSPLabelsPerTarget; i++ {
			target.Labels = append(target.Labels, uint32(i))
		}
		if _, err := target.Validate(); err != nil {
			t.Errorf("exactly the cap must be accepted: %v", err)
		}
		target.Labels = append(target.Labels, MaxSPLabelsPerTarget)
		if _, err := target.Validate(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("one over the cap: got %v, want ErrInvalidArgument", err)
		}
	})
}

// TestScanSecretIsNotPrintedByFormatting: the scan secret is a credential the
// SDK holds in memory and mirrors across reconnects. A stray %v of a target -
// or of any struct containing one - must not put it in a log.
func TestScanSecretIsNotPrintedByFormatting(t *testing.T) {
	var sk [32]byte
	for i := range sk {
		sk[i] = 0xAB
	}
	target := SilentPaymentTarget{ScanSecret: sk, SpendPubkey: [33]byte{0x02}, Labels: []uint32{0}}
	for _, s := range []string{
		formatValue("%v", target),
		formatValue("%+v", target),
		formatValue("%s", target),
		formatValue("%v", &target),
		// A container holding one must not leak it either.
		formatValue("%v", struct{ T SilentPaymentTarget }{target}),
		formatValue("%v", []SilentPaymentTarget{target}),
	} {
		if strings.Contains(s, "abab") || strings.Contains(s, "171 171") {
			t.Errorf("the scan secret leaked into %q", s)
		}
		if !strings.Contains(s, "redacted") {
			t.Errorf("expected a redaction marker in %q", s)
		}
	}
}

func TestZeroScrubsTheScanSecret(t *testing.T) {
	target := SilentPaymentTarget{ScanSecret: secretOf(0x11)}
	target.Zero()
	for i, b := range target.ScanSecret {
		if b != 0 {
			t.Fatalf("byte %d survived Zero(): %#x", i, b)
		}
	}
}

func TestSameWatchComparesLabelsAsSets(t *testing.T) {
	a := SilentPaymentTarget{SpendPubkey: [33]byte{2}, Labels: []uint32{0, 7, 7}}
	b := SilentPaymentTarget{SpendPubkey: [33]byte{2}, Labels: []uint32{7, 0}}
	if !a.sameWatch(&b) {
		t.Error("label order and duplicates must not make two targets differ")
	}
	c := SilentPaymentTarget{SpendPubkey: [33]byte{2}, Labels: []uint32{0}}
	if a.sameWatch(&c) {
		t.Error("a dropped label is a real difference")
	}
	d := SilentPaymentTarget{SpendPubkey: [33]byte{3}, Labels: []uint32{0, 7}}
	if a.sameWatch(&d) {
		t.Error("a different spend key is a real difference")
	}
}

func TestCloneDoesNotAliasLabels(t *testing.T) {
	orig := SilentPaymentTarget{Labels: []uint32{1, 2}}
	cp := orig.clone()
	cp.Labels[0] = 99
	if orig.Labels[0] != 1 {
		t.Error("clone aliased the caller's Labels slice")
	}
}

// formatValue renders v through fmt, so the redaction tests exercise the same
// path a stray log line would.
func formatValue(verb string, v any) string { return fmt.Sprintf(verb, v) }
