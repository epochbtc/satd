package bip352

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// The receiver derivation under test takes a shortcut: it computes the spending
// key d = b_spend + t_k and then the output key as d·G, rather than the output
// key as the point addition B_spend + t_k·G. The two are equal because
// B_spend = b_spend·G, but "equal by algebra I wrote in a comment" is not a
// property a test should assume.
//
// So these tests play the SENDER, which reaches the same output key by a
// genuinely different route:
//
//   - The shared secret comes from the other side of the ECDH. The receiver
//     computes b_scan·T; the sender computes a·B_scan. Same point, different
//     scalar and different base — a mistake in one is not mirrored in the other.
//   - The output key is built by point addition on the sender's side against
//     scalar addition on the receiver's.
//
// A test that re-derived the receiver's way would agree with any bug it had.
//
// Two pieces are NOT independently checked here, and saying so is cheaper than
// letting a reader assume otherwise:
//
//   - taggedHash is shared with the code under test, so a spec misreading of the
//     BIP 340 construction would be mirrored on both sides. The test below at
//     least pins it against an explicit re-statement of the formula, which
//     catches a coding slip if not a misreading.
//   - A real sender structurally cannot compute the label tweak: it is derived
//     from b_scan, and a sender just pays a labelled address that already has
//     the tweak folded into B_spend. So the sender view here is handed one — but
//     computed from the BIP text in specLabelTweak, not by calling the function
//     under test, so a bug inside labelTweak does not cancel out on both sides.
//
// The authoritative check that this agrees with BIP 352 as deployed is the
// node's own silent-payment index matching real payments, which the E2E suite
// covers; this file guards the arithmetic these examples do on top of it.

// senderView is the sender half of a BIP 352 payment, built independently of
// the code under test.
type senderView struct {
	// a is the sender's aggregated input key. The real protocol multiplies the
	// summed input keys by an input hash first; the product is what matters
	// here, so treat a as already aggregated.
	a *btcec.PrivateKey
	// tweak is T = a·G — exactly what the node publishes to scanners.
	tweak []byte
	// bScan, bSpend are the receiver's public keys, as a sender knows them.
	bScan, bSpend *btcec.PublicKey
}

func newSenderView(t *testing.T, senderSecret, scanSecret, spendSecret *btcec.PrivateKey) senderView {
	t.Helper()
	return senderView{
		a:      senderSecret,
		tweak:  senderSecret.PubKey().SerializeCompressed(),
		bScan:  scanSecret.PubKey(),
		bSpend: spendSecret.PubKey(),
	}
}

// outputKey is the x-only taproot key the sender would pay for counter k and
// optional label m: B_spend + t_k·G [+ label_m·G], via point addition.
func (s senderView) outputKey(t *testing.T, k uint32, label *uint32, labelTweakBytes [32]byte) [32]byte {
	t.Helper()

	// ecdh = a·B_scan — the sender's side of the same shared secret the
	// receiver reaches as b_scan·T.
	var bScanJ, ecdhJ btcec.JacobianPoint
	s.bScan.AsJacobian(&bScanJ)
	btcec.ScalarMultNonConst(&s.a.Key, &bScanJ, &ecdhJ)
	ecdhJ.ToAffine()
	shared := btcec.NewPublicKey(&ecdhJ.X, &ecdhJ.Y)

	var kb [4]byte
	binary.BigEndian.PutUint32(kb[:], k)
	tkBytes := taggedHash("BIP0352/SharedSecret", shared.SerializeCompressed(), kb[:])

	var tk btcec.ModNScalar
	if overflow := tk.SetBytes(&tkBytes); overflow != 0 {
		t.Fatal("shared-secret tweak overflowed the curve order")
	}

	// P_k = B_spend + t_k·G
	var bSpendJ, tkG, sum btcec.JacobianPoint
	s.bSpend.AsJacobian(&bSpendJ)
	btcec.ScalarBaseMultNonConst(&tk, &tkG)
	btcec.AddNonConst(&bSpendJ, &tkG, &sum)

	if label != nil {
		// P_k + label_m·G
		var lm btcec.ModNScalar
		if overflow := lm.SetBytes(&labelTweakBytes); overflow != 0 {
			t.Fatal("label tweak overflowed the curve order")
		}
		var lmG, withLabel btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&lm, &lmG)
		btcec.AddNonConst(&sum, &lmG, &withLabel)
		sum = withLabel
	}

	sum.ToAffine()
	pub := btcec.NewPublicKey(&sum.X, &sum.Y)

	var out [32]byte
	copy(out[:], pub.SerializeCompressed()[1:])
	return out
}

// specLabelTweak restates BIP 352 §5 directly —
// label_m = hash_BIP0352/Label(ser256(b_scan) ‖ ser32(m)) — rather than calling
// labelTweak. Reusing the implementation would make the sender agree with any
// bug in it: keying the hash on the wrong secret, or serializing m the wrong
// way round, would cancel out on both sides and the test would stay green.
func specLabelTweak(scanSecret *btcec.PrivateKey, m uint32) [32]byte {
	scan := scanSecret.Serialize()
	var mb [4]byte
	binary.BigEndian.PutUint32(mb[:], m)
	return taggedHash("BIP0352/Label", scan, mb[:])
}

func testKeys(t *testing.T) (sender, scan, spend *btcec.PrivateKey) {
	t.Helper()
	// Fixed scalars: this test must be deterministic, and these are not secrets.
	sender, _ = btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x07}, 32))
	scan, _ = btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x11}, 32))
	spend, _ = btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x22}, 32))
	return sender, scan, spend
}

func TestDerivedOutputKeyMatchesTheSender(t *testing.T) {
	senderSecret, scan, spend := testKeys(t)
	view := newSenderView(t, senderSecret, scan, spend)

	label := uint32(0)
	for _, tc := range []struct {
		name  string
		k     uint32
		label *uint32
	}{
		{name: "unlabelled k=0", k: 0},
		{name: "unlabelled k=1", k: 1},
		{name: "labelled k=0", k: 0, label: &label},
		{name: "labelled k=3", k: 3, label: &label},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveFor(scan, spend, view.tweak, tc.k, tc.label)
			if err != nil {
				t.Fatalf("DeriveFor: %v", err)
			}

			var lm [32]byte
			if tc.label != nil {
				lm = specLabelTweak(scan, *tc.label)
			}
			want := view.outputKey(t, tc.k, tc.label, lm)

			if got.OutputKey != want {
				t.Errorf("output key disagrees with the sender\n got %x\nwant %x", got.OutputKey, want)
			}
		})
	}
}

// The spending key is the whole point: an output key that matches while its
// spending key does not control the output is a wallet that sees payments it
// can never move.
func TestSpendKeyControlsTheDerivedOutput(t *testing.T) {
	senderSecret, scan, spend := testKeys(t)
	view := newSenderView(t, senderSecret, scan, spend)

	label := uint32(7)
	c, err := DeriveFor(scan, spend, view.tweak, 0, &label)
	if err != nil {
		t.Fatalf("DeriveFor: %v", err)
	}

	_, pub := btcec.PrivKeyFromBytes(c.SpendKey[:])
	var xOnly [32]byte
	copy(xOnly[:], pub.SerializeCompressed()[1:])

	if xOnly != c.OutputKey {
		t.Errorf("spend key does not control the output key\n key·G %x\noutput %x", xOnly, c.OutputKey)
	}
}

// Omitting the label tweak is the classic BIP 352 integration bug: it yields a
// key that looks fine and does not control the output, so change silently
// becomes unspendable. That failure is only detectable if the labelled and
// unlabelled derivations genuinely differ.
func TestLabelChangesBothKeys(t *testing.T) {
	senderSecret, scan, spend := testKeys(t)
	view := newSenderView(t, senderSecret, scan, spend)

	label := uint32(0)
	plain, err := DeriveFor(scan, spend, view.tweak, 0, nil)
	if err != nil {
		t.Fatalf("DeriveFor unlabelled: %v", err)
	}
	labelled, err := DeriveFor(scan, spend, view.tweak, 0, &label)
	if err != nil {
		t.Fatalf("DeriveFor labelled: %v", err)
	}

	if plain.OutputKey == labelled.OutputKey {
		t.Error("label 0 produced the same output key as no label at all")
	}
	if plain.SpendKey == labelled.SpendKey {
		t.Error("label 0 produced the same spend key as no label at all")
	}
}

// Each k must give a distinct output, or a transaction paying the same receiver
// twice would collapse into one detectable output.
func TestCounterChangesTheOutputKey(t *testing.T) {
	senderSecret, scan, spend := testKeys(t)
	view := newSenderView(t, senderSecret, scan, spend)

	seen := map[[32]byte]uint32{}
	for k := uint32(0); k < 4; k++ {
		c, err := DeriveFor(scan, spend, view.tweak, k, nil)
		if err != nil {
			t.Fatalf("DeriveFor k=%d: %v", k, err)
		}
		if prev, dup := seen[c.OutputKey]; dup {
			t.Fatalf("k=%d derived the same output key as k=%d", k, prev)
		}
		seen[c.OutputKey] = k
	}
}

func TestDeriveReturnsUnlabelledFirstThenEachLabel(t *testing.T) {
	senderSecret, scan, spend := testKeys(t)
	view := newSenderView(t, senderSecret, scan, spend)

	labels := []uint32{0, 5}
	got, err := Derive(scan, spend, view.tweak, 1, labels)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if len(got) != len(labels)+1 {
		t.Fatalf("want %d candidates, got %d", len(labels)+1, len(got))
	}
	if got[0].Label != nil {
		t.Errorf("first candidate should be the unlabelled one, got label %d", *got[0].Label)
	}
	for i, m := range labels {
		c := got[i+1]
		if c.Label == nil || *c.Label != m {
			t.Errorf("candidate %d: want label %d, got %v", i+1, m, c.Label)
			continue
		}
		// Each labelled candidate must match what DeriveFor produces for that
		// label — a loop that closed over the wrong variable would still return
		// the right COUNT of candidates with the right labels attached to the
		// wrong keys.
		want, err := DeriveFor(scan, spend, view.tweak, 1, &m)
		if err != nil {
			t.Fatalf("DeriveFor label %d: %v", m, err)
		}
		if c.OutputKey != want.OutputKey {
			t.Errorf("candidate for label %d has the wrong output key", m)
		}
	}
}

// BIP 340's tagged hash is SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg). The doubled
// tag hash is the part that gets written once by accident, and the result still
// looks like a hash — so pin the shape against an explicit re-statement.
func TestTaggedHashIsTheBIP340Construction(t *testing.T) {
	const tag = "BIP0352/SharedSecret"
	msg := []byte("some message")

	th := sha256.Sum256([]byte(tag))
	want := sha256.Sum256(append(append(append([]byte{}, th[:]...), th[:]...), msg...))

	if got := taggedHash(tag, msg); got != want {
		t.Errorf("tagged hash\n got %x\nwant %x", got, want)
	}

	// The variadic message pieces must concatenate, not be hashed separately.
	if got := taggedHash(tag, msg[:4], msg[4:]); got != want {
		t.Errorf("split message hashed differently from the whole\n got %x\nwant %x", got, want)
	}
}

func TestTweakThatIsNotAPointIsRejected(t *testing.T) {
	_, scan, spend := testKeys(t)

	for name, tweak := range map[string][]byte{
		"empty":              {},
		"too short":          bytes.Repeat([]byte{0x02}, 32),
		"not on the curve":   append([]byte{0x02}, bytes.Repeat([]byte{0xff}, 32)...),
		"bad parity prefix":  append([]byte{0x05}, bytes.Repeat([]byte{0x11}, 32)...),
		"uncompressed sized": bytes.Repeat([]byte{0x04}, 65),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DeriveFor(scan, spend, tweak, 0, nil); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}
