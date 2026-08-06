// Package bip352 is the BIP 352 receiver-side derivation the silent-payment
// examples share: given the public tweak T the node publishes and the wallet's
// own (b_scan, b_spend), derive the output key to look for and the key that
// spends it.
//
// It is one package rather than a copy in each example on purpose. The label
// arm below is the part integrators get wrong — omitting the label tweak
// produces a key that looks fine and does not control the output, so change
// silently becomes unspendable — and a single reviewed implementation with one
// test is worth more here than two copy-pasteable ones.
//
// This lives under the examples module, not the SDK, so its curve dependency
// stays out of every consumer's module graph. The SDK itself never needs it:
// validating a scan key is an on-curve check it does in-tree, while DERIVING
// spending keys is wallet work that belongs to whatever key stack the wallet
// already has.
package bip352

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Candidate is one output a wallet could own for a given tweak and counter k.
type Candidate struct {
	// Label is the BIP 352 §5 label m this candidate assumes, or nil for the
	// unlabelled one.
	Label *uint32
	// OutputKey is the 32-byte x-only taproot output key to look for on-chain.
	OutputKey [32]byte
	// SpendKey is the key that spends that output — IF OutputKey really is
	// on-chain. Deriving it costs nothing and proves nothing on its own; a
	// candidate is only yours once its output key is found in the transaction.
	SpendKey [32]byte
}

// DeriveFor derives the single candidate for tweak T at counter k, assuming
// label m (nil for an unlabelled output).
//
// The wallet's spending key is d = b_spend + t_k (+ label_m), where
// t_k = hash_BIP0352/SharedSecret(b_scan·T ‖ ser32(k)) and
// label_m = hash_BIP0352/Label(ser256(b_scan) ‖ ser32(m)). The output key is
// simply d·G — this shortcut holds because B_spend = b_spend·G, so
// B_spend + t_k·G and (b_spend + t_k)·G are the same point.
//
// A WATCH-ONLY scanner that holds B_spend but not b_spend cannot take that
// shortcut: it computes the output key as the point addition B_spend + t_k·G
// and has no spending key to report. That is the only structural difference.
func DeriveFor(scanSecret, spendSecret *btcec.PrivateKey, tweak []byte, k uint32, label *uint32) (Candidate, error) {
	tk, err := sharedSecretTweak(scanSecret, tweak, k)
	if err != nil {
		return Candidate{}, err
	}

	// d = b_spend + t_k
	d := spendSecret.Key
	d.Add(&tk)

	if label != nil {
		lm, err := labelTweak(scanSecret, *label)
		if err != nil {
			return Candidate{}, err
		}
		d.Add(&lm)
	}

	if d.IsZero() {
		// b_spend + t_k ≡ 0 (mod n). Not reachable in practice — it needs a
		// tweak that is exactly the negation of the spend key — but a zero
		// scalar is not a valid key, and returning it as one would hand the
		// caller a private key that signs nothing.
		return Candidate{}, errors.New("bip352: derived a zero spending key")
	}

	spendBytes := d.Bytes()
	_, pub := btcec.PrivKeyFromBytes(spendBytes[:])
	// The compressed encoding is 0x02/0x03 ‖ x, so dropping the parity byte
	// leaves exactly the x-only key a taproot output carries.
	var outputKey [32]byte
	copy(outputKey[:], pub.SerializeCompressed()[1:])

	return Candidate{Label: label, OutputKey: outputKey, SpendKey: spendBytes}, nil
}

// Derive returns every candidate a wallet could own for tweak T at counter k:
// the unlabelled one, plus one per configured label.
//
// A label-less receiver passes no labels. A receiver that uses labels should
// include 0 — BIP 352 reserves it for the sender's own change, so a scanner
// that omits it misses its own change outputs.
func Derive(scanSecret, spendSecret *btcec.PrivateKey, tweak []byte, k uint32, labels []uint32) ([]Candidate, error) {
	out := make([]Candidate, 0, 1+len(labels))
	c, err := DeriveFor(scanSecret, spendSecret, tweak, k, nil)
	if err != nil {
		return nil, err
	}
	out = append(out, c)

	for _, m := range labels {
		c, err := DeriveFor(scanSecret, spendSecret, tweak, k, &m)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// sharedSecretTweak is t_k = hash_BIP0352/SharedSecret(b_scan·T ‖ ser32(k)).
func sharedSecretTweak(scanSecret *btcec.PrivateKey, tweak []byte, k uint32) (btcec.ModNScalar, error) {
	var tk btcec.ModNScalar

	t, err := btcec.ParsePubKey(tweak)
	if err != nil {
		return tk, fmt.Errorf("bip352: tweak is not a valid public key: %w", err)
	}

	var tj, ecdh btcec.JacobianPoint
	t.AsJacobian(&tj)
	btcec.ScalarMultNonConst(&scanSecret.Key, &tj, &ecdh)
	ecdh.ToAffine()
	shared := btcec.NewPublicKey(&ecdh.X, &ecdh.Y)

	var kb [4]byte
	binary.BigEndian.PutUint32(kb[:], k)
	h := taggedHash("BIP0352/SharedSecret", shared.SerializeCompressed(), kb[:])

	if overflow := tk.SetBytes(&h); overflow != 0 {
		// The hash landed at or above the curve order. Reducing it silently
		// would derive a key that disagrees with every other implementation.
		return tk, errors.New("bip352: shared-secret tweak is not a valid scalar")
	}
	return tk, nil
}

// labelTweak is label_m = hash_BIP0352/Label(ser256(b_scan) ‖ ser32(m)).
func labelTweak(scanSecret *btcec.PrivateKey, m uint32) (btcec.ModNScalar, error) {
	var s btcec.ModNScalar

	scan := scanSecret.Key.Bytes()
	var mb [4]byte
	binary.BigEndian.PutUint32(mb[:], m)
	h := taggedHash("BIP0352/Label", scan[:], mb[:])

	// Same reasoning as the shared-secret tweak: silently reducing an
	// out-of-range hash would derive a key no other implementation agrees with.
	if overflow := s.SetBytes(&h); overflow != 0 {
		return s, errors.New("bip352: label tweak is not a valid scalar")
	}
	return s, nil
}

// taggedHash is the BIP 340 construction SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg).
func taggedHash(tag string, msg ...[]byte) [32]byte {
	th := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(th[:])
	h.Write(th[:])
	for _, m := range msg {
		h.Write(m)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
