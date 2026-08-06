package satdevents

import (
	"crypto/subtle"
	"math/big"
	"sort"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// secp256k1 domain parameters. Used for exactly two things: deriving a
// silent-payment target's identity b_scan*G, and checking that a supplied
// compressed spend public key is a real curve point.
//
// This is in-tree rather than a btcec dependency on purpose. The SDK's whole
// dependency surface is gRPC + protobuf; pulling btcec would put two
// third-party crypto modules (btcec/v2 wraps Decred's dcrec/secp256k1/v4) into
// every consumer's module graph and force MVS version bumps on btcd- and
// lnd-ecosystem applications, all to validate a public key and multiply the
// base point once per registered target.
//
// SCOPE AND LIMITS. math/big is not constant-time, and neither is the ladder
// below. That is acceptable for exactly this use: b_scan is a WATCH credential
// that the client discloses to the node by design (it lets the node run the
// ECDH match; it confers no spend authority, which stays with B_spend's private
// half and is never sent). A timing side channel on a key that is about to be
// handed over in the clear is not this SDK's weakest link. Do NOT reuse this
// code for a spending key.
var (
	secpP  = mustBig("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	secpN  = mustBig("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	secpB  = big.NewInt(7)
	secpGx = mustBig("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	secpGy = mustBig("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
)

func mustBig(hexStr string) *big.Int {
	v, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		panic("satdevents: bad secp256k1 constant " + hexStr)
	}
	return v
}

// point is an affine curve point; a nil X and Y is the point at infinity.
type point struct{ X, Y *big.Int }

func (p point) isInfinity() bool { return p.X == nil }

func fieldAdd(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), secpP) }
func fieldSub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), secpP) }
func fieldMul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), secpP) }
func fieldInv(a *big.Int) *big.Int    { return new(big.Int).ModInverse(a, secpP) }

// pointAdd is the affine group law, including the doubling and infinity cases.
func pointAdd(p, q point) point {
	if p.isInfinity() {
		return q
	}
	if q.isInfinity() {
		return p
	}
	if p.X.Cmp(q.X) == 0 {
		if fieldAdd(p.Y, q.Y).Sign() == 0 {
			return point{} // p == -q
		}
		// Doubling: lambda = 3x^2 / 2y (a = 0 for secp256k1).
		num := fieldMul(big.NewInt(3), fieldMul(p.X, p.X))
		den := fieldInv(fieldAdd(p.Y, p.Y))
		lambda := fieldMul(num, den)
		x := fieldSub(fieldMul(lambda, lambda), fieldAdd(p.X, p.X))
		y := fieldSub(fieldMul(lambda, fieldSub(p.X, x)), p.Y)
		return point{X: x, Y: y}
	}
	lambda := fieldMul(fieldSub(q.Y, p.Y), fieldInv(fieldSub(q.X, p.X)))
	x := fieldSub(fieldSub(fieldMul(lambda, lambda), p.X), q.X)
	y := fieldSub(fieldMul(lambda, fieldSub(p.X, x)), p.Y)
	return point{X: x, Y: y}
}

// scalarBaseMult computes k*G with a double-and-add-always ladder: every bit
// performs both operations and selects the result, so the number of group
// operations does not depend on the scalar. (The underlying math/big field
// arithmetic is still data-dependent - see the note on the parameters above.)
func scalarBaseMult(k *big.Int) point {
	g := point{X: new(big.Int).Set(secpGx), Y: new(big.Int).Set(secpGy)}
	var acc point
	for i := secpN.BitLen() - 1; i >= 0; i-- {
		acc = pointAdd(acc, acc)
		// Computed on every bit and used only when the bit is set: that is the
		// "always" in double-and-add-always. pointAdd is far too large to
		// inline, so the call is not elided when the result is dropped.
		sum := pointAdd(acc, g)
		if k.Bit(i) == 1 {
			acc = sum
		}
	}
	return acc
}

// compress serializes a point in the 33-byte compressed SEC form.
func compress(p point) [33]byte {
	var out [33]byte
	out[0] = 2 + byte(p.Y.Bit(0))
	p.X.FillBytes(out[1:])
	return out
}

// isOnCurveCompressed reports whether a 33-byte compressed encoding names a
// real secp256k1 point.
//
// Decompression is unnecessary: a compressed key is valid exactly when the
// prefix selects a parity, x is a field element in [1, p-1], and x^3 + 7 is a
// quadratic residue mod p - which Euler's criterion answers with one modular
// exponentiation, no square root and no point arithmetic.
func isOnCurveCompressed(key []byte) bool {
	if len(key) != 33 || (key[0] != 0x02 && key[0] != 0x03) {
		return false
	}
	x := new(big.Int).SetBytes(key[1:])
	if x.Sign() == 0 || x.Cmp(secpP) >= 0 {
		return false
	}
	// y^2 = x^3 + 7 mod p
	y2 := fieldAdd(fieldMul(fieldMul(x, x), x), secpB)
	if y2.Sign() == 0 {
		// y = 0 is not on secp256k1 (b != 0), but guard it rather than let the
		// Legendre symbol below report 0 and fall through as "not a residue".
		return false
	}
	// Euler's criterion: y2 is a residue iff y2^((p-1)/2) == 1 mod p.
	exp := new(big.Int).Rsh(new(big.Int).Sub(secpP, big.NewInt(1)), 1)
	return new(big.Int).Exp(y2, exp, secpP).Cmp(big.NewInt(1)) == 0
}

// SilentPaymentTarget is a BIP 352 scan-key watch target (Tier 2): a
// (ScanSecret, SpendPubkey) pair plus optional labels, registered via
// [WatchHandle.AddSilentPayments]. The node runs the ECDH match and pushes
// [SilentPaymentMatched].
//
// ScanSecret is a WATCH CREDENTIAL, not a spending key: disclosing it lets the
// node (and anyone who compromises it) learn WHICH outputs are yours, but never
// spend them - spend authority stays with SpendPubkey's private half, which is
// never sent. The node holds it in memory per connection, never persists or
// logs it, and a [ResilientWatch] re-discloses it on every reconnect rather
// than the server retaining it.
//
// Its String method redacts the scan secret, so a %v or %+v of a target (or of
// anything containing one) does not put the credential in a log.
type SilentPaymentTarget struct {
	// ScanSecret is the 32-byte scan secret b_scan.
	ScanSecret [32]byte
	// SpendPubkey is the 33-byte compressed spend public key B_spend (the public
	// half only).
	SpendPubkey [33]byte
	// Labels are receiver label integers to also match. Include 0 to catch
	// change. At most [MaxSPLabelsPerTarget] distinct values.
	Labels []uint32
}

// String redacts the scan secret. Defined on the value receiver so it applies
// to both a target and a pointer to one, under %v and %+v alike.
func (t SilentPaymentTarget) String() string {
	return "SilentPaymentTarget{ScanSecret: <redacted>, SpendPubkey: " +
		DisplayHexUnreversed(t.SpendPubkey[:]) + ", Labels: " + formatUints(t.Labels) + "}"
}

// ScanPubkey returns the target's identity b_scan*G (33-byte compressed) - the
// key [WatchHandle.RemoveSilentPayments] takes, and how a [ResilientWatch]
// tracks the target. It never echoes the secret.
func (t *SilentPaymentTarget) ScanPubkey() ([33]byte, error) {
	var out [33]byte
	k := new(big.Int).SetBytes(t.ScanSecret[:])
	// A scan secret must be a scalar in [1, n): 0 has no public key and a value
	// at or above the group order is not a distinct key.
	if k.Sign() == 0 || k.Cmp(secpN) >= 0 {
		return out, newError(KindInvalidArgument, "scan secret is not a valid scalar")
	}
	return compress(scalarBaseMult(k)), nil
}

// Validate checks BOTH curve values - the ScanSecret scalar and the
// SpendPubkey point - along with the label cap, and returns the identity
// b_scan*G.
//
// Client-side validation turns a malformed target into a deterministic error at
// the call site instead of a silent server-side skip, which would return
// success while installing no watch (and, through a [ResilientWatch], replay
// the invalid target on every reconnect forever).
func (t *SilentPaymentTarget) Validate() ([33]byte, error) {
	id, err := t.ScanPubkey() // validates the b_scan scalar
	if err != nil {
		return id, err
	}
	if !isOnCurveCompressed(t.SpendPubkey[:]) {
		return id, newError(KindInvalidArgument, "spend pubkey is not a valid compressed point")
	}
	// Mirror the server's per-target label cap: an over-label target is
	// otherwise silently skipped by the node while the client believes it was
	// installed.
	if n := distinctCount(t.Labels); n > MaxSPLabelsPerTarget {
		return id, newError(KindInvalidArgument,
			"too many silent-payment labels: %d distinct (max %d)", n, MaxSPLabelsPerTarget)
	}
	return id, nil
}

// Zero scrubs the retained scan secret.
//
// The Rust SDK zeroizes on drop; Go has no destructor, so this is explicit. The
// SDK calls it when it discards a mirrored target. Note that Go's garbage
// collector may already have copied the value elsewhere, so unlike the Rust
// guarantee this is best-effort hygiene, not an assurance the bytes are gone.
func (t *SilentPaymentTarget) Zero() {
	for i := range t.ScanSecret {
		t.ScanSecret[i] = 0
	}
}

// clone returns a deep copy, so a mirrored target does not alias the caller's
// Labels slice.
func (t *SilentPaymentTarget) clone() SilentPaymentTarget {
	out := SilentPaymentTarget{ScanSecret: t.ScanSecret, SpendPubkey: t.SpendPubkey}
	if t.Labels != nil {
		out.Labels = append([]uint32(nil), t.Labels...)
	}
	return out
}

// sameWatch reports whether two targets ask for the same thing - the comparison
// a reload uses to decide an entry is unchanged. Labels are compared as sets,
// since the server dedups them.
func (t *SilentPaymentTarget) sameWatch(other *SilentPaymentTarget) bool {
	if subtle.ConstantTimeCompare(t.SpendPubkey[:], other.SpendPubkey[:]) != 1 {
		return false
	}
	a, b := sortedDistinct(t.Labels), sortedDistinct(other.Labels)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (t *SilentPaymentTarget) toProto() *eventspb.SilentPaymentTarget {
	return &eventspb.SilentPaymentTarget{
		ScanSecret:  append([]byte(nil), t.ScanSecret[:]...),
		SpendPubkey: append([]byte(nil), t.SpendPubkey[:]...),
		Labels:      append([]uint32(nil), t.Labels...),
	}
}

func sortedDistinct(in []uint32) []uint32 {
	if len(in) == 0 {
		return nil
	}
	out := append([]uint32(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	n := 0
	for i, v := range out {
		if i == 0 || v != out[n-1] {
			out[n] = v
			n++
		}
	}
	return out[:n]
}

func distinctCount(in []uint32) int { return len(sortedDistinct(in)) }

func formatUints(in []uint32) string {
	if len(in) == 0 {
		return "[]"
	}
	out := "["
	for i, v := range in {
		if i > 0 {
			out += " "
		}
		out += itoa(uint64(v))
	}
	return out + "]"
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// DisplayHexUnreversed renders raw bytes as lowercase hex WITHOUT the byte
// reversal [DisplayHex] applies.
//
// Use it for anything that is not a hash or txid - a public key, a tweak, a
// scriptPubKey - where the wire bytes are already the display form. Keeping the
// two helpers distinct is deliberate: applying the reversing one to a public
// key produces a plausible-looking string that is wrong.
func DisplayHexUnreversed(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
