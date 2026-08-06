package satdevents

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// spk builds a distinct, plausible scriptPubKey per tag (OP_RETURN <tag>).
func spk(tag byte) []byte { return []byte{0x6a, 0x01, tag} }

func TestScripthashIsASingleSha256OfTheScript(t *testing.T) {
	// The node keys watches on a plain sha256 of the scriptPubKey bytes - not a
	// double-sha256, and not of the address or the script hash160. Getting this
	// wrong makes every watch silently match nothing.
	s := spk(1)
	want := sha256.Sum256(s)
	if got := ScripthashOf(s); got != want {
		t.Errorf("ScripthashOf = %x, want %x", got, want)
	}
}

func TestPrefixOfTakesTheTopBytesOfTheScripthash(t *testing.T) {
	s := spk(7)
	sh := ScripthashOf(s)
	cases := []struct {
		bits     uint32
		wantLen  int
		wantBits uint32
	}{
		{8, 1, 8},
		{12, 2, 12}, // ceil(12/8) = 2
		{16, 2, 16},
		{32, 4, 32},
		// Past the node's 32-bit bucketing ceiling: clamped, never a wider prefix
		// the node would silently drop.
		{33, 4, 32},
		{256, 4, 32},
		// Below 1 bit is meaningless; clamped up rather than producing an empty
		// prefix the node would reject.
		{0, 1, 1},
	}
	for _, c := range cases {
		got := PrefixOf(s, c.bits)
		if got.Bits != c.wantBits {
			t.Errorf("PrefixOf(%d).Bits = %d, want %d", c.bits, got.Bits, c.wantBits)
		}
		if len(got.Prefix) != c.wantLen {
			t.Errorf("PrefixOf(%d) is %d byte(s), want %d", c.bits, len(got.Prefix), c.wantLen)
		}
		want := append([]byte(nil), sh[:c.wantLen]...)
		if rem := c.wantBits % 8; rem != 0 {
			want[c.wantLen-1] &= byte(0xff) << (8 - rem)
		}
		if !bytes.Equal(got.Prefix, want) {
			t.Errorf("PrefixOf(%d) = %x, want the masked top bytes %x", c.bits, got.Prefix, want)
		}
		// Nothing past the declared width may reach the wire: those bits are
		// scripthash the node masks away anyway, so sending them only narrows the
		// anonymity set for free.
		if rem := c.wantBits % 8; rem != 0 {
			if got.Prefix[c.wantLen-1]&^(byte(0xff)<<(8-rem)) != 0 {
				t.Errorf("PrefixOf(%d) leaked %d bit(s) past the bucket width: %x",
					c.bits, 8-rem, got.Prefix)
			}
		}
	}
}

// TestPrefixOfIsCompatibleWithTheWireValidator: a prefix this package derives
// must always be one AddScriptPrefixes will accept. If the clamp and the
// validator ever disagree, a consumer following the documented path gets a
// rejection it cannot act on.
func TestPrefixOfIsCompatibleWithTheWireValidator(t *testing.T) {
	for _, bits := range []uint32{0, 1, 7, 8, 9, 16, 31, 32, 33, 1000} {
		p := PrefixOf(spk(3), bits)
		if _, err := validatePrefix(p); err != nil {
			t.Errorf("PrefixOf(%d) produced %v, which the wire validator rejects: %v",
				bits, p, err)
		}
	}
}

func TestPrefixWatcherMembership(t *testing.T) {
	w := NewPrefixWatcher()
	if w.Len() != 0 {
		t.Fatalf("a new watcher holds %d scripts", w.Len())
	}

	sh := w.WatchScript(spk(1))
	if sh != ScripthashOf(spk(1)) {
		t.Errorf("WatchScript returned %x", sh)
	}
	if !w.IsWatched(sh) {
		t.Error("the watched script is not reported as watched")
	}
	// Idempotent: re-watching does not double-count.
	w.WatchScript(spk(1))
	if w.Len() != 1 {
		t.Errorf("Len = %d after watching the same script twice", w.Len())
	}

	if !w.UnwatchScript(spk(1)) {
		t.Error("UnwatchScript reported the script was not watched")
	}
	if w.UnwatchScript(spk(1)) {
		t.Error("UnwatchScript reported a second removal of the same script")
	}
	if w.Len() != 0 || w.IsWatched(sh) {
		t.Error("the script survived being unwatched")
	}
}

// TestPrefixesCollapseSharedBuckets is the privacy property: the node must not
// be able to count how many of your scripts fall in a bucket.
func TestPrefixesCollapseSharedBuckets(t *testing.T) {
	w := NewPrefixWatcher()
	for i := byte(0); i < 40; i++ {
		w.WatchScript(spk(i))
	}
	if w.Len() != 40 {
		t.Fatalf("Len = %d", w.Len())
	}

	// At 1 bit every script shares one of two buckets, so 40 scripts must
	// register at most 2 registrations - never 40.
	narrow := w.Prefixes(1)
	if len(narrow) > 2 {
		t.Errorf("40 scripts produced %d one-bit buckets, want at most 2", len(narrow))
	}
	for _, p := range narrow {
		if p.Bits != 1 || len(p.Prefix) != 1 {
			t.Errorf("one-bit bucket = %+v", p)
		}
	}

	// Every watched script must be covered by some registered bucket, or the
	// consumer silently stops hearing about it.
	for i := byte(0); i < 40; i++ {
		want := PrefixOf(spk(i), 16)
		covered := false
		for _, p := range w.Prefixes(16) {
			if bytes.Equal(p.Prefix, want.Prefix) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("script %d is not covered by any registered 16-bit bucket", i)
		}
	}
}

func TestPrefixesAreDeterministic(t *testing.T) {
	w := NewPrefixWatcher()
	for i := byte(0); i < 30; i++ {
		w.WatchScript(spk(i))
	}
	first := w.Prefixes(16)
	for run := 0; run < 20; run++ {
		got := w.Prefixes(16)
		if len(got) != len(first) {
			t.Fatalf("run %d produced %d buckets, first run produced %d", run, len(got), len(first))
		}
		for i := range got {
			if !bytes.Equal(got[i].Prefix, first[i].Prefix) {
				t.Fatalf("run %d bucket %d = %x, first run had %x",
					run, i, got[i].Prefix, first[i].Prefix)
			}
		}
	}
}

// buildPrefixMatch wraps a raw transaction and its matched prevouts the way the
// node delivers them.
func buildPrefixMatch(raw []byte, prevouts ...SpentPrevout) *PrefixMatched {
	return &PrefixMatched{
		Prefix:          ScriptPrefix{Prefix: []byte{0x00, 0x00}, Bits: 16},
		RawTx:           raw,
		Confirmed:       true,
		Height:          800000,
		MatchedPrevouts: prevouts,
	}
}

// simpleTx serializes a one-input transaction with the given outputs.
func simpleTx(t *testing.T, prevTxid [32]byte, prevVout uint32, outputs ...txOutput) []byte {
	t.Helper()
	b := appendUint32(nil, 2)
	b = appendCompactSize(b, 1)
	b = append(b, prevTxid[:]...)
	b = appendUint32(b, prevVout)
	b = appendCompactSize(b, 0) // empty scriptSig
	b = appendUint32(b, 0xffffffff)
	b = appendCompactSize(b, uint64(len(outputs)))
	for _, o := range outputs {
		b = appendUint64(b, o.value)
		b = appendCompactSize(b, uint64(len(o.scriptPubKey)))
		b = append(b, o.scriptPubKey...)
	}
	return appendUint32(b, 0)
}

// TestFilterKeepsOnlyTheWatchedOutput is the whole point of a prefix watch: the
// bucket delivers decoys, and only the real script may be reported.
func TestFilterKeepsOnlyTheWatchedOutput(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	raw := simpleTx(t, [32]byte{0xaa}, 0,
		txOutput{value: 1000, scriptPubKey: spk(9)}, // decoy sharing the bucket
		txOutput{value: 4200, scriptPubKey: spk(1)}, // the real one
		txOutput{value: 7, scriptPubKey: spk(8)},    // another decoy
	)

	hits, err := w.Filter(buildPrefixMatch(raw))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if !hits.IsMatch() {
		t.Fatal("the watched output was not reported as a match")
	}
	if len(hits.Funding) != 1 {
		t.Fatalf("%d funding hit(s), want only the watched script", len(hits.Funding))
	}
	f := hits.Funding[0]
	if f.Vout != 1 {
		t.Errorf("vout = %d, want 1", f.Vout)
	}
	if f.Value != 4200 {
		t.Errorf("value = %d, want 4200", f.Value)
	}
	if f.Scripthash != ScripthashOf(spk(1)) {
		t.Errorf("scripthash = %x", f.Scripthash)
	}
	if !bytes.Equal(f.ScriptPubKey, spk(1)) {
		t.Errorf("scriptPubKey = %x", f.ScriptPubKey)
	}
	if hits.HasUnresolved() {
		t.Errorf("a pure funding match reported unresolved prevouts: %v", hits.Unresolved)
	}
	if !hits.Confirmed || hits.Height != 800000 {
		t.Errorf("delivery context lost: confirmed=%v height=%d", hits.Confirmed, hits.Height)
	}
}

func TestFilterReportsNoMatchForAPureDecoy(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	raw := simpleTx(t, [32]byte{0xaa}, 0, txOutput{value: 1000, scriptPubKey: spk(9)})

	hits, err := w.Filter(buildPrefixMatch(raw))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if hits.IsMatch() {
		t.Errorf("a bucket decoy was reported as a match: %+v", hits.Funding)
	}
	if hits.HasUnresolved() {
		t.Error("a decoy with no prevouts reported something unresolved")
	}
}

// TestFilterMatchesTheSpendSideAndLocatesItsInput: the spend side is what a
// wallet needs to see its own coins leave.
func TestFilterMatchesTheSpendSideAndLocatesItsInput(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	prevTxid := [32]byte{0xbb}
	raw := simpleTx(t, prevTxid, 3, txOutput{value: 500, scriptPubKey: spk(9)})

	amount := uint64(999)
	hits, err := w.Filter(buildPrefixMatch(raw, SpentPrevout{
		Outpoint:     Outpoint{Txid: prevTxid[:], Vout: 3},
		ScriptPubkey: spk(1),
		Amount:       &amount,
	}))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(hits.Spending) != 1 {
		t.Fatalf("%d spending hit(s), want 1", len(hits.Spending))
	}
	s := hits.Spending[0]
	if s.Vin == nil {
		t.Fatal("the spending input was not located in the decoded transaction")
	}
	if *s.Vin != 0 {
		t.Errorf("vin = %d, want 0", *s.Vin)
	}
	if s.Amount == nil || *s.Amount != 999 {
		t.Errorf("amount = %v, want 999", s.Amount)
	}
	if s.Scripthash != ScripthashOf(spk(1)) {
		t.Errorf("scripthash = %x", s.Scripthash)
	}
}

// TestFilterIgnoresASpendOfAnUnwatchedPrevout: the bucket fires on the prevout's
// script, so most spend-side deliveries are decoys too.
func TestFilterIgnoresASpendOfAnUnwatchedPrevout(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	prevTxid := [32]byte{0xbb}
	raw := simpleTx(t, prevTxid, 0, txOutput{value: 500, scriptPubKey: spk(9)})

	hits, err := w.Filter(buildPrefixMatch(raw, SpentPrevout{
		Outpoint:     Outpoint{Txid: prevTxid[:], Vout: 0},
		ScriptPubkey: spk(9), // a decoy's script, not ours
	}))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if hits.IsMatch() {
		t.Errorf("a decoy prevout was reported as a match: %+v", hits.Spending)
	}
}

// TestUnretainedPrevoutIsUnresolvedNotAMiss is the safety-critical distinction:
// when the node did not retain the prevout's script, the SDK CANNOT tell whether
// it was ours. Reporting it as a non-match would make a wallet miss its own
// outgoing payment.
func TestUnretainedPrevoutIsUnresolvedNotAMiss(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	prevTxid := [32]byte{0xcc}
	raw := simpleTx(t, prevTxid, 2, txOutput{value: 500, scriptPubKey: spk(9)})

	hits, err := w.Filter(buildPrefixMatch(raw, SpentPrevout{
		Outpoint:     Outpoint{Txid: prevTxid[:], Vout: 2},
		ScriptPubkey: nil, // not retained
	}))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if !hits.HasUnresolved() {
		t.Fatal("an unretained prevout was silently dropped instead of surfacing " +
			"as unresolved - a wallet would miss its own spend")
	}
	if len(hits.Unresolved) != 1 || hits.Unresolved[0].Vout != 2 {
		t.Errorf("unresolved = %+v", hits.Unresolved)
	}
	if len(hits.Spending) != 0 {
		t.Errorf("an unhashable prevout was counted as a spending hit: %+v", hits.Spending)
	}
	// It is not a match, but it is not a confirmed miss either - that is exactly
	// what HasUnresolved is for.
	if hits.IsMatch() {
		t.Error("an unresolved prevout was reported as a positive match")
	}
}

func TestFilterReportsTheRecomputedTxid(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	raw := mustHexBytes(t, genesisCoinbaseHex)
	hits, err := w.Filter(buildPrefixMatch(raw))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if got := DisplayHex(hits.Txid[:]); got != genesisTxidDisplay {
		t.Errorf("txid = %s, want %s", got, genesisTxidDisplay)
	}
}

func TestFilterRejectsAMalformedTransaction(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	if _, err := w.Filter(buildPrefixMatch([]byte{0x02, 0x00})); !errors.Is(err, ErrDecode) {
		t.Errorf("got %v, want a decode error", err)
	}
}

// TestFilterFindsBothSidesOfASelfSpend: a transaction that both spends and pays
// a watched script must report both, not just the first one found.
func TestFilterFindsBothSidesOfASelfSpend(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	prevTxid := [32]byte{0xdd}
	raw := simpleTx(t, prevTxid, 1,
		txOutput{value: 100, scriptPubKey: spk(1)},
		txOutput{value: 200, scriptPubKey: spk(1)},
	)
	hits, err := w.Filter(buildPrefixMatch(raw, SpentPrevout{
		Outpoint:     Outpoint{Txid: prevTxid[:], Vout: 1},
		ScriptPubkey: spk(1),
	}))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(hits.Funding) != 2 {
		t.Errorf("%d funding hit(s), want both outputs", len(hits.Funding))
	}
	if len(hits.Spending) != 1 {
		t.Errorf("%d spending hit(s), want 1", len(hits.Spending))
	}
}

// TestFilterLeavesVinNilOnAMismatchedPrevout: the node should never send a
// prevout the transaction does not spend, but a nil vin is the honest answer if
// it does - better than pointing at an unrelated input.
func TestFilterLeavesVinNilOnAMismatchedPrevout(t *testing.T) {
	w := NewPrefixWatcherWithScripts(spk(1))
	raw := simpleTx(t, [32]byte{0xee}, 3, txOutput{value: 1, scriptPubKey: spk(9)})
	hits, err := w.Filter(buildPrefixMatch(raw, SpentPrevout{
		// Same vout as the real input, different txid - so a lookup that only
		// compared the index would wrongly claim vin 0.
		Outpoint:     Outpoint{Txid: bytes.Repeat([]byte{0x77}, 32), Vout: 3},
		ScriptPubkey: spk(1),
	}))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(hits.Spending) != 1 {
		t.Fatalf("%d spending hit(s), want 1", len(hits.Spending))
	}
	if hits.Spending[0].Vin != nil {
		t.Errorf("vin = %d for a prevout the transaction does not spend", *hits.Spending[0].Vin)
	}
}
