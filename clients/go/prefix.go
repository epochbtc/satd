package satdevents

import "sort"

// Privacy-preserving prefix-watch local re-filter.
//
// A prefix watch trades precision for privacy: the consumer registers a
// bits-wide prefix of sha256(scriptPubKey), and the node delivers EVERY
// transaction whose output or spent prevout falls in that 2^-bits bucket. The
// node therefore learns only the bucket, never the exact script - but the
// stream now carries decoys the consumer has to filter out itself.
//
// [PrefixWatcher] is that filter. It holds the consumer's real scriptPubKeys (as
// their scripthashes) and, given a [PrefixMatched], decodes the inline raw
// transaction, recomputes sha256(scriptPubKey) for every output and every
// retained spent prevout, and reports only the true hits - with no precise
// follow-up fetch that would re-leak the exact script.

// PrefixOf derives the (prefix, bits) registration tuple for a scriptPubKey: the
// top ceil(bits/8) bytes of its scripthash, with every bit below bits zeroed.
//
// bits is clamped to 1..=[MaxPrefixBits]. The node buckets on the top 32 bits of
// the scripthash only, so a wider prefix is meaningless and would be silently
// dropped; [WatchHandle.AddScriptPrefixes] re-validates the same bound.
//
// The masking matters for the privacy this feature exists to provide. The wire
// carries whole bytes, so a 12-bit bucket ships 2 bytes - and the node keys on
// the top 12 bits only, masking the rest away. Sending those 4 extra bits
// unmasked would hand the node more of the scripthash than the declared bucket
// width, narrowing the anonymity set for free. Masking costs nothing: the node
// derives the identical bucket key either way.
func PrefixOf(scriptPubKey []byte, bits uint32) ScriptPrefix {
	bits = clampPrefixBits(bits)
	sh := ScripthashOf(scriptPubKey)
	return ScriptPrefix{Prefix: maskPrefix(sh[:], bits), Bits: bits}
}

// maskPrefix takes the top ceil(bits/8) bytes and zeroes every bit past bits.
func maskPrefix(scripthash []byte, bits uint32) []byte {
	n := (bits + 7) / 8
	out := append([]byte(nil), scripthash[:n]...)
	if rem := bits % 8; rem != 0 {
		out[n-1] &= byte(0xff) << (8 - rem)
	}
	return out
}

// maskPrefixSafe is maskPrefix for the declarative paths, where an invalid
// (Prefix, Bits) pair is not reported until render time. A wrong-length or
// out-of-range input is copied through untouched so the error still surfaces
// from validatePrefix, rather than becoming a slice-bounds panic here.
func maskPrefixSafe(prefix []byte, bits uint32) []byte {
	if bits < 1 || bits > MaxPrefixBits || len(prefix) != int((bits+7)/8) {
		return append([]byte(nil), prefix...)
	}
	return maskPrefix(prefix, bits)
}

func clampPrefixBits(bits uint32) uint32 {
	if bits < 1 {
		return 1
	}
	if bits > MaxPrefixBits {
		return MaxPrefixBits
	}
	return bits
}

// FundingHit is an output of a delivered transaction that pays a watched script.
type FundingHit struct {
	// Vout is the output index within the transaction.
	Vout uint32
	// Scripthash is the matched sha256(scriptPubKey).
	Scripthash [32]byte
	// Value is the output value in satoshis.
	Value uint64
	// ScriptPubKey is the output's script.
	ScriptPubKey []byte
}

// SpendingHit is a spent prevout of a delivered transaction that consumed a
// watched script.
//
// Only produced for prevouts whose script the node retained; the rest surface in
// [PrefixHits.Unresolved].
type SpendingHit struct {
	// Vin is the input index that spends the prevout, if it was located in the
	// decoded transaction. nil only on a malformed or mismatched payload.
	Vin *uint32
	// Outpoint is the consumed outpoint.
	Outpoint Outpoint
	// Scripthash is the matched sha256(scriptPubKey).
	Scripthash [32]byte
	// ScriptPubKey is the prevout's script.
	ScriptPubKey []byte
	// Amount is the prevout value in satoshis. nil when the node retained the
	// script but not the value - which is distinct from a genuine 0-sat prevout,
	// where this is non-nil and zero.
	Amount *uint64
}

// PrefixHits is the result of re-filtering one [PrefixMatched] against the
// watched set.
type PrefixHits struct {
	// Txid is the delivered transaction's id, recomputed from the raw bytes, in
	// internal byte order.
	Txid [32]byte
	// Confirmed is false for a mempool delivery, true for one in a connected
	// block.
	Confirmed bool
	// Height is the block height when confirmed, 0 in the mempool.
	Height uint32
	// Funding holds the outputs paying a watched script.
	Funding []FundingHit
	// Spending holds the spent prevouts of a watched script whose script the node
	// retained.
	Spending []SpendingHit
	// Unresolved holds spend-side prevouts the node did NOT retain the script for
	// (a mempool spend below the `full` retention tier): the bucket fired but the
	// script is absent, so the match cannot be settled locally. Resolve these
	// outpoints yourself to complete the filter - never treat them as
	// non-matches.
	Unresolved []Outpoint
}

// IsMatch reports whether any genuine output or spend match was found.
func (h *PrefixHits) IsMatch() bool {
	return len(h.Funding) > 0 || len(h.Spending) > 0
}

// HasUnresolved reports whether any spend-side prevout could not be filtered
// locally. The caller must resolve [PrefixHits.Unresolved] before concluding
// that this transaction is a true non-match.
func (h *PrefixHits) HasUnresolved() bool { return len(h.Unresolved) > 0 }

// PrefixWatcher holds the consumer's real scriptPubKeys and re-filters coarse
// prefix-bucket deliveries down to true matches.
//
// It is not safe for concurrent use; guard it yourself if the filtering and the
// watch registration happen on different goroutines.
type PrefixWatcher struct {
	watched map[[32]byte]struct{}
}

// NewPrefixWatcher returns an empty watcher.
func NewPrefixWatcher() *PrefixWatcher {
	return &PrefixWatcher{watched: map[[32]byte]struct{}{}}
}

// NewPrefixWatcherWithScripts returns a watcher over scripts.
func NewPrefixWatcherWithScripts(scripts ...[]byte) *PrefixWatcher {
	w := NewPrefixWatcher()
	for _, s := range scripts {
		w.WatchScript(s)
	}
	return w
}

// WatchScript watches a scriptPubKey and returns its scripthash - the value the
// node keys watches on. Idempotent.
func (w *PrefixWatcher) WatchScript(scriptPubKey []byte) [32]byte {
	if w.watched == nil {
		w.watched = map[[32]byte]struct{}{}
	}
	sh := ScripthashOf(scriptPubKey)
	w.watched[sh] = struct{}{}
	return sh
}

// UnwatchScript stops watching a scriptPubKey, reporting whether it had been
// watched.
func (w *PrefixWatcher) UnwatchScript(scriptPubKey []byte) bool {
	sh := ScripthashOf(scriptPubKey)
	if _, ok := w.watched[sh]; !ok {
		return false
	}
	delete(w.watched, sh)
	return true
}

// IsWatched reports whether scripthash is in the watched set.
func (w *PrefixWatcher) IsWatched(scripthash [32]byte) bool {
	_, ok := w.watched[scripthash]
	return ok
}

// Len is the number of watched scripts.
func (w *PrefixWatcher) Len() int { return len(w.watched) }

// Prefixes is the deduplicated set of buckets covering every watched script at
// width bits - pass it straight to [WatchHandle.AddScriptPrefixes] or
// [ResilientWatch.AddScriptPrefixes].
//
// Distinct scripts sharing a bucket collapse to one registration, which is the
// point: the node cannot tell how many of your scripts a bucket covers. Bits
// below the bucket width are masked off before deduplicating, so a narrow bucket
// really does collapse - at 1 bit, any number of scripts registers at most two
// buckets, not one per distinct leading byte. bits is clamped to
// 1..=[MaxPrefixBits], matching [PrefixOf].
//
// The result is sorted, so the same watched set always registers the same
// buckets in the same order.
func (w *PrefixWatcher) Prefixes(bits uint32) []ScriptPrefix {
	bits = clampPrefixBits(bits)
	seen := map[string]struct{}{}
	out := make([]ScriptPrefix, 0, len(w.watched))
	for sh := range w.watched {
		p := maskPrefix(sh[:], bits)
		if _, dup := seen[string(p)]; dup {
			continue
		}
		seen[string(p)] = struct{}{}
		out = append(out, ScriptPrefix{Prefix: p, Bits: bits})
	}
	sort.Slice(out, func(i, j int) bool { return compareBytes(out[i].Prefix, out[j].Prefix) < 0 })
	return out
}

// Filter re-filters a [PrefixMatched] against the watched set.
//
// It decodes the delivered transaction, recomputes sha256(scriptPubKey) for each
// output and each retained spent prevout, and returns the true hits. A raw
// transaction that is not a valid consensus serialization is a decode error.
func (w *PrefixWatcher) Filter(m *PrefixMatched) (*PrefixHits, error) {
	tx, err := decodeTx(m.RawTx)
	if err != nil {
		return nil, err
	}

	hits := &PrefixHits{
		Txid:      tx.txid,
		Confirmed: m.Confirmed,
		Height:    m.Height,
	}

	for vout, out := range tx.outputs {
		sh := ScripthashOf(out.scriptPubKey)
		if _, ok := w.watched[sh]; !ok {
			continue
		}
		hits.Funding = append(hits.Funding, FundingHit{
			Vout:         uint32(vout),
			Scripthash:   sh,
			Value:        out.value,
			ScriptPubKey: out.scriptPubKey,
		})
	}

	for _, sp := range m.MatchedPrevouts {
		if len(sp.ScriptPubkey) == 0 {
			// The node did not retain the script, so it cannot be hashed here.
			// This is NOT a non-match - the caller has to resolve it.
			hits.Unresolved = append(hits.Unresolved, sp.Outpoint)
			continue
		}
		sh := ScripthashOf(sp.ScriptPubkey)
		if _, ok := w.watched[sh]; !ok {
			continue
		}
		hits.Spending = append(hits.Spending, SpendingHit{
			Vin:          findVin(tx, sp.Outpoint),
			Outpoint:     sp.Outpoint,
			Scripthash:   sh,
			ScriptPubKey: sp.ScriptPubkey,
			Amount:       sp.Amount,
		})
	}

	return hits, nil
}

// findVin locates the input index spending outpoint, comparing the raw internal
// byte order the wire carries.
func findVin(tx *decodedTx, outpoint Outpoint) *uint32 {
	for i, in := range tx.inputs {
		if in.prevVout != outpoint.Vout {
			continue
		}
		if len(outpoint.Txid) == 32 && string(in.prevTxid[:]) == string(outpoint.Txid) {
			v := uint32(i)
			return &v
		}
	}
	return nil
}
