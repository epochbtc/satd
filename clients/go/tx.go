package satdevents

import (
	"crypto/sha256"
	"encoding/binary"
)

// A minimal consensus transaction decoder.
//
// The SDK deliberately depends on no Bitcoin library - a consumer should be free
// to use btcd, btcsuite, or none at all - but the prefix-privacy re-filter has to
// look inside the transactions the node delivers: it recomputes
// sha256(scriptPubKey) for every output to tell a real match from a
// bucket decoy. That needs exactly two things from a transaction, its outputs
// and its input outpoints, plus the txid. This decoder provides those and
// nothing else.
//
// It is a decoder, not a validator: it accepts anything structurally
// well-formed. It is only ever fed bytes the node produced, so the risk it
// guards against is a malformed or truncated payload causing a panic or a wild
// allocation, not an adversarial consensus divergence.

// decodedTx is the slice of a transaction the prefix filter needs.
type decodedTx struct {
	// txid is the transaction id in INTERNAL byte order (as the wire carries it,
	// reversed from how explorers display it).
	txid [32]byte
	// inputs holds each input's spent outpoint, in order.
	inputs []txInput
	// outputs holds each output's value and script, in order.
	outputs []txOutput
}

type txInput struct {
	prevTxid [32]byte
	prevVout uint32
}

type txOutput struct {
	value        uint64
	scriptPubKey []byte
}

// decodeTx parses a consensus-serialized transaction.
//
// Both the legacy and the BIP 144 segwit serializations are accepted. The txid
// is always computed over the LEGACY serialization (no marker, flag, or
// witnesses), which is what makes a segwit transaction's txid stable under
// witness malleation - and what the node's wire txids are.
func decodeTx(raw []byte) (*decodedTx, error) {
	r := &byteReader{buf: raw}

	version, err := r.uint32()
	if err != nil {
		return nil, newError(KindDecode, "transaction version: %s", err)
	}

	// BIP 144: a zero input count is the segwit marker, followed by a non-zero
	// flag. A real transaction never has zero inputs, so this is unambiguous.
	segwit := false
	inputCount, err := r.compactSize()
	if err != nil {
		return nil, newError(KindDecode, "input count: %s", err)
	}
	if inputCount == 0 {
		flag, err := r.byteValue()
		if err != nil {
			return nil, newError(KindDecode, "segwit flag: %s", err)
		}
		if flag != 1 {
			return nil, newError(KindDecode, "unknown segwit flag 0x%02x", flag)
		}
		segwit = true
		if inputCount, err = r.compactSize(); err != nil {
			return nil, newError(KindDecode, "input count after the segwit marker: %s", err)
		}
	}
	if inputCount == 0 {
		return nil, newError(KindDecode, "transaction has no inputs")
	}
	if err := r.canHold(inputCount, 41); err != nil { // 32+4+1+4 minimum per input
		return nil, newError(KindDecode, "input count %d: %s", inputCount, err)
	}

	tx := &decodedTx{
		inputs: make([]txInput, 0, inputCount),
	}
	// The legacy serialization is rebuilt as we go, so the txid can be hashed
	// over it without a second pass or a byte-range dance.
	legacy := make([]byte, 0, len(raw))
	legacy = appendUint32(legacy, version)
	legacy = appendCompactSize(legacy, inputCount)

	for i := uint64(0); i < inputCount; i++ {
		var in txInput
		if err := r.read(in.prevTxid[:]); err != nil {
			return nil, newError(KindDecode, "input %d prevout txid: %s", i, err)
		}
		if in.prevVout, err = r.uint32(); err != nil {
			return nil, newError(KindDecode, "input %d prevout index: %s", i, err)
		}
		script, err := r.varBytes()
		if err != nil {
			return nil, newError(KindDecode, "input %d scriptSig: %s", i, err)
		}
		sequence, err := r.uint32()
		if err != nil {
			return nil, newError(KindDecode, "input %d sequence: %s", i, err)
		}
		tx.inputs = append(tx.inputs, in)

		legacy = append(legacy, in.prevTxid[:]...)
		legacy = appendUint32(legacy, in.prevVout)
		legacy = appendCompactSize(legacy, uint64(len(script)))
		legacy = append(legacy, script...)
		legacy = appendUint32(legacy, sequence)
	}

	outputCount, err := r.compactSize()
	if err != nil {
		return nil, newError(KindDecode, "output count: %s", err)
	}
	if err := r.canHold(outputCount, 9); err != nil { // 8+1 minimum per output
		return nil, newError(KindDecode, "output count %d: %s", outputCount, err)
	}
	tx.outputs = make([]txOutput, 0, outputCount)
	legacy = appendCompactSize(legacy, outputCount)

	for i := uint64(0); i < outputCount; i++ {
		value, err := r.uint64()
		if err != nil {
			return nil, newError(KindDecode, "output %d value: %s", i, err)
		}
		script, err := r.varBytes()
		if err != nil {
			return nil, newError(KindDecode, "output %d scriptPubKey: %s", i, err)
		}
		tx.outputs = append(tx.outputs, txOutput{value: value, scriptPubKey: script})

		legacy = appendUint64(legacy, value)
		legacy = appendCompactSize(legacy, uint64(len(script)))
		legacy = append(legacy, script...)
	}

	// Witnesses are read only to reach the locktime; they are excluded from the
	// legacy bytes, which is precisely why the txid is witness-invariant.
	if segwit {
		for i := uint64(0); i < inputCount; i++ {
			items, err := r.compactSize()
			if err != nil {
				return nil, newError(KindDecode, "input %d witness count: %s", i, err)
			}
			if err := r.canHold(items, 1); err != nil {
				return nil, newError(KindDecode, "input %d witness count %d: %s", i, items, err)
			}
			for j := uint64(0); j < items; j++ {
				if _, err := r.varBytes(); err != nil {
					return nil, newError(KindDecode, "input %d witness item %d: %s", i, j, err)
				}
			}
		}
	}

	lockTime, err := r.uint32()
	if err != nil {
		return nil, newError(KindDecode, "lock time: %s", err)
	}
	legacy = appendUint32(legacy, lockTime)

	first := sha256.Sum256(legacy)
	tx.txid = sha256.Sum256(first[:])
	return tx, nil
}

// byteReader is a bounds-checked cursor over the serialized transaction.
type byteReader struct {
	buf []byte
	pos int
}

func (r *byteReader) remaining() int { return len(r.buf) - r.pos }

func (r *byteReader) read(into []byte) error {
	if r.remaining() < len(into) {
		return errShortRead(len(into), r.remaining())
	}
	copy(into, r.buf[r.pos:r.pos+len(into)])
	r.pos += len(into)
	return nil
}

func (r *byteReader) byteValue() (byte, error) {
	if r.remaining() < 1 {
		return 0, errShortRead(1, 0)
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *byteReader) uint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, errShortRead(4, r.remaining())
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *byteReader) uint64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, errShortRead(8, r.remaining())
	}
	v := binary.LittleEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// compactSize reads Bitcoin's variable-length integer.
//
// Non-canonical encodings (a value that would fit in a shorter form) are
// accepted rather than rejected: this decoder's job is to read what the node
// sent, and a strictness disagreement would turn a deliverable match into a
// dropped one.
func (r *byteReader) compactSize() (uint64, error) {
	tag, err := r.byteValue()
	if err != nil {
		return 0, err
	}
	switch {
	case tag < 0xfd:
		return uint64(tag), nil
	case tag == 0xfd:
		if r.remaining() < 2 {
			return 0, errShortRead(2, r.remaining())
		}
		v := binary.LittleEndian.Uint16(r.buf[r.pos:])
		r.pos += 2
		return uint64(v), nil
	case tag == 0xfe:
		v, err := r.uint32()
		return uint64(v), err
	default:
		return r.uint64()
	}
}

// varBytes reads a compact-size length followed by that many bytes. The length
// is checked against what is actually left before allocating, so a corrupt
// length cannot induce a large allocation.
func (r *byteReader) varBytes() ([]byte, error) {
	n, err := r.compactSize()
	if err != nil {
		return nil, err
	}
	if n > uint64(r.remaining()) {
		return nil, errShortRead(int(min64(n, 1<<31)), r.remaining())
	}
	out := make([]byte, n)
	if err := r.read(out); err != nil {
		return nil, err
	}
	return out, nil
}

// canHold rejects an item count that could not possibly fit in the bytes left,
// before it is used to size an allocation.
//
// A count is a varint, so a truncated payload can claim billions of items and
// send make() into a multi-gigabyte allocation before the read that would have
// failed. Bounding by the bytes actually remaining is the whole guard: it needs
// no arbitrary ceiling, because the payload length already is one.
func (r *byteReader) canHold(count uint64, minBytesEach int) error {
	// Phrased as a division on the bytes left rather than count*minBytesEach,
	// which would wrap for a count near 2^64 and let the check pass.
	if count > uint64(r.remaining())/uint64(minBytesEach) {
		return newError(KindDecode, "%d items need at least %d bytes each, %d remain",
			count, minBytesEach, r.remaining())
	}
	return nil
}

func errShortRead(want, have int) error {
	return newError(KindDecode, "short read: want %d bytes, %d remain", want, have)
}

func appendUint32(b []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(b, v)
}

func appendUint64(b []byte, v uint64) []byte {
	return binary.LittleEndian.AppendUint64(b, v)
}

func appendCompactSize(b []byte, v uint64) []byte {
	switch {
	case v < 0xfd:
		return append(b, byte(v))
	case v <= 0xffff:
		return binary.LittleEndian.AppendUint16(append(b, 0xfd), uint16(v))
	case v <= 0xffffffff:
		return binary.LittleEndian.AppendUint32(append(b, 0xfe), uint32(v))
	default:
		return binary.LittleEndian.AppendUint64(append(b, 0xff), v)
	}
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
