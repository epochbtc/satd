package satdevents

import (
	"encoding/hex"
)

// DisplayHex renders a raw wire hash or txid - 32 bytes in internal (consensus)
// byte order, as every hash and txid on this API is carried - as the lowercase
// hex string in the reversed display order used by block explorers and Bitcoin
// Core JSON-RPC.
//
// Use it on a hash or txid field (Txid, BlockHash, ...). Do NOT apply it to a
// public key or tweak (OutputPubkey, Tweak, ScanPubkey): those are raw bytes
// and are not reversed for display.
//
// This mismatch is the single most common integration bug against this API - a
// txid compared against getrawtransaction output will silently never match if
// it is not converted here.
func DisplayHex(internalHash []byte) string {
	out := make([]byte, len(internalHash))
	for i, b := range internalHash {
		out[len(internalHash)-1-i] = b
	}
	return hex.EncodeToString(out)
}

// ParseTxid validates a raw wire txid (32 bytes, internal byte order) and
// returns it as a fixed-size array - the form the watch helpers take, and one
// that is comparable and usable as a map key.
//
// The bytes are carried through unchanged; use [DisplayHex] when you need the
// explorer / JSON-RPC rendering.
func ParseTxid(raw []byte) ([32]byte, error) {
	var out [32]byte
	if len(raw) != 32 {
		return out, newError(KindInvalidArgument, "txid must be 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// TxidFromDisplayHex parses a txid in the reversed display order that block
// explorers and Bitcoin Core JSON-RPC use, returning the internal-byte-order
// array the watch helpers take.
//
// This is the inverse of [DisplayHex] and the conversion to reach for when
// feeding a txid from getrawtransaction, sendrawtransaction, or a user into a
// watch registration.
func TxidFromDisplayHex(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, wrapError(KindInvalidArgument, err, "txid hex: %s", err)
	}
	if len(raw) != 32 {
		return out, newError(KindInvalidArgument, "txid must be 32 bytes, got %d", len(raw))
	}
	for i, b := range raw {
		out[31-i] = b
	}
	return out, nil
}
