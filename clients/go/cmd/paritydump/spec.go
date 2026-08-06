package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// The watch spec both dumpers read.
//
// It is JSON rather than flags because the whole point of the harness is that
// the Go and the Rust dumper are driven by BYTE-IDENTICAL input: one file, two
// readers. A flag surface would have to be kept in sync by hand, and a drift
// there would look exactly like a parity bug in the SDKs.
//
// Every hash and id is hex in INTERNAL byte order - the order the wire carries,
// not the reversed order explorers display - so the spec needs no endianness
// convention beyond "what the protocol says".

type spec struct {
	// Categories is the firehose category bitfield; 0 means all.
	Categories uint32 `json:"categories"`
	// IncludeRawTx opts into inline raw transactions on match events.
	IncludeRawTx bool `json:"include_raw_tx"`

	Scripts        []specScript    `json:"scripts"`
	Outpoints      []specOutpoint  `json:"outpoints"`
	Lifecycles     []specLifecycle `json:"lifecycles"`
	DepthAlarms    []specDepth     `json:"depth_alarms"`
	Descriptors    []specDesc      `json:"descriptors"`
	Prefixes       []specPrefix    `json:"prefixes"`
	SilentPayments []specSP        `json:"silent_payments"`
}

type specScript struct {
	Scripthash string  `json:"scripthash"`
	MinValue   *uint64 `json:"min_value"`
}

type specOutpoint struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type specLifecycle struct {
	Txid string `json:"txid"`
	// AutoCloseDepth is the auto-close depth: 0 never closes, N closes at N
	// confirmations. A depth is the one shape both SDKs can express - Go models
	// AutoClose as a uint32 depth, Rust as `Never | AtDepth(u32)`.
	AutoCloseDepth uint32 `json:"auto_close_depth"`
}

type specDepth struct {
	Txid  string `json:"txid"`
	Depth uint32 `json:"depth"`
}

type specDesc struct {
	Descriptor string `json:"descriptor"`
	GapLimit   uint32 `json:"gap_limit"`
	Start      uint32 `json:"start"`
}

type specPrefix struct {
	Prefix string `json:"prefix"`
	Bits   uint32 `json:"bits"`
}

type specSP struct {
	ScanSecret  string   `json:"scan_secret"`
	SpendPubkey string   `json:"spend_pubkey"`
	Labels      []uint32 `json:"labels"`
}

func loadSpec(path string) (*spec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	// An unknown key means the Rust twin grew a field this side does not read,
	// which would silently narrow the Go watch set and show up as a mystery
	// diff. Fail on it instead.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// hash32 decodes a 32-byte hex field, rejecting a wrong length outright rather
// than zero-padding it into a watch that silently never matches.
func hash32(field, s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("%s: %w", field, err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("%s: want 32 bytes, got %d", field, len(b))
	}
	copy(out[:], b)
	return out, nil
}

func hash33(field, s string) ([33]byte, error) {
	var out [33]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("%s: %w", field, err)
	}
	if len(b) != 33 {
		return out, fmt.Errorf("%s: want 33 bytes, got %d", field, len(b))
	}
	copy(out[:], b)
	return out, nil
}

// apply registers the whole spec on a live watch handle.
//
// Ordering is fixed and matches the Rust twin's: the node acknowledges each
// control separately, and a different registration order would put the
// WatchSetReplaced acks in a different sequence in the two dumps.
func (s *spec) apply(ctx context.Context, h *satdevents.WatchHandle) error {
	if s.Categories != 0 {
		if err := h.SetCategories(ctx, s.Categories); err != nil {
			return err
		}
	}
	if s.IncludeRawTx {
		if err := h.SetWatchOptions(ctx, true); err != nil {
			return err
		}
	}

	if len(s.Scripts) > 0 {
		items := make([]satdevents.ScriptWatch, 0, len(s.Scripts))
		for i, sc := range s.Scripts {
			sh, err := hash32(fmt.Sprintf("scripts[%d].scripthash", i), sc.Scripthash)
			if err != nil {
				return err
			}
			items = append(items, satdevents.ScriptWatch{Scripthash: sh, MinValue: sc.MinValue})
		}
		if err := h.AddScripts(ctx, items); err != nil {
			return err
		}
	}

	if len(s.Outpoints) > 0 {
		items := make([]satdevents.OutpointRef, 0, len(s.Outpoints))
		for i, op := range s.Outpoints {
			txid, err := hash32(fmt.Sprintf("outpoints[%d].txid", i), op.Txid)
			if err != nil {
				return err
			}
			items = append(items, satdevents.OutpointRef{Txid: txid, Vout: op.Vout})
		}
		if err := h.AddOutpoints(ctx, items); err != nil {
			return err
		}
	}

	// Lifecycles are grouped by policy: AddTxLifecycle takes one policy for the
	// whole batch, and issuing one control per txid would change the ack count.
	byPolicy := map[uint32][][32]byte{}
	order := []uint32{}
	for i, lc := range s.Lifecycles {
		txid, err := hash32(fmt.Sprintf("lifecycles[%d].txid", i), lc.Txid)
		if err != nil {
			return err
		}
		if _, seen := byPolicy[lc.AutoCloseDepth]; !seen {
			order = append(order, lc.AutoCloseDepth)
		}
		byPolicy[lc.AutoCloseDepth] = append(byPolicy[lc.AutoCloseDepth], txid)
	}
	for _, p := range order {
		if err := h.AddTxLifecycle(ctx, byPolicy[p], satdevents.AutoClose(p)); err != nil {
			return err
		}
	}

	if len(s.DepthAlarms) > 0 {
		txids := make([][32]byte, 0, len(s.DepthAlarms))
		depths := make([]uint32, 0, len(s.DepthAlarms))
		for i, da := range s.DepthAlarms {
			txid, err := hash32(fmt.Sprintf("depth_alarms[%d].txid", i), da.Txid)
			if err != nil {
				return err
			}
			txids = append(txids, txid)
			depths = append(depths, da.Depth)
		}
		if err := h.AddDepthAlarms(ctx, txids, depths); err != nil {
			return err
		}
	}

	for _, d := range s.Descriptors {
		if err := h.AddDescriptor(ctx, d.Descriptor, d.GapLimit, d.Start); err != nil {
			return err
		}
	}

	if len(s.Prefixes) > 0 {
		items := make([]satdevents.ScriptPrefix, 0, len(s.Prefixes))
		for i, p := range s.Prefixes {
			b, err := hex.DecodeString(p.Prefix)
			if err != nil {
				return fmt.Errorf("prefixes[%d].prefix: %w", i, err)
			}
			items = append(items, satdevents.ScriptPrefix{Prefix: b, Bits: p.Bits})
		}
		if err := h.AddScriptPrefixes(ctx, items); err != nil {
			return err
		}
	}

	if len(s.SilentPayments) > 0 {
		items := make([]satdevents.SilentPaymentTarget, 0, len(s.SilentPayments))
		for i, sp := range s.SilentPayments {
			scan, err := hash32(fmt.Sprintf("silent_payments[%d].scan_secret", i), sp.ScanSecret)
			if err != nil {
				return err
			}
			spend, err := hash33(fmt.Sprintf("silent_payments[%d].spend_pubkey", i), sp.SpendPubkey)
			if err != nil {
				return err
			}
			items = append(items, satdevents.SilentPaymentTarget{
				ScanSecret: scan, SpendPubkey: spend, Labels: sp.Labels,
			})
		}
		if err := h.AddSilentPayments(ctx, items); err != nil {
			return err
		}
	}

	return nil
}
