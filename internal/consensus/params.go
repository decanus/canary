// Package consensus implements the Canary consensus rules (SPEC.md §3–§5).
//
// Everything here is deterministic integer arithmetic using only the standard library:
// no floats, no randomness and no big.Int.ProbablyPrime.
package consensus

import "errors"

// Params holds the chain parameters of SPEC.md §2. The JSON tags match the "params" object of
// the chain JSON format (§11) and of reference/test_vectors.json.
type Params struct {
	Tau           int64  `json:"tau"`            // target block interval, seconds
	Epoch         int64  `json:"epoch"`          // blocks per difficulty epoch
	GenesisBits   uint32 `json:"genesis_bits"`   // b for height 0
	MinBits       uint32 `json:"min_bits"`       // lower clamp on b
	MaxBits       uint32 `json:"max_bits"`       // upper clamp on b
	MaxCurveCtr   uint32 `json:"max_curve_ctr"`  // curve_ctr must be < MaxCurveCtr
	MaxStep       int64  `json:"max_step"`       // max change of b per retarget
	TimewarpSlack int64  `json:"timewarp_slack"` // first block of an epoch >= prev time - slack
	MTPWindow     int64  `json:"mtp_window"`     // median-time-past window
	FutureLimit   int64  `json:"future_limit"`   // max seconds ahead of the local clock

	// Network settings; not consensus and not part of the chain JSON.
	Magic   uint32 `json:"-"`
	P2PPort int    `json:"-"`
	APIPort int    `json:"-"`
}

// Prototype is the default profile.
var Prototype = Params{
	Tau:           10,
	Epoch:         64,
	GenesisBits:   36,
	MinBits:       32,
	MaxBits:       240,
	MaxCurveCtr:   1 << 20,
	MaxStep:       4,
	TimewarpSlack: 600,
	MTPWindow:     11,
	FutureLimit:   7200,
	Magic:         0xCA4A2701,
	P2PPort:       18555,
	APIPort:       18556,
}

// Mainnet is defined but not the default.
var Mainnet = func() Params {
	p := Prototype
	p.Tau, p.Epoch, p.GenesisBits = 600, 2016, 64
	p.Magic, p.P2PPort, p.APIPort = 0xCA4A2700, 8555, 8556
	return p
}()

// SameConsensus reports whether p and q agree on every consensus parameter (network settings
// are ignored).
func (p *Params) SameConsensus(q *Params) bool {
	a, b := *p, *q
	a.Magic, a.P2PPort, a.APIPort = 0, 0, 0
	b.Magic, b.P2PPort, b.APIPort = 0, 0, 0
	return a == b
}

// Validate rejects parameter sets the consensus code cannot run with (for example params read
// from an untrusted chain JSON file).
func (p *Params) Validate() error {
	switch {
	case p.Tau <= 0:
		return errors.New("params: tau must be positive")
	case p.Epoch <= 0:
		return errors.New("params: epoch must be positive")
	case p.MinBits < 3 || p.MinBits > p.MaxBits || p.MaxBits > 256:
		return errors.New("params: need 3 <= min_bits <= max_bits <= 256")
	case p.GenesisBits < p.MinBits || p.GenesisBits > p.MaxBits:
		return errors.New("params: genesis_bits outside [min_bits, max_bits]")
	case p.MaxCurveCtr == 0:
		return errors.New("params: max_curve_ctr must be positive")
	case p.MaxStep < 0 || p.MaxStep > 64:
		return errors.New("params: max_step must be in [0, 64]")
	case p.TimewarpSlack < 0 || p.FutureLimit < 0:
		return errors.New("params: timewarp_slack and future_limit must be non-negative")
	case p.MTPWindow < 1:
		// SPEC: the reference treats mtp_window=0 as "whole chain" (Python's chain[-0:]); that is an
		// accident of slicing, not a meaningful setting, so it is rejected here.
		return errors.New("params: mtp_window must be at least 1")
	}
	return nil
}
