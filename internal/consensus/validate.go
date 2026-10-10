package consensus

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrInvalid is wrapped by every consensus rejection from ValidateBlock.
var ErrInvalid = errors.New("invalid block")

// ErrTooNew is the future-time rejection (rule 7). It wraps ErrInvalid, but unlike the other
// rules it depends on the local clock, so a peer relaying such a block is not misbehaving.
var ErrTooNew = fmt.Errorf("%w: time too far in future", ErrInvalid)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// PuzzlePoint returns P = HashToCurve(tag("P") ‖ H2(preHeader), p, a, b) for header h on c.
func PuzzlePoint(c *Curve, h *Header) *Point {
	ph := H2(h.PreHeader())
	return HashToCurve(append(Tag("P"), ph[:]...), c.P, c.A, c.B)
}

// ValidateBlock checks blk against the chain below it, whose account state is parent
// (SPEC.md §5.5), and returns the state after blk and the addresses it changed. now is the
// local clock in Unix seconds for live blocks; pass nil when replaying stored or vector chains
// to skip the future-time rule. Errors wrap ErrInvalid.
func ValidateBlock(p *Params, chain ChainView, parent State, blk *Block, now *int64) (State, []Address, error) {
	fail := func(err error) (State, []Address, error) { return nil, nil, err }
	if !blk.WellFormed() {
		return fail(invalid("malformed block"))
	}
	h := blk.Header
	height := chain.Len()

	// 1. prev_hash links to the tip.
	var tipHash [32]byte
	if height > 0 {
		tipHash = chain.Header(height - 1).Hash()
	}
	if h.PrevHash != tipHash {
		return fail(invalid("prev_hash mismatch"))
	}

	// 2. bits.
	if want := NextBits(p, chain); h.Bits != want {
		return fail(invalid("bits %d != required %d", h.Bits, want))
	}

	// 3. curve_ctr range (it is unsigned, so only the upper bound needs checking).
	if h.CurveCtr >= p.MaxCurveCtr {
		return fail(invalid("curve_ctr out of range"))
	}

	// 4. transactions and merkle root.
	// SPEC: the reference checks only non-emptiness and the merkle root; the §4.2 size limits are
	// enforced here as well so that blocks that cannot be serialized are never accepted.
	if err := checkTxCount(uint64(len(blk.Txs))); err != nil {
		return fail(invalid("%v", err))
	}
	for i, tx := range blk.Txs {
		if err := checkTxSize(i, uint64(len(tx))); err != nil {
			return fail(invalid("%v", err))
		}
	}
	if blk.SerializedSize() > MaxBlockSize {
		return fail(invalid("block too large"))
	}
	if MerkleRoot(blk.Txs) != h.MerkleRoot {
		return fail(invalid("merkle_root mismatch"))
	}

	// 5–6. timestamps against the chain.
	if height > 0 {
		if int64(h.Time) <= MedianTimePast(p, chain) {
			return fail(invalid("time <= median time past"))
		}
		prevTime := int64(chain.Header(height - 1).Time)
		if int64(height)%p.Epoch == 0 && int64(h.Time) < prevTime-p.TimewarpSlack {
			return fail(invalid("timewarp rule"))
		}
	}

	// 7. future limit (live blocks only).
	// Written as a subtraction so that a huge now cannot overflow.
	if now != nil && int64(h.Time)-p.FutureLimit > *now {
		return fail(ErrTooNew)
	}

	// 8. version and transaction structure.
	if h.Version != Version {
		return fail(invalid("bad version %d", h.Version))
	}
	cb, transfers, err := DecodeBlockTxs(blk.Txs, height)
	if err != nil {
		return fail(invalid("%v", err))
	}

	// 9. curve and order.
	c := DeriveCurve(h.PrevHash, h.Bits, h.CurveCtr)
	if err := CheckCurve(c, h.N, h.Bits); err != nil {
		return fail(invalid("curve: %v", err))
	}

	// 10. puzzle.
	if h.K.Cmp(bigOne) < 0 || h.K.Cmp(h.N) >= 0 {
		return fail(invalid("k out of range"))
	}
	if !c.Mul(h.K, c.G).Equal(PuzzlePoint(c, h)) {
		return fail(invalid("k*G != P"))
	}

	// 11. state transition. Signatures are checked here, after the puzzle, so that making a
	// node verify them costs a solved block.
	genesisHash := h.Hash()
	if height > 0 {
		genesisHash = chain.Header(0).Hash()
	}
	st, touched, err := ApplyBlock(parent, cb, transfers, Reward(h), genesisHash)
	if err != nil {
		return fail(invalid("%v", err))
	}
	if StateRoot(st) != h.StateRoot {
		return fail(invalid("state_root mismatch"))
	}
	return st, touched, nil
}

// ValidateChain replays blocks from genesis without the future-time rule and returns the
// cumulative work and the final state.
func ValidateChain(p *Params, blocks []*Block) (*big.Int, State, error) {
	chain := make(Headers, 0, len(blocks))
	work := new(big.Int)
	st := State{}
	for i, blk := range blocks {
		var err error
		if st, _, err = ValidateBlock(p, chain, st, blk, nil); err != nil {
			return nil, nil, fmt.Errorf("block %d: %w", i, err)
		}
		chain = append(chain, blk.Header)
		work.Add(work, Work(blk.Header))
	}
	return work, st, nil
}
