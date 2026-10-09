package consensus

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrInvalid is wrapped by every consensus rejection from ValidateBlock.
var ErrInvalid = errors.New("invalid block")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// PuzzlePoint returns P = HashToCurve(tag("P") ‖ H2(preHeader), p, a, b) for header h on c.
func PuzzlePoint(c *Curve, h *Header) *Point {
	ph := H2(h.PreHeader())
	return HashToCurve(append(Tag("P"), ph[:]...), c.P, c.A, c.B)
}

// ValidateBlock checks blk against the chain below it (SPEC.md §5.5). now is the local clock in
// Unix seconds for live blocks; pass nil when replaying stored or vector chains to skip the
// future-time rule. The returned error wraps ErrInvalid.
func ValidateBlock(p *Params, chain ChainView, blk *Block, now *int64) error {
	if blk == nil || blk.Header == nil || blk.Header.N == nil || blk.Header.K == nil {
		return invalid("malformed block")
	}
	h := blk.Header
	height := chain.Len()

	// 1. prev_hash links to the tip.
	var tipHash [32]byte
	if height > 0 {
		tipHash = chain.Header(height - 1).Hash()
	}
	if h.PrevHash != tipHash {
		return invalid("prev_hash mismatch")
	}

	// 2. bits.
	if want := NextBits(p, chain); h.Bits != want {
		return invalid("bits %d != required %d", h.Bits, want)
	}

	// 3. curve_ctr range (it is unsigned, so only the upper bound needs checking).
	if h.CurveCtr >= p.MaxCurveCtr {
		return invalid("curve_ctr out of range")
	}

	// 4. transactions and merkle root.
	// SPEC: the reference checks only non-emptiness and the merkle root; the §4.2 size limits are
	// enforced here as well so that blocks that cannot be serialized are never accepted.
	if err := checkTxCount(uint64(len(blk.Txs))); err != nil {
		return invalid("%v", err)
	}
	for i, tx := range blk.Txs {
		if err := checkTxSize(i, uint64(len(tx))); err != nil {
			return invalid("%v", err)
		}
	}
	if blk.SerializedSize() > MaxBlockSize {
		return invalid("block too large")
	}
	if MerkleRoot(blk.Txs) != h.MerkleRoot {
		return invalid("merkle_root mismatch")
	}

	// 5–6. timestamps against the chain.
	if height > 0 {
		if int64(h.Time) <= MedianTimePast(p, chain) {
			return invalid("time <= median time past")
		}
		prevTime := int64(chain.Header(height - 1).Time)
		if int64(height)%p.Epoch == 0 && int64(h.Time) < prevTime-p.TimewarpSlack {
			return invalid("timewarp rule")
		}
	}

	// 7. future limit (live blocks only).
	// Written as a subtraction so that a huge now cannot overflow.
	if now != nil && int64(h.Time)-p.FutureLimit > *now {
		return invalid("time too far in future")
	}

	// 8. curve and order.
	c := DeriveCurve(h.PrevHash, h.Bits, h.CurveCtr)
	if err := CheckCurve(c, h.N, h.Bits); err != nil {
		return invalid("curve: %v", err)
	}

	// 9. puzzle.
	if h.K.Cmp(bigOne) < 0 || h.K.Cmp(h.N) >= 0 {
		return invalid("k out of range")
	}
	if !c.Mul(h.K, c.G).Equal(PuzzlePoint(c, h)) {
		return invalid("k*G != P")
	}
	return nil
}

// ValidateChain replays blocks from genesis without the future-time rule and returns the
// cumulative work.
func ValidateChain(p *Params, blocks []*Block) (*big.Int, error) {
	chain := make(Headers, 0, len(blocks))
	work := new(big.Int)
	for i, blk := range blocks {
		if err := ValidateBlock(p, chain, blk, nil); err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		chain = append(chain, blk.Header)
		work.Add(work, Work(blk.Header))
	}
	return work, nil
}
