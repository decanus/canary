package miner

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/decanus/canary/internal/consensus"
)

// Result describes a mined block.
type Result struct {
	Block     *consensus.Block
	CurveCtr  uint32
	CurveTime time.Duration
	RhoTime   time.Duration
	Rho       RhoStats
}

// MineBlock mines the next block on chain: it finds a curve, builds the coinbase and header, solves
// the puzzle and re-validates the result with consensus.ValidateBlock. now is the timestamp to
// use (raised to median-time-past + 1 if needed).
func MineBlock(ctx context.Context, p *consensus.Params, chain consensus.ChainView, minerAddress string, threads int, now int64) (*Result, error) {
	height := chain.Len()
	var prevHash [32]byte
	if height > 0 {
		prevHash = chain.Header(height - 1).Hash()
	}
	bits := consensus.NextBits(p, chain)

	t0 := time.Now()
	ctr, c, n, err := FindCurve(ctx, p, prevHash, bits)
	if err != nil {
		return nil, err
	}
	t1 := time.Now()

	ts := now
	if height > 0 {
		ts = max(ts, consensus.MedianTimePast(p, chain)+1)
	}
	if ts < 0 || ts > int64(^uint32(0)) {
		return nil, fmt.Errorf("timestamp %d does not fit in u32", ts)
	}
	txs := [][]byte{consensus.Coinbase(uint32(height), minerAddress, nil)}
	h := &consensus.Header{
		Version:    1,
		PrevHash:   prevHash,
		MerkleRoot: consensus.MerkleRoot(txs),
		Time:       uint32(ts),
		Bits:       bits,
		CurveCtr:   ctr,
		N:          n,
		K:          new(big.Int),
	}
	k, stats, err := SolveDLP(ctx, c, consensus.PuzzlePoint(c, h), n, threads)
	if err != nil {
		return nil, err
	}
	h.K = k
	blk := &consensus.Block{Header: h, Txs: txs}
	nowCopy := now
	if err := consensus.ValidateBlock(p, chain, blk, &nowCopy); err != nil {
		return nil, fmt.Errorf("mined block failed validation: %w", err)
	}
	return &Result{Block: blk, CurveCtr: ctr, CurveTime: t1.Sub(t0), RhoTime: time.Since(t1), Rho: stats}, nil
}
