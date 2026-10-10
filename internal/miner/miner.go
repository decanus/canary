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

// MineBlock mines the next block on chain, whose account state is parent. It finds a curve,
// pays the reward plus fees to minerAddr, includes transfers (which must be valid in order on
// parent), solves the puzzle and re-validates the result with consensus.ValidateBlock. now is
// the local clock; the timestamp is raised to the earliest time the rules allow if needed.
func MineBlock(ctx context.Context, p *consensus.Params, chain consensus.ChainView, parent consensus.State, minerAddr consensus.Address, transfers []*consensus.Transfer, threads int, now int64) (*Result, error) {
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

	ts, err := timestamp(p, chain, now)
	if err != nil {
		return nil, err
	}
	h := &consensus.Header{
		Version:  consensus.Version,
		PrevHash: prevHash,
		Time:     ts,
		Bits:     bits,
		CurveCtr: ctr,
		N:        n,
		K:        new(big.Int),
	}
	reward := consensus.Reward(h)
	fees := new(big.Int)
	for _, t := range transfers {
		fees.Add(fees, t.Fee)
	}
	cb := &consensus.Coinbase{Height: uint32(height), To: minerAddr, Amount: new(big.Int).Add(reward, fees)}
	txs := [][]byte{cb.Serialize()}
	for _, t := range transfers {
		txs = append(txs, t.Serialize())
	}
	genesisHash := [32]byte{}
	if height > 0 {
		genesisHash = chain.Header(0).Hash()
	}
	st, _, err := consensus.ApplyBlock(parent, cb, transfers, reward, genesisHash)
	if err != nil {
		return nil, fmt.Errorf("building block: %w", err)
	}
	h.MerkleRoot = consensus.MerkleRoot(txs)
	h.StateRoot = consensus.StateRoot(st)

	k, stats, err := SolveDLP(ctx, c, consensus.PuzzlePoint(c, h), n, threads)
	if err != nil {
		return nil, err
	}
	h.K = k
	blk := &consensus.Block{Header: h, Txs: txs}
	if _, _, err := consensus.ValidateBlock(p, chain, parent, blk, &now); err != nil {
		return nil, fmt.Errorf("mined block failed validation: %w", err)
	}
	return &Result{Block: blk, CurveCtr: ctr, CurveTime: t1.Sub(t0), RhoTime: time.Since(t1), Rho: stats}, nil
}

// timestamp returns the block time to use: now, raised to satisfy the median-time-past and
// timewarp rules. It fails before any work is done if the result would break the future limit
// (the local clock is far behind the chain) or not fit in a u32.
func timestamp(p *consensus.Params, chain consensus.ChainView, now int64) (uint32, error) {
	ts := now
	if h := chain.Len(); h > 0 {
		ts = max(ts, consensus.MedianTimePast(p, chain)+1)
		if int64(h)%p.Epoch == 0 {
			ts = max(ts, int64(chain.Header(h-1).Time)-p.TimewarpSlack)
		}
	}
	if ts-p.FutureLimit > now {
		return 0, fmt.Errorf("earliest valid timestamp %d is beyond the future limit of the local clock %d", ts, now)
	}
	if ts < 0 || ts > int64(^uint32(0)) {
		return 0, fmt.Errorf("timestamp %d does not fit in u32", ts)
	}
	return uint32(ts), nil
}
