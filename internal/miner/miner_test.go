package miner

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/decanus/canary/internal/conformance"
	"github.com/decanus/canary/internal/consensus"
)

// The curve search must find the same first curve_ctr as the reference for every valid curve
// vector.
func TestFindCurveMatchesVectors(t *testing.T) {
	v, err := conformance.Load("../../reference/test_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, c := range v.Curves {
		if !c.Valid {
			continue
		}
		var prev [32]byte
		b, err := hex.DecodeString(c.PrevHash)
		if err != nil || len(b) != 32 {
			t.Fatalf("bad prev_hash %q", c.PrevHash)
		}
		copy(prev[:], b)
		ctr, _, n, err := FindCurve(context.Background(), &v.Params, prev, c.Bits)
		if err != nil {
			t.Fatal(err)
		}
		if ctr != c.CurveCtr || n.String() != *c.N {
			t.Errorf("bits=%d: got ctr=%d n=%s, want ctr=%d n=%s", c.Bits, ctr, n, c.CurveCtr, *c.N)
		}
		found++
	}
	if found == 0 {
		t.Fatal("no valid curve vectors")
	}
}

func TestMineChain(t *testing.T) {
	p := consensus.Prototype
	p.GenesisBits, p.MinBits, p.Epoch = 32, 28, 4
	var chain consensus.Headers
	var blocks []*consensus.Block
	st := consensus.State{}
	miner := consensus.Address{1}
	now := int64(1_800_000_000)
	for i := 0; i < 6; i++ {
		res, err := MineBlock(context.Background(), &p, chain, st, miner, nil, 4, now+int64(i))
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		chain = append(chain, res.Block.Header)
		blocks = append(blocks, res.Block)
		st, _, _ = consensus.ValidateBlock(&p, chain[:i], st, res.Block, nil)
	}
	// Blocks 1s apart against tau=10 retarget upward at height 4.
	if chain[4].Bits <= chain[3].Bits {
		t.Errorf("no retarget: bits %d -> %d", chain[3].Bits, chain[4].Bits)
	}
	work, final, err := consensus.ValidateChain(&p, blocks)
	if err != nil {
		t.Fatal(err)
	}
	// Supply equals cumulative work, all paid to the miner.
	if final.Supply().Cmp(work) != 0 || final.Get(miner).Balance.Cmp(work) != 0 {
		t.Fatalf("supply %s, miner %s, work %s", final.Supply(), final.Get(miner).Balance, work)
	}
}

func TestTimestampRules(t *testing.T) {
	p := consensus.Prototype
	p.Epoch = 4
	hs := func(times ...uint32) consensus.Headers {
		out := make(consensus.Headers, len(times))
		for i, tm := range times {
			out[i] = &consensus.Header{Time: tm}
		}
		return out
	}
	const T = 1_800_000_000
	// A peer with a fast clock made block 3; block 4 opens an epoch, so the timewarp rule
	// requires time >= block3.time - slack even though MTP is far lower.
	ts, err := timestamp(&p, hs(T, T+1, T+2, T+5000), T+3)
	if err != nil || int64(ts) != T+5000-p.TimewarpSlack {
		t.Fatalf("timewarp: got %d, %v", ts, err)
	}
	// Mid-epoch only MTP applies.
	if ts, _ := timestamp(&p, hs(T, T+1, T+5000), T+3); ts != T+3 {
		t.Fatalf("mid-epoch: got %d", ts)
	}
	// A clock far behind the chain fails before any work is done.
	if _, err := timestamp(&p, hs(T, T+1, T+2), T-p.FutureLimit-10); err == nil {
		t.Fatal("expected a future-limit error")
	}
}
