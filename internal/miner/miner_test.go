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
	now := int64(1_800_000_000)
	for i := 0; i < 6; i++ {
		res, err := MineBlock(context.Background(), &p, chain, "test-miner", 4, now+int64(i))
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		chain = append(chain, res.Block.Header)
		blocks = append(blocks, res.Block)
	}
	// Blocks 1s apart against tau=10 retarget upward at height 4.
	if chain[4].Bits <= chain[3].Bits {
		t.Errorf("no retarget: bits %d -> %d", chain[3].Bits, chain[4].Bits)
	}
	if _, err := consensus.ValidateChain(&p, blocks); err != nil {
		t.Fatal(err)
	}
}
