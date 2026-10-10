package consensus_test

import (
	"testing"

	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/conformance"
	"github.com/decanus/canary/internal/consensus"
)

// FuzzValidateBlock checks that ValidateBlock never panics on arbitrary bytes, validated on top of
// the vector chain (so the bits/prev_hash checks can be passed by mutating a real block).
func FuzzValidateBlock(f *testing.F) {
	v, err := conformance.Load(vectorsPath)
	if err != nil {
		f.Fatal(err)
	}
	blocks, err := chainjson.DecodeBlocks(v.Chain.Blocks)
	if err != nil {
		f.Fatal(err)
	}
	base := make(consensus.Headers, 0, len(blocks))
	for _, b := range blocks[:len(blocks)-1] {
		base = append(base, b.Header)
	}
	last := blocks[len(blocks)-1]
	heights := []int{0, len(base) / 2, len(base)}
	states := make([]consensus.State, len(heights))
	for i, h := range heights {
		if _, states[i], err = consensus.ValidateChain(&v.Params, blocks[:h]); err != nil {
			f.Fatal(err)
		}
	}
	f.Add(last.Serialize(), int64(0))
	f.Add([]byte{}, int64(-1))
	f.Add(make([]byte, consensus.HeaderSize+1), int64(5))
	params := v.Params
	f.Fuzz(func(t *testing.T, b []byte, now int64) {
		// Also validate the raw header with arbitrary tx data, so inputs that fail
		// DeserializeBlock still reach ValidateBlock.
		if len(b) >= consensus.HeaderSize {
			h, _ := consensus.DeserializeHeader(b[:consensus.HeaderSize])
			blk := &consensus.Block{Header: h, Txs: [][]byte{b[consensus.HeaderSize:]}}
			for i, height := range heights {
				consensus.ValidateBlock(&params, base[:height], states[i], blk, &now)
			}
		}
		if blk, err := consensus.DeserializeBlock(b); err == nil {
			consensus.ValidateBlock(&params, base, states[len(states)-1], blk, nil)
		}
	})
}
