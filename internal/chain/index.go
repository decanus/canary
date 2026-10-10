package chain

import (
	"math/big"

	"github.com/decanus/canary/internal/consensus"
)

// node is one block in the block tree.
type node struct {
	hash   [32]byte
	block  *consensus.Block
	height int
	work   *big.Int // cumulative work from genesis through this block
	parent *node    // nil for a genesis block
}

// view is a consensus.ChainView of the chain ending at tip (inclusive), or of the empty chain if
// tip is nil. Heights up to the fork point with the active chain are served from active; the
// side branch above it is collected once.
type view struct {
	active []*node
	fork   int     // highest height shared with active (-1 if none)
	side   []*node // side[i] is at height fork+1+i
}

func newView(active []*node, tip *node) *view {
	v := &view{active: active, fork: -1}
	if tip == nil {
		return v
	}
	n := tip
	for n != nil && !(n.height < len(active) && active[n.height] == n) {
		v.side = append(v.side, n)
		n = n.parent
	}
	if n != nil {
		v.fork = n.height
	}
	for i, j := 0, len(v.side)-1; i < j; i, j = i+1, j-1 {
		v.side[i], v.side[j] = v.side[j], v.side[i]
	}
	return v
}

func (v *view) Len() int { return v.fork + 1 + len(v.side) }

func (v *view) Header(i int) *consensus.Header {
	if i <= v.fork {
		return v.active[i].block.Header
	}
	return v.side[i-v.fork-1].block.Header
}
