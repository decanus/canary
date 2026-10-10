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
	diff   []change // accounts this block changed
}

// change records one account before and after a block, so state can be moved along the tree.
type change struct {
	addr          consensus.Address
	before, after consensus.Account
}

// stateAt returns the account state after n (empty for nil), given the active chain and the
// state after its tip. It undoes active blocks above the fork point and redoes n's branch.
// The result may be tipState itself; callers must not modify it.
func stateAt(active []*node, tipState consensus.State, n *node) consensus.State {
	if n == nil {
		return consensus.State{}
	}
	if len(active) > 0 && active[len(active)-1] == n {
		return tipState
	}
	var branch []*node
	c := n
	for c != nil && !onActive(active, c) {
		branch = append(branch, c)
		c = c.parent
	}
	fork := -1
	if c != nil {
		fork = c.height
	}
	st := tipState.Clone()
	for h := len(active) - 1; h > fork; h-- {
		for _, ch := range active[h].diff {
			st.Set(ch.addr, ch.before)
		}
	}
	for i := len(branch) - 1; i >= 0; i-- {
		for _, ch := range branch[i].diff {
			st.Set(ch.addr, ch.after)
		}
	}
	return st
}

// diffOf records the touched accounts' values in before and after.
func diffOf(before, after consensus.State, touched []consensus.Address) []change {
	seen := make(map[consensus.Address]bool, len(touched))
	var out []change
	for _, a := range touched {
		if !seen[a] {
			seen[a] = true
			out = append(out, change{addr: a, before: before.Get(a), after: after.Get(a)})
		}
	}
	return out
}

// onActive reports whether n is on the active chain.
func onActive(active []*node, n *node) bool {
	return n.height < len(active) && active[n.height] == n
}

// view is a consensus.ChainView of the chain ending at tip (inclusive), or the empty chain if
// tip is nil. It walks back from tip lazily and switches to the active chain at the first
// shared ancestor, so validation, which reads at most one epoch back, never walks a whole
// side branch.
type view struct {
	active []*node
	tip    *node
	path   []*node // path[i] is at height tip.height - i
	fork   int     // height of the first active ancestor, valid once done; -1 if none
	done   bool
}

func newView(active []*node, tip *node) *view {
	return &view{active: active, tip: tip, fork: -1}
}

func (v *view) Len() int {
	if v.tip == nil {
		return 0
	}
	return v.tip.height + 1
}

func (v *view) Header(i int) *consensus.Header {
	for !v.done && (len(v.path) == 0 || v.path[len(v.path)-1].height > i) {
		next := v.tip
		if len(v.path) > 0 {
			next = v.path[len(v.path)-1].parent
		}
		switch {
		case next == nil:
			v.done = true
		case onActive(v.active, next):
			v.fork, v.done = next.height, true
		default:
			v.path = append(v.path, next)
		}
	}
	if i <= v.fork {
		return v.active[i].block.Header
	}
	return v.path[v.tip.height-i].block.Header
}
