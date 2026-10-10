// Package mempool holds signed transfers waiting to be mined (non-consensus). Transfers are kept
// per sender in nonce order without gaps, so any prefix of a sender's queue is valid on the
// current state.
package mempool

import (
	"container/heap"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/decanus/canary/internal/consensus"
)

// Limits.
const (
	MaxTxs       = 5000 // about 40 MB of transfers
	MaxPerSender = 64
)

var (
	// ErrInvalid marks a transfer no honest node would relay: bad encoding or signature. Peers
	// relaying one are misbehaving.
	ErrInvalid = errors.New("invalid transfer")
	// ErrKnown means the transfer is already in the pool.
	ErrKnown = errors.New("transfer already in pool")
)

// Pool is a mempool. It is safe for concurrent use.
type Pool struct {
	mu      sync.Mutex
	genesis [32]byte
	ready   bool // genesis is known
	state   consensus.State
	senders map[consensus.Address][]*consensus.Transfer // nonce order, starting at the state nonce
	count   int
}

// New returns an empty pool. Call Update with the chain's state before adding transfers.
func New() *Pool {
	return &Pool{state: consensus.State{}, senders: make(map[consensus.Address][]*consensus.Transfer)}
}

// Update sets the chain the pool works against: its genesis hash and the state after its tip.
// Transfers that were mined or are no longer valid on state are dropped.
func (p *Pool) Update(genesis [32]byte, state consensus.State) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready && genesis != p.genesis {
		p.senders = make(map[consensus.Address][]*consensus.Transfer) // different chain: start over
	}
	p.genesis, p.ready, p.state = genesis, true, state
	p.count = 0
	for from, q := range p.senders {
		acc := state.Get(from)
		// Drop the prefix that the chain already includes.
		for len(q) > 0 && q[0].Nonce < acc.Nonce {
			q = q[1:]
		}
		// Keep the longest prefix that is contiguous and affordable.
		spent := new(big.Int)
		keep := 0
		for i, t := range q {
			spent.Add(spent, cost(t))
			if t.Nonce != acc.Nonce+uint64(i) || spent.Cmp(acc.Balance) > 0 {
				break
			}
			keep++
		}
		if keep == 0 {
			delete(p.senders, from)
			continue
		}
		p.senders[from] = q[:keep]
		p.count += keep
	}
}

// Add validates t against the pool's state and queues it. A transfer with the same sender and
// nonce as a queued one replaces it if its fee is higher (later transfers from that sender stay
// only if still affordable).
func (p *Pool) Add(t *consensus.Transfer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready {
		return errors.New("mempool: chain not known yet")
	}
	if t.Scheme != consensus.SchemeSLHDSA || len(t.PubKey) != consensus.PubKeySize || len(t.Sig) != consensus.SignatureSize ||
		t.Amount == nil || t.Fee == nil || t.Amount.BitLen() > 128 || t.Fee.BitLen() > 128 || t.Amount.Sign() < 0 || t.Fee.Sign() < 0 {
		return fmt.Errorf("%w: bad encoding", ErrInvalid)
	}
	from := t.Sender()
	q := p.senders[from]
	acc := p.state.Get(from)
	idx := int64(t.Nonce) - int64(acc.Nonce)
	switch {
	case t.Nonce < acc.Nonce:
		return fmt.Errorf("mempool: nonce %d already used (account nonce %d)", t.Nonce, acc.Nonce)
	case idx > int64(len(q)):
		return fmt.Errorf("mempool: nonce gap: got %d, next is %d", t.Nonce, acc.Nonce+uint64(len(q)))
	case idx == int64(len(q)) && len(q) >= MaxPerSender:
		return fmt.Errorf("mempool: sender has %d pending transfers", len(q))
	}
	replace := idx < int64(len(q))
	if replace {
		old := q[idx]
		if string(old.Serialize()) == string(t.Serialize()) {
			return ErrKnown
		}
		if t.Fee.Cmp(old.Fee) <= 0 {
			return errors.New("mempool: replacement must pay a higher fee")
		}
	}
	// Signature last: it is the expensive check.
	if !t.VerifySignature(p.genesis) {
		return fmt.Errorf("%w: bad signature", ErrInvalid)
	}
	// Affordability of the queue up to and including t.
	spent := new(big.Int)
	for _, x := range q[:idx] {
		spent.Add(spent, cost(x))
	}
	if spent.Add(spent, cost(t)).Cmp(acc.Balance) > 0 {
		return errors.New("mempool: insufficient balance")
	}
	if !replace && p.count >= MaxTxs && !p.evictCheaper(t.Fee) {
		return errors.New("mempool: full")
	}
	if replace {
		nq := append(append([]*consensus.Transfer{}, q[:idx]...), t)
		// Keep later transfers only while still affordable.
		for _, x := range q[idx+1:] {
			if spent.Add(spent, cost(x)).Cmp(acc.Balance) > 0 {
				break
			}
			nq = append(nq, x)
		}
		p.count += len(nq) - len(q)
		p.senders[from] = nq
		return nil
	}
	p.senders[from] = append(q, t)
	p.count++
	return nil
}

// evictCheaper drops the last queued transfer of the sender whose last transfer pays the lowest
// fee, if that fee is below fee. Dropping a queue's last entry keeps the queue contiguous.
func (p *Pool) evictCheaper(fee *big.Int) bool {
	var victim consensus.Address
	var low *big.Int
	for from, q := range p.senders {
		f := q[len(q)-1].Fee
		if low == nil || f.Cmp(low) < 0 {
			victim, low = from, f
		}
	}
	if low == nil || low.Cmp(fee) >= 0 {
		return false
	}
	q := p.senders[victim]
	if len(q) == 1 {
		delete(p.senders, victim)
	} else {
		p.senders[victim] = q[:len(q)-1]
	}
	p.count--
	return true
}

// Len returns the number of queued transfers.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

// Pending returns how many transfers from addr are queued (the next nonce to use is the
// account nonce plus this).
func (p *Pool) Pending(addr consensus.Address) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.senders[addr])
}

// Select picks transfers for a block on state, highest fee first while keeping each sender's
// nonce order, up to maxBytes of transfers. Each sender's queue is re-checked against state, so
// the result is valid in order on state even if the pool has not caught up with it yet.
func (p *Pool) Select(state consensus.State, maxBytes int) []*consensus.Transfer {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := &feeHeap{}
	for from, q := range p.senders {
		acc := state.Get(from)
		for len(q) > 0 && q[0].Nonce < acc.Nonce {
			q = q[1:]
		}
		spent := new(big.Int)
		n := 0
		for i, t := range q {
			if t.Nonce != acc.Nonce+uint64(i) || spent.Add(spent, cost(t)).Cmp(acc.Balance) > 0 {
				break
			}
			n++
		}
		if n > 0 {
			heap.Push(h, cursor{q: q[:n]})
		}
	}
	var out []*consensus.Transfer
	size := 0
	for h.Len() > 0 && size+consensus.TransferSize <= maxBytes {
		c := heap.Pop(h).(cursor)
		out = append(out, c.q[c.i])
		size += consensus.TransferSize
		if c.i+1 < len(c.q) {
			heap.Push(h, cursor{q: c.q, i: c.i + 1})
		}
	}
	return out
}

func cost(t *consensus.Transfer) *big.Int { return new(big.Int).Add(t.Amount, t.Fee) }

// cursor points at the next unselected transfer of one sender's queue.
type cursor struct {
	q []*consensus.Transfer
	i int
}

type feeHeap []cursor

func (h feeHeap) Len() int           { return len(h) }
func (h feeHeap) Less(i, j int) bool { return h[i].q[h[i].i].Fee.Cmp(h[j].q[h[j].i].Fee) > 0 }
func (h feeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *feeHeap) Push(x any)        { *h = append(*h, x.(cursor)) }
func (h *feeHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}
