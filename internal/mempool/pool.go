// Package mempool holds signed transfers waiting to be mined (non-consensus). Transfers are kept
// per sender in nonce order without gaps, so any prefix of a sender's queue is valid on the
// current state.
package mempool

import (
	"bytes"
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
// Queues are rebuilt from the pooled transfers plus readd (transfers from blocks a reorg
// removed, which are already known to be validly signed for this chain): mined and no longer
// valid transfers are dropped, and returned ones are queued again.
func (p *Pool) Update(genesis [32]byte, state consensus.State, readd []*consensus.Transfer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready && genesis != p.genesis {
		p.senders = make(map[consensus.Address][]*consensus.Transfer) // different chain: start over
		readd = nil
	}
	p.genesis, p.ready, p.state = genesis, true, state

	// Best candidate per (sender, nonce): the higher fee wins.
	cands := make(map[consensus.Address]map[uint64]*consensus.Transfer)
	consider := func(t *consensus.Transfer) {
		from := t.Sender()
		if cands[from] == nil {
			cands[from] = make(map[uint64]*consensus.Transfer)
		}
		if old := cands[from][t.Nonce]; old == nil || t.Fee.Cmp(old.Fee) > 0 {
			cands[from][t.Nonce] = t
		}
	}
	for _, q := range p.senders {
		for _, t := range q {
			consider(t)
		}
	}
	for _, t := range readd {
		consider(t)
	}

	p.senders = make(map[consensus.Address][]*consensus.Transfer, len(cands))
	p.count = 0
	for from, byNonce := range cands {
		acc := state.Get(from)
		spent := new(big.Int)
		var q []*consensus.Transfer
		for nonce := acc.Nonce; len(q) < MaxPerSender && p.count < MaxTxs; nonce++ {
			t := byNonce[nonce]
			if t == nil || spent.Add(spent, cost(t)).Cmp(acc.Balance) > 0 {
				break
			}
			q = append(q, t)
			p.count++
		}
		if len(q) > 0 {
			p.senders[from] = q
		}
	}
}

// Add validates t against the pool's state and queues it. A transfer with the same sender and
// nonce as a queued one replaces it if its fee is higher (later transfers from that sender stay
// only if still affordable). The signature is checked without holding the pool lock.
func (p *Pool) Add(t *consensus.Transfer) error {
	if t.Scheme != consensus.SchemeSLHDSA || len(t.PubKey) != consensus.PubKeySize || len(t.Sig) != consensus.SignatureSize ||
		t.Amount == nil || t.Fee == nil || t.Amount.Sign() < 0 || t.Fee.Sign() < 0 || t.Amount.BitLen() > 128 || t.Fee.BitLen() > 128 {
		return fmt.Errorf("%w: bad encoding", ErrInvalid)
	}
	p.mu.Lock()
	genesis := p.genesis
	_, _, err := p.slot(t)
	p.mu.Unlock()
	if err != nil {
		return err
	}
	if !t.VerifySignature(genesis) {
		return fmt.Errorf("%w: bad signature", ErrInvalid)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.genesis != genesis {
		return errors.New("mempool: chain changed during validation")
	}
	return p.insert(t) // re-checks against the state, which may have moved meanwhile
}

// slot returns t's sender queue and t's index in it (len(q) to append), or why t cannot be queued.
// The caller holds p.mu.
func (p *Pool) slot(t *consensus.Transfer) ([]*consensus.Transfer, int, error) {
	if !p.ready {
		return nil, 0, errors.New("mempool: chain not known yet")
	}
	q := p.senders[t.Sender()]
	acc := p.state.Get(t.Sender())
	if t.Nonce < acc.Nonce {
		return nil, 0, fmt.Errorf("mempool: nonce %d already used (account nonce %d)", t.Nonce, acc.Nonce)
	}
	// Unsigned arithmetic: the difference cannot wrap, unlike a signed subtraction.
	d := t.Nonce - acc.Nonce
	switch {
	case d > uint64(len(q)):
		return nil, 0, fmt.Errorf("mempool: nonce gap: got %d, next is %d", t.Nonce, acc.Nonce+uint64(len(q)))
	case d == uint64(len(q)) && len(q) >= MaxPerSender:
		return nil, 0, fmt.Errorf("mempool: sender has %d pending transfers", len(q))
	case d < uint64(len(q)):
		old := q[d]
		if bytes.Equal(old.Serialize(), t.Serialize()) {
			return nil, 0, ErrKnown
		}
		if t.Fee.Cmp(old.Fee) <= 0 {
			return nil, 0, errors.New("mempool: replacement must pay a higher fee")
		}
	}
	return q, int(d), nil
}

// insert queues a validly signed t; the caller holds p.mu.
func (p *Pool) insert(t *consensus.Transfer) error {
	q, idx, err := p.slot(t)
	if err != nil {
		return err
	}
	from := t.Sender()
	acc := p.state.Get(from)
	spent := new(big.Int)
	for _, x := range q[:idx] {
		spent.Add(spent, cost(x))
	}
	if spent.Add(spent, cost(t)).Cmp(acc.Balance) > 0 {
		return errors.New("mempool: insufficient balance")
	}
	if idx < len(q) {
		// Replacement: keep later transfers only while still affordable.
		nq := append(append([]*consensus.Transfer{}, q[:idx]...), t)
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
	if p.count >= MaxTxs && !p.evictCheaper(t.Fee, from) {
		return errors.New("mempool: full")
	}
	p.senders[from] = append(p.senders[from], t)
	p.count++
	return nil
}

// evictCheaper drops the last queued transfer of the sender (other than except) whose last
// transfer pays the lowest fee, if that fee is below fee. Dropping a queue's last entry keeps
// the queue contiguous.
func (p *Pool) evictCheaper(fee *big.Int, except consensus.Address) bool {
	var victim consensus.Address
	var low *big.Int
	for from, q := range p.senders {
		if from == except {
			continue
		}
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

// NextNonce returns the nonce for addr's next transfer, given its nonce on the chain: one past
// the queued transfers that continue from it. Transfers the chain already includes are skipped,
// so a pool that has not caught up with the chain yet does not over-count.
func (p *Pool) NextNonce(addr consensus.Address, chainNonce uint64) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := chainNonce
	for _, t := range p.senders[addr] {
		if t.Nonce == next {
			next++
		}
	}
	return next
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
