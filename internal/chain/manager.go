package chain

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/decanus/canary/internal/consensus"
)

// MaxOrphans caps the orphan pool; the oldest orphan is evicted first.
const MaxOrphans = 100

// Status is the outcome of AddBlock.
type Status int

// The zero Status accompanies an error, so it is never mistaken for an outcome.
const (
	// Duplicate: the block is already known (in the index or the orphan pool).
	Duplicate Status = iota + 1
	// Orphan: the parent is unknown; the block waits in the orphan pool.
	Orphan
	// SideChain: the block is valid and stored but did not become the tip.
	SideChain
	// NewTip: the block (or an orphan it connected) became the new tip.
	NewTip
)

func (s Status) String() string {
	switch s {
	case Duplicate:
		return "duplicate"
	case Orphan:
		return "orphan"
	case SideChain:
		return "side-chain"
	case NewTip:
		return "new-tip"
	}
	return "error"
}

// TipEvent announces a change of the active tip.
type TipEvent struct {
	Hash   [32]byte
	Height int
	Header *consensus.Header
	Work   *big.Int // cumulative work
	// Reorg is the number of previously active blocks that left the active chain.
	Reorg int
}

// Manager owns the block tree, the active chain and the block store.
type Manager struct {
	params *consensus.Params
	store  *Store

	mu      sync.RWMutex
	index   map[[32]byte]*node
	active  []*node // active[h] is the active block at height h
	orphans map[[32]byte]*consensus.Block
	order   [][32]byte              // orphan arrival order, for eviction
	waiting map[[32]byte][][32]byte // parent hash -> orphan hashes
	subs    []chan TipEvent
}

// Open opens the data directory for writing and rebuilds the index by replaying the stored
// blocks through validation (without the future-time rule). The directory's recorded params
// must match p; a new directory records p.
func Open(dir string, p *consensus.Params) (*Manager, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	store, blocks, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	m, err := replay(p, blocks)
	if err == nil {
		err = checkParams(dir, p)
	}
	if err != nil {
		store.Close()
		return nil, err
	}
	m.store = store
	return m, nil
}

// OpenReadOnly rebuilds an in-memory manager from dir with its recorded params, without
// modifying the directory. The result has no store, so added blocks are not persisted.
func OpenReadOnly(dir string) (*Manager, error) {
	p, err := ReadParams(dir)
	if err != nil {
		return nil, err
	}
	blocks, err := ReadStore(dir)
	if err != nil {
		return nil, err
	}
	return replay(p, blocks)
}

func replay(p *consensus.Params, blocks []*consensus.Block) (*Manager, error) {
	m := newManager(p)
	for i, blk := range blocks {
		if _, err := m.add(blk, nil, false); err != nil {
			return nil, fmt.Errorf("replaying stored block %d: %w", i, err)
		}
	}
	// Stored blocks are written only once connected, so a replay leaves no orphans.
	if len(m.orphans) != 0 {
		return nil, fmt.Errorf("%d stored blocks have unknown parents", len(m.orphans))
	}
	return m, nil
}

// NewMemory returns a manager without persistence.
func NewMemory(p *consensus.Params) (*Manager, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return newManager(p), nil
}

func newManager(p *consensus.Params) *Manager {
	return &Manager{
		params:  p,
		index:   make(map[[32]byte]*node),
		orphans: make(map[[32]byte]*consensus.Block),
		waiting: make(map[[32]byte][][32]byte),
	}
}

// Close closes the block store.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		return nil
	}
	return m.store.Close()
}

// Params returns the chain parameters.
func (m *Manager) Params() *consensus.Params { return m.params }

// AddBlock validates blk and adds it to the tree, reorganizing if it creates a chain with more
// work than the tip (ties keep the first seen). now is the local clock in Unix seconds, used
// for the future-time rule. An invalid block returns an error wrapping consensus.ErrInvalid.
func (m *Manager) AddBlock(blk *consensus.Block, now int64) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.add(blk, &now, true)
}

func (m *Manager) add(blk *consensus.Block, now *int64, persist bool) (Status, error) {
	if !blk.WellFormed() {
		return 0, fmt.Errorf("%w: malformed block", consensus.ErrInvalid)
	}
	hash := blk.Hash()
	if _, ok := m.index[hash]; ok {
		return Duplicate, nil
	}
	if _, ok := m.orphans[hash]; ok {
		return Duplicate, nil
	}
	parent, ok := m.index[blk.Header.PrevHash]
	if !ok && blk.Header.PrevHash != ([32]byte{}) {
		m.addOrphan(hash, blk)
		return Orphan, nil
	}

	oldTip := m.tip()
	status, err := m.connect(hash, blk, parent, now, persist)
	if err != nil {
		return status, err
	}

	// Connect orphans that were waiting on this block, breadth first. An invalid orphan is
	// dropped (it does not make its parent invalid); any other failure, such as a storage
	// error, puts it back in the pool and is reported.
	queue := [][32]byte{hash}
	for len(queue) > 0 && err == nil {
		ph := queue[0]
		queue = queue[1:]
		children := m.waiting[ph]
		delete(m.waiting, ph)
		for _, ch := range children {
			ob, ok := m.orphans[ch]
			if !ok {
				continue // evicted
			}
			m.removeOrphan(ch)
			if _, cerr := m.connect(ch, ob, m.index[ph], now, persist); cerr == nil {
				queue = append(queue, ch)
			} else if !errors.Is(cerr, consensus.ErrInvalid) {
				m.addOrphan(ch, ob)
				err = fmt.Errorf("connecting orphan %x: %w", ch[:8], cerr)
			}
		}
	}

	if m.tip() != oldTip {
		m.notify(oldTip)
		status = NewTip
	}
	return status, err
}

// connect validates blk on top of parent, stores it and switches the tip if it has more work.
func (m *Manager) connect(hash [32]byte, blk *consensus.Block, parent *node, now *int64, persist bool) (Status, error) {
	if err := consensus.ValidateBlock(m.params, newView(m.active, parent), blk, now); err != nil {
		return 0, err
	}
	if persist && m.store != nil {
		if err := m.store.Append(blk); err != nil {
			return 0, fmt.Errorf("storing block: %w", err)
		}
	}
	n := &node{hash: hash, block: blk, parent: parent, work: consensus.Work(blk.Header)}
	if parent != nil {
		n.height = parent.height + 1
		n.work.Add(n.work, parent.work)
	}
	m.index[hash] = n
	if tip := m.tip(); tip == nil || n.work.Cmp(tip.work) > 0 {
		m.setTip(n)
		return NewTip, nil
	}
	return SideChain, nil
}

// setTip makes n the active tip, rewriting the active chain above the fork point.
func (m *Manager) setTip(n *node) {
	path := []*node{}
	for c := n; c != nil && !onActive(m.active, c); c = c.parent {
		path = append(path, c)
	}
	forkHeight := n.height - len(path) // height of the last shared block, -1 if none
	m.active = m.active[:forkHeight+1]
	for i := len(path) - 1; i >= 0; i-- {
		m.active = append(m.active, path[i])
	}
}

func (m *Manager) tip() *node {
	if len(m.active) == 0 {
		return nil
	}
	return m.active[len(m.active)-1]
}

func (m *Manager) addOrphan(hash [32]byte, blk *consensus.Block) {
	for len(m.order) >= MaxOrphans {
		m.removeOrphan(m.order[0])
	}
	m.orphans[hash] = blk
	m.order = append(m.order, hash)
	ph := blk.Header.PrevHash
	m.waiting[ph] = append(m.waiting[ph], hash)
}

func (m *Manager) removeOrphan(hash [32]byte) {
	blk, ok := m.orphans[hash]
	if !ok {
		return
	}
	delete(m.orphans, hash)
	for i, h := range m.order {
		if h == hash {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	ph := blk.Header.PrevHash
	ws := m.waiting[ph]
	for i, h := range ws {
		if h == hash {
			ws = append(ws[:i], ws[i+1:]...)
			break
		}
	}
	if len(ws) == 0 {
		delete(m.waiting, ph)
	} else {
		m.waiting[ph] = ws
	}
}

// notify sends a TipEvent to every subscriber. Each subscription holds only the latest event, so
// a slow subscriber sees the newest tip rather than blocking the manager.
func (m *Manager) notify(oldTip *node) {
	tip := m.tip()
	reorg := 0
	if oldTip != nil {
		for c := oldTip; c != nil && !onActive(m.active, c); c = c.parent {
			reorg++
		}
	}
	ev := TipEvent{Hash: tip.hash, Height: tip.height, Header: tip.block.Header, Work: new(big.Int).Set(tip.work), Reorg: reorg}
	for _, ch := range m.subs {
		select {
		case <-ch:
		default:
		}
		ch <- ev
	}
}

// Subscribe returns a channel that receives tip changes. Only the latest undelivered event is
// kept.
func (m *Manager) Subscribe() <-chan TipEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := make(chan TipEvent, 1)
	m.subs = append(m.subs, ch)
	return ch
}

// ErrNotFound is returned for unknown blocks.
var ErrNotFound = errors.New("block not found")

// Tip returns the active tip's hash, height and cumulative work; ok is false for an empty chain.
func (m *Manager) Tip() (hash [32]byte, height int, work *big.Int, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := m.tip()
	if t == nil {
		return hash, -1, new(big.Int), false
	}
	return t.hash, t.height, new(big.Int).Set(t.work), true
}

// Height returns the active chain length (the height of the next block).
func (m *Manager) Height() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.active)
}

// ActiveHeaders returns a snapshot of the active chain's headers, usable as a ChainView.
func (m *Manager) ActiveHeaders() consensus.Headers {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hs := make(consensus.Headers, len(m.active))
	for i, n := range m.active {
		hs[i] = n.block.Header
	}
	return hs
}

// ActiveBlocks returns the active chain's blocks from genesis.
func (m *Manager) ActiveBlocks() []*consensus.Block {
	return m.BlocksFrom(0, math.MaxInt)
}

// BlocksFrom returns up to max active blocks starting at height from.
func (m *Manager) BlocksFrom(from, max int) []*consensus.Block {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if from < 0 {
		from = 0
	}
	var out []*consensus.Block
	for h := from; h < len(m.active) && len(out) < max; h++ {
		out = append(out, m.active[h].block)
	}
	return out
}

// BlockByHeight returns the active block at height h.
func (m *Manager) BlockByHeight(h int) (*consensus.Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if h < 0 || h >= len(m.active) {
		return nil, ErrNotFound
	}
	return m.active[h].block, nil
}

// BlockByHash returns any known block (active or side chain) and its height.
func (m *Manager) BlockByHash(hash [32]byte) (*consensus.Block, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.index[hash]
	if !ok {
		return nil, 0, ErrNotFound
	}
	return n.block, n.height, nil
}

// IsActive reports whether hash is on the active chain, and its height if so.
func (m *Manager) IsActive(hash [32]byte) (int, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.index[hash]
	if !ok || !onActive(m.active, n) {
		return 0, false
	}
	return n.height, true
}

// Has reports whether hash is known (indexed or orphaned).
func (m *Manager) Has(hash [32]byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.index[hash]
	_, orphan := m.orphans[hash]
	return ok || orphan
}

// NumOrphans returns the orphan pool size.
func (m *Manager) NumOrphans() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.orphans)
}

// Locator returns active-chain hashes for a sync request, newest first: the last 10 blocks,
// then exponentially sparser back to genesis, at most 32 in all.
func (m *Manager) Locator() [][32]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out [][32]byte
	step := 1
	for h := len(m.active) - 1; h >= 0 && len(out) < 31; h -= step {
		out = append(out, m.active[h].hash)
		if len(out) >= 10 {
			step *= 2
		}
	}
	if len(m.active) > 0 && out[len(out)-1] != m.active[0].hash {
		out = append(out, m.active[0].hash)
	}
	return out
}

// TipBlock returns the active tip block with its height and cumulative work, read atomically;
// ok is false for an empty chain.
func (m *Manager) TipBlock() (blk *consensus.Block, height int, work *big.Int, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := m.tip()
	if t == nil {
		return nil, -1, new(big.Int), false
	}
	return t.block, t.height, new(big.Int).Set(t.work), true
}

// ActiveTail returns the headers of the last (up to) n active blocks, read atomically, and the
// height of the first one.
func (m *Manager) ActiveTail(n int) (start int, headers []*consensus.Header) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	start = max(len(m.active)-n, 0)
	for _, nd := range m.active[start:] {
		headers = append(headers, nd.block.Header)
	}
	return start, headers
}
