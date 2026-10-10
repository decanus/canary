package chain

import (
	"context"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/miner"
)

// testParams keeps blocks tiny (24-bit) so tests mine in milliseconds.
func testParams() *consensus.Params {
	p := consensus.Prototype
	p.GenesisBits, p.MinBits, p.Epoch = 24, 20, 1000
	return &p
}

const now = int64(1_800_000_000)

// mine mines one block on top of the given chain (oldest first).
func mine(t *testing.T, p *consensus.Params, chain []*consensus.Block, addr string) *consensus.Block {
	t.Helper()
	hs := make(consensus.Headers, len(chain))
	for i, b := range chain {
		hs[i] = b.Header
	}
	res, err := miner.MineBlock(context.Background(), p, hs, addr, 2, now+int64(len(chain)))
	if err != nil {
		t.Fatal(err)
	}
	return res.Block
}

// fork mines n blocks extending base, each with the given miner address.
func fork(t *testing.T, p *consensus.Params, base []*consensus.Block, n int, addr string) []*consensus.Block {
	t.Helper()
	chain := append([]*consensus.Block{}, base...)
	for i := 0; i < n; i++ {
		chain = append(chain, mine(t, p, chain, addr))
	}
	return chain[len(base):]
}

func add(t *testing.T, m *Manager, b *consensus.Block, want Status) {
	t.Helper()
	got, err := m.AddBlock(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("AddBlock: status %v, want %v", got, want)
	}
}

func tipHash(t *testing.T, m *Manager) [32]byte {
	t.Helper()
	h, _, _, ok := m.Tip()
	if !ok {
		t.Fatal("empty chain")
	}
	return h
}

func work(bs ...*consensus.Block) *big.Int {
	w := new(big.Int)
	for _, b := range bs {
		w.Add(w, consensus.Work(b.Header))
	}
	return w
}

func TestReorg(t *testing.T) {
	p := testParams()
	m, _ := NewMemory(p)
	events := m.Subscribe()
	g := mine(t, p, nil, "genesis")
	a := fork(t, p, []*consensus.Block{g}, 2, "alice")
	b := fork(t, p, []*consensus.Block{g}, 3, "bob")

	add(t, m, g, NewTip)
	add(t, m, a[0], NewTip)
	add(t, m, a[1], NewTip)

	// a[0] and b[0] share a parent and bits, so the same curve and n: equal work, first seen wins.
	if consensus.Work(a[0].Header).Cmp(consensus.Work(b[0].Header)) != 0 {
		t.Fatal("expected equal work for siblings")
	}
	add(t, m, b[0], SideChain)
	if work(b[0], b[1]).Cmp(work(a[0], a[1])) > 0 {
		add(t, m, b[1], NewTip)
	} else {
		add(t, m, b[1], SideChain)
	}
	// Three 24-bit blocks always outweigh two: 3·√(2^23) > 2·√(2^24).
	if tipHash(t, m) == b[1].Hash() {
		add(t, m, b[2], NewTip)
	} else {
		<-events // drain
		add(t, m, b[2], NewTip)
		if ev := <-events; ev.Reorg != 2 || ev.Hash != b[2].Hash() || ev.Height != 3 {
			t.Fatalf("event %+v, want reorg of 2 to b[2] at height 3", ev)
		}
	}

	want := []*consensus.Block{g, b[0], b[1], b[2]}
	active := m.ActiveBlocks()
	if len(active) != len(want) {
		t.Fatalf("active length %d, want %d", len(active), len(want))
	}
	for i := range want {
		if active[i].Hash() != want[i].Hash() {
			t.Fatalf("active[%d] is not the heavier fork", i)
		}
	}
	for _, blk := range a {
		if _, ok := m.IsActive(blk.Hash()); ok {
			t.Error("old fork block still active")
		}
		if _, _, err := m.BlockByHash(blk.Hash()); err != nil {
			t.Error("side-chain block was dropped")
		}
	}
	if _, _, w, _ := m.Tip(); w.Cmp(work(g, b[0], b[1], b[2])) != 0 {
		t.Errorf("tip work %s", w)
	}
}

func TestOrphans(t *testing.T) {
	p := testParams()
	m, _ := NewMemory(p)
	chain := fork(t, p, nil, 4, "miner")

	// Deliver in reverse: everything but genesis waits as an orphan.
	for i := len(chain) - 1; i >= 1; i-- {
		add(t, m, chain[i], Orphan)
	}
	add(t, m, chain[3], Duplicate)
	if m.NumOrphans() != 3 {
		t.Fatalf("orphans %d, want 3", m.NumOrphans())
	}
	add(t, m, chain[0], NewTip)
	if m.NumOrphans() != 0 || tipHash(t, m) != chain[3].Hash() || m.Height() != 4 {
		t.Fatalf("orphans not connected: orphans=%d height=%d", m.NumOrphans(), m.Height())
	}
}

func TestOrphanEviction(t *testing.T) {
	m, _ := NewMemory(testParams())
	fake := func(i int) *consensus.Block {
		h := &consensus.Header{Version: 1, Time: uint32(i), N: new(big.Int), K: new(big.Int)}
		h.PrevHash[0], h.PrevHash[1] = 0xff, byte(i)
		return &consensus.Block{Header: h, Txs: [][]byte{{byte(i)}}}
	}
	first := fake(0)
	add(t, m, first, Orphan)
	for i := 1; i <= MaxOrphans; i++ {
		add(t, m, fake(i), Orphan)
	}
	if m.NumOrphans() != MaxOrphans {
		t.Fatalf("orphans %d, want %d", m.NumOrphans(), MaxOrphans)
	}
	if m.Has(first.Hash()) {
		t.Error("oldest orphan was not evicted")
	}
}

func TestInvalidBlockRejected(t *testing.T) {
	p := testParams()
	m, _ := NewMemory(p)
	g := mine(t, p, nil, "genesis")
	bad := *g.Header
	bad.K = new(big.Int).Add(g.Header.K, big.NewInt(1))
	if _, err := m.AddBlock(&consensus.Block{Header: &bad, Txs: g.Txs}, now); !errors.Is(err, consensus.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
	if m.Height() != 0 || m.Has((&bad).Hash()) {
		t.Fatal("invalid block was indexed")
	}
	// The future-time rule applies to live blocks.
	if _, err := m.AddBlock(g, int64(g.Header.Time)-p.FutureLimit-1); !errors.Is(err, consensus.ErrInvalid) {
		t.Fatalf("future block: got %v, want ErrInvalid", err)
	}
}

func TestRestart(t *testing.T) {
	p := testParams()
	dir := t.TempDir()
	g := mine(t, p, nil, "genesis")
	main := fork(t, p, []*consensus.Block{g}, 3, "alice")
	side := fork(t, p, []*consensus.Block{g}, 1, "bob")

	m, err := Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range append([]*consensus.Block{g}, main...) {
		if _, err := m.AddBlock(b, now); err != nil {
			t.Fatal(err)
		}
	}
	add(t, m, side[0], SideChain)
	wantTip := tipHash(t, m)
	m.Close()

	// Simulate a crash mid-append: a torn record at the end of the file.
	path := filepath.Join(dir, BlocksFile)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{200, 0, 0, 0, 1, 2, 3})
	f.Close()
	before, _ := os.Stat(path)

	m, err = Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	if tipHash(t, m) != wantTip || m.Height() != 4 {
		t.Fatalf("tip after restart differs (height %d)", m.Height())
	}
	if _, _, err := m.BlockByHash(side[0].Hash()); err != nil {
		t.Error("side-chain block lost across restart")
	}
	after, _ := os.Stat(path)
	if after.Size() != before.Size()-7 {
		t.Errorf("torn tail not truncated: %d -> %d", before.Size(), after.Size())
	}
	// The store still appends correctly after truncation.
	next := mine(t, p, append([]*consensus.Block{g}, main...), "alice")
	add(t, m, next, NewTip)
	m.Close()
	m, err = Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	if tipHash(t, m) != next.Hash() {
		t.Fatal("block appended after truncation was lost")
	}
	m.Close()

	// A complete but undecodable record is corruption, not a torn tail.
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{3, 0, 0, 0, 1, 2, 3})
	f.Close()
	if _, err := Open(dir, p); err == nil {
		t.Fatal("opened a corrupt block file")
	}
}
