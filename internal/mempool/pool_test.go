package mempool

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/wallet"
)

var genesis = [32]byte{9}

type spec struct {
	key       *wallet.Key
	nonce     uint64
	amount    int64
	fee       int64
	corruptSg bool
}

// signAll signs the transfers in parallel (SLH-DSA signing takes seconds each).
func signAll(t *testing.T, specs []spec) []*consensus.Transfer {
	t.Helper()
	out := make([]*consensus.Transfer, len(specs))
	var wg sync.WaitGroup
	for i, s := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx := &consensus.Transfer{To: consensus.Address{0xee}, Amount: big.NewInt(s.amount), Fee: big.NewInt(s.fee), Nonce: s.nonce}
			if err := s.key.SignTransfer(tx, genesis); err != nil {
				panic(err)
			}
			if s.corruptSg {
				tx.Sig[0] ^= 1
			}
			out[i] = tx
		}()
	}
	wg.Wait()
	return out
}

func TestPool(t *testing.T) {
	alice, _ := wallet.Generate()
	bob, _ := wallet.Generate()
	st := consensus.State{}
	st.Set(alice.Address(), consensus.Account{Balance: big.NewInt(100)})
	st.Set(bob.Address(), consensus.Account{Balance: big.NewInt(1000), Nonce: 5})

	txs := signAll(t, []spec{
		{alice, 0, 10, 1, false},  // 0: a0 fee 1
		{alice, 1, 10, 10, false}, // 1: a1 fee 10
		{alice, 3, 10, 1, false},  // 2: gap
		{alice, 1, 85, 3, false},  // 3: unaffordable after a0 (11 + 88 > 100)
		{bob, 5, 10, 5, false},    // 4: b5 fee 5
		{bob, 4, 1, 1, false},     // 5: nonce already used
		{bob, 6, 1, 1, true},      // 6: bad signature
		{alice, 1, 10, 20, false}, // 7: replaces a1 with a higher fee
	})
	p := New()
	p.Update(genesis, st, nil)

	mustAdd := func(i int) {
		t.Helper()
		if err := p.Add(txs[i]); err != nil {
			t.Fatalf("tx %d: %v", i, err)
		}
	}
	mustAdd(0)
	mustAdd(1)
	mustAdd(4)
	if err := p.Add(txs[0]); !errors.Is(err, ErrKnown) {
		t.Errorf("duplicate: %v", err)
	}
	for _, i := range []int{2, 5} {
		if err := p.Add(txs[i]); err == nil || errors.Is(err, ErrInvalid) {
			t.Errorf("tx %d: got %v, want a non-invalid rejection", i, err)
		}
	}
	if err := p.Add(txs[6]); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad signature: got %v, want ErrInvalid", err)
	}
	if err := p.Add(txs[3]); err == nil {
		t.Error("accepted an unaffordable replacement")
	}

	// Fee order across senders, nonce order within: b5 (5), a0 (1), a1 (10).
	sel := p.Select(st, 1<<20)
	if len(sel) != 3 || sel[0] != txs[4] || sel[1] != txs[0] || sel[2] != txs[1] {
		t.Fatalf("selection order wrong")
	}
	// The selection applies cleanly in a block.
	cb := &consensus.Coinbase{To: consensus.Address{1}, Amount: big.NewInt(16)}
	if _, _, err := consensus.ApplyBlock(st, cb, sel, big.NewInt(0), genesis); err != nil {
		t.Fatalf("selection does not apply: %v", err)
	}
	if got := p.Select(st, consensus.TransferSize); len(got) != 1 {
		t.Fatalf("byte limit: selected %d", len(got))
	}

	mustAdd(7) // higher-fee replacement of a1
	if sel := p.Select(st, 1<<20); sel[len(sel)-1] != txs[7] && sel[0] != txs[7] {
		t.Fatal("replacement not selected")
	}

	// After a block that mined a0 and b5, only a1 (replacement) remains.
	after, _, err := consensus.ApplyBlock(st, cb, []*consensus.Transfer{txs[0], txs[4]}, big.NewInt(10), genesis)
	if err != nil {
		t.Fatal(err)
	}
	// Select against the newer state skips what that state already includes, even before Update.
	if sel := p.Select(after, 1<<20); len(sel) != 1 || sel[0] != txs[7] {
		t.Fatalf("select on newer state: got %d transfers", len(sel))
	}
	p.Update(genesis, after, nil)
	if p.Len() != 1 || p.NextNonce(alice.Address(), 1) != 2 || p.NextNonce(bob.Address(), 6) != 6 {
		t.Fatalf("after update: len %d", p.Len())
	}
	// A different chain clears the pool.
	p.Update([32]byte{1}, after, nil)
	if p.Len() != 0 {
		t.Fatal("pool kept transfers across chains")
	}
}

func TestPoolNonceEdgesAndReorg(t *testing.T) {
	alice, _ := wallet.Generate()
	st := consensus.State{}
	st.Set(alice.Address(), consensus.Account{Balance: big.NewInt(100)})
	txs := signAll(t, []spec{
		{alice, 1 << 63, 1, 1, false},   // 0: nonce that used to wrap the signed index
		{alice, 0, 10, 1, false},        // 1: a0
		{alice, 1, 10, 1, false},        // 2: a1
		{alice, ^uint64(0), 1, 1, true}, // 3: max nonce, bad signature
	})
	p := New()
	p.Update(genesis, st, nil)
	for _, i := range []int{0, 3} {
		if err := p.Add(txs[i]); err == nil {
			t.Fatalf("tx %d accepted", i)
		}
	}
	if err := p.Add(txs[1]); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(txs[2]); err != nil {
		t.Fatal(err)
	}

	// A block mines a0; the chain moves before the pool does. NextNonce must not over-count.
	cb := &consensus.Coinbase{To: consensus.Address{1}, Amount: big.NewInt(1)}
	after, _, err := consensus.ApplyBlock(st, cb, []*consensus.Transfer{txs[1]}, big.NewInt(0), genesis)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.NextNonce(alice.Address(), after.Get(alice.Address()).Nonce); got != 2 {
		t.Fatalf("NextNonce before update = %d, want 2", got)
	}
	p.Update(genesis, after, nil)
	if p.Len() != 1 {
		t.Fatalf("after mining a0: len %d, want 1", p.Len())
	}

	// That block is reorged out: a0 returns, and a1 (queued behind it) survives.
	p.Update(genesis, st, []*consensus.Transfer{txs[1]})
	if p.Len() != 2 || p.NextNonce(alice.Address(), 0) != 2 {
		t.Fatalf("after reorg: len %d, want 2", p.Len())
	}
	if sel := p.Select(st, 1<<20); len(sel) != 2 || sel[0] != txs[1] || sel[1] != txs[2] {
		t.Fatal("reorged transfers not selectable in nonce order")
	}
}
