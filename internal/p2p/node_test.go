package p2p

import (
	"context"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/miner"
)

func testParams() *consensus.Params {
	p := consensus.Prototype
	p.GenesisBits, p.MinBits, p.Epoch, p.Network = 24, 20, 1000, "test"
	return &p
}

const t0 = int64(1_800_000_000)

// extend mines n blocks on top of base (oldest first) and returns base plus the new blocks.
func extend(t *testing.T, p *consensus.Params, base []*consensus.Block, n int, addr string) []*consensus.Block {
	t.Helper()
	out := append([]*consensus.Block{}, base...)
	for i := 0; i < n; i++ {
		hs := make(consensus.Headers, len(out))
		for j, b := range out {
			hs[j] = b.Header
		}
		res, err := miner.MineBlock(context.Background(), p, hs, addr, 2, t0+int64(len(out)))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, res.Block)
	}
	return out
}

func newNode(t *testing.T, p *consensus.Params, blocks []*consensus.Block, peers ...*Node) *Node {
	t.Helper()
	cm, err := chain.NewMemory(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		if _, err := cm.AddBlock(b, t0+1e6); err != nil {
			t.Fatal(err)
		}
	}
	var addrs []string
	for _, pn := range peers {
		addrs = append(addrs, pn.Addrs()[0].String())
	}
	n, err := New(cm, Config{
		DataDir:   t.TempDir(),
		Listen:    []string{"/ip4/127.0.0.1/tcp/0"},
		Peers:     addrs,
		PollEvery: time.Hour,
		Now:       func() int64 { return t0 + 1e6 },
		Logf:      t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// A heavier branch that is longer than one sync batch, and whose first batch does not outweigh
// our own fork, must still be fetched to the end.
func TestSyncLongSideBranch(t *testing.T) {
	// Restored in a cleanup registered before the nodes', so it runs after they close.
	old := syncBatch
	syncBatch = 5
	t.Cleanup(func() { syncBatch = old })

	p := testParams()
	genesis := extend(t, p, nil, 1, "genesis")
	ours := extend(t, p, genesis, 8, "b")
	theirs := extend(t, p, genesis, 20, "a")

	a := newNode(t, p, theirs)
	b := newNode(t, p, ours, a)
	want := theirs[len(theirs)-1].Hash()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if h, _, _, _ := b.chain.Tip(); h == want {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("b did not reorg onto the longer branch (height %d)", b.chain.Height())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A block that is only "too new" for our clock is ignored, and its relayer is not banned.
func TestTooNewBlockDoesNotBan(t *testing.T) {
	p := testParams()
	n := newNode(t, p, nil)
	res, err := miner.MineBlock(context.Background(), p, consensus.Headers{}, "x", 2, t0+1e6+p.FutureLimit+100)
	if err != nil {
		t.Fatal(err)
	}
	from := peer.ID("relayer")
	msg := &pubsub.Message{Message: &pb.Message{Data: res.Block.Serialize()}}
	if got := n.validate(context.Background(), from, msg); got != pubsub.ValidationIgnore {
		t.Fatalf("validation result %v, want ignore", got)
	}
	if n.gater.isBanned(from) {
		t.Fatal("relayer of a too-new block was banned")
	}
}
