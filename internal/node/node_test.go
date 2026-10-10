package node

import (
	"context"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/miner"
	"github.com/decanus/canary/internal/p2p"
)

// testParams keeps blocks at 24 bits so mining takes milliseconds, on a private network name.
func testParams() *consensus.Params {
	p := consensus.Prototype
	p.GenesisBits, p.MinBits, p.Epoch, p.Network = 24, 20, 1000, "test"
	return &p
}

// start runs a node connected to peers. Status polling is effectively off, so new blocks must
// arrive by gossip (or the status exchange on connect).
func start(t *testing.T, p *consensus.Params, mine bool, peers ...*Node) *Node {
	t.Helper()
	var addrs []string
	for _, pn := range peers {
		addrs = append(addrs, pn.P2P.Addrs()[0].String())
	}
	n, err := Open(Config{
		DataDir:      t.TempDir(),
		Params:       p,
		P2P:          p2p.Config{Listen: []string{"/ip4/127.0.0.1/tcp/0"}, Peers: addrs, PollEvery: time.Hour},
		Mine:         mine,
		MinerAddress: consensus.Address{0xaa},
		Threads:      2,
		MineDelay:    200 * time.Millisecond,
		Logf:         t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func tip(n *Node) [32]byte {
	h, _, _, _ := n.Chain.Tip()
	return h
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestNodesConvergeAndLateSync(t *testing.T) {
	p := testParams()
	a := start(t, p, true)
	b := start(t, p, false, a)
	c := start(t, p, false, b) // not connected to the miner: blocks must be relayed through b

	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()
	eventually(t, 30*time.Second, "a to mine 8 blocks", func() bool { return a.Chain.Height() >= 8 })
	stop()
	<-done

	eventually(t, 30*time.Second, "b and c to reach a's tip", func() bool {
		return tip(b) == tip(a) && tip(c) == tip(a)
	})

	// A node started later syncs the whole chain from scratch through c.
	d := start(t, p, false, c)
	eventually(t, 30*time.Second, "late node to sync", func() bool { return tip(d) == tip(a) })
	if d.Chain.Height() != a.Chain.Height() {
		t.Fatalf("late node height %d, want %d", d.Chain.Height(), a.Chain.Height())
	}
}

func TestPeerSendingInvalidBlockIsBanned(t *testing.T) {
	p := testParams()
	a := start(t, p, false)
	// Give a a short chain so the attacker can build a block that passes the cheap checks.
	for i := 0; i < 3; i++ {
		headers, st := a.Chain.Snapshot()
		res, err := miner.MineBlock(context.Background(), p, headers, st, consensus.Address{1}, nil, 2, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Chain.AddBlock(res.Block, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	headers, st := a.Chain.Snapshot()
	res, err := miner.MineBlock(context.Background(), p, headers, st, consensus.Address{2}, nil, 2, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	bad := *res.Block.Header
	bad.K = new(big.Int).Add(bad.K, big.NewInt(1))
	badBlock := &consensus.Block{Header: &bad, Txs: res.Block.Txs}

	// The attacker is a bare libp2p host on the same gossip topic.
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ps, err := pubsub.NewGossipSub(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	topic, err := ps.Join("/canary/test/blocks/1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := topic.Subscribe(); err != nil {
		t.Fatal(err)
	}
	info, err := peer.AddrInfoFromP2pAddr(a.P2P.Addrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Connect(context.Background(), *info); err != nil {
		t.Fatal(err)
	}
	connected := func() bool {
		return slices.ContainsFunc(a.P2P.Peers(), func(pi peer.AddrInfo) bool { return pi.ID == h.ID() })
	}
	eventually(t, 10*time.Second, "attacker to see a on the topic", func() bool {
		return slices.Contains(topic.ListPeers(), a.P2P.ID())
	})

	// A publish sent right after the subscription handshake can be dropped by the attacker's
	// own gossip router, so keep publishing until a reacts.
	eventually(t, 15*time.Second, "a to drop the attacker", func() bool {
		if !connected() {
			return true
		}
		topic.Publish(context.Background(), badBlock.Serialize())
		time.Sleep(250 * time.Millisecond)
		return false
	})
	if a.Chain.Has(badBlock.Hash()) {
		t.Fatal("invalid block was stored")
	}

	// The ban holds: a refuses the attacker's reconnection.
	h.Connect(context.Background(), *info)
	time.Sleep(500 * time.Millisecond)
	if connected() {
		t.Fatal("banned peer reconnected")
	}
}
