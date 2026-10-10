package node

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/decanus/canary/internal/api"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/p2p"
	"github.com/decanus/canary/internal/wallet"
)

// TestTransferEndToEnd: node a mines to alice; alice's transfer to bob is submitted through node
// b's HTTP API, relayed by gossip, mined by a, and visible on b.
func TestTransferEndToEnd(t *testing.T) {
	p := testParams()
	alice, err := wallet.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bob := consensus.Address{0xb0, 0xb0}

	open := func(mine bool, apiAddr string, peers ...*Node) *Node {
		var addrs []string
		for _, pn := range peers {
			addrs = append(addrs, pn.P2P.Addrs()[0].String())
		}
		n, err := Open(Config{
			DataDir: t.TempDir(), Params: p,
			P2P:  p2p.Config{Listen: []string{"/ip4/127.0.0.1/tcp/0"}, Peers: addrs, PollEvery: 2 * time.Second},
			Mine: mine, MinerAddress: alice.Address(), Threads: 2, MineDelay: 300 * time.Millisecond,
			API: apiAddr, Logf: t.Logf,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		return n
	}
	a := open(true, "")
	b := open(false, "127.0.0.1:0", a)

	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()
	defer func() {
		stop()
		<-done
	}()

	client := api.NewClient("http://" + b.API.Addr())
	eventually(t, 30*time.Second, "alice to have coins on b", func() bool {
		acc, err := client.Account(alice.Address())
		return err == nil && acc.Balance != "0"
	})

	tip, err := client.Tip()
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := wallet.ParseAddress(tip.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := client.Account(alice.Address())
	if err != nil {
		t.Fatal(err)
	}
	tx := &consensus.Transfer{To: bob, Amount: big.NewInt(1000), Fee: big.NewInt(7), Nonce: acc.NextNonce}
	if err := alice.SignTransfer(tx, genesis); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubmitTx(tx); err != nil {
		t.Fatal(err)
	}
	if next, _ := client.Account(alice.Address()); next.NextNonce != acc.NextNonce+1 {
		t.Errorf("nextNonce %d after submit, want %d", next.NextNonce, acc.NextNonce+1)
	}

	eventually(t, 60*time.Second, "bob's transfer to be mined and seen on b", func() bool {
		acc, err := client.Account(bob)
		return err == nil && acc.Balance == "1000"
	})
	if a.Pool.Len() != 0 || b.Pool.Len() != 0 {
		t.Errorf("mempools not cleared after mining: a=%d b=%d", a.Pool.Len(), b.Pool.Len())
	}
}
