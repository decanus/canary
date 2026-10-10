// Package node runs a full Canary node: chain storage, libp2p networking and optional mining.
package node

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/decanus/canary/internal/api"
	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/mempool"
	"github.com/decanus/canary/internal/miner"
	"github.com/decanus/canary/internal/p2p"
)

// Config configures a Node.
type Config struct {
	DataDir      string
	Params       *consensus.Params
	P2P          p2p.Config // DataDir, Now and Logf default to the node's
	Mine         bool
	MinerAddress consensus.Address
	Threads      int
	MineDelay    time.Duration // pause after each mined block (tests use it to pace mining)
	API          string        // listen address for the HTTP API (host:port); empty disables it
	Now          func() int64  // default time.Now().Unix
	Logf         func(format string, args ...any)
}

// Node is a running full node.
type Node struct {
	Chain *chain.Manager
	Pool  *mempool.Pool
	P2P   *p2p.Node
	API   *api.Server // nil if disabled
	cfg   Config

	cancel context.CancelFunc
	done   chan struct{}
}

// Open opens the data directory and starts networking.
func Open(cfg Config) (*Node, error) {
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Threads < 1 {
		cfg.Threads = 1
	}
	cm, err := chain.Open(cfg.DataDir, cfg.Params)
	if err != nil {
		return nil, err
	}
	pool := mempool.New()
	// Subscribe before the first update so no tip change in between is missed.
	events := cm.Subscribe()
	if genesis, st, ok := cm.TipState(); ok {
		pool.Update(genesis, st, nil)
	}
	pc := cfg.P2P
	pc.DataDir, pc.Now, pc.Logf, pc.Pool = cfg.DataDir, cfg.Now, cfg.Logf, pool
	pn, err := p2p.New(cm, pc)
	if err != nil {
		cm.Close()
		return nil, err
	}
	n := &Node{Chain: cm, Pool: pool, P2P: pn, cfg: cfg, done: make(chan struct{})}
	if cfg.API != "" {
		if n.API, err = api.Listen(cfg.API, api.Backend{Chain: cm, Pool: pool, PublishTx: pn.PublishTx}); err != nil {
			pn.Close()
			cm.Close()
			return nil, fmt.Errorf("api: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	go n.followTip(ctx, events)
	return n, nil
}

// followTip keeps the mempool in step with the chain, returning transfers from blocks a reorg
// removed. (Events are latest-wins, so back-to-back reorgs can still lose some; wallets can
// resubmit.)
func (n *Node) followTip(ctx context.Context, events <-chan chain.TipEvent) {
	defer close(n.done)
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			var readd []*consensus.Transfer
			for _, blk := range ev.Removed {
				for _, raw := range blk.Txs {
					if t, err := consensus.DecodeTx(raw); err == nil {
						if t, ok := t.(*consensus.Transfer); ok {
							readd = append(readd, t)
						}
					}
				}
			}
			if genesis, st, ok := n.Chain.TipState(); ok {
				n.Pool.Update(genesis, st, readd)
			}
		}
	}
}

// Run mines (if enabled) until ctx is cancelled; otherwise it just waits, since networking runs
// in the background.
func (n *Node) Run(ctx context.Context) error {
	if !n.cfg.Mine {
		<-ctx.Done()
		return nil
	}
	n.mine(ctx)
	return nil
}

// Close stops the API and networking and closes the data directory.
func (n *Node) Close() error {
	var err error
	if n.API != nil {
		err = n.API.Close()
	}
	n.cancel()
	<-n.done
	return errors.Join(err, n.P2P.Close(), n.Chain.Close())
}

// maxTransferBytes leaves room in a block for the header, coinbase and length prefixes.
const maxTransferBytes = consensus.MaxBlockSize - consensus.HeaderSize - 1024

// mine repeatedly mines on the current tip, abandoning a solve when the tip changes, and
// publishes every block it finds.
func (n *Node) mine(ctx context.Context) {
	events := n.Chain.Subscribe()
	for ctx.Err() == nil {
		// Drop the event for a tip we are about to read anyway (including our own last block).
		select {
		case <-events:
		default:
		}
		headers, state := n.Chain.Snapshot()
		solveCtx, cancel := context.WithCancel(ctx)
		done, watcherExited := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(watcherExited)
			select {
			case <-events:
				cancel()
			case <-done:
			}
		}()
		transfers := n.Pool.Select(state, maxTransferBytes)
		if len(headers) == 0 {
			transfers = nil // the genesis block may contain only its coinbase
		}
		res, err := miner.MineBlock(solveCtx, n.cfg.Params, headers, state, n.cfg.MinerAddress, transfers, n.cfg.Threads, n.cfg.Now())
		close(done)
		// Wait for the watcher so it cannot take a tip event meant for the next iteration.
		<-watcherExited
		cancel()
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, context.Canceled):
			continue // new tip
		case err != nil:
			n.cfg.Logf("miner: %v", err)
			sleep(ctx, time.Second)
			continue
		}
		st, err := n.Chain.AddBlock(res.Block, n.cfg.Now())
		if err != nil {
			n.cfg.Logf("miner: own block rejected: %v", err)
			continue
		}
		if st == chain.NewTip {
			h := res.Block.Hash()
			n.cfg.Logf("mined block %d bits=%d txs=%d hash=%x (rho %.2fs)", len(headers), res.Block.Header.Bits, len(res.Block.Txs), h[:8], res.RhoTime.Seconds())
			if err := n.P2P.Publish(res.Block); err != nil {
				n.cfg.Logf("miner: publish: %v", err)
			}
		}
		sleep(ctx, n.cfg.MineDelay)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
