// Package node runs a full Canary node: chain storage, libp2p networking and optional mining.
package node

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/decanus/canary/internal/api"
	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/miner"
	"github.com/decanus/canary/internal/p2p"
)

// Config configures a Node.
type Config struct {
	DataDir      string
	Params       *consensus.Params
	P2P          p2p.Config // DataDir, Now and Logf default to the node's
	API          string     // HTTP API listen address (SPEC.md §10); empty disables the API
	Mine         bool
	MinerAddress string
	Threads      int
	MineDelay    time.Duration // pause after each mined block (tests use it to pace mining)
	Now          func() int64  // default time.Now().Unix
	Logf         func(format string, args ...any)
}

// Node is a running full node.
type Node struct {
	Chain *chain.Manager
	P2P   *p2p.Node
	cfg   Config
	api   *http.Server // nil if the API is disabled
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
	pc := cfg.P2P
	pc.DataDir, pc.Now, pc.Logf = cfg.DataDir, cfg.Now, cfg.Logf
	pn, err := p2p.New(cm, pc)
	if err != nil {
		cm.Close()
		return nil, err
	}
	n := &Node{Chain: cm, P2P: pn, cfg: cfg}
	if cfg.API != "" {
		// Listen now so that a bad or busy address fails Open rather than a background goroutine.
		ln, err := net.Listen("tcp", cfg.API)
		if err != nil {
			return nil, errors.Join(err, pn.Close(), cm.Close())
		}
		// The timeouts bound every handler, so Close can wait for them before closing the chain.
		// Addr is informational (Serve uses ln) and records the resolved port for APIAddr.
		n.api = &http.Server{
			Addr:              ln.Addr().String(),
			Handler:           api.New(cm, pn, cfg.Now),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		go func() {
			if err := n.api.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				cfg.Logf("api: %v", err)
			}
		}()
	}
	return n, nil
}

// APIAddr returns the HTTP API's listen address (host:port), or "" if the API is disabled.
func (n *Node) APIAddr() string {
	if n.api == nil {
		return ""
	}
	return n.api.Addr
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
	if n.api != nil {
		// No deadline: a handler still running after a forced close could use the closed chain.
		err = n.api.Shutdown(context.Background())
	}
	return errors.Join(err, n.P2P.Close(), n.Chain.Close())
}

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
		headers := n.Chain.ActiveHeaders()
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
		res, err := miner.MineBlock(solveCtx, n.cfg.Params, headers, n.cfg.MinerAddress, n.cfg.Threads, n.cfg.Now())
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
			n.cfg.Logf("mined block %d bits=%d hash=%x (rho %.2fs)", len(headers), res.Block.Header.Bits, h[:8], res.RhoTime.Seconds())
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
