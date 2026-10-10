package p2p

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/mempool"
)

// Config configures a Node. Zero values get the defaults noted.
type Config struct {
	DataDir     string        // holds node.key and peers.json
	Pool        *mempool.Pool // receives gossiped transfers; nil disables transaction relay
	Listen      []string      // multiaddrs, e.g. /ip4/0.0.0.0/tcp/18555
	Peers       []string      // static peers, multiaddrs ending in /p2p/<id>
	MaxPeers    int           // default 16
	BanDuration time.Duration // default 10 minutes
	PollEvery   time.Duration // status re-check interval, default 15s
	Now         func() int64  // local clock, default time.Now().Unix
	Logf        func(format string, args ...any)
}

// Node is a libp2p host that relays blocks into and out of a chain manager.
type Node struct {
	cfg    Config
	chain  *chain.Manager
	host   host.Host
	gater  *gater
	topic  *pubsub.Topic
	sub    *pubsub.Subscription
	txs    *pubsub.Topic // nil without a pool
	txSub  *pubsub.Subscription
	static []peer.AddrInfo

	ctx    context.Context
	cancel context.CancelFunc

	// Every goroutine that touches the chain (our own, pubsub validators, stream handlers)
	// registers in wg via enter, so Close can wait for all of them before the chain closes.
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	syncMu  sync.Mutex
	syncing map[peer.ID]bool
}

// New starts a node on top of cm. It listens, joins the block topic and dials the static and
// saved peers in the background.
func New(cm *chain.Manager, cfg Config) (*Node, error) {
	if cfg.MaxPeers == 0 {
		cfg.MaxPeers = 16
	}
	if cfg.BanDuration == 0 {
		cfg.BanDuration = 10 * time.Minute
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 15 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	netName := cm.Params().Network
	if netName == "" {
		return nil, errors.New("p2p: params have no network name")
	}
	static, err := parsePeers(cfg.Peers)
	if err != nil {
		return nil, fmt.Errorf("p2p: --peers: %w", err)
	}
	saved, bad, err := loadPeers(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("p2p: %s: %w", peersFile, err)
	}
	for _, err := range bad {
		cfg.Logf("p2p: %s: skipping %v", peersFile, err)
	}
	sk, err := loadIdentity(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("p2p: identity: %w", err)
	}

	g := newGater(cfg.MaxPeers)
	conns, err := connmgr.NewConnManager(cfg.MaxPeers*3/4, cfg.MaxPeers, connmgr.WithGracePeriod(20*time.Second))
	if err != nil {
		return nil, err
	}
	h, err := libp2p.New(
		libp2p.Identity(sk),
		libp2p.ListenAddrStrings(cfg.Listen...),
		libp2p.ConnectionManager(conns),
		libp2p.ConnectionGater(g),
	)
	if err != nil {
		return nil, err
	}
	hostNet := h.Network()
	g.net.Store(&hostNet)

	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		cfg: cfg, chain: cm, host: h, gater: g, static: static,
		ctx: ctx, cancel: cancel, syncing: make(map[peer.ID]bool),
	}
	fail := func(err error) (*Node, error) {
		cancel()
		h.Close()
		return nil, err
	}

	ps, err := pubsub.NewGossipSub(ctx, h,
		// Identify messages by block hash so the same block from two publishers is one message.
		pubsub.WithMessageIdFn(func(m *pb.Message) string {
			sum := sha256.Sum256(m.Data)
			return string(sum[:])
		}),
		pubsub.WithMaxMessageSize(consensus.MaxBlockSize+64<<10),
	)
	if err != nil {
		return fail(err)
	}
	topicName := blocksTopic(netName)
	if err := ps.RegisterTopicValidator(topicName, n.validate); err != nil {
		return fail(err)
	}
	if n.topic, err = ps.Join(topicName); err != nil {
		return fail(err)
	}
	if n.sub, err = n.topic.Subscribe(); err != nil {
		return fail(err)
	}
	if cfg.Pool != nil {
		txTopic := txsTopic(netName)
		if err := ps.RegisterTopicValidator(txTopic, n.validateTx); err != nil {
			return fail(err)
		}
		if n.txs, err = ps.Join(txTopic); err != nil {
			return fail(err)
		}
		if n.txSub, err = n.txs.Subscribe(); err != nil {
			return fail(err)
		}
	}

	h.SetStreamHandler(statusProtocol(netName), n.handleStatus)
	h.SetStreamHandler(syncProtocol(netName), n.handleSync)
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			// The dialer starts the status exchange; the handler side answers it.
			if c.Stat().Direction == network.DirOutbound {
				n.spawn(func() { n.exchangeStatus(c.RemotePeer()) })
			}
		},
	})

	n.spawn(func() { drain(n.ctx, n.sub) })
	if n.txSub != nil {
		n.spawn(func() { drain(n.ctx, n.txSub) })
	}
	n.spawn(n.poll)
	for _, info := range append(static, saved...) {
		n.spawn(func() { n.dial(info) })
	}
	return n, nil
}

// enter registers a unit of work for Close to wait on; it returns false once the node is
// closing. Callers that get true must call n.wg.Done.
func (n *Node) enter() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	n.wg.Add(1)
	return true
}

// spawn runs f in a goroutine that Close waits for, unless the node is closing.
func (n *Node) spawn(f func()) {
	if !n.enter() {
		return
	}
	go func() {
		defer n.wg.Done()
		f()
	}()
}

// ID returns the node's peer ID.
func (n *Node) ID() peer.ID { return n.host.ID() }

// Addrs returns the node's listen addresses including /p2p/<id>.
func (n *Node) Addrs() []ma.Multiaddr {
	addrs, _ := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: n.host.ID(), Addrs: n.host.Addrs()})
	return addrs
}

// Peers returns the connected peers.
func (n *Node) Peers() []peer.AddrInfo {
	var out []peer.AddrInfo
	for _, p := range n.host.Network().Peers() {
		out = append(out, n.host.Peerstore().PeerInfo(p))
	}
	return out
}

// Connect dials a peer given as a multiaddr ending in /p2p/<id>.
func (n *Node) Connect(ctx context.Context, addr string) error {
	info, err := peer.AddrInfoFromString(addr)
	if err != nil {
		return err
	}
	return n.host.Connect(ctx, *info)
}

// Publish gossips a block that the chain manager has already accepted.
func (n *Node) Publish(blk *consensus.Block) error {
	return n.topic.Publish(n.ctx, blk.Serialize())
}

// PublishTx gossips a transfer that the pool has already accepted.
func (n *Node) PublishTx(t *consensus.Transfer) error {
	if n.txs == nil {
		return errors.New("p2p: transaction relay disabled")
	}
	return n.txs.Publish(n.ctx, t.Serialize())
}

// Close saves the connected peers to peers.json and shuts the node down. When it returns, no
// goroutine of the node is still using the chain manager.
func (n *Node) Close() error {
	var err error
	if peers := n.Peers(); len(peers) > 0 {
		err = savePeers(n.cfg.DataDir, peers)
	}
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	n.cancel()
	n.sub.Cancel()
	if n.txSub != nil {
		n.txSub.Cancel()
	}
	err = errors.Join(err, n.host.Close())
	n.wg.Wait()
	return err
}

func (n *Node) dial(info peer.AddrInfo) {
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	if err := n.host.Connect(ctx, info); err != nil && n.ctx.Err() == nil {
		n.cfg.Logf("p2p: dial %s: %v", info.ID, err)
	}
}

// drain consumes a subscription; messages are processed in the topic validators.
func drain(ctx context.Context, sub *pubsub.Subscription) {
	for {
		if _, err := sub.Next(ctx); err != nil {
			return
		}
	}
}

// poll periodically re-checks every peer's status (catching blocks missed in gossip) and
// redials static peers when the node has no connections.
func (n *Node) poll() {
	t := time.NewTicker(n.cfg.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		}
		peers := n.host.Network().Peers()
		for _, p := range peers {
			n.spawn(func() { n.exchangeStatus(p) })
		}
		if len(peers) == 0 {
			for _, info := range n.static {
				n.spawn(func() { n.dial(info) })
			}
		}
	}
}

// validate is the gossip topic validator: it adds the block to the chain. Invalid blocks are
// rejected and their sender banned; orphans trigger a sync with the sender. A block we already
// validated (for example via sync) is accepted so that it is still relayed onward.
func (n *Node) validate(_ context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	if !n.enter() {
		return pubsub.ValidationIgnore
	}
	defer n.wg.Done()
	if from == n.host.ID() {
		// Published by us after AddBlock. (msg.Local is not yet set when validators run.)
		return pubsub.ValidationAccept
	}
	blk, err := consensus.DeserializeBlock(msg.Data)
	if err != nil {
		n.punish(from, err)
		return pubsub.ValidationReject
	}
	st, err := n.chain.AddBlock(blk, n.cfg.Now())
	switch {
	case errors.Is(err, consensus.ErrTooNew):
		return pubsub.ValidationIgnore // our clock may simply be behind the sender's
	case errors.Is(err, consensus.ErrInvalid):
		n.punish(from, err)
		return pubsub.ValidationReject
	case err != nil:
		n.cfg.Logf("p2p: adding gossiped block: %v", err)
		return pubsub.ValidationIgnore
	case st == chain.Orphan:
		n.spawn(func() { n.syncFrom(from) })
		return pubsub.ValidationIgnore
	case st == chain.Duplicate:
		if _, _, err := n.chain.BlockByHash(blk.Hash()); err != nil {
			return pubsub.ValidationIgnore // a still-unvalidated orphan
		}
	}
	return pubsub.ValidationAccept
}

// validateTx is the transaction topic validator: it adds the transfer to the pool. Bad encodings
// and signatures are punished; state-dependent rejections (nonce, balance, pool limits) are
// ignored, since honest nodes can briefly disagree about state.
func (n *Node) validateTx(_ context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	if !n.enter() {
		return pubsub.ValidationIgnore
	}
	defer n.wg.Done()
	if from == n.host.ID() {
		return pubsub.ValidationAccept // published by us after Pool.Add
	}
	tx, err := consensus.DecodeTx(msg.Data)
	t, ok := tx.(*consensus.Transfer)
	if err != nil || !ok {
		n.punish(from, fmt.Errorf("undecodable transfer: %v", err))
		return pubsub.ValidationReject
	}
	switch err := n.cfg.Pool.Add(t); {
	case err == nil:
		return pubsub.ValidationAccept
	case errors.Is(err, mempool.ErrInvalid):
		n.punish(from, err)
		return pubsub.ValidationReject
	default:
		return pubsub.ValidationIgnore
	}
}

// punish bans and disconnects a peer that sent an invalid block or transfer.
func (n *Node) punish(p peer.ID, err error) {
	n.cfg.Logf("p2p: banning %s: %v", p, err)
	n.gater.ban(p, n.cfg.BanDuration)
	n.host.Network().ClosePeer(p)
}

func (n *Node) ownStatus() Status {
	tip, _, work, _ := n.chain.Tip()
	return Status{Version: ProtocolVersion, Height: uint32(n.chain.Height()), Tip: tip, Work: work}
}

// exchangeStatus sends our status to p, reads theirs, and syncs if p has more work.
func (n *Node) exchangeStatus(p peer.ID) {
	s, err := n.host.NewStream(n.ctx, p, statusProtocol(n.chain.Params().Network))
	if err != nil {
		return
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeStatus(s, n.ownStatus()); err != nil {
		s.Reset()
		return
	}
	remote, err := readStatus(s)
	if err != nil {
		s.Reset()
		return
	}
	n.maybeSync(p, remote)
}

func (n *Node) handleStatus(s network.Stream) {
	if !n.enter() {
		s.Reset()
		return
	}
	defer n.wg.Done()
	defer s.Close()
	s.SetDeadline(time.Now().Add(30 * time.Second))
	remote, err := readStatus(s)
	if err != nil {
		s.Reset()
		return
	}
	if err := writeStatus(s, n.ownStatus()); err != nil {
		s.Reset()
		return
	}
	n.maybeSync(s.Conn().RemotePeer(), remote)
}

func (n *Node) maybeSync(p peer.ID, remote Status) {
	if remote.Version != ProtocolVersion {
		return
	}
	if _, _, work, _ := n.chain.Tip(); remote.Work.Cmp(work) > 0 {
		n.spawn(func() { n.syncFrom(p) })
	}
}

// syncFrom fetches p's active chain from where it diverges from ours until p has nothing more.
// The first request carries our locator; each later one leads with the last block received, so
// the cursor follows p's chain even through a long side branch whose blocks do not move our
// tip. At most one sync per peer runs at a time.
func (n *Node) syncFrom(p peer.ID) {
	n.syncMu.Lock()
	if n.syncing[p] {
		n.syncMu.Unlock()
		return
	}
	n.syncing[p] = true
	n.syncMu.Unlock()
	defer func() {
		n.syncMu.Lock()
		delete(n.syncing, p)
		n.syncMu.Unlock()
	}()

	var cursor *[32]byte
	for n.ctx.Err() == nil {
		locator := n.chain.Locator()
		if cursor != nil {
			locator = append([][32]byte{*cursor}, locator...)
		}
		blocks, err := n.requestBlocks(p, locator)
		if errors.Is(err, consensus.ErrInvalid) {
			n.punish(p, err)
			return
		}
		if err != nil || len(blocks) == 0 {
			return
		}
		if cursor != nil && blocks[0].Header.PrevHash != *cursor {
			return // p's chain changed under us (or p is misbehaving); the next poll retries
		}
		for _, blk := range blocks {
			st, err := n.chain.AddBlock(blk, n.cfg.Now())
			switch {
			case errors.Is(err, consensus.ErrTooNew):
				return
			case errors.Is(err, consensus.ErrInvalid):
				n.punish(p, err)
				return
			case err != nil:
				n.cfg.Logf("p2p: adding synced block: %v", err)
				return
			case st == chain.Orphan:
				return // not a continuation of anything we know
			}
		}
		last := blocks[len(blocks)-1].Hash()
		cursor = &last
	}
}

func (n *Node) requestBlocks(p peer.ID, locator [][32]byte) ([]*consensus.Block, error) {
	s, err := n.host.NewStream(n.ctx, p, syncProtocol(n.chain.Params().Network))
	if err != nil {
		return nil, err
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(60 * time.Second))
	if err := writeLocator(s, locator); err != nil {
		s.Reset()
		return nil, err
	}
	if err := s.CloseWrite(); err != nil {
		s.Reset()
		return nil, err
	}
	blocks, err := readBlocks(s)
	if err != nil {
		s.Reset()
	}
	return blocks, err
}

// handleSync answers a locator with the active blocks after the first locator hash on our
// active chain (from genesis if none), bounded by count and size.
func (n *Node) handleSync(s network.Stream) {
	if !n.enter() {
		s.Reset()
		return
	}
	defer n.wg.Done()
	defer s.Close()
	s.SetDeadline(time.Now().Add(60 * time.Second))
	locator, err := readLocator(s)
	if err != nil {
		s.Reset()
		return
	}
	start := 0
	for _, h := range locator {
		if height, ok := n.chain.IsActive(h); ok {
			start = height + 1
			break
		}
	}
	blocks := n.chain.BlocksFrom(start, syncBatch)
	size := 0
	for i, b := range blocks {
		if size += b.SerializedSize(); size > maxSyncBytes {
			blocks = blocks[:i]
			break
		}
	}
	if err := writeBlocks(s, blocks); err != nil {
		s.Reset()
	}
}
