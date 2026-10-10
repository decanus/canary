package p2p

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// gater refuses connections to and from banned peers, and inbound connections beyond maxPeers.
type gater struct {
	maxPeers int
	peers    func() int // current connected peer count; set once the host exists

	mu     sync.Mutex
	banned map[peer.ID]time.Time
}

func newGater(maxPeers int) *gater {
	return &gater{maxPeers: maxPeers, banned: make(map[peer.ID]time.Time)}
}

func (g *gater) ban(p peer.ID, d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.banned[p] = time.Now().Add(d)
}

func (g *gater) isBanned(p peer.ID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.banned[p]
	if ok && time.Now().After(until) {
		delete(g.banned, p)
		return false
	}
	return ok
}

func (g *gater) InterceptPeerDial(p peer.ID) bool                 { return !g.isBanned(p) }
func (g *gater) InterceptAddrDial(p peer.ID, _ ma.Multiaddr) bool { return !g.isBanned(p) }
func (g *gater) InterceptAccept(network.ConnMultiaddrs) bool      { return true }

func (g *gater) InterceptSecured(dir network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	if g.isBanned(p) {
		return false
	}
	return dir == network.DirOutbound || g.peers == nil || g.peers() < g.maxPeers
}

func (g *gater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) { return true, 0 }
