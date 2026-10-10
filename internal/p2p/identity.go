package p2p

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	keyFile   = "node.key"
	peersFile = "peers.json"
)

// loadIdentity returns the node's persistent libp2p key from dir, creating it if needed.
// SPEC: peer identities are Ed25519 (go-libp2p has no post-quantum key type). They are not a
// trust boundary: every block is validated regardless of sender (SPEC.md "Cryptographic
// assumptions").
func loadIdentity(dir string) (crypto.PrivKey, error) {
	path := filepath.Join(dir, keyFile)
	data, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	sk, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		return nil, err
	}
	data, err = crypto.MarshalPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return sk, os.WriteFile(path, data, 0o600)
}

// loadPeers reads the saved peer addresses, skipping (and returning) entries that do not parse;
// a missing file is empty.
func loadPeers(dir string) ([]peer.AddrInfo, []error, error) {
	data, err := os.ReadFile(filepath.Join(dir, peersFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var addrs []string
	if err := json.Unmarshal(data, &addrs); err != nil {
		return nil, nil, err
	}
	var good []ma.Multiaddr
	var bad []error
	for _, s := range addrs {
		if a, err := parseP2pAddr(s); err != nil {
			bad = append(bad, err)
		} else {
			good = append(good, a)
		}
	}
	infos, err := peer.AddrInfosFromP2pAddrs(good...)
	return infos, bad, err
}

func savePeers(dir string, infos []peer.AddrInfo) error {
	var addrs []string
	for _, info := range infos {
		full, err := peer.AddrInfoToP2pAddrs(&info)
		if err != nil {
			continue
		}
		for _, a := range full {
			addrs = append(addrs, a.String())
		}
	}
	data, err := json.MarshalIndent(addrs, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, peersFile), append(data, '\n'), 0o644)
}

// parsePeers parses multiaddrs ending in /p2p/<peer id>, merging addresses of the same peer.
func parsePeers(addrs []string) ([]peer.AddrInfo, error) {
	var mas []ma.Multiaddr
	for _, s := range addrs {
		a, err := parseP2pAddr(s)
		if err != nil {
			return nil, err
		}
		mas = append(mas, a)
	}
	return peer.AddrInfosFromP2pAddrs(mas...)
}

func parseP2pAddr(s string) (ma.Multiaddr, error) {
	a, err := ma.NewMultiaddr(s)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", s, err)
	}
	if _, err := peer.AddrInfoFromP2pAddr(a); err != nil {
		return nil, fmt.Errorf("%q: %w", s, err)
	}
	return a, nil
}
