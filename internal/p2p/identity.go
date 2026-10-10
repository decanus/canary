package p2p

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
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

// loadPeers reads the saved peer addresses; a missing file is empty.
func loadPeers(dir string) ([]peer.AddrInfo, error) {
	data, err := os.ReadFile(filepath.Join(dir, peersFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var addrs []string
	if err := json.Unmarshal(data, &addrs); err != nil {
		return nil, err
	}
	return parsePeers(addrs)
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
	byID := map[peer.ID]*peer.AddrInfo{}
	var order []peer.ID
	for _, s := range addrs {
		info, err := peer.AddrInfoFromString(s)
		if err != nil {
			return nil, err
		}
		if cur, ok := byID[info.ID]; ok {
			cur.Addrs = append(cur.Addrs, info.Addrs...)
			continue
		}
		byID[info.ID] = info
		order = append(order, info.ID)
	}
	out := make([]peer.AddrInfo, len(order))
	for i, id := range order {
		out[i] = *byID[id]
	}
	return out, nil
}
