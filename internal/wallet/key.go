// Package wallet holds SLH-DSA-SHA2-128s keys and signs transfers. It is not consensus code:
// signatures it makes are checked by consensus like any other.
package wallet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/slhdsa"

	"github.com/decanus/canary/internal/consensus"
)

// Key is an SLH-DSA-SHA2-128s key pair.
type Key struct {
	priv slhdsa.PrivateKey
	pub  []byte
}

// seedSize is n for SHA2-128s; keys are generated from three n-byte seeds.
const seedSize = 16

// Generate creates a key from the system random source.
func Generate() (*Key, error) {
	seeds := make([]byte, 3*seedSize)
	if _, err := rand.Read(seeds); err != nil {
		return nil, err
	}
	return FromSeeds(seeds[:seedSize], seeds[seedSize:2*seedSize], seeds[2*seedSize:])
}

// FromSeeds derives a key deterministically (FIPS 205 slh_keygen_internal).
func FromSeeds(skSeed, skPrf, pkSeed []byte) (*Key, error) {
	if len(skSeed) != seedSize || len(skPrf) != seedSize || len(pkSeed) != seedSize {
		return nil, errors.New("wallet: seeds must be 16 bytes each")
	}
	// GenerateKey reads SK.seed, SK.prf, PK.seed in that order.
	r := bytes.NewReader(append(append(append([]byte{}, skSeed...), skPrf...), pkSeed...))
	pub, priv, err := slhdsa.GenerateKey(r, slhdsa.SHA2_128s)
	if err != nil {
		return nil, err
	}
	pb, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv, pub: pb}, nil
}

// PublicKey returns the 32-byte public key.
func (k *Key) PublicKey() []byte { return bytes.Clone(k.pub) }

// Address returns the key's account address.
func (k *Key) Address() consensus.Address {
	return consensus.AddressOf(consensus.SchemeSLHDSA, k.pub)
}

// SignTransfer fills in t's scheme, public key and signature for the chain with genesisHash.
// Signing takes about a second.
func (k *Key) SignTransfer(t *consensus.Transfer, genesisHash [32]byte) error {
	t.Scheme, t.PubKey = consensus.SchemeSLHDSA, k.PublicKey()
	d := t.Digest(genesisHash)
	sig, err := slhdsa.SignRandomized(&k.priv, rand.Reader, slhdsa.NewMessage(d[:]), nil)
	if err != nil {
		return err
	}
	t.Sig = sig
	return nil
}

// Save writes the private key as hex to path, readable only by the owner.
func (k *Key) Save(path string) error {
	b, err := k.priv.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("wallet: %s already exists", path)
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(b)+"\n"), 0o600)
}

// Load reads a key written by Save.
func Load(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("wallet: %s: %w", path, err)
	}
	k := &Key{priv: slhdsa.PrivateKey{ID: slhdsa.SHA2_128s}}
	if err := k.priv.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("wallet: %s: %w", path, err)
	}
	pub := k.priv.PublicKey()
	if k.pub, err = pub.MarshalBinary(); err != nil {
		return nil, err
	}
	return k, nil
}

// ParseAddress decodes a 64-character hex address.
func ParseAddress(s string) (consensus.Address, error) {
	var a consensus.Address
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(a) {
		return a, fmt.Errorf("address must be 64 hex characters")
	}
	copy(a[:], b)
	return a, nil
}
