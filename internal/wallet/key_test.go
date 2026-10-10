package wallet

import (
	"math/big"
	"path/filepath"
	"testing"

	"github.com/decanus/canary/internal/consensus"
)

func TestSignVerifyAndSaveLoad(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	genesis := [32]byte{7}
	tx := &consensus.Transfer{To: consensus.Address{1}, Amount: big.NewInt(5), Fee: big.NewInt(1), Nonce: 3}
	if err := k.SignTransfer(tx, genesis); err != nil {
		t.Fatal(err)
	}
	if tx.Sender() != k.Address() || !tx.VerifySignature(genesis) {
		t.Fatal("signature does not verify for the key's address")
	}
	if tx.VerifySignature([32]byte{8}) {
		t.Fatal("signature verified for another chain")
	}
	tx.Amount = big.NewInt(6)
	if tx.VerifySignature(genesis) {
		t.Fatal("signature verified after the amount changed")
	}

	path := filepath.Join(t.TempDir(), "key")
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := k.Save(path); err == nil {
		t.Fatal("Save overwrote an existing key")
	}
	k2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Address() != k.Address() {
		t.Fatal("loaded key has a different address")
	}
}
