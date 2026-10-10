package wallet

import (
	"math/big"
	"testing"

	"github.com/decanus/canary/internal/consensus"
)

func BenchmarkSign(b *testing.B) {
	k, _ := Generate()
	tx := &consensus.Transfer{Amount: big.NewInt(1), Fee: big.NewInt(1)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.SignTransfer(tx, [32]byte{})
	}
}

func BenchmarkVerify(b *testing.B) {
	k, _ := Generate()
	tx := &consensus.Transfer{Amount: big.NewInt(1), Fee: big.NewInt(1)}
	k.SignTransfer(tx, [32]byte{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !tx.VerifySignature([32]byte{}) {
			b.Fatal("bad")
		}
	}
}
