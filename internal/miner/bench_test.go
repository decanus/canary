package miner

import (
	"context"
	"testing"

	"github.com/decanus/canary/internal/consensus"
)

// BenchmarkSolve36 solves a fresh 36-bit puzzle per iteration on 8 threads.
func BenchmarkSolve36(b *testing.B) {
	p := consensus.Prototype
	_, c, n, err := FindCurve(context.Background(), &p, [32]byte{1}, 36)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		P := c.Mul(randBelow(n), c.G)
		if _, _, err := SolveDLP(context.Background(), c, P, n, 8); err != nil {
			b.Fatal(err)
		}
	}
}
