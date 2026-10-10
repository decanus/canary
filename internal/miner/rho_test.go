package miner

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/decanus/canary/internal/consensus"
)

func TestSolveDLP(t *testing.T) {
	ctx := context.Background()
	p := consensus.Prototype
	for _, bits := range []uint32{24, 32} {
		_, c, n, err := FindCurve(ctx, &p, [32]byte{byte(bits)}, bits)
		if err != nil {
			t.Fatal(err)
		}
		k := randBelow(n)
		P := c.Mul(k, c.G)
		start := time.Now()
		got, stats, err := SolveDLP(ctx, c, P, n, 4)
		if err != nil {
			t.Fatal(err)
		}
		if got.Cmp(k) != 0 {
			t.Fatalf("bits=%d: got k=%s, want %s", bits, got, k)
		}
		t.Logf("bits=%d solved in %v (%d DPs)", bits, time.Since(start), stats.DistinguishedPoints)
	}
}

func TestSolveDLPCancel(t *testing.T) {
	p := consensus.Prototype
	_, c, n, err := FindCurve(context.Background(), &p, [32]byte{}, 48)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := SolveDLP(ctx, c, c.Mul(big.NewInt(12345), c.G), n, 2); err == nil {
		t.Fatal("48-bit solve finished in 50ms; expected cancellation")
	}
}
