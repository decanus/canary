package miner

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"sync"

	"github.com/decanus/canary/internal/consensus"
)

// partitions is the number of random-walk partitions R (SPEC.md §6.2).
const partitions = 32

// dp is a distinguished point X = α·G + β·P.
type dp struct {
	x, y        *big.Int
	alpha, beta *big.Int
}

type step struct {
	pt   *consensus.Point
	c, d *big.Int
}

// RhoStats reports the work a solve did.
type RhoStats struct {
	DistinguishedPoints int
}

// SolveDLP finds k with k·G = P on curve c, where G has prime order n, using parallel Pollard rho
// with distinguished points. It returns ctx.Err() if ctx is cancelled first.
func SolveDLP(ctx context.Context, c *consensus.Curve, P *consensus.Point, n *big.Int, threads int) (*big.Int, RhoStats, error) {
	if threads < 1 {
		threads = 1
	}
	if P == nil {
		return nil, RhoStats{}, errors.New("puzzle point is the identity")
	}
	table := make([]step, partitions)
	for j := range table {
		cj, dj := randBelow(n), randBelow(n)
		table[j] = step{pt: c.Add(c.Mul(cj, c.G), c.Mul(dj, P)), c: cj, d: dj}
	}
	dpBits := max(2, n.BitLen()/4-3)

	ctx, cancel := context.WithCancel(ctx)
	dps := make(chan dp, 64*threads)
	var wg sync.WaitGroup
	// Workers may be blocked sending a DP, so cancel before waiting for them.
	defer func() {
		cancel()
		wg.Wait()
	}()
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			walk(ctx, c, P, n, table, dpBits, dps)
		}()
	}

	seen := make(map[string]dp)
	for {
		select {
		case <-ctx.Done():
			return nil, RhoStats{DistinguishedPoints: len(seen)}, ctx.Err()
		case d := <-dps:
			key := string(d.x.Bytes())
			prev, ok := seen[key]
			if !ok {
				seen[key] = d
				continue
			}
			k := solveCollision(n, prev, d)
			if k != nil && c.Mul(k, c.G).Equal(P) {
				return k, RhoStats{DistinguishedPoints: len(seen)}, nil
			}
		}
	}
}

// walk runs random walks from fresh random starts, sending each distinguished point to out.
func walk(ctx context.Context, c *consensus.Curve, P *consensus.Point, n *big.Int, table []step, dpBits int, out chan<- dp) {
	maxLen := 20 << dpBits
	var mask big.Int
	mask.Lsh(one, uint(dpBits)).Sub(&mask, one)
	var t, idx big.Int
	r := big.NewInt(partitions - 1)
	for ctx.Err() == nil {
		alpha, beta := randBelow(n), randBelow(n)
		X := c.Add(c.Mul(alpha, c.G), c.Mul(beta, P))
	steps:
		for i := 0; i < maxLen && X != nil; i++ {
			if i&1023 == 0 && ctx.Err() != nil {
				return
			}
			if t.And(X.X, &mask).Sign() == 0 {
				// alpha and beta are fresh per walk and this walk ends here, so sending them
				// without copying is safe.
				select {
				case out <- dp{x: X.X, y: X.Y, alpha: alpha, beta: beta}:
				case <-ctx.Done():
				}
				break steps
			}
			s := table[idx.And(X.X, r).Int64()]
			X = c.Add(X, s.pt)
			alpha.Add(alpha, s.c)
			if alpha.Cmp(n) >= 0 {
				alpha.Sub(alpha, n)
			}
			beta.Add(beta, s.d)
			if beta.Cmp(n) >= 0 {
				beta.Sub(beta, n)
			}
		}
	}
}

// solveCollision recovers k from two walks reaching the same x: equal y means
// α₁ + β₁k = α₂ + β₂k, negated y means α₁ + β₁k = −(α₂ + β₂k). It returns nil if the
// denominator vanishes mod n.
func solveCollision(n *big.Int, d1, d2 dp) *big.Int {
	num, den := new(big.Int), new(big.Int)
	if d1.y.Cmp(d2.y) == 0 {
		num.Sub(d1.alpha, d2.alpha)
		den.Sub(d2.beta, d1.beta)
	} else {
		num.Add(d1.alpha, d2.alpha).Neg(num)
		den.Add(d1.beta, d2.beta)
	}
	den.Mod(den, n)
	if den.Sign() == 0 {
		return nil
	}
	den.ModInverse(den, n)
	return num.Mul(num, den).Mod(num, n)
}

func randBelow(n *big.Int) *big.Int {
	k, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return k
}
