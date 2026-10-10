// Package miner finds valid curves and solves block puzzles. Nothing here is consensus: a block is
// valid iff consensus.ValidateBlock accepts it, however it was found.
package miner

import (
	"context"
	"errors"
	"math/big"

	"github.com/decanus/canary/internal/consensus"
)

var (
	one = big.NewInt(1)
)

// ErrNoCurve is returned when no curve_ctr below MaxCurveCtr yields a valid curve.
var ErrNoCurve = errors.New("no valid curve found")

// FindCurve returns the first curve_ctr whose curve passes consensus.CheckCurve, with the curve
// and its prime order n.
//
// Any correct order search gives the same first ctr as the reference: if a curve passes, G has
// prime order n ≈ p, the Hasse interval (width 4√p) holds exactly one multiple of n, and so every
// m in the interval with m·G = O equals n. The 2-torsion filter only skips curves of even order.
func FindCurve(ctx context.Context, p *consensus.Params, prevHash [32]byte, bits uint32) (uint32, *consensus.Curve, *big.Int, error) {
	for ctr := uint32(0); ctr < p.MaxCurveCtr; ctr++ {
		if ctr%16 == 0 && ctx.Err() != nil {
			return 0, nil, nil, ctx.Err()
		}
		c := consensus.DeriveCurve(prevHash, bits, ctr)
		if c.G == nil || has2Torsion(c) {
			continue
		}
		n := orderInHasse(c)
		if n == nil {
			continue
		}
		if consensus.CheckCurve(c, n, bits) == nil {
			return ctr, c, n, nil
		}
	}
	return 0, nil, nil, ErrNoCurve
}

// has2Torsion reports whether f = x³ + ax + b has a root in F_p, i.e. gcd(x^p − x, f) ≠ 1.
// A root is a point of order 2, so #E is even and cannot be a large prime.
func has2Torsion(c *consensus.Curve) bool {
	f := poly{c.B, c.A, big.NewInt(0), big.NewInt(1)}
	xp := polyPowXMod(c, c.P)
	g := xp.sub(poly{big.NewInt(0), big.NewInt(1)}, c.P)
	if g.degree() < 0 {
		return true // f divides x^p − x: all three roots are in F_p
	}
	return polyGCD(f, g, c.P).degree() >= 1
}

// poly is a polynomial over F_p, lowest coefficient first.
type poly []*big.Int

func (u poly) degree() int {
	for i := len(u) - 1; i >= 0; i-- {
		if u[i].Sign() != 0 {
			return i
		}
	}
	return -1
}

func (u poly) sub(v poly, p *big.Int) poly {
	out := make(poly, max(len(u), len(v)))
	for i := range out {
		out[i] = new(big.Int)
		if i < len(u) {
			out[i].Add(out[i], u[i])
		}
		if i < len(v) {
			out[i].Sub(out[i], v[i])
		}
		out[i].Mod(out[i], p)
	}
	return out
}

// polyMod returns u mod v over F_p; v must be nonzero.
func polyMod(u, v poly, p *big.Int) poly {
	r := make(poly, len(u))
	for i := range u {
		r[i] = new(big.Int).Set(u[i])
	}
	dv := v.degree()
	inv := new(big.Int).ModInverse(v[dv], p)
	t := new(big.Int)
	for dr := r.degree(); dr >= dv; dr = r.degree() {
		coef := t.Mul(r[dr], inv)
		coef.Mod(coef, p)
		shift := dr - dv
		for i := 0; i <= dv; i++ {
			s := new(big.Int).Mul(coef, v[i])
			r[shift+i].Sub(r[shift+i], s).Mod(r[shift+i], p)
		}
	}
	return r
}

func polyGCD(a, b poly, p *big.Int) poly {
	for b.degree() >= 0 {
		a, b = b, polyMod(a, b, p)
	}
	return a
}

// polyPowXMod computes x^e mod (x³ + ax + b) over F_p as a degree <= 2 polynomial.
func polyPowXMod(c *consensus.Curve, e *big.Int) poly {
	p := c.P
	mul := func(u, v poly) poly {
		var r [5]*big.Int
		for i := range r {
			r[i] = new(big.Int)
		}
		t := new(big.Int)
		for i := 0; i < 3; i++ {
			for j := 0; j < 3; j++ {
				r[i+j].Add(r[i+j], t.Mul(u[i], v[j]))
			}
		}
		// Reduce with x³ = −ax − b, from the top degree down.
		for d := 4; d >= 3; d-- {
			r[d].Mod(r[d], p)
			r[d-2].Sub(r[d-2], t.Mul(r[d], c.A))
			r[d-3].Sub(r[d-3], t.Mul(r[d], c.B))
		}
		return poly{r[0].Mod(r[0], p), r[1].Mod(r[1], p), r[2].Mod(r[2], p)}
	}
	res := poly{big.NewInt(1), new(big.Int), new(big.Int)}
	base := poly{new(big.Int), big.NewInt(1), new(big.Int)}
	for i := e.BitLen() - 1; i >= 0; i-- {
		res = mul(res, res)
		if e.Bit(i) == 1 {
			res = mul(res, base)
		}
	}
	return res
}

// orderInHasse finds m in [p+1−r, p+1+r], r = ⌊√(4p)⌋+1, with m·G = O by baby-step giant-step,
// or nil if G has small order or no such m exists.
func orderInHasse(c *consensus.Curve) *big.Int {
	r := new(big.Int).Sqrt(new(big.Int).Lsh(c.P, 2))
	r.Add(r, one)
	center := new(big.Int).Add(c.P, one)
	lo := new(big.Int).Sub(center, r)
	hi := new(big.Int).Add(center, r)

	// Baby steps j·G for j = 1..m, keyed by x. A giant point S = base·G that matches ±j·G gives
	// (base ∓ j)·G = O, so each giant step covers 2m+1 candidates.
	m := new(big.Int).Sqrt(new(big.Int).Sub(hi, lo)).Int64()/2 + 1
	type baby struct {
		j int64
		y *big.Int
	}
	table := make(map[string]baby, m)
	var pt *consensus.Point
	for j := int64(1); j <= m; j++ {
		pt = c.Add(pt, c.G)
		if pt == nil {
			return nil // order j: tiny, cannot be a valid n
		}
		table[string(pt.X.Bytes())] = baby{j, pt.Y}
	}
	stride := 2*m + 1
	step := c.Mul(big.NewInt(stride), c.G)
	base := new(big.Int).Add(lo, big.NewInt(m))
	S := c.Mul(base, c.G)
	cand := new(big.Int)
	for base.Cmp(new(big.Int).Add(hi, big.NewInt(m))) <= 0 {
		if S == nil {
			cand.Set(base)
		} else if b, ok := table[string(S.X.Bytes())]; ok {
			if S.Y.Cmp(b.y) == 0 {
				cand.Sub(base, big.NewInt(b.j)) // S = jG
			} else {
				cand.Add(base, big.NewInt(b.j)) // S = −jG
			}
		} else {
			cand.SetInt64(-1)
		}
		if cand.Sign() > 0 && cand.Cmp(lo) >= 0 && cand.Cmp(hi) <= 0 {
			return new(big.Int).Set(cand)
		}
		S = c.Add(S, step)
		base.Add(base, big.NewInt(stride))
	}
	return nil
}
