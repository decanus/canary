package consensus

import "math/big"

// Point is an affine point on a curve. The identity O is represented by a nil *Point.
type Point struct {
	X, Y *big.Int
}

// Equal reports whether p and q are the same point (both may be the identity).
func (p *Point) Equal(q *Point) bool {
	if p == nil || q == nil {
		return p == nil && q == nil
	}
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}

// Curve is E(A, B, P): y² = x³ + A·x + B over F_P, with base point G.
// G is nil when the derived curve is invalid (SPEC.md §5.1).
type Curve struct {
	P, A, B *big.Int
	G       *Point
}

// OnCurve reports whether pt lies on c.
func (c *Curve) OnCurve(pt *Point) bool {
	if pt == nil {
		return true
	}
	lhs := new(big.Int).Mul(pt.Y, pt.Y)
	rhs := c.rhs(pt.X)
	return lhs.Sub(lhs, rhs).Mod(lhs, c.P).Sign() == 0
}

// rhs returns (x³ + A·x + B) mod P.
func (c *Curve) rhs(x *big.Int) *big.Int {
	r := new(big.Int).Mul(x, x)
	r.Add(r, c.A)
	r.Mul(r, x)
	r.Add(r, c.B)
	return r.Mod(r, c.P)
}

// Neg returns -pt.
func (c *Curve) Neg(pt *Point) *Point {
	if pt == nil {
		return nil
	}
	y := new(big.Int).Neg(pt.Y)
	return &Point{X: new(big.Int).Set(pt.X), Y: y.Mod(y, c.P)}
}

// Add returns p1 + p2 using standard affine formulas.
func (c *Curve) Add(p1, p2 *Point) *Point {
	if p1 == nil {
		return p2
	}
	if p2 == nil {
		return p1
	}
	p := c.P
	lam := new(big.Int)
	t := new(big.Int)
	if p1.X.Cmp(p2.X) == 0 {
		if t.Add(p1.Y, p2.Y).Mod(t, p).Sign() == 0 {
			return nil
		}
		// lam = (3x² + A) / 2y
		lam.Mul(p1.X, p1.X).Mul(lam, bigThree).Add(lam, c.A)
		t.Lsh(p1.Y, 1).Mod(t, p)
	} else {
		// lam = (y2 - y1) / (x2 - x1)
		lam.Sub(p2.Y, p1.Y)
		t.Sub(p2.X, p1.X).Mod(t, p)
	}
	if t.ModInverse(t, p) == nil {
		// Unreachable for prime p and valid inputs; treat as identity rather than panic.
		return nil
	}
	lam.Mul(lam, t).Mod(lam, p)
	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, p1.X).Sub(x3, p2.X).Mod(x3, p)
	y3 := new(big.Int).Sub(p1.X, x3)
	y3.Mul(y3, lam).Sub(y3, p1.Y).Mod(y3, p)
	return &Point{X: x3, Y: y3}
}

// Mul returns k·pt for k >= 0 by double-and-add.
func (c *Curve) Mul(k *big.Int, pt *Point) *Point {
	var r *Point
	if k.Sign() < 0 {
		k = new(big.Int).Neg(k)
		pt = c.Neg(pt)
	}
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			r = c.Add(r, pt)
		}
		pt = c.Add(pt, pt)
	}
	return r
}
