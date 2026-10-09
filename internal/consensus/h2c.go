package consensus

import "math/big"

// HashToCurve maps msg to a point of E(a, b, p) by try-and-increment (SPEC.md §3.4).
// p must be a prime ≡ 3 (mod 4).
func HashToCurve(msg []byte, p, a, b *big.Int) *Point {
	c := &Curve{P: p, A: a, B: b}
	legendreExp := new(big.Int).Rsh(new(big.Int).Sub(p, bigOne), 1) // (p-1)/2
	sqrtExp := new(big.Int).Rsh(new(big.Int).Add(p, bigOne), 2)     // (p+1)/4
	t := new(big.Int)
	for i := uint32(0); ; i++ {
		ib := u32le(i)
		h0 := H(msg, ib, []byte{0})
		h1 := H(msg, ib, []byte{1})
		x := intBE(append(h0[:], h1[:]...))
		x.Mod(x, p)
		r := c.rhs(x)
		if r.Sign() == 0 || t.Exp(r, legendreExp, p).Cmp(bigOne) != 0 {
			continue
		}
		y := new(big.Int).Exp(r, sqrtExp, p)
		h2 := H(msg, ib, []byte{2})
		if y.Bit(0) != uint(h2[0]&1) {
			y.Sub(p, y)
		}
		return &Point{X: x, Y: y}
	}
}
