package consensus

import (
	"errors"
	"math/big"
)

// EmbeddingMin is the minimum embedding degree: p^j mod n != 1 for j = 1..EmbeddingMin.
const EmbeddingMin = 100

func curveSeed(prevHash [32]byte, bits, ctr uint32) []byte {
	seed := append([]byte{}, prevHash[:]...)
	seed = append(seed, u32le(bits)...)
	return append(seed, u32le(ctr)...)
}

// DeriveCurve derives the curve for (prevHash, bits, ctr) per SPEC.md §5.1. The returned curve has
// G == nil if it is invalid (a == 0, b == 0 or singular).
func DeriveCurve(prevHash [32]byte, bits, ctr uint32) *Curve {
	seed := curveSeed(prevHash, bits, ctr)
	// SPEC: bits < 3 can never pass validation (bits is checked against NextBits first, which is
	// >= MinBits). Clamp the shifts so the function is total instead of panicking.
	shift := uint(2)
	if bits >= 3 {
		shift = uint(bits)
	}
	N := new(big.Int).Lsh(bigOne, shift-1)
	mod := new(big.Int).Lsh(bigOne, shift-2)
	hp := H(Tag("p"), seed)
	x := intBE(hp[:])
	x.Mod(x, mod).Add(x, N)
	p := NextPrime3Mod4(x)

	ha := H(Tag("a"), seed)
	a := intBE(ha[:])
	a.Mod(a, p)
	hb := H(Tag("b"), seed)
	b := intBE(hb[:])
	b.Mod(b, p)

	c := &Curve{P: p, A: a, B: b}
	if singularOrExcluded(c) {
		return c
	}
	c.G = HashToCurve(append(Tag("G"), seed...), p, a, b)
	return c
}

// singularOrExcluded reports a == 0, b == 0 or 4a³ + 27b² ≡ 0 (mod p).
func singularOrExcluded(c *Curve) bool {
	if c.A.Sign() == 0 || c.B.Sign() == 0 {
		return true
	}
	d := new(big.Int).Exp(c.A, bigThree, nil)
	d.Mul(d, bigFour)
	t := new(big.Int).Mul(c.B, c.B)
	t.Mul(t, big.NewInt(27))
	d.Add(d, t)
	return d.Mod(d, c.P).Sign() == 0
}

// Curve validity errors (SPEC.md §5.2).
var (
	ErrCurveExcluded    = errors.New("singular or excluded curve")
	ErrOrderNotPrime    = errors.New("n not prime")
	ErrOrderBitLength   = errors.New("n has wrong bit length")
	ErrOrderHasse       = errors.New("n outside Hasse interval")
	ErrCurveAnomalous   = errors.New("anomalous curve")
	ErrOrderNotOrderOfG = errors.New("n*G != O")
	ErrEmbeddingDegree  = errors.New("embedding degree too small")
)

// CheckCurve returns nil if (c, n) passes every check of SPEC.md §5.2 for bit-size bits.
func CheckCurve(c *Curve, n *big.Int, bits uint32) error {
	if c.G == nil || singularOrExcluded(c) {
		return ErrCurveExcluded
	}
	if !IsPrime(n) {
		return ErrOrderNotPrime
	}
	if n.BitLen() != int(bits) {
		return ErrOrderBitLength
	}
	// (n - p - 1)² <= 4p
	t := new(big.Int).Sub(n, c.P)
	t.Sub(t, bigOne)
	t.Mul(t, t)
	if t.Cmp(new(big.Int).Lsh(c.P, 2)) > 0 {
		return ErrOrderHasse
	}
	if n.Cmp(c.P) == 0 {
		return ErrCurveAnomalous
	}
	if c.Mul(n, c.G) != nil {
		return ErrOrderNotOrderOfG
	}
	pm := new(big.Int).Mod(c.P, n)
	acc := big.NewInt(1)
	for j := 0; j < EmbeddingMin; j++ {
		acc.Mul(acc, pm).Mod(acc, n)
		if acc.Cmp(bigOne) == 0 {
			return ErrEmbeddingDegree
		}
	}
	return nil
}
