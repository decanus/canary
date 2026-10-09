package consensus

import "math/big"

var smallPrimes = []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47}

var (
	bigOne   = big.NewInt(1)
	bigTwo   = big.NewInt(2)
	bigThree = big.NewInt(3)
	bigFour  = big.NewInt(4)
)

// IsPrime is the consensus-defined Baillie–PSW test (SPEC.md §3.3): trial division by the primes
// up to 47, a strong Miller–Rabin test to base 2, a perfect-square check, and a strong Lucas test
// with Selfridge method A parameters. It must match reference/canary.py:is_prime exactly, so it
// deliberately does not use big.Int.ProbablyPrime (whose Lucas test differs).
func IsPrime(n *big.Int) bool {
	if n.Cmp(bigTwo) < 0 {
		return false
	}
	var q, r big.Int
	for _, sp := range smallPrimes {
		q.SetInt64(sp)
		if r.Mod(n, &q).Sign() == 0 {
			return n.Cmp(&q) == 0
		}
	}
	if !strongMRBase2(n) {
		return false
	}
	if isSquare(n) {
		return false
	}
	return strongLucas(n)
}

func strongMRBase2(n *big.Int) bool {
	nm1 := new(big.Int).Sub(n, bigOne)
	s := nm1.TrailingZeroBits()
	d := new(big.Int).Rsh(nm1, s)
	x := new(big.Int).Exp(bigTwo, d, n)
	if x.Cmp(bigOne) == 0 || x.Cmp(nm1) == 0 {
		return true
	}
	for i := uint(1); i < s; i++ {
		x.Mul(x, x).Mod(x, n)
		if x.Cmp(nm1) == 0 {
			return true
		}
	}
	return false
}

func isSquare(n *big.Int) bool {
	r := new(big.Int).Sqrt(n)
	return r.Mul(r, r).Cmp(n) == 0
}

// jacobi computes the Jacobi symbol (a/n) for odd n > 0, as reference _jacobi.
func jacobi(a, n *big.Int) int {
	x := new(big.Int).Mod(a, n)
	y := new(big.Int).Set(n)
	result := 1
	for x.Sign() != 0 {
		tz := x.TrailingZeroBits()
		x.Rsh(x, tz)
		if tz%2 == 1 {
			// y mod 8 is 3 or 5 exactly when bits 1 and 2 differ (y is odd).
			if y.Bit(1) != y.Bit(2) {
				result = -result
			}
		}
		x, y = y, x
		if x.Bit(0) == 1 && x.Bit(1) == 1 && y.Bit(0) == 1 && y.Bit(1) == 1 {
			result = -result
		}
		x.Mod(x, y)
	}
	if y.Cmp(bigOne) == 0 {
		return result
	}
	return 0
}

// strongLucas is the strong Lucas probable-prime test with Selfridge method A parameters.
// n is odd, > 47 and not a perfect square.
func strongLucas(n *big.Int) bool {
	// First D in 5, -7, 9, -11, ... with jacobi(D, n) = -1.
	D := int64(5)
	Dbig := new(big.Int)
	for {
		Dbig.SetInt64(D)
		j := jacobi(Dbig, n)
		if j == -1 {
			break
		}
		if j == 0 && new(big.Int).Abs(Dbig).Cmp(n) != 0 {
			return false
		}
		if D > 0 {
			D = -D - 2
		} else {
			D = -D + 2
		}
	}
	// P = 1 throughout, so the P·U and P·V products below are just U and V.
	Q := big.NewInt((1 - D) / 4) // exact: D ≡ 1 (mod 4) for every candidate

	np1 := new(big.Int).Add(n, bigOne)
	s := np1.TrailingZeroBits()
	d := new(big.Int).Rsh(np1, s)

	// half returns x/2 mod n. Reducing x first gives the same residue as the reference, which
	// halves the unreduced (possibly negative) value.
	half := func(x *big.Int) *big.Int {
		x.Mod(x, n)
		if x.Bit(0) == 1 {
			x.Add(x, n)
		}
		return x.Rsh(x, 1)
	}

	U := big.NewInt(1)
	V := big.NewInt(1) // V_1 = P
	Qk := new(big.Int).Mod(Q, n)
	t1, t2 := new(big.Int), new(big.Int)
	for i := d.BitLen() - 2; i >= 0; i-- {
		// U, V = U*V, V*V - 2*Qk
		t1.Mul(U, V)
		U.Mod(t1, n)
		t1.Mul(V, V)
		t2.Lsh(Qk, 1)
		V.Mod(t1.Sub(t1, t2), n)
		Qk.Mul(Qk, Qk).Mod(Qk, n)
		if d.Bit(i) == 1 {
			// U, V = (P*U + V)/2, (D*U + P*V)/2
			nu := t1.Add(U, V)
			nv := t2.Mul(Dbig, U)
			nv.Add(nv, V)
			U.Set(half(nu))
			V.Set(half(nv))
			Qk.Mul(Qk, Q).Mod(Qk, n)
		}
	}
	if U.Sign() == 0 || V.Sign() == 0 {
		return true
	}
	for r := uint(1); r < s; r++ {
		t1.Mul(V, V)
		t2.Lsh(Qk, 1)
		V.Mod(t1.Sub(t1, t2), n)
		Qk.Mul(Qk, Qk).Mod(Qk, n)
		if V.Sign() == 0 {
			return true
		}
	}
	return false
}

// NextPrime3Mod4 returns the smallest y >= x with y ≡ 3 (mod 4) and IsPrime(y).
func NextPrime3Mod4(x *big.Int) *big.Int {
	off := new(big.Int).Sub(bigThree, x)
	off.Mod(off, bigFour)
	y := new(big.Int).Add(x, off)
	for !IsPrime(y) {
		y.Add(y, bigFour)
	}
	return y
}
