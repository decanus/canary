package consensus

import (
	"math/big"
	"math/rand"
	"testing"
)

// Strong pseudoprimes to base 2 that the Lucas half must reject.
var spsp2 = []int64{2047, 3277, 4033, 4681, 8321, 15841, 29341, 42799, 49141, 52633, 65281,
	74665, 80581, 85489, 88357, 90751, 1373653, 25326001, 3215031751}

func TestIsPrimeStrongPseudoprimes(t *testing.T) {
	for _, n := range spsp2 {
		bn := big.NewInt(n)
		if !strongMRBase2(bn) {
			t.Fatalf("%d should pass MR base 2", n)
		}
		if IsPrime(bn) {
			t.Errorf("IsPrime(%d) = true", n)
		}
	}
}

func TestIsPrimeSmall(t *testing.T) {
	sieve := make([]bool, 20000)
	for i := 2; i < len(sieve); i++ {
		sieve[i] = true
	}
	for i := 2; i*i < len(sieve); i++ {
		if sieve[i] {
			for j := i * i; j < len(sieve); j += i {
				sieve[j] = false
			}
		}
	}
	for i := range sieve {
		if got := IsPrime(big.NewInt(int64(i))); got != sieve[i] {
			t.Errorf("IsPrime(%d) = %v", i, got)
		}
	}
}

// IsPrime and Go's BPSW use different Lucas tests, but no BPSW counterexample is known, so they
// must agree on every input we can generate.
func TestIsPrimeMatchesProbablyPrime(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		bits := 2 + rng.Intn(255)
		n := new(big.Int).Rand(rng, new(big.Int).Lsh(bigOne, uint(bits)))
		n.SetBit(n, 0, 1)
		if got, want := IsPrime(n), n.ProbablyPrime(0); got != want {
			t.Fatalf("IsPrime(%s) = %v, ProbablyPrime = %v", n, got, want)
		}
	}
	// Products of two primes (hard composites) and primes ≡ 3 mod 4 from NextPrime3Mod4.
	for i := 0; i < 500; i++ {
		x := new(big.Int).Rand(rng, new(big.Int).Lsh(bigOne, 64))
		p := NextPrime3Mod4(x)
		if !p.ProbablyPrime(20) || new(big.Int).Mod(p, bigFour).Int64() != 3 {
			t.Fatalf("NextPrime3Mod4(%s) = %s", x, p)
		}
		q := NextPrime3Mod4(new(big.Int).Add(p, bigOne))
		if IsPrime(new(big.Int).Mul(p, q)) {
			t.Fatalf("IsPrime(%s*%s) = true", p, q)
		}
	}
}

func TestJacobi(t *testing.T) {
	for n := int64(1); n < 200; n += 2 {
		for a := int64(-50); a < 200; a++ {
			got := jacobi(big.NewInt(a), big.NewInt(n))
			if want := big.Jacobi(new(big.Int).Mod(big.NewInt(a), big.NewInt(n)), big.NewInt(n)); got != want {
				t.Fatalf("jacobi(%d, %d) = %d, want %d", a, n, got, want)
			}
		}
	}
}
