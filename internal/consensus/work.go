package consensus

import "math/big"

// Work returns the work of a block: isqrt(n).
func Work(h *Header) *big.Int {
	return new(big.Int).Sqrt(h.N)
}
