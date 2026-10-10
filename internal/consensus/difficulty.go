package consensus

import (
	"math/big"
	"slices"
)

// ChainView is read access to the active chain below the block being validated.
// Header(i) must return the header at height i for 0 <= i < Len().
type ChainView interface {
	Len() int
	Header(i int) *Header
}

// Headers is a ChainView over a slice of headers ordered by height.
type Headers []*Header

func (hs Headers) Len() int             { return len(hs) }
func (hs Headers) Header(i int) *Header { return hs[i] }

// RetargetDelta returns round(log2((expected/actual)²)) clamped to ±maxStep, in integers only:
// the largest d with (expected/actual)^4 >= 2^(2d-1). expected and actual must be positive.
func RetargetDelta(expected, actual, maxStep int64) int64 {
	A := new(big.Int).Exp(big.NewInt(expected), bigFour, nil)
	B := new(big.Int).Exp(big.NewInt(actual), bigFour, nil)
	t := new(big.Int)
	for d := maxStep; d >= -maxStep; d-- {
		e := 2*d - 1
		var ok bool
		if e >= 0 {
			ok = A.Cmp(t.Lsh(B, uint(e))) >= 0
		} else {
			ok = t.Lsh(A, uint(-e)).Cmp(B) >= 0
		}
		if ok {
			return d
		}
	}
	return -maxStep
}

// NextBits returns the bit-size required for the block at height chain.Len() (SPEC.md §5.4).
func NextBits(p *Params, chain ChainView) uint32 {
	h := int64(chain.Len())
	if h == 0 {
		return p.GenesisBits
	}
	prev := chain.Header(int(h - 1)).Bits
	if h%p.Epoch != 0 {
		return prev
	}
	s := max(h-1-p.Epoch, 0)
	actual := int64(chain.Header(int(h-1)).Time) - int64(chain.Header(int(s)).Time)
	expected := (h - 1 - s) * p.Tau
	actual = max(expected/4, min(actual, 4*expected))
	actual = max(actual, 1)
	d := RetargetDelta(expected, actual, p.MaxStep)
	next := int64(prev) + d
	return uint32(max(int64(p.MinBits), min(int64(p.MaxBits), next)))
}

// MedianTimePast returns the median (sorted[len/2]) of the last min(MTPWindow, Len()) block
// times. The chain must be non-empty.
func MedianTimePast(p *Params, chain ChainView) int64 {
	h := chain.Len()
	w := min(int(p.MTPWindow), h)
	times := make([]int64, w)
	for i := range times {
		times[i] = int64(chain.Header(h - w + i).Time)
	}
	slices.Sort(times)
	return times[len(times)/2]
}
