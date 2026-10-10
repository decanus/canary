package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
)

// Account is a balance and the number of transfers sent.
type Account struct {
	Balance *big.Int
	Nonce   uint64
}

func (a Account) isZero() bool { return a.Balance.Sign() == 0 && a.Nonce == 0 }

// State maps addresses to accounts; an absent address is the zero account. A State is treated as
// immutable once built: ApplyBlock returns a new one.
type State map[Address]Account

// Get returns the account at addr (zero if absent).
func (s State) Get(addr Address) Account {
	if a, ok := s[addr]; ok {
		return a
	}
	return Account{Balance: new(big.Int)}
}

// Set stores a at addr, removing the entry if a is the zero account. Only use it on a State you
// own (for example a Clone): published States are shared and must not change.
func (s State) Set(addr Address, a Account) {
	if a.isZero() {
		delete(s, addr)
	} else {
		s[addr] = a
	}
}

// Clone returns a shallow copy (accounts are replaced, never mutated).
func (s State) Clone() State {
	out := make(State, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// Supply returns the sum of all balances.
func (s State) Supply() *big.Int {
	sum := new(big.Int)
	for _, a := range s {
		sum.Add(sum, a.Balance)
	}
	return sum
}

// Reward is the block reward: the block's work, isqrt(n) (SPEC.md §5.8).
func Reward(h *Header) *big.Int { return Work(h) }

// ApplyBlock applies a block's transactions to parent (SPEC.md §5.7) and returns the new state
// and the addresses whose accounts changed. parent is not modified.
func ApplyBlock(parent State, cb *Coinbase, transfers []*Transfer, reward *big.Int, genesisHash [32]byte) (State, []Address, error) {
	st := parent.Clone()
	var touched []Address
	fees := new(big.Int)
	for _, t := range transfers {
		if !t.VerifySignature(genesisHash) {
			return nil, nil, errors.New("bad signature")
		}
		from := t.Sender()
		acc := st.Get(from)
		if t.Nonce != acc.Nonce {
			return nil, nil, errors.New("bad nonce")
		}
		cost := new(big.Int).Add(t.Amount, t.Fee)
		if cost.Cmp(acc.Balance) > 0 {
			return nil, nil, errors.New("insufficient balance")
		}
		if acc.Nonce == ^uint64(0) {
			return nil, nil, errors.New("nonce overflow")
		}
		st.Set(from, Account{Balance: new(big.Int).Sub(acc.Balance, cost), Nonce: acc.Nonce + 1})
		if err := credit(st, t.To, t.Amount); err != nil {
			return nil, nil, err
		}
		fees.Add(fees, t.Fee)
		touched = append(touched, from, t.To)
	}
	if want := new(big.Int).Add(reward, fees); cb.Amount.Cmp(want) != 0 {
		return nil, nil, errors.New("coinbase amount != reward + fees")
	}
	if err := credit(st, cb.To, cb.Amount); err != nil {
		return nil, nil, err
	}
	return st, append(touched, cb.To), nil
}

func credit(st State, to Address, amount *big.Int) error {
	acc := st.Get(to)
	bal := new(big.Int).Add(acc.Balance, amount)
	if bal.Cmp(U128Max) > 0 {
		return errors.New("balance overflow")
	}
	st.Set(to, Account{Balance: bal, Nonce: acc.Nonce})
	return nil
}

// StateRoot is the root of the compact sparse Merkle tree over the state (SPEC.md §5.7).
func StateRoot(s State) [32]byte {
	addrs := make([]Address, 0, len(s))
	for a := range s {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(x, y Address) int { return bytes.Compare(x[:], y[:]) })
	return smtRoot(s, addrs, 0)
}

// smtRoot hashes sorted addresses that agree on their first depth bits.
func smtRoot(s State, addrs []Address, depth int) [32]byte {
	switch len(addrs) {
	case 0:
		return [32]byte{}
	case 1:
		a := s[addrs[0]]
		var bal [16]byte
		a.Balance.FillBytes(bal[:])
		slices.Reverse(bal[:])
		return H(Tag("leaf"), addrs[0][:], bal[:], binary.LittleEndian.AppendUint64(nil, a.Nonce))
	}
	// Sorted order puts every address with bit depth = 0 before those with bit depth = 1.
	split, _ := slices.BinarySearchFunc(addrs, 1, func(a Address, _ int) int {
		if addrBit(a, depth) == 0 {
			return -1
		}
		return 1
	})
	l := smtRoot(s, addrs[:split], depth+1)
	r := smtRoot(s, addrs[split:], depth+1)
	return H(Tag("node"), l[:], r[:])
}

func addrBit(a Address, i int) int {
	return int(a[i/8]>>(7-i%8)) & 1
}
