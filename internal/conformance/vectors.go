// Package conformance runs the consensus library against reference/test_vectors.json
// (SPEC.md §14).
package conformance

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/wallet"
)

// Vectors is the layout of test_vectors.json.
type Vectors struct {
	Profile   string           `json:"profile"`
	Params    consensus.Params `json:"params"`
	Primality []struct {
		N           *string `json:"n"`
		Prime       *bool   `json:"prime"`
		NextPrimeOf *string `json:"next_prime_3mod4_of"`
		Result      *string `json:"result"`
	} `json:"primality"`
	RetargetDelta []struct {
		Expected      int64 `json:"expected"`
		ActualClamped int64 `json:"actual_clamped"`
		Delta         int64 `json:"delta"`
	} `json:"retarget_delta"`
	Curves []struct {
		PrevHash string    `json:"prev_hash"`
		Bits     uint32    `json:"bits"`
		CurveCtr uint32    `json:"curve_ctr"`
		P        string    `json:"p"`
		A        string    `json:"a"`
		B        string    `json:"b"`
		G        *[]string `json:"G"`
		N        *string   `json:"n"`
		Valid    bool      `json:"valid"`
	} `json:"curves"`
	HashToCurve []struct {
		Msg string `json:"msg"`
		P   string `json:"p"`
		A   string `json:"a"`
		B   string `json:"b"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"hash_to_curve"`
	Keys []struct {
		Name    string `json:"name"`
		SKSeed  string `json:"sk_seed"`
		SKPrf   string `json:"sk_prf"`
		PKSeed  string `json:"pk_seed"`
		PubKey  string `json:"pubkey"`
		Address string `json:"address"`
	} `json:"keys"`
	StateRoots []struct {
		Accounts [][3]string `json:"accounts"` // address, balance, nonce
		Root     string      `json:"root"`
	} `json:"state_roots"`
	Transactions []TxVector `json:"transactions"`
	Chain        struct {
		CumulativeWork string                `json:"cumulative_work"`
		Supply         string                `json:"supply"`
		State          [][3]string           `json:"state"`
		Blocks         []chainjson.BlockJSON `json:"blocks"`
	} `json:"chain"`
	InvalidBlocks struct {
		Cases []struct {
			Name         string   `json:"name"`
			ParentHeight int      `json:"parent_height"`
			HeaderHex    string   `json:"header_hex"`
			Txs          []string `json:"txs"`
			Reason       string   `json:"reason"`
		} `json:"cases"`
	} `json:"invalid_blocks"`
}

// TxVector is one entry of the "transactions" section: a transfer or a coinbase.
type TxVector struct {
	GenesisHash    string `json:"genesis_hash"`
	Tx             string `json:"tx"`
	Sender         string `json:"sender"`
	To             string `json:"to"`
	Amount         string `json:"amount"`
	Fee            string `json:"fee"`
	Nonce          string `json:"nonce"`
	Digest         string `json:"digest"`
	ValidSignature bool   `json:"valid_signature"`
	Coinbase       bool   `json:"coinbase"`
	Height         uint32 `json:"height"`
	Extra          string `json:"extra"`
}

// Result is the outcome of one vector.
type Result struct {
	Section string
	Name    string
	Err     error // nil if the vector passed
}

// Load reads and parses a vectors file.
func Load(path string) (*Vectors, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Vectors
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Run checks every vector and returns one result per vector.
func Run(v *Vectors) []Result {
	var out []Result
	add := func(section, name string, err error) {
		out = append(out, Result{Section: section, Name: name, Err: err})
	}

	if err := v.Params.Validate(); err != nil {
		add("params", "load", err)
		return out
	}
	p := &v.Params

	for i, c := range v.Primality {
		name := fmt.Sprintf("#%d", i)
		switch {
		case c.N != nil && c.Prime != nil:
			name = "is_prime(" + *c.N + ")"
			n, err := parseInt(*c.N)
			if err == nil && consensus.IsPrime(n) != *c.Prime {
				err = fmt.Errorf("got %v, want %v", !*c.Prime, *c.Prime)
			}
			add("primality", name, err)
		case c.NextPrimeOf != nil && c.Result != nil:
			name = "next_prime_3mod4(" + *c.NextPrimeOf + ")"
			x, err := parseInt(*c.NextPrimeOf)
			if err == nil {
				err = wantInt(consensus.NextPrime3Mod4(x), *c.Result)
			}
			add("primality", name, err)
		default:
			add("primality", name, errors.New("unrecognised vector"))
		}
	}

	for _, c := range v.RetargetDelta {
		name := fmt.Sprintf("expected=%d actual=%d", c.Expected, c.ActualClamped)
		var err error
		if got := consensus.RetargetDelta(c.Expected, c.ActualClamped, p.MaxStep); got != c.Delta {
			err = fmt.Errorf("got %d, want %d", got, c.Delta)
		}
		add("retarget_delta", name, err)
	}

	for _, c := range v.Curves {
		name := fmt.Sprintf("bits=%d ctr=%d prev=%.8s…", c.Bits, c.CurveCtr, c.PrevHash)
		if c.Valid {
			name += " (valid)"
		}
		add("curves", name, checkCurveVector(c.PrevHash, c.Bits, c.CurveCtr, c.P, c.A, c.B, c.G, c.N, c.Valid))
	}

	for i, c := range v.HashToCurve {
		name := fmt.Sprintf("#%d msg=%.16s", i, c.Msg)
		add("hash_to_curve", name, checkH2C(c.Msg, c.P, c.A, c.B, c.X, c.Y))
	}

	for _, k := range v.Keys {
		add("keys", k.Name, checkKey(k.SKSeed, k.SKPrf, k.PKSeed, k.PubKey, k.Address))
	}
	for i, c := range v.StateRoots {
		add("state_roots", fmt.Sprintf("#%d (%d accounts)", i, len(c.Accounts)), checkStateRoot(c.Accounts, c.Root))
	}
	for i, c := range v.Transactions {
		add("transactions", fmt.Sprintf("#%d", i), checkTx(c))
	}

	blocks, err := chainjson.DecodeBlocks(v.Chain.Blocks)
	if err != nil {
		add("chain", "decode", err)
		return out
	}
	states, err := checkChain(p, v.Chain.Blocks, blocks, v.Chain.CumulativeWork, v.Chain.Supply, v.Chain.State)
	add("chain", fmt.Sprintf("replay %d blocks", len(blocks)), err)
	if err != nil {
		// The invalid cases are mutations built on this chain; with a broken replay they would
		// be rejected for the wrong reason and pass vacuously.
		add("invalid_blocks", "skipped", errors.New("chain replay failed"))
		return out
	}

	headers := make(consensus.Headers, len(blocks))
	for i, b := range blocks {
		headers[i] = b.Header
	}
	controlled := map[int]bool{}
	for _, c := range v.InvalidBlocks.Cases {
		ph := c.ParentHeight
		if ph < -1 || ph+1 >= len(blocks) {
			add("invalid_blocks", c.Name, fmt.Errorf("parent_height %d out of range", ph))
			continue
		}
		base, parent := headers[:ph+1], consensus.State{}
		if ph >= 0 {
			parent = states[ph]
		}
		// Control: the real next block is accepted on the same base, so each rejection below is
		// caused by its mutation.
		if !controlled[ph] {
			controlled[ph] = true
			_, _, err := consensus.ValidateBlock(p, base, parent, blocks[ph+1], nil)
			add("invalid_blocks", fmt.Sprintf("control at parent %d", ph), err)
		}
		add("invalid_blocks", c.Name, checkInvalid(p, base, parent, c.HeaderHex, c.Txs))
	}
	return out
}

func checkCurveVector(prevHex string, bits, ctr uint32, ps, as, bs string, g *[]string, ns *string, valid bool) error {
	prev, err := parseHash(prevHex)
	if err != nil {
		return err
	}
	c := consensus.DeriveCurve(prev, bits, ctr)
	if err := wantInt(c.P, ps); err != nil {
		return fmt.Errorf("p: %w", err)
	}
	if err := wantInt(c.A, as); err != nil {
		return fmt.Errorf("a: %w", err)
	}
	if err := wantInt(c.B, bs); err != nil {
		return fmt.Errorf("b: %w", err)
	}
	if g == nil {
		if c.G != nil {
			return errors.New("G: derived a point, want invalid curve")
		}
	} else {
		if c.G == nil {
			return errors.New("G: derived invalid curve, want a point")
		}
		if len(*g) != 2 {
			return errors.New("G: malformed vector")
		}
		if err := wantInt(c.G.X, (*g)[0]); err != nil {
			return fmt.Errorf("G.x: %w", err)
		}
		if err := wantInt(c.G.Y, (*g)[1]); err != nil {
			return fmt.Errorf("G.y: %w", err)
		}
		if !c.OnCurve(c.G) {
			return errors.New("G not on curve")
		}
	}
	if valid {
		if ns == nil {
			return errors.New("valid curve vector without n")
		}
		n, err := parseInt(*ns)
		if err != nil {
			return err
		}
		if err := consensus.CheckCurve(c, n, bits); err != nil {
			return fmt.Errorf("CheckCurve: %w", err)
		}
	}
	return nil
}

func checkH2C(msgHex, ps, as, bs, xs, ys string) error {
	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		return err
	}
	p, err1 := parseInt(ps)
	a, err2 := parseInt(as)
	b, err3 := parseInt(bs)
	if err := errors.Join(err1, err2, err3); err != nil {
		return err
	}
	pt := consensus.HashToCurve(msg, p, a, b)
	if err := wantInt(pt.X, xs); err != nil {
		return fmt.Errorf("x: %w", err)
	}
	if err := wantInt(pt.Y, ys); err != nil {
		return fmt.Errorf("y: %w", err)
	}
	return nil
}

// checkChain replays the vector chain and returns the state after each block.
func checkChain(p *consensus.Params, js []chainjson.BlockJSON, blocks []*consensus.Block, wantWork, wantSupply string, wantState [][3]string) ([]consensus.State, error) {
	for i, blk := range blocks {
		h := blk.Hash()
		if got := hex.EncodeToString(h[:]); got != js[i].Hash {
			return nil, fmt.Errorf("block %d hash %s, want %s", i, got, js[i].Hash)
		}
	}
	chain := make(consensus.Headers, 0, len(blocks))
	states := make([]consensus.State, len(blocks))
	st, work := consensus.State{}, new(big.Int)
	for i, blk := range blocks {
		var err error
		if st, _, err = consensus.ValidateBlock(p, chain, st, blk, nil); err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		chain = append(chain, blk.Header)
		states[i] = st
		work.Add(work, consensus.Work(blk.Header))
	}
	if err := wantInt(work, wantWork); err != nil {
		return nil, fmt.Errorf("cumulative work: %w", err)
	}
	if err := wantInt(st.Supply(), wantSupply); err != nil {
		return nil, fmt.Errorf("supply: %w", err)
	}
	want, err := parseState(wantState)
	if err != nil {
		return nil, err
	}
	if len(want) != len(st) {
		return nil, fmt.Errorf("final state has %d accounts, want %d", len(st), len(want))
	}
	for addr, a := range want {
		got := st.Get(addr)
		if got.Balance.Cmp(a.Balance) != 0 || got.Nonce != a.Nonce {
			return nil, fmt.Errorf("account %x: got (%s, %d), want (%s, %d)", addr[:8], got.Balance, got.Nonce, a.Balance, a.Nonce)
		}
	}
	return states, nil
}

func parseState(rows [][3]string) (consensus.State, error) {
	st := consensus.State{}
	for _, r := range rows {
		addr, err := parseHash(r[0])
		if err != nil {
			return nil, err
		}
		bal, err := parseInt(r[1])
		if err != nil {
			return nil, err
		}
		nonce, err := strconv.ParseUint(r[2], 10, 64)
		if err != nil {
			return nil, err
		}
		st.Set(addr, consensus.Account{Balance: bal, Nonce: nonce})
	}
	return st, nil
}

func checkKey(skSeed, skPrf, pkSeed, wantPub, wantAddr string) error {
	var seeds [3][]byte
	for i, h := range []string{skSeed, skPrf, pkSeed} {
		b, err := hex.DecodeString(h)
		if err != nil {
			return err
		}
		seeds[i] = b
	}
	k, err := wallet.FromSeeds(seeds[0], seeds[1], seeds[2])
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(k.PublicKey()); got != wantPub {
		return fmt.Errorf("pubkey %s, want %s", got, wantPub)
	}
	if a := k.Address(); hex.EncodeToString(a[:]) != wantAddr {
		return fmt.Errorf("address %x, want %s", a, wantAddr)
	}
	return nil
}

func checkStateRoot(rows [][3]string, wantRoot string) error {
	st, err := parseState(rows)
	if err != nil {
		return err
	}
	if r := consensus.StateRoot(st); hex.EncodeToString(r[:]) != wantRoot {
		return fmt.Errorf("root %x, want %s", r, wantRoot)
	}
	return nil
}

func checkTx(c TxVector) error {
	raw, err := hex.DecodeString(c.Tx)
	if err != nil {
		return err
	}
	tx, err := consensus.DecodeTx(raw)
	if err != nil {
		return err
	}
	if c.Coinbase {
		cb, ok := tx.(*consensus.Coinbase)
		if !ok {
			return errors.New("decoded as a transfer, want coinbase")
		}
		if cb.Height != c.Height || hex.EncodeToString(cb.To[:]) != c.To || hex.EncodeToString(cb.Extra) != c.Extra {
			return errors.New("coinbase fields differ")
		}
		if !bytes.Equal(cb.Serialize(), raw) {
			return errors.New("coinbase does not re-serialize identically")
		}
		return wantInt(cb.Amount, c.Amount)
	}
	t, ok := tx.(*consensus.Transfer)
	if !ok {
		return errors.New("decoded as a coinbase, want transfer")
	}
	if !bytes.Equal(t.Serialize(), raw) {
		return errors.New("transfer does not re-serialize identically")
	}
	genesis, err := parseHash(c.GenesisHash)
	if err != nil {
		return err
	}
	if d := t.Digest(genesis); hex.EncodeToString(d[:]) != c.Digest {
		return fmt.Errorf("digest %x, want %s", d, c.Digest)
	}
	if got := t.VerifySignature(genesis); got != c.ValidSignature {
		return fmt.Errorf("signature valid = %v, want %v", got, c.ValidSignature)
	}
	if c.Sender == "" {
		return nil // corrupted-signature case: only the signature result is specified
	}
	if s := t.Sender(); hex.EncodeToString(s[:]) != c.Sender || hex.EncodeToString(t.To[:]) != c.To {
		return errors.New("sender or recipient differs")
	}
	if strconv.FormatUint(t.Nonce, 10) != c.Nonce {
		return fmt.Errorf("nonce %d, want %s", t.Nonce, c.Nonce)
	}
	return errors.Join(wantInt(t.Amount, c.Amount), wantInt(t.Fee, c.Fee))
}

func checkInvalid(p *consensus.Params, base consensus.Headers, parent consensus.State, headerHex string, hexTxs []string) error {
	blk, err := (&chainjson.BlockJSON{HeaderHex: headerHex, Txs: hexTxs}).ToBlock()
	if err != nil {
		return err
	}
	_, _, err = consensus.ValidateBlock(p, base, parent, blk, nil)
	if err == nil {
		return errors.New("accepted, want rejection")
	}
	if !errors.Is(err, consensus.ErrInvalid) {
		return fmt.Errorf("rejected with non-consensus error: %w", err)
	}
	return nil
}

func parseInt(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("bad integer %q", s)
	}
	return n, nil
}

func parseHash(s string) ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	if len(b) != 32 {
		return h, fmt.Errorf("hash must be 32 bytes, got %d", len(b))
	}
	copy(h[:], b)
	return h, nil
}

func wantInt(got *big.Int, want string) error {
	w, err := parseInt(want)
	if err != nil {
		return err
	}
	if got.Cmp(w) != 0 {
		return fmt.Errorf("got %s, want %s", got, want)
	}
	return nil
}
