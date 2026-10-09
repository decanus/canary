// Package conformance runs the consensus library against reference/test_vectors.json
// (SPEC.md §14).
package conformance

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/consensus"
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
	Chain struct {
		CumulativeWork string                `json:"cumulative_work"`
		Blocks         []chainjson.BlockJSON `json:"blocks"`
	} `json:"chain"`
	InvalidBlocks struct {
		ParentHeight int `json:"parent_height"`
		Cases        []struct {
			Name      string   `json:"name"`
			HeaderHex string   `json:"header_hex"`
			Txs       []string `json:"txs"`
			Reason    string   `json:"reason"`
		} `json:"cases"`
	} `json:"invalid_blocks"`
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

	blocks, err := chainjson.DecodeBlocks(v.Chain.Blocks)
	if err != nil {
		add("chain", "decode", err)
		return out
	}
	if err := checkChain(p, v.Chain.Blocks, blocks, v.Chain.CumulativeWork); err != nil {
		// The invalid cases are mutations of a chain block; with a broken replay they would be
		// rejected for the wrong reason and pass vacuously.
		add("chain", fmt.Sprintf("replay %d blocks", len(blocks)), err)
		add("invalid_blocks", "skipped", errors.New("chain replay failed"))
		return out
	}
	add("chain", fmt.Sprintf("replay %d blocks", len(blocks)), nil)

	ph := v.InvalidBlocks.ParentHeight
	if ph < 0 || ph+1 >= len(blocks) {
		add("invalid_blocks", "parent_height", fmt.Errorf("parent_height %d out of range", ph))
		return out
	}
	base := make(consensus.Headers, ph+1)
	for i := range base {
		base[i] = blocks[i].Header
	}
	// Control: the unmutated block must be accepted on the same base, so that each rejection
	// below is caused by its mutation.
	if err := consensus.ValidateBlock(p, base, blocks[ph+1], nil); err != nil {
		add("invalid_blocks", "control (unmutated block)", err)
		return out
	}
	add("invalid_blocks", "control (unmutated block)", nil)
	for _, c := range v.InvalidBlocks.Cases {
		add("invalid_blocks", c.Name, checkInvalid(p, base, c.HeaderHex, c.Txs))
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

func checkChain(p *consensus.Params, js []chainjson.BlockJSON, blocks []*consensus.Block, wantWork string) error {
	for i, blk := range blocks {
		h := blk.Hash()
		if got := hex.EncodeToString(h[:]); got != js[i].Hash {
			return fmt.Errorf("block %d hash %s, want %s", i, got, js[i].Hash)
		}
	}
	work, err := consensus.ValidateChain(p, blocks)
	if err != nil {
		return err
	}
	return wantInt(work, wantWork)
}

func checkInvalid(p *consensus.Params, base consensus.Headers, headerHex string, hexTxs []string) error {
	blk, err := (&chainjson.BlockJSON{HeaderHex: headerHex, Txs: hexTxs}).ToBlock()
	if err != nil {
		return err
	}
	err = consensus.ValidateBlock(p, base, blk, nil)
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
