// Package chainjson reads and writes the chain JSON format shared with the Python reference
// (SPEC.md §11). header_hex and txs are authoritative; the other block fields are informational.
package chainjson

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/decanus/canary/internal/consensus"
)

// BlockJSON is one block in the chain JSON format.
type BlockJSON struct {
	Hash       string   `json:"hash"`
	HeaderHex  string   `json:"header_hex"`
	Version    uint32   `json:"version"`
	PrevHash   string   `json:"prev_hash"`
	MerkleRoot string   `json:"merkle_root"`
	Time       uint32   `json:"time"`
	Bits       uint32   `json:"bits"`
	CurveCtr   uint32   `json:"curve_ctr"`
	N          string   `json:"n"`
	K          string   `json:"k"`
	Txs        []string `json:"txs"`
}

// File is a chain JSON document.
type File struct {
	Params consensus.Params `json:"params"`
	Blocks []BlockJSON      `json:"blocks"`
}

// ToBlock decodes the authoritative fields (header_hex, txs).
func (b *BlockJSON) ToBlock() (*consensus.Block, error) {
	hb, err := hex.DecodeString(b.HeaderHex)
	if err != nil {
		return nil, fmt.Errorf("header_hex: %w", err)
	}
	h, err := consensus.DeserializeHeader(hb)
	if err != nil {
		return nil, err
	}
	txs, err := DecodeTxs(b.Txs)
	if err != nil {
		return nil, err
	}
	return &consensus.Block{Header: h, Txs: txs}, nil
}

// DecodeTxs decodes a list of hex transactions.
func DecodeTxs(hexTxs []string) ([][]byte, error) {
	txs := make([][]byte, len(hexTxs))
	for i, t := range hexTxs {
		tx, err := hex.DecodeString(t)
		if err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
		txs[i] = tx
	}
	return txs, nil
}

// FromBlock encodes blk with all informational fields filled in.
func FromBlock(blk *consensus.Block) BlockJSON {
	h := blk.Header
	hash := h.Hash()
	txs := make([]string, len(blk.Txs))
	for i, t := range blk.Txs {
		txs[i] = hex.EncodeToString(t)
	}
	return BlockJSON{
		Hash:       hex.EncodeToString(hash[:]),
		HeaderHex:  hex.EncodeToString(h.Serialize()),
		Version:    h.Version,
		PrevHash:   hex.EncodeToString(h.PrevHash[:]),
		MerkleRoot: hex.EncodeToString(h.MerkleRoot[:]),
		Time:       h.Time,
		Bits:       h.Bits,
		CurveCtr:   h.CurveCtr,
		N:          h.N.String(),
		K:          h.K.String(),
		Txs:        txs,
	}
}

// Load reads a chain JSON file and decodes its blocks.
func Load(path string) (*consensus.Params, []*consensus.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, err
	}
	if err := f.Params.Validate(); err != nil {
		return nil, nil, err
	}
	blocks, err := DecodeBlocks(f.Blocks)
	if err != nil {
		return nil, nil, err
	}
	return &f.Params, blocks, nil
}

// DecodeBlocks decodes a list of JSON blocks.
func DecodeBlocks(bs []BlockJSON) ([]*consensus.Block, error) {
	blocks := make([]*consensus.Block, len(bs))
	for i := range bs {
		blk, err := bs[i].ToBlock()
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		blocks[i] = blk
	}
	return blocks, nil
}

// Save writes params and blocks as a chain JSON file.
func Save(path string, p *consensus.Params, blocks []*consensus.Block) error {
	f := File{Params: *p, Blocks: make([]BlockJSON, len(blocks))}
	for i, b := range blocks {
		f.Blocks[i] = FromBlock(b)
	}
	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
