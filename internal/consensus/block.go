package consensus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// v0.1 block limits (SPEC.md §4.2).
const (
	MaxTxs       = 1000
	MaxTxSize    = 100_000
	MaxBlockSize = 1_000_000
)

// Block is a header plus a list of opaque transactions; Txs[0] is conventionally the coinbase.
type Block struct {
	Header *Header
	Txs    [][]byte
}

// WellFormed reports whether b can be hashed and serialized: header present and N, K in
// [0, 2^256). Blocks from DeserializeBlock always are.
func (b *Block) WellFormed() bool {
	if b == nil || b.Header == nil {
		return false
	}
	for _, x := range []*big.Int{b.Header.N, b.Header.K} {
		if x == nil || x.Sign() < 0 || x.BitLen() > 256 {
			return false
		}
	}
	return true
}

// Hash returns the block hash (the hash of its header).
func (b *Block) Hash() [32]byte { return b.Header.Hash() }

// Serialize returns header ‖ varint(len(txs)) ‖ (varint(len(tx)) ‖ tx)*.
func (b *Block) Serialize() []byte {
	out := b.Header.Serialize()
	out = appendVarint(out, uint64(len(b.Txs)))
	for _, tx := range b.Txs {
		out = appendVarint(out, uint64(len(tx)))
		out = append(out, tx...)
	}
	return out
}

// SerializedSize returns len(b.Serialize()) without allocating the encoding.
func (b *Block) SerializedSize() int {
	n := HeaderSize + varintSize(uint64(len(b.Txs)))
	for _, tx := range b.Txs {
		n += varintSize(uint64(len(tx))) + len(tx)
	}
	return n
}

var errTruncated = errors.New("truncated block")

// checkTxCount and checkTxSize enforce the v0.1 limits of SPEC.md §4.2; they are shared by
// DeserializeBlock and ValidateBlock.
func checkTxCount(count uint64) error {
	if count < 1 || count > MaxTxs {
		return fmt.Errorf("tx count %d out of range [1, %d]", count, MaxTxs)
	}
	return nil
}

func checkTxSize(i int, size uint64) error {
	if size > MaxTxSize {
		return fmt.Errorf("tx %d exceeds %d bytes", i, MaxTxSize)
	}
	return nil
}

// DeserializeBlock parses a serialized block, enforcing the v0.1 size limits.
func DeserializeBlock(b []byte) (*Block, error) {
	if len(b) > MaxBlockSize {
		return nil, fmt.Errorf("block exceeds %d bytes", MaxBlockSize)
	}
	if len(b) < HeaderSize {
		return nil, errTruncated
	}
	h, err := DeserializeHeader(b[:HeaderSize])
	if err != nil {
		return nil, err
	}
	rest := b[HeaderSize:]
	count, n, err := readVarint(rest)
	if err != nil {
		return nil, err
	}
	rest = rest[n:]
	if err := checkTxCount(count); err != nil {
		return nil, err
	}
	txs := make([][]byte, 0, count)
	for i := uint64(0); i < count; i++ {
		size, n, err := readVarint(rest)
		if err != nil {
			return nil, err
		}
		rest = rest[n:]
		if err := checkTxSize(int(i), size); err != nil {
			return nil, err
		}
		if uint64(len(rest)) < size {
			return nil, errTruncated
		}
		txs = append(txs, append([]byte(nil), rest[:size]...))
		rest = rest[size:]
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after block")
	}
	return &Block{Header: h, Txs: txs}, nil
}

// appendVarint appends a Bitcoin CompactSize integer.
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 0xfd:
		return append(b, byte(v))
	case v <= 0xffff:
		return binary.LittleEndian.AppendUint16(append(b, 0xfd), uint16(v))
	case v <= 0xffffffff:
		return binary.LittleEndian.AppendUint32(append(b, 0xfe), uint32(v))
	default:
		return binary.LittleEndian.AppendUint64(append(b, 0xff), v)
	}
}

func varintSize(v uint64) int {
	switch {
	case v < 0xfd:
		return 1
	case v <= 0xffff:
		return 3
	case v <= 0xffffffff:
		return 5
	default:
		return 9
	}
}

// readVarint reads a CompactSize integer and returns it with the number of bytes consumed.
// SPEC: the Python reference has no block serialization. Like Bitcoin Core we reject non-minimal
// encodings so that every block has exactly one serialization.
func readVarint(b []byte) (uint64, int, error) {
	if len(b) < 1 {
		return 0, 0, errTruncated
	}
	var v uint64
	var n int
	switch b[0] {
	case 0xfd:
		if len(b) < 3 {
			return 0, 0, errTruncated
		}
		v, n = uint64(binary.LittleEndian.Uint16(b[1:])), 3
	case 0xfe:
		if len(b) < 5 {
			return 0, 0, errTruncated
		}
		v, n = uint64(binary.LittleEndian.Uint32(b[1:])), 5
	case 0xff:
		if len(b) < 9 {
			return 0, 0, errTruncated
		}
		v, n = binary.LittleEndian.Uint64(b[1:]), 9
	default:
		return uint64(b[0]), 1, nil
	}
	if varintSize(v) != n {
		return 0, 0, errors.New("non-canonical varint")
	}
	return v, n, nil
}
