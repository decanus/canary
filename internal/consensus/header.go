package consensus

import (
	"encoding/binary"
	"errors"
	"math/big"
)

const (
	// HeaderSize is the fixed serialized header size.
	HeaderSize = 176
	// Version is the only valid header version.
	Version = 2
)

// Header is the 176-byte block header of SPEC.md §4.1.
type Header struct {
	Version    uint32
	PrevHash   [32]byte
	MerkleRoot [32]byte
	StateRoot  [32]byte // account state after this block
	Time       uint32
	Bits       uint32
	CurveCtr   uint32
	N          *big.Int // claimed prime group order, 0 <= N < 2^256
	K          *big.Int // solution, 0 <= K < 2^256
}

var errHeaderSize = errors.New("header must be 176 bytes")

// PreHeader returns bytes [0, 144): everything except k.
func (h *Header) PreHeader() []byte {
	b := make([]byte, 0, HeaderSize)
	b = binary.LittleEndian.AppendUint32(b, h.Version)
	b = append(b, h.PrevHash[:]...)
	b = append(b, h.MerkleRoot[:]...)
	b = append(b, h.StateRoot[:]...)
	b = binary.LittleEndian.AppendUint32(b, h.Time)
	b = binary.LittleEndian.AppendUint32(b, h.Bits)
	b = binary.LittleEndian.AppendUint32(b, h.CurveCtr)
	n := le32(h.N)
	return append(b, n[:]...)
}

// Serialize returns the 176-byte header encoding.
func (h *Header) Serialize() []byte {
	k := le32(h.K)
	return append(h.PreHeader(), k[:]...)
}

// Hash returns blockHash = H2(header). It identifies and links blocks; it carries no work.
func (h *Header) Hash() [32]byte {
	return H2(h.Serialize())
}

// DeserializeHeader parses a 176-byte header.
func DeserializeHeader(b []byte) (*Header, error) {
	if len(b) != HeaderSize {
		return nil, errHeaderSize
	}
	h := &Header{
		Version:  binary.LittleEndian.Uint32(b[0:4]),
		Time:     binary.LittleEndian.Uint32(b[100:104]),
		Bits:     binary.LittleEndian.Uint32(b[104:108]),
		CurveCtr: binary.LittleEndian.Uint32(b[108:112]),
		N:        fromLE32(b[112:144]),
		K:        fromLE32(b[144:176]),
	}
	copy(h.PrevHash[:], b[4:36])
	copy(h.MerkleRoot[:], b[36:68])
	copy(h.StateRoot[:], b[68:100])
	return h, nil
}
