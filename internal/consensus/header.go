package consensus

import (
	"encoding/binary"
	"errors"
	"math/big"
)

const (
	// HeaderSize is the fixed serialized header size.
	HeaderSize = 144
	// preHeaderSize is the size of everything except k.
	preHeaderSize = 112
)

// Header is the 144-byte block header of SPEC.md §4.1.
type Header struct {
	Version    uint32
	PrevHash   [32]byte
	MerkleRoot [32]byte
	Time       uint32
	Bits       uint32
	CurveCtr   uint32
	N          *big.Int // claimed prime group order, 0 <= N < 2^256
	K          *big.Int // solution, 0 <= K < 2^256
}

var errHeaderSize = errors.New("header must be 144 bytes")

// PreHeader returns bytes [0, 112): everything except k.
func (h *Header) PreHeader() []byte {
	b := make([]byte, 0, HeaderSize)
	b = binary.LittleEndian.AppendUint32(b, h.Version)
	b = append(b, h.PrevHash[:]...)
	b = append(b, h.MerkleRoot[:]...)
	b = binary.LittleEndian.AppendUint32(b, h.Time)
	b = binary.LittleEndian.AppendUint32(b, h.Bits)
	b = binary.LittleEndian.AppendUint32(b, h.CurveCtr)
	n := le32(h.N)
	return append(b, n[:]...)
}

// Serialize returns the 144-byte header encoding.
func (h *Header) Serialize() []byte {
	k := le32(h.K)
	return append(h.PreHeader(), k[:]...)
}

// Hash returns blockHash = H2(header). It identifies and links blocks; it carries no work.
func (h *Header) Hash() [32]byte {
	return H2(h.Serialize())
}

// DeserializeHeader parses a 144-byte header.
func DeserializeHeader(b []byte) (*Header, error) {
	if len(b) != HeaderSize {
		return nil, errHeaderSize
	}
	h := &Header{
		Version:  binary.LittleEndian.Uint32(b[0:4]),
		Time:     binary.LittleEndian.Uint32(b[68:72]),
		Bits:     binary.LittleEndian.Uint32(b[72:76]),
		CurveCtr: binary.LittleEndian.Uint32(b[76:80]),
		N:        fromLE32(b[80:112]),
		K:        fromLE32(b[112:144]),
	}
	copy(h.PrevHash[:], b[4:36])
	copy(h.MerkleRoot[:], b[36:68])
	return h, nil
}
