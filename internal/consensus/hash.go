package consensus

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// H is SHA-256 over the concatenation of parts.
func H(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// H2 is SHA-256(SHA-256(x)) over the concatenation of parts.
func H2(parts ...[]byte) [32]byte {
	first := H(parts...)
	return sha256.Sum256(first[:])
}

// Tag returns the domain-separation tag "canary/" + name + 0x00.
func Tag(name string) []byte {
	return append([]byte("canary/"+name), 0)
}

func u32le(x uint32) []byte {
	return binary.LittleEndian.AppendUint32(nil, x)
}

// intBE reads b as an unsigned big-endian integer.
func intBE(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// le32 encodes x (0 <= x < 2^256) as a 32-byte little-endian integer.
func le32(x *big.Int) [32]byte {
	var be [32]byte
	x.FillBytes(be[:])
	var out [32]byte
	for i := range be {
		out[i] = be[31-i]
	}
	return out
}

// fromLE32 decodes a 32-byte little-endian unsigned integer.
func fromLE32(b []byte) *big.Int {
	var be [32]byte
	for i := 0; i < 32; i++ {
		be[i] = b[31-i]
	}
	return new(big.Int).SetBytes(be[:])
}
