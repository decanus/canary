package consensus

import (
	"encoding/binary"
	"errors"
	"math/big"
)

// Transaction kinds and signature schemes (SPEC.md §4.4).
const (
	KindCoinbase = 0
	KindTransfer = 1

	SchemeSLHDSA = 1

	MaxCoinbaseExtra = 64
	coinbaseFixed    = 1 + 4 + 32 + 16 + 1
	transferBodySize = 1 + 1 + 32 + 32 + 16 + 16 + 8
	TransferSize     = transferBodySize + SignatureSize
)

var (
	// U128Max is the largest balance or amount.
	U128Max = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 128), bigOne)
)

// Address is the hash of a signature scheme and public key.
type Address [32]byte

// AddressOf returns H(tag("addr") ‖ u8 scheme ‖ pubkey).
func AddressOf(scheme byte, pubkey []byte) Address {
	return H(Tag("addr"), []byte{scheme}, pubkey)
}

// Coinbase is txs[0] of every block: it pays the reward plus fees to To.
type Coinbase struct {
	Height uint32
	To     Address
	Amount *big.Int
	Extra  []byte
}

// Serialize encodes the coinbase.
func (c *Coinbase) Serialize() []byte {
	b := []byte{KindCoinbase}
	b = binary.LittleEndian.AppendUint32(b, c.Height)
	b = append(b, c.To[:]...)
	b = appendU128(b, c.Amount)
	b = append(b, byte(len(c.Extra)))
	return append(b, c.Extra...)
}

// Transfer moves Amount from the key's account to To, paying Fee to the miner.
type Transfer struct {
	Scheme byte
	PubKey []byte // PubKeySize bytes
	To     Address
	Amount *big.Int
	Fee    *big.Int
	Nonce  uint64
	Sig    []byte // SignatureSize bytes
}

// Body returns the signed part of the transfer (everything but the signature).
func (t *Transfer) Body() []byte {
	b := []byte{KindTransfer, t.Scheme}
	b = append(b, t.PubKey...)
	b = append(b, t.To[:]...)
	b = appendU128(b, t.Amount)
	b = appendU128(b, t.Fee)
	return binary.LittleEndian.AppendUint64(b, t.Nonce)
}

// Serialize encodes the transfer.
func (t *Transfer) Serialize() []byte { return append(t.Body(), t.Sig...) }

// Sender returns the address that pays for the transfer.
func (t *Transfer) Sender() Address { return AddressOf(t.Scheme, t.PubKey) }

// Digest returns H(tag("tx") ‖ genesisHash ‖ body), the message that is signed.
func (t *Transfer) Digest(genesisHash [32]byte) [32]byte {
	return H(Tag("tx"), genesisHash[:], t.Body())
}

// VerifySignature checks the transfer's signature for the chain with the given genesis hash.
func (t *Transfer) VerifySignature(genesisHash [32]byte) bool {
	d := t.Digest(genesisHash)
	return t.Scheme == SchemeSLHDSA && verifySLHDSA(t.PubKey, d[:], t.Sig)
}

var errTxEncoding = errors.New("bad transaction encoding")

// DecodeTx decodes one transaction exactly: it returns a *Coinbase or a *Transfer.
func DecodeTx(b []byte) (any, error) {
	if len(b) == 0 {
		return nil, errTxEncoding
	}
	switch b[0] {
	case KindCoinbase:
		if len(b) < coinbaseFixed {
			return nil, errTxEncoding
		}
		extra := int(b[coinbaseFixed-1])
		if extra > MaxCoinbaseExtra || len(b) != coinbaseFixed+extra {
			return nil, errTxEncoding
		}
		c := &Coinbase{
			Height: binary.LittleEndian.Uint32(b[1:5]),
			Amount: readU128(b[37:53]),
			Extra:  append([]byte(nil), b[coinbaseFixed:]...),
		}
		copy(c.To[:], b[5:37])
		return c, nil
	case KindTransfer:
		if len(b) != TransferSize || b[1] != SchemeSLHDSA {
			return nil, errTxEncoding
		}
		t := &Transfer{
			Scheme: b[1],
			PubKey: append([]byte(nil), b[2:34]...),
			Amount: readU128(b[66:82]),
			Fee:    readU128(b[82:98]),
			Nonce:  binary.LittleEndian.Uint64(b[98:106]),
			Sig:    append([]byte(nil), b[106:]...),
		}
		copy(t.To[:], b[34:66])
		return t, nil
	}
	return nil, errTxEncoding
}

// DecodeBlockTxs applies rule 8: every tx decodes, txs[0] is the only coinbase and carries this
// height, and the genesis block has no transfers.
func DecodeBlockTxs(txs [][]byte, height int) (*Coinbase, []*Transfer, error) {
	if len(txs) == 0 {
		return nil, nil, errors.New("no transactions")
	}
	var cb *Coinbase
	var transfers []*Transfer
	for i, raw := range txs {
		tx, err := DecodeTx(raw)
		if err != nil {
			return nil, nil, err
		}
		switch tx := tx.(type) {
		case *Coinbase:
			if i != 0 {
				return nil, nil, errors.New("coinbase is not the first transaction")
			}
			cb = tx
		case *Transfer:
			if i == 0 {
				return nil, nil, errors.New("first transaction is not a coinbase")
			}
			transfers = append(transfers, tx)
		}
	}
	if int64(cb.Height) != int64(height) {
		return nil, nil, errors.New("coinbase height mismatch")
	}
	if height == 0 && len(transfers) > 0 {
		return nil, nil, errors.New("transfers in genesis block")
	}
	return cb, transfers, nil
}

func appendU128(b []byte, x *big.Int) []byte {
	var buf [16]byte
	x.FillBytes(buf[:])
	for i := 15; i >= 0; i-- {
		b = append(b, buf[i])
	}
	return b
}

func readU128(b []byte) *big.Int {
	var be [16]byte
	for i := range be {
		be[i] = b[15-i]
	}
	return new(big.Int).SetBytes(be[:])
}
