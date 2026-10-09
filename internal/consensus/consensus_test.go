package consensus

import (
	"bytes"
	"math/big"
	"testing"
)

func TestRetargetDeltaLargeInputs(t *testing.T) {
	// Mainnet-sized epochs overflow int64 when raised to the 4th power.
	exp := int64(2016 * 600)
	cases := []struct{ actual, want int64 }{{exp, 0}, {exp / 4, 4}, {4 * exp, -4}, {exp / 2, 2}, {2 * exp, -2}}
	for _, c := range cases {
		if got := RetargetDelta(exp, c.actual, 4); got != c.want {
			t.Errorf("RetargetDelta(%d, %d) = %d, want %d", exp, c.actual, got, c.want)
		}
	}
}

func TestNextBits(t *testing.T) {
	p := Prototype
	mk := func(n int, step uint32, bits uint32) Headers {
		hs := make(Headers, n)
		for i := range hs {
			hs[i] = &Header{Time: 1000 + uint32(i)*step, Bits: bits, N: new(big.Int), K: new(big.Int)}
		}
		return hs
	}
	if got := NextBits(&p, Headers{}); got != p.GenesisBits {
		t.Errorf("genesis: %d", got)
	}
	if got := NextBits(&p, mk(10, 1, 36)); got != 36 {
		t.Errorf("mid-epoch: %d", got)
	}
	if got := NextBits(&p, mk(64, 10, 36)); got != 36 {
		t.Errorf("on-target: %d", got)
	}
	if got := NextBits(&p, mk(64, 1, 36)); got != 40 {
		t.Errorf("fast: %d", got)
	}
	if got := NextBits(&p, mk(64, 1000, 33)); got != p.MinBits {
		t.Errorf("slow clamp: %d", got)
	}
}

func TestMerkleRoot(t *testing.T) {
	a, b, c := []byte("a"), []byte("b"), []byte("c")
	if MerkleRoot([][]byte{a}) != H2(a) {
		t.Error("single tx root")
	}
	ha, hb, hc := H2(a), H2(b), H2(c)
	ab := H2(ha[:], hb[:])
	cc := H2(hc[:], hc[:])
	if MerkleRoot([][]byte{a, b, c}) != H2(ab[:], cc[:]) {
		t.Error("three tx root")
	}
}

func TestCurveArithmetic(t *testing.T) {
	c := DeriveCurve([32]byte{}, 36, 0)
	if c.G == nil {
		t.Skip("curve invalid")
	}
	g := c.G
	if !c.OnCurve(g) {
		t.Fatal("G not on curve")
	}
	two := c.Add(g, g)
	three := c.Add(two, g)
	if !c.Mul(big.NewInt(3), g).Equal(three) || !c.OnCurve(three) {
		t.Error("3G")
	}
	if c.Add(g, c.Neg(g)) != nil {
		t.Error("G + -G != O")
	}
	if !c.Mul(big.NewInt(-2), g).Equal(c.Neg(two)) {
		t.Error("-2G")
	}
}

func TestBlockRoundTrip(t *testing.T) {
	txs := [][]byte{Coinbase(7, "miner", nil), make([]byte, 300), {}}
	h := &Header{Version: 1, Time: 5, Bits: 36, CurveCtr: 9, N: big.NewInt(12345), K: new(big.Int).Lsh(bigOne, 255)}
	h.PrevHash[0] = 1
	h.MerkleRoot = MerkleRoot(txs)
	blk := &Block{Header: h, Txs: txs}
	enc := blk.Serialize()
	if len(enc) != blk.SerializedSize() {
		t.Fatalf("SerializedSize %d != %d", blk.SerializedSize(), len(enc))
	}
	dec, err := DeserializeBlock(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Serialize(), enc) || dec.Hash() != blk.Hash() {
		t.Fatal("round trip mismatch")
	}
	// Non-canonical varint for the tx count.
	bad := append(append([]byte{}, enc[:HeaderSize]...), 0xfd, 3, 0)
	bad = append(bad, enc[HeaderSize+1:]...)
	if _, err := DeserializeBlock(bad); err == nil {
		t.Error("accepted non-canonical varint")
	}
}

func FuzzHeaderRoundTrip(f *testing.F) {
	f.Add(make([]byte, HeaderSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DeserializeHeader(b)
		if err != nil {
			if len(b) == HeaderSize {
				t.Fatal(err)
			}
			return
		}
		if !bytes.Equal(h.Serialize(), b) {
			t.Fatal("header round trip mismatch")
		}
	})
}

func FuzzBlockRoundTrip(f *testing.F) {
	h := &Header{Version: 1, N: big.NewInt(1), K: big.NewInt(1)}
	f.Add((&Block{Header: h, Txs: [][]byte{[]byte("tx")}}).Serialize())
	f.Fuzz(func(t *testing.T, b []byte) {
		blk, err := DeserializeBlock(b)
		if err != nil {
			return
		}
		if !bytes.Equal(blk.Serialize(), b) {
			t.Fatal("block round trip mismatch")
		}
	})
}
