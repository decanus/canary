package p2p

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/decanus/canary/internal/consensus"
)

func TestStatusRoundTrip(t *testing.T) {
	in := Status{Version: 1, Height: 42, Work: new(big.Int).Lsh(big.NewInt(3), 200)}
	in.Tip[0] = 7
	var buf bytes.Buffer
	if err := writeStatus(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := readStatus(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != in.Version || out.Height != in.Height || out.Tip != in.Tip || out.Work.Cmp(in.Work) != 0 {
		t.Fatalf("got %+v, want %+v", out, in)
	}
}

func TestLocatorAndBlocksRoundTrip(t *testing.T) {
	loc := [][32]byte{{1}, {2}, {3}}
	var buf bytes.Buffer
	writeLocator(&buf, loc)
	got, err := readLocator(&buf)
	if err != nil || len(got) != 3 || got[2] != loc[2] {
		t.Fatalf("locator: %v %v", got, err)
	}

	h := &consensus.Header{Version: 1, N: big.NewInt(5), K: big.NewInt(6)}
	blks := []*consensus.Block{{Header: h, Txs: [][]byte{[]byte("a")}}, {Header: h, Txs: [][]byte{[]byte("b"), {}}}}
	buf.Reset()
	writeBlocks(&buf, blks)
	out, err := readBlocks(&buf)
	if err != nil || len(out) != 2 || out[1].Hash() != blks[1].Hash() {
		t.Fatalf("blocks: %v", err)
	}

	// Undecodable block bytes are an invalid-block offence.
	bad := []byte{1, 0, 0, 0, 3, 0, 0, 0, 1, 2, 3}
	if _, err := readBlocks(bytes.NewReader(bad)); err == nil {
		t.Fatal("decoded garbage")
	}
}
